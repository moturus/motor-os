use crate::cli::{BuildOptions, Verbosity};
use crate::config::Config;
use crate::diagnostic::{Error, Result};
use std::env;
use std::fs;
use std::path::Path;

pub fn execute(options: &BuildOptions, verbosity: Verbosity) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let root = fs::canonicalize(&current).map_err(|error| {
        Error::failure(format!(
            "failed to canonicalize package directory `{}`: {error}",
            current.display()
        ))
    })?;
    let manifest = root.join("Cargo.toml");
    if !manifest.is_file() {
        return Err(Error::failure(format!(
            "manifest `{}` does not exist; Lorry does not search parent directories",
            manifest.display()
        )));
    }

    let target = if options.release || options.target.is_some() {
        Config::load(&root)?.selected_target(options.target.as_deref())?
    } else {
        None
    };
    let removed = clean_artifacts(&root, options.release, target.as_deref())?;
    if verbosity != Verbosity::Quiet {
        if removed {
            eprintln!(
                "Removed Lorry artifacts from `{}`",
                root.join("target/lorry").display()
            );
        } else {
            eprintln!("Removed 0 Lorry artifacts");
        }
    }
    Ok(0)
}

fn clean_artifacts(root: &Path, release: bool, target: Option<&str>) -> Result<bool> {
    let target_parent = root.join("target");
    if !real_directory(&target_parent, "artifact parent")? {
        return Ok(false);
    }
    let lorry_root = target_parent.join("lorry");
    if !real_directory(&lorry_root, "Lorry artifact root")? {
        return Ok(false);
    }

    if !release && target.is_none() {
        remove_directory(&lorry_root)?;
        return Ok(true);
    }

    let mut selected_parent = lorry_root.clone();
    if let Some(target) = target {
        selected_parent.push(target);
        real_directory(&selected_parent, "target artifact directory")?;
    }
    let selected = if release {
        selected_parent.join("release")
    } else {
        selected_parent
    };
    let selected_exists = real_directory(&selected, "selected artifact directory")?;
    let cache = lorry_root.join(".cache");
    let cache_exists = real_directory(&cache, "Lorry artifact cache")?;

    if selected_exists {
        remove_directory(&selected)?;
    }
    if cache_exists && cache != selected {
        remove_directory(&cache)?;
    }
    Ok(selected_exists || cache_exists)
}

fn real_directory(path: &Path, description: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(Error::failure(format!(
                "refusing to clean {description} `{}` because it is not a real directory",
                path.display()
            )))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect {description} `{}`: {error}",
            path.display()
        ))),
    }
}

fn remove_directory(path: &Path) -> Result<()> {
    fs::remove_dir_all(path).map_err(|error| {
        Error::failure(format!(
            "failed to remove Lorry artifacts `{}`: {error}",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let path = env::temp_dir().join(format!(
                "lorry-clean-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn directory(&self, relative: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(&path).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cleans_only_lorrys_complete_artifact_root() {
        let fixture = Fixture::new("all");
        fixture.directory("target/debug");
        fixture.directory("target/lorry/debug/deps");
        fixture.directory("target/lorry/.cache/objects");

        assert!(clean_artifacts(&fixture.0, false, None).unwrap());
        assert!(!fixture.0.join("target/lorry").exists());
        assert!(fixture.0.join("target/debug").is_dir());
        assert!(!clean_artifacts(&fixture.0, false, None).unwrap());
    }

    #[test]
    fn selective_clean_removes_profile_and_shared_cache() {
        let fixture = Fixture::new("release");
        fixture.directory("target/lorry/debug");
        fixture.directory("target/lorry/release/deps");
        fixture.directory("target/lorry/.cache/objects");

        assert!(clean_artifacts(&fixture.0, true, None).unwrap());
        assert!(fixture.0.join("target/lorry/debug").is_dir());
        assert!(!fixture.0.join("target/lorry/release").exists());
        assert!(!fixture.0.join("target/lorry/.cache").exists());

        fixture.directory("target/lorry/x86_64-unknown-motor/debug/deps");
        fixture.directory("target/lorry/x86_64-unknown-motor/release/deps");
        assert!(clean_artifacts(&fixture.0, false, Some("x86_64-unknown-motor")).unwrap());
        assert!(!fixture.0.join("target/lorry/x86_64-unknown-motor").exists());
        assert!(fixture.0.join("target/lorry/debug").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_artifact_root() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("symlink");
        let outside = fixture.directory("outside");
        fixture.directory("target");
        symlink(&outside, fixture.0.join("target/lorry")).unwrap();

        let error = clean_artifacts(&fixture.0, false, None).unwrap_err();
        assert!(error.render().contains("not a real directory"));
        assert!(outside.is_dir());
    }
}
