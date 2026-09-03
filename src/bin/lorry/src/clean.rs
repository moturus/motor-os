use crate::cli::{CleanOptions, Verbosity};
use crate::config::Config;
use crate::diagnostic::{Error, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub fn execute(options: &CleanOptions, package: Option<&str>, verbosity: Verbosity) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let manifest = crate::manifest::Manifest::load_selected(&current, package)?;
    let target_directory = target_directory(&current, &manifest, options.target_dir.as_deref());
    let artifact_root = super::engine::artifact_root_in(&manifest, &target_directory);

    let target = if options.build.release || options.build.target.is_some() {
        Config::load(&manifest.root)?.selected_target(options.build.target.as_deref())?
    } else {
        None
    };
    let removed = clean_manifest_artifacts(
        &manifest,
        &target_directory,
        options.build.release,
        target.as_deref(),
    )?;
    if verbosity != Verbosity::Quiet {
        if removed {
            eprintln!("Removed Lorry artifacts from `{}`", artifact_root.display());
        } else {
            eprintln!("Removed 0 Lorry artifacts");
        }
    }
    Ok(0)
}

fn target_directory(
    current: &Path,
    manifest: &crate::manifest::Manifest,
    requested: Option<&str>,
) -> PathBuf {
    match requested.map(Path::new) {
        Some(path) if path.is_absolute() => path.to_owned(),
        Some(path) => current.join(path),
        None => manifest.workspace_root.join("target"),
    }
}

#[cfg(test)]
fn clean_artifacts(root: &Path, release: bool, target: Option<&str>) -> Result<bool> {
    clean_artifacts_root(&root.join("target/lorry"), release, target)
}

fn clean_manifest_artifacts(
    manifest: &crate::manifest::Manifest,
    target_parent: &Path,
    release: bool,
    target: Option<&str>,
) -> Result<bool> {
    if manifest.root == manifest.workspace_root {
        return clean_artifacts_root(&target_parent.join("lorry"), release, target);
    }
    if !real_directory(target_parent, "artifact parent")? {
        return Ok(false);
    }
    let lorry_root = target_parent.join("lorry");
    if !real_directory(&lorry_root, "Lorry artifact root")? {
        return Ok(false);
    }
    let packages = lorry_root.join("packages");
    if !real_directory(&packages, "workspace package artifact root")? {
        return Ok(false);
    }
    let selected = packages.join(&manifest.name);
    if !real_directory(&selected, "selected package artifact root")? {
        return Ok(false);
    }
    clean_artifacts_root(&selected, release, target)
}

fn clean_artifacts_root(root: &Path, release: bool, target: Option<&str>) -> Result<bool> {
    let parent = root
        .parent()
        .ok_or_else(|| Error::failure("artifact root has no parent"))?;
    if !real_directory(parent, "artifact parent")? || !real_directory(root, "Lorry artifact root")?
    {
        return Ok(false);
    }
    if !release && target.is_none() {
        remove_directory(root)?;
        return Ok(true);
    }
    let mut selected_parent = root.to_owned();
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
    let cache = root.join(".cache");
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
        fixture.directory("global-cache/v1/units");

        assert!(clean_artifacts(&fixture.0, false, None).unwrap());
        assert!(!fixture.0.join("target/lorry").exists());
        assert!(fixture.0.join("target/debug").is_dir());
        assert!(fixture.0.join("global-cache/v1/units").is_dir());
        assert!(!clean_artifacts(&fixture.0, false, None).unwrap());
    }

    #[test]
    fn selective_clean_removes_profile_and_project_cache() {
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

    #[test]
    fn cleans_only_the_selected_workspace_member() {
        let fixture = Fixture::new("workspace");
        fs::create_dir_all(fixture.0.join("app/src")).unwrap();
        fs::write(
            fixture.0.join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        fs::write(
            fixture.0.join("app/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(fixture.0.join("app/src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            fixture.0.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fixture.directory("target/lorry/packages/app/debug");
        fixture.directory("target/lorry/packages/other/debug");
        let manifest = crate::manifest::Manifest::load_selected(&fixture.0, Some("app")).unwrap();
        assert_eq!(
            target_directory(&manifest.root, &manifest, None),
            fixture.0.join("target")
        );
        assert_eq!(
            target_directory(&manifest.root, &manifest, Some("editor-target")),
            manifest.root.join("editor-target")
        );

        assert!(
            clean_manifest_artifacts(&manifest, &fixture.0.join("target"), false, None).unwrap()
        );
        assert!(!fixture.0.join("target/lorry/packages/app").exists());
        assert!(fixture.0.join("target/lorry/packages/other/debug").is_dir());

        fixture.directory("editor-target/lorry/packages/app/debug");
        fixture.directory("editor-target/lorry/packages/other/debug");
        assert!(
            clean_manifest_artifacts(&manifest, &fixture.0.join("editor-target"), false, None)
                .unwrap()
        );
        assert!(!fixture.0.join("editor-target/lorry/packages/app").exists());
        assert!(
            fixture
                .0
                .join("editor-target/lorry/packages/other/debug")
                .is_dir()
        );
    }

    #[test]
    fn cleans_a_custom_target_directory_only() {
        let fixture = Fixture::new("custom-target");
        fixture.directory("target/lorry/debug");
        let custom = fixture.directory("editor-target/lorry/debug");

        assert!(clean_artifacts_root(custom.parent().unwrap(), false, None).unwrap());
        assert!(!fixture.0.join("editor-target/lorry").exists());
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
