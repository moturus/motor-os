use std::fs;
use std::path::Path;

use crate::cli::Verbosity;
use crate::diagnostic::{Error, Result};

pub fn execute(verbosity: Verbosity) -> Result<i32> {
    let root = crate::config::Config::load_global()?.cache_directory()?;
    let removed = clean(&root)?;
    if verbosity != Verbosity::Quiet {
        if removed {
            eprintln!("Removed global Lorry cache from `{}`", root.display());
        } else {
            eprintln!("Removed 0 global Lorry cache entries");
        }
    }
    Ok(0)
}

fn clean(root: &Path) -> Result<bool> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::failure(format!(
                "refusing to clean global Lorry cache `{}` because it is not a real directory",
                root.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect global Lorry cache `{}`: {error}",
                root.display()
            )));
        }
    }
    fs::remove_dir_all(root).map_err(|error| {
        Error::failure(format!(
            "failed to remove global Lorry cache `{}`: {error}",
            root.display()
        ))
    })?;
    Ok(true)
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
            let path = std::env::temp_dir().join(format!(
                "lorry-cache-clean-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn removes_only_the_selected_cache_root() {
        let fixture = Fixture::new("root");
        let root = fixture.0.join(".cache/lorry");
        fs::create_dir_all(root.join("v1/units")).unwrap();
        fs::create_dir_all(root.join("sources/demo-1.0.0-digest")).unwrap();
        fs::write(fixture.0.join("keep"), "unrelated").unwrap();

        assert!(clean(&root).unwrap());
        assert!(!root.exists());
        assert_eq!(
            fs::read_to_string(fixture.0.join("keep")).unwrap(),
            "unrelated"
        );
        assert!(!clean(&root).unwrap());
    }

    #[test]
    fn refuses_a_non_directory_cache_root() {
        let fixture = Fixture::new("file");
        let root = fixture.0.join("lorry");
        fs::write(&root, "not a cache directory").unwrap();

        assert!(
            clean(&root)
                .unwrap_err()
                .render()
                .contains("not a real directory")
        );
        assert!(root.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlinked_cache_root() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("symlink");
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside).unwrap();
        let root = fixture.0.join("lorry");
        symlink(&outside, &root).unwrap();

        assert!(
            clean(&root)
                .unwrap_err()
                .render()
                .contains("not a real directory")
        );
        assert!(outside.is_dir());
    }
}
