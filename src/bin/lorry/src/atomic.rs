use crate::diagnostic::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct AtomicDirectory {
    path: PathBuf,
    committed: bool,
}

impl AtomicDirectory {
    pub fn new(parent: &Path, label: &str) -> Result<Self> {
        fs::create_dir_all(parent).map_err(|error| {
            Error::failure(format!(
                "failed to create output parent `{}`: {error}",
                parent.display()
            ))
        })?;
        for _ in 0..100 {
            let path = parent.join(unique_name(label, "staging"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_private(&path)?;
                    return Ok(Self {
                        path,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Error::failure(format!(
                        "failed to create private output staging `{}`: {error}",
                        path.display()
                    )));
                }
            }
        }
        Err(Error::failure(format!(
            "could not allocate private output staging below `{}`",
            parent.display()
        )))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn commit(mut self, destination: &Path) -> Result<()> {
        let parent = destination.parent().ok_or_else(|| {
            Error::failure(format!(
                "output destination `{}` has no parent",
                destination.display()
            ))
        })?;
        if self.path.parent() != Some(parent) {
            return Err(Error::failure(
                "atomic output staging and destination are not siblings",
            ));
        }

        let backup = parent.join(unique_name(
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("output"),
            "previous",
        ));
        let had_previous = match fs::symlink_metadata(destination) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(Error::failure(format!(
                    "refusing to replace non-directory output `{}`",
                    destination.display()
                )));
            }
            Ok(_) => {
                fs::rename(destination, &backup).map_err(|error| {
                    Error::failure(format!(
                        "failed to preserve previous output `{}`: {error}",
                        destination.display()
                    ))
                })?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to inspect output `{}`: {error}",
                    destination.display()
                )));
            }
        };

        if let Err(error) = fs::rename(&self.path, destination) {
            if had_previous {
                let _ = fs::rename(&backup, destination);
            }
            return Err(Error::failure(format!(
                "failed to atomically install output `{}`: {error}",
                destination.display()
            )));
        }
        self.committed = true;
        if had_previous {
            fs::remove_dir_all(&backup).map_err(|error| {
                Error::failure(format!(
                    "installed new output but failed to remove previous output `{}`: {error}",
                    backup.display()
                ))
            })?;
        }
        Ok(())
    }
}

impl Drop for AtomicDirectory {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn unique_name(label: &str, role: &str) -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(
        ".{label}.lorry-{role}-{}-{time:x}-{sequence:x}",
        std::process::id()
    )
}

fn set_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            Error::failure(format!(
                "failed to make staging `{}` private: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(unique_name(label, "test"));
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn commits_complete_directory_and_replaces_previous() {
        let root = temp_root("commit");
        let destination = root.join("debug");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("old"), b"old").unwrap();

        let staging = AtomicDirectory::new(&root, "debug").unwrap();
        fs::write(staging.path().join("new"), b"new").unwrap();
        staging.commit(&destination).unwrap();

        assert!(!destination.join("old").exists());
        assert_eq!(fs::read(destination.join("new")).unwrap(), b"new");
        assert_eq!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .count(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_or_dropped_staging_never_replaces_output() {
        let root = temp_root("drop");
        let destination = root.join("release");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("good"), b"good").unwrap();
        {
            let staging = AtomicDirectory::new(&root, "release").unwrap();
            fs::write(staging.path().join("partial"), b"partial").unwrap();
        }
        assert_eq!(fs::read(destination.join("good")).unwrap(), b"good");
        assert_eq!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .count(),
            1
        );
        fs::remove_dir_all(root).unwrap();
    }
}
