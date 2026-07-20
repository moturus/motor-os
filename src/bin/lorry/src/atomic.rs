use crate::diagnostic::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct AtomicDirectory {
    path: PathBuf,
    committed: bool,
}

#[derive(Debug)]
pub struct AtomicFile {
    path: PathBuf,
    destination: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl AtomicFile {
    pub fn new(destination: &Path) -> Result<Self> {
        let parent = destination.parent().ok_or_else(|| {
            Error::failure(format!(
                "file destination `{}` has no parent",
                destination.display()
            ))
        })?;
        let label = destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file");
        for _ in 0..100 {
            let path = parent.join(unique_name(label, "staging"));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    if let Err(error) = set_private_file(&file, &path) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self {
                        path,
                        destination: destination.to_owned(),
                        file: Some(file),
                        committed: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(Error::failure(format!(
                        "failed to create private file staging `{}`: {error}",
                        path.display()
                    )));
                }
            }
        }
        Err(Error::failure(format!(
            "could not allocate private file staging below `{}`",
            parent.display()
        )))
    }

    pub fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| Error::failure("atomic file staging is already closed"))?
            .write_all(bytes)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to write staged file `{}`: {error}",
                    self.path.display()
                ))
            })
    }

    pub fn commit(mut self) -> Result<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| Error::failure("atomic file staging is already closed"))?;
        file.sync_all().map_err(|error| {
            Error::failure(format!(
                "failed to persist staged file `{}`: {error}",
                self.path.display()
            ))
        })?;
        drop(file);

        match fs::symlink_metadata(&self.destination) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(Error::failure(format!(
                    "refusing to replace non-file destination `{}`",
                    self.destination.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::failure(format!(
                    "failed to inspect file destination `{}`: {error}",
                    self.destination.display()
                )));
            }
        }
        fs::rename(&self.path, &self.destination).map_err(|error| {
            Error::failure(format!(
                "failed to atomically install file `{}`: {error}",
                self.destination.display()
            ))
        })?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = fs::remove_file(&self.path);
        }
    }
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
            match create_private_directory(&path) {
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

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
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

fn set_private(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            Error::failure(format!(
                "failed to make staging `{}` private: {error}",
                _path.display()
            ))
        })?;
    }
    #[cfg(target_os = "motor")]
    {
        let path = _path.to_str().ok_or_else(|| {
            Error::failure(format!(
                "private staging path is not UTF-8: `{}`",
                _path.display()
            ))
        })?;
        moto_rt::fs::set_perm(
            path,
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE | moto_rt::fs::PERM_EXEC,
        )
        .map_err(|error| {
            Error::failure(format!(
                "failed to make staging `{}` private: {error}",
                _path.display()
            ))
        })?;
    }
    Ok(())
}

fn set_private_file(_file: &File, _path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            Error::failure(format!(
                "failed to make staged file `{}` private: {error}",
                _path.display()
            ))
        })?;
    }
    #[cfg(target_os = "motor")]
    {
        use std::os::fd::AsRawFd;
        moto_rt::fs::set_file_perm(
            _file.as_raw_fd(),
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE,
        )
        .map_err(|error| {
            Error::failure(format!(
                "failed to make staged file `{}` private: {error}",
                _path.display()
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

    #[test]
    fn atomically_replaces_regular_files_and_cleans_dropped_staging() {
        let root = temp_root("file");
        let destination = root.join("Cargo.lock");
        fs::write(&destination, b"old").unwrap();
        {
            let mut staging = AtomicFile::new(&destination).unwrap();
            staging.write_all(b"incomplete").unwrap();
        }
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

        let mut staging = AtomicFile::new(&destination).unwrap();
        staging.write_all(b"new").unwrap();
        staging.commit().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
