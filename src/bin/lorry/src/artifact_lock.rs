use crate::diagnostic::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::path::Path;

const LOCK_NAME: &str = ".lorry-artifacts.lock";
#[cfg(target_os = "linux")]
const LEASE_NAME: &str = ".lorry-artifacts.lease";

/// Held while one command reads or changes a target directory's Lorry outputs.
/// The file stays outside the cleanable `lorry/` tree and is never unlinked.
pub struct ArtifactLock {
    _file: File,
    #[cfg(target_os = "linux")]
    _lease: File,
}

impl ArtifactLock {
    pub fn acquire(target_directory: &Path) -> Result<Self> {
        fs::create_dir_all(target_directory).map_err(|error| {
            Error::failure(format!(
                "failed to create target directory `{}`: {error}",
                target_directory.display()
            ))
        })?;
        let directory = fs::canonicalize(target_directory).map_err(|error| {
            Error::failure(format!(
                "failed to resolve target directory `{}`: {error}",
                target_directory.display()
            ))
        })?;
        let path = directory.join(LOCK_NAME);
        require_regular_or_absent(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
            #[cfg(target_os = "linux")]
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(&path).map_err(|error| {
            Error::failure(format!(
                "failed to open artifact lock `{}`: {error}",
                path.display()
            ))
        })?;
        verify_open_file(&file, &path)?;
        file.lock().map_err(|error| {
            Error::failure(format!(
                "failed to acquire artifact lock `{}`: {error}",
                path.display()
            ))
        })?;
        verify_open_file(&file, &path)?;
        #[cfg(target_os = "linux")]
        let lease = acquire_child_lease(&directory)?;
        Ok(Self {
            _file: file,
            #[cfg(target_os = "linux")]
            _lease: lease,
        })
    }
}

#[cfg(target_os = "linux")]
fn acquire_child_lease(directory: &Path) -> Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let path = directory.join(LEASE_NAME);
    require_regular_or_absent(&path)?;
    let mut create = OpenOptions::new();
    create.read(true).write(true).create(true);
    create
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let created = create.open(&path).map_err(|error| {
        Error::failure(format!(
            "failed to create artifact child lease `{}`: {error}",
            path.display()
        ))
    })?;
    verify_open_file(&created, &path)?;
    drop(created);

    // The child inherits a read-only descriptor. Its lifetime holds the
    // lease after an abrupt parent exit, including while it runs descendants.
    let mut open = OpenOptions::new();
    open.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let lease = open.open(&path).map_err(|error| {
        Error::failure(format!(
            "failed to open artifact child lease `{}`: {error}",
            path.display()
        ))
    })?;
    verify_open_file(&lease, &path)?;
    lease.lock().map_err(|error| {
        Error::failure(format!(
            "failed to wait for artifact child lease `{}`: {error}",
            path.display()
        ))
    })?;
    verify_open_file(&lease, &path)?;
    // SAFETY: fcntl only reads or changes flags on this owned descriptor.
    let flags = unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(lease.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
    {
        return Err(Error::failure(format!(
            "failed to make artifact child lease inheritable: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(lease)
}

fn require_regular_or_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::failure(format!(
                "artifact lock `{}` is not a regular file",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect artifact lock `{}`: {error}",
            path.display()
        ))),
    }
}

fn verify_open_file(file: &File, path: &Path) -> Result<()> {
    let visible = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect visible artifact lock `{}`: {error}",
            path.display()
        ))
    })?;
    if !visible.is_file() || visible.file_type().is_symlink() {
        return Err(Error::failure(format!(
            "artifact lock `{}` is not a regular file",
            path.display()
        )));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file
            .metadata()
            .map_err(|error| Error::failure(format!("failed to inspect artifact lock: {error}")))?;
        if opened.dev() != visible.dev() || opened.ino() != visible.ino() {
            return Err(Error::failure(format!(
                "artifact lock `{}` changed while being acquired",
                path.display()
            )));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_writers_and_survives_cleaning_the_artifact_tree() {
        let root = std::env::temp_dir().join(format!("lorry-artifact-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let lock = ArtifactLock::acquire(&root).unwrap();
        let path = root.join(LOCK_NAME);
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        fs::create_dir(root.join("lorry")).unwrap();
        fs::remove_dir(root.join("lorry")).unwrap();
        assert!(path.is_file());
        drop(lock);
        contender.try_lock().unwrap();
        drop(contender);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_keeps_lease_after_parent_releases_target_lock() {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};

        let root = std::env::temp_dir().join(format!(
            "lorry-child-lease-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        let lock = ArtifactLock::acquire(&root).unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "printf ready; read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = [0; 5];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .unwrap();
        assert_eq!(&ready, b"ready");
        drop(lock);

        let contender = OpenOptions::new()
            .read(true)
            .open(root.join(LEASE_NAME))
            .unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        child.stdin.as_mut().unwrap().write_all(b"done\n").unwrap();
        assert!(child.wait().unwrap().success());
        contender.try_lock().unwrap();
        drop(contender);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlinked_lock_file() {
        use std::os::unix::fs::symlink;
        let root =
            std::env::temp_dir().join(format!("lorry-artifact-lock-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        symlink(root.join("other"), root.join(LOCK_NAME)).unwrap();
        assert!(ArtifactLock::acquire(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
