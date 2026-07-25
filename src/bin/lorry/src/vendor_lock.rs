use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::diagnostic::{Error, Result};

const LOCK_NAME: &str = ".vendor.lock";

/// A process-lifetime exclusive lock for one package root.
///
/// The operating system releases the lock when this owner is dropped,
/// including when a vendor transaction returns early.
#[derive(Debug)]
pub struct ProjectVendorLock {
    #[allow(dead_code)]
    file: File,
    path: PathBuf,
}

impl ProjectVendorLock {
    pub fn acquire(package_root: &Path) -> Result<Self> {
        let target = real_child_directory(package_root, "target")?;
        let lock_root = real_child_directory(&target, "lorry")?;
        let path = lock_root.join(LOCK_NAME);
        reject_link_or_non_file_if_present(&path)?;

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
                "failed to open project vendor lock `{}`: {error}",
                path.display()
            ))
        })?;
        verify_open_file(&file, &path)?;
        file.lock().map_err(|error| {
            Error::failure(format!(
                "failed to acquire project vendor lock `{}`: {error}",
                path.display()
            ))
        })?;
        verify_open_file(&file, &path)?;
        Ok(Self { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn real_child_directory(parent: &Path, child: &str) -> Result<PathBuf> {
    let path = parent.join(child);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to create vendor lock directory `{}`: {error}",
                path.display()
            )));
        }
    }
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect vendor lock directory `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "vendor lock directory `{}` is not a real directory",
            path.display()
        )));
    }
    Ok(path)
}

fn reject_link_or_non_file_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(Error::failure(format!(
                "project vendor lock `{}` is not a real regular file",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect project vendor lock `{}`: {error}",
            path.display()
        ))),
    }
}

fn verify_open_file(_file: &File, path: &Path) -> Result<()> {
    reject_link_or_non_file_if_present(path)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;

        let opened = _file.metadata().map_err(|error| {
            Error::failure(format!(
                "failed to inspect opened project vendor lock `{}`: {error}",
                path.display()
            ))
        })?;
        let visible = fs::metadata(path).map_err(|error| {
            Error::failure(format!(
                "failed to inspect visible project vendor lock `{}`: {error}",
                path.display()
            ))
        })?;
        if opened.dev() != visible.dev() || opened.ino() != visible.ino() {
            return Err(Error::failure(format!(
                "project vendor lock `{}` changed while it was being acquired",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "lorry-vendor-lock-{label}-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn spawn(&self, name: &str) -> (Child, PathBuf, PathBuf) {
            let ready = self.0.join(format!("{name}.ready"));
            let release = self.0.join(format!("{name}.release"));
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vendor_lock::tests::vendor_lock_child",
                    "--nocapture",
                ])
                .env("LORRY_VENDOR_LOCK_CHILD_ROOT", &self.0)
                .env("LORRY_VENDOR_LOCK_CHILD_READY", &ready)
                .env("LORRY_VENDOR_LOCK_CHILD_RELEASE", &release)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            (child, ready, release)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn wait_for(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn release(child: Child, release: &Path) {
        fs::write(release, b"release").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn serializes_one_project_but_not_different_projects() {
        let first = Fixture::new("same");
        let (first_child, first_ready, first_release) = first.spawn("first");
        wait_for(&first_ready);

        let (second_child, second_ready, second_release) = first.spawn("second");
        thread::sleep(Duration::from_millis(150));
        assert!(!second_ready.exists());

        let independent = Fixture::new("different");
        let (other_child, other_ready, other_release) = independent.spawn("other");
        wait_for(&other_ready);
        release(other_child, &other_release);

        release(first_child, &first_release);
        wait_for(&second_ready);
        release(second_child, &second_release);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_directories_and_lock_files() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("links");
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, fixture.0.join("target")).unwrap();
        assert!(ProjectVendorLock::acquire(&fixture.0).is_err());

        fs::remove_file(fixture.0.join("target")).unwrap();
        fs::create_dir(fixture.0.join("target")).unwrap();
        fs::create_dir(fixture.0.join("target/lorry")).unwrap();
        symlink(
            fixture.0.join("sentinel"),
            fixture.0.join("target/lorry").join(LOCK_NAME),
        )
        .unwrap();
        assert!(ProjectVendorLock::acquire(&fixture.0).is_err());
    }

    #[test]
    fn vendor_lock_child() {
        let Some(root) = std::env::var_os("LORRY_VENDOR_LOCK_CHILD_ROOT") else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os("LORRY_VENDOR_LOCK_CHILD_READY").unwrap());
        let release = PathBuf::from(std::env::var_os("LORRY_VENDOR_LOCK_CHILD_RELEASE").unwrap());
        let lock = ProjectVendorLock::acquire(Path::new(&root)).unwrap();
        assert_eq!(lock.path().file_name().unwrap(), LOCK_NAME);
        fs::write(ready, b"ready").unwrap();
        while !release.exists() {
            thread::sleep(Duration::from_millis(10));
        }
    }
}
