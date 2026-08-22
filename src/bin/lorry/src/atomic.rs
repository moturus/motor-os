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

    /// Persists and closes the staged file without making it visible.
    pub fn persist(&mut self) -> Result<()> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        file.sync_all().map_err(|error| {
            Error::failure(format!(
                "failed to persist staged file `{}`: {error}",
                self.path.display()
            ))
        })?;
        Ok(())
    }

    pub fn commit(mut self) -> Result<()> {
        self.persist()?;

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
        Self::create(parent, || unique_name(label, "staging"))
    }

    pub fn new_compact(parent: &Path) -> Result<Self> {
        Self::create(parent, compact_unique_name)
    }

    fn create(parent: &Path, mut next_name: impl FnMut() -> String) -> Result<Self> {
        fs::create_dir_all(parent).map_err(|error| {
            Error::failure(format!(
                "failed to create output parent `{}`: {error}",
                parent.display()
            ))
        })?;
        for _ in 0..100 {
            let path = parent.join(next_name());
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

    /// Publishes this staging directory only when `destination` does not
    /// already exist. Returns `false` when another writer won the race.
    pub fn commit_no_replace(mut self, destination: &Path) -> Result<bool> {
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

        let installed = move_no_replace(&self.path, destination)?;
        if installed {
            self.committed = true;
        }
        Ok(installed)
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

#[cfg(target_os = "linux")]
pub(crate) fn move_no_replace(source: &Path, destination: &Path) -> Result<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| Error::failure("atomic output source contains a NUL byte"))?;
    let destination_c = CString::new(destination.as_os_str().as_bytes())
        .map_err(|_| Error::failure("atomic output destination contains a NUL byte"))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EEXIST) {
        return Ok(false);
    }
    Err(Error::failure(format!(
        "failed to atomically install output `{}`: {error}",
        destination.display()
    )))
}

#[cfg(target_os = "motor")]
pub(crate) fn move_no_replace(source: &Path, destination: &Path) -> Result<bool> {
    let source = source.to_str().ok_or_else(|| {
        Error::failure(format!(
            "atomic output source is not UTF-8: `{}`",
            source.display()
        ))
    })?;
    let destination_path = destination.to_str().ok_or_else(|| {
        Error::failure(format!(
            "atomic output destination is not UTF-8: `{}`",
            destination.display()
        ))
    })?;
    match moto_rt::fs::move_noreplace(source, destination_path) {
        Ok(()) => Ok(true),
        Err(moto_rt::Error::AlreadyInUse) => Ok(false),
        Err(error) => Err(Error::failure(format!(
            "failed to atomically install output `{}`: {error}",
            destination.display()
        ))),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "motor")))]
pub(crate) fn move_no_replace(_source: &Path, destination: &Path) -> Result<bool> {
    Err(Error::failure(format!(
        "atomic no-replace output is unsupported on this platform: `{}`",
        destination.display()
    )))
}

fn unique_name(label: &str, role: &str) -> String {
    format!(".{label}.lorry-{role}-{}", unique_suffix())
}

fn compact_unique_name() -> String {
    format!(".l-{}", unique_suffix())
}

fn unique_suffix() -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{time:x}-{sequence:x}", std::process::id())
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

pub(crate) fn set_private_file(_file: &File, _path: &Path) -> Result<()> {
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
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

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
    fn compact_staging_keeps_build_paths_short() {
        let root = temp_root("compact");
        let staging = AtomicDirectory::new_compact(&root).unwrap();
        let name = staging.path().file_name().unwrap().to_string_lossy();
        assert!(name.len() <= 32, "staging name is too long: {name}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_replace_publish_preserves_the_first_complete_directory() {
        let root = temp_root("no-replace");
        let destination = root.join("entry");

        let first = AtomicDirectory::new(&root, "entry").unwrap();
        fs::write(first.path().join("value"), b"first").unwrap();
        assert!(first.commit_no_replace(&destination).unwrap());

        let second = AtomicDirectory::new(&root, "entry").unwrap();
        fs::write(second.path().join("value"), b"second").unwrap();
        assert!(!second.commit_no_replace(&destination).unwrap());
        assert_eq!(fs::read(destination.join("value")).unwrap(), b"first");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn competing_processes_publish_exactly_one_directory() {
        let root = temp_root("competing-publish");
        let start = root.join("start");
        let (first, first_ready, first_result) = spawn_publisher(&root, &start, "first");
        let (second, second_ready, second_result) = spawn_publisher(&root, &start, "second");
        wait_for(&first_ready);
        wait_for(&second_ready);
        fs::write(&start, b"go").unwrap();
        wait_for_child(first);
        wait_for_child(second);

        let first_result = fs::read_to_string(first_result).unwrap();
        let second_result = fs::read_to_string(second_result).unwrap();
        assert!(
            matches!(
                (first_result.as_str(), second_result.as_str()),
                ("won", "lost") | ("lost", "won")
            ),
            "unexpected publisher results: {first_result:?}, {second_result:?}"
        );
        let published = fs::read_to_string(root.join("entry/value")).unwrap();
        assert_eq!(
            published,
            if first_result == "won" {
                "first"
            } else {
                "second"
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_replace_publish_child() {
        let Some(root) = std::env::var_os("LORRY_ATOMIC_PUBLISH_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let value = std::env::var("LORRY_ATOMIC_PUBLISH_VALUE").unwrap();
        let ready = PathBuf::from(std::env::var_os("LORRY_ATOMIC_PUBLISH_READY").unwrap());
        let start = PathBuf::from(std::env::var_os("LORRY_ATOMIC_PUBLISH_START").unwrap());
        let result = PathBuf::from(std::env::var_os("LORRY_ATOMIC_PUBLISH_RESULT").unwrap());

        let staging = AtomicDirectory::new(&root, "entry").unwrap();
        fs::write(staging.path().join("value"), &value).unwrap();
        fs::write(ready, b"ready").unwrap();
        wait_for(&start);
        let outcome = if staging.commit_no_replace(&root.join("entry")).unwrap() {
            "won"
        } else {
            "lost"
        };
        fs::write(result, outcome).unwrap();
    }

    fn spawn_publisher(root: &Path, start: &Path, value: &str) -> (Child, PathBuf, PathBuf) {
        let ready = root.join(format!("{value}.ready"));
        let result = root.join(format!("{value}.result"));
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "atomic::tests::no_replace_publish_child",
                "--nocapture",
            ])
            .env("LORRY_ATOMIC_PUBLISH_ROOT", root)
            .env("LORRY_ATOMIC_PUBLISH_VALUE", value)
            .env("LORRY_ATOMIC_PUBLISH_READY", &ready)
            .env("LORRY_ATOMIC_PUBLISH_START", start)
            .env("LORRY_ATOMIC_PUBLISH_RESULT", &result)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        (child, ready, result)
    }

    fn wait_for(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_child(child: Child) {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
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

    #[test]
    fn persisted_file_remains_hidden_until_commit() {
        let root = temp_root("persist-file");
        let destination = root.join("Cargo.lock");
        fs::write(&destination, b"old").unwrap();

        let mut staging = AtomicFile::new(&destination).unwrap();
        staging.write_all(b"new").unwrap();
        staging.persist().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        assert!(staging.write_all(b"late").is_err());

        staging.commit().unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        fs::remove_dir_all(root).unwrap();
    }
}
