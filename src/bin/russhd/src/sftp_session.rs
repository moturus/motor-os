//! SFTP server implementation.
//!
//! Protocol: https://www.ietf.org/proceedings/50/I-D/secsh-filexfer-00.txt

use russh_sftp::protocol::{
    File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Default)]
pub struct SftpSession {
    version: Option<u32>,

    // Handle: u64 as hex.
    open_files: HashMap<String, OpenFile>,
    // Handle: u64 as hex -> open directory, read incrementally by readdir.
    open_dirs: HashMap<String, tokio::fs::ReadDir>,
    next_id: u64,
}

struct OpenFile {
    file: tokio::fs::File,
    path: String,
}

impl SftpSession {
    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

fn io_status(err: &std::io::Error) -> StatusCode {
    match err.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            StatusCode::BadMessage
        }
        std::io::ErrorKind::Unsupported => StatusCode::OpUnsupported,
        _ => StatusCode::Failure,
    }
}

fn permission_mode(attrs: &FileAttributes) -> Result<Option<u32>, StatusCode> {
    if attrs.size.is_some() || attrs.uid.is_some() || attrs.gid.is_some() {
        return Err(StatusCode::OpUnsupported);
    }
    // Motor has no API for setting file timestamps. OpenSSH's `put -p` sends
    // them together with the mode, so accept the timestamps and preserve the
    // supported permission attribute instead of rejecting the whole request.
    Ok(attrs.permissions.map(|mode| mode & 0o777))
}

#[cfg(unix)]
async fn set_path_permissions(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).await
}

#[cfg(target_os = "motor")]
async fn set_path_permissions(path: &str, mode: u32) -> std::io::Result<()> {
    moto_rt::fs::set_perm(path, motor_permissions(mode))
        .map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(unix)]
async fn set_file_permissions(file: &OpenFile, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.file
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .await
}

#[cfg(target_os = "motor")]
async fn set_file_permissions(file: &OpenFile, mode: u32) -> std::io::Result<()> {
    moto_rt::fs::set_perm(&file.path, motor_permissions(mode))
        .map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(target_os = "motor")]
fn motor_permissions(mode: u32) -> u64 {
    let mut permissions = 0;
    if mode & 0o444 != 0 {
        permissions |= moto_rt::fs::PERM_READ;
    }
    if mode & 0o222 != 0 {
        permissions |= moto_rt::fs::PERM_WRITE;
    }
    if mode & 0o111 != 0 {
        permissions |= moto_rt::fs::PERM_EXEC;
    }
    permissions
}

fn file_attributes(path: &str, metadata: &std::fs::Metadata) -> Result<FileAttributes, StatusCode> {
    #[cfg(target_os = "motor")]
    let mut attrs = FileAttributes::from(metadata);
    #[cfg(not(target_os = "motor"))]
    let attrs = FileAttributes::from(metadata);
    #[cfg(target_os = "motor")]
    {
        let motor = moto_rt::fs::stat(path).map_err(|error| {
            log::warn!("stat permissions for {path}: {error}");
            StatusCode::Failure
        })?;
        let mut mode = if metadata.is_dir() {
            0o040000
        } else {
            0o100000
        };
        if motor.perm & moto_rt::fs::PERM_READ != 0 {
            mode |= 0o444;
        }
        if motor.perm & moto_rt::fs::PERM_WRITE != 0 {
            mode |= 0o222;
        }
        if motor.perm & moto_rt::fs::PERM_EXEC != 0 {
            mode |= 0o111;
        }
        attrs.permissions = Some(mode);
    }
    #[cfg(not(target_os = "motor"))]
    let _ = path;
    Ok(attrs)
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        if self.version.is_some() {
            log::error!("duplicate SSH_FXP_VERSION packet");
            return Err(StatusCode::ConnectionLost);
        }

        self.version = Some(version);
        log::info!("version: {:?}, extensions: {:?}", self.version, extensions);
        Ok(Version::new())
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        if let Some(mut open_file) = self.open_files.remove(&handle) {
            // Tokio accepts writes into an internal buffer before its blocking
            // file operation completes. SSH_FXP_CLOSE must not acknowledge the
            // handle until those writes have reached the underlying file.
            open_file.file.flush().await.map_err(|err| {
                log::warn!("close: flush '{handle}' failed: {err:?}");
                io_status(&err)
            })?;
            log::info!("close {handle}: Ok");
            Ok(ok_status(id))
        } else if self.open_dirs.remove(&handle).is_some() {
            log::info!("close {handle}: Ok");
            Ok(ok_status(id))
        } else {
            log::warn!("close: handle: '{handle}' not found");
            Err(StatusCode::BadMessage)
        }
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let read_dir = tokio::fs::read_dir(path.as_str()).await.map_err(|err| {
            log::warn!("opendir: '{path}': Err: {err:?}");
            StatusCode::NoSuchFile
        })?;

        let handle = format!("{:x}", self.new_id());
        if let Some(_prev) = self.open_dirs.insert(handle.clone(), read_dir) {
            log::warn!("opendir: dropping prev handle for '{path}'");
        }

        log::info!("opendir: {path}: Ok {handle}");
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        // Number of entries returned per readdir reply. The client keeps calling
        // readdir until it gets EOF, so we stream the directory in batches rather
        // than buffering the whole listing.
        const BATCH: usize = 64;

        let Some(read_dir) = self.open_dirs.get_mut(&handle) else {
            log::warn!("readdir {handle}: Err: not found");
            return Err(StatusCode::BadMessage);
        };

        let mut files = Vec::new();
        while files.len() < BATCH {
            match read_dir.next_entry().await {
                Ok(Some(entry)) => {
                    let Ok(filename) = entry.file_name().into_string() else {
                        log::warn!("Entry '{:?}' has non-Utf8 filename", entry.file_name());
                        continue;
                    };
                    let attrs = match entry.metadata().await {
                        Ok(metadata) => match entry.path().to_str() {
                            Some(path) => match file_attributes(path, &metadata) {
                                Ok(attrs) => attrs,
                                Err(_) => continue,
                            },
                            None => continue,
                        },
                        Err(err) => {
                            log::warn!(
                                "readdir {handle}: metadata for '{filename}' failed: {err:?}"
                            );
                            continue;
                        }
                    };
                    files.push(File::new(filename, attrs));
                }
                Ok(None) => break,
                Err(err) => {
                    log::warn!("readdir {handle}: next_entry failed: {err:?}");
                    break;
                }
            }
        }

        // No more entries: signal end of directory.
        if files.is_empty() {
            log::info!("readdir {handle}: Eof");
            return Err(StatusCode::Eof);
        }

        log::warn!("readdir {handle}: Ok, {} entries", files.len());
        Ok(Name { id, files })
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let canonical = canonicalize_lexical(&path);
        log::info!("realpath: {path} -> {canonical}");
        Ok(Name {
            id,
            files: vec![File::dummy(canonical)],
        })
    }

    /// Called on SSH_FXP_OPEN
    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if !pflags.intersects(OpenFlags::READ | OpenFlags::WRITE) {
            log::warn!("open: {filename}: missing read/write flag in 0x{pflags:x}");
            return Err(StatusCode::BadMessage);
        }

        // russh-sftp's conversion implements the SFTP v3 flag semantics,
        // including CREATE|EXCLUDE (create_new), TRUNCATE, and APPEND.
        let options: std::fs::OpenOptions = pflags.into();
        let file = tokio::fs::OpenOptions::from(options)
            .open(filename.as_str())
            .await
            .map_err(|err| {
                log::warn!("open: {filename}: Err: {err:?}");
                io_status(&err)
            })?;

        let handle = format!("{:x}", self.new_id());
        assert!(
            self.open_files
                .insert(
                    handle.clone(),
                    OpenFile {
                        file,
                        path: filename.clone(),
                    },
                )
                .is_none()
        );

        log::info!("open: {filename}: Ok {handle}");
        Ok(Handle { id, handle })
    }

    /// Called on SSH_FXP_READ
    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        let Some(open_file) = self.open_files.get_mut(&handle) else {
            log::warn!("read {handle}: Err: not found");
            return Err(StatusCode::BadMessage);
        };

        open_file
            .file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|err| {
                log::warn!("seek {handle} {offset} failed: {err:?}");
                StatusCode::Eof
            })?;

        let mut data = vec![0; len as usize];
        let mut total_read = 0;
        loop {
            if total_read >= data.len() {
                break;
            }
            let num_read = open_file
                .file
                .read(&mut data.as_mut_slice()[total_read..])
                .await
                .map_err(|err| {
                    log::warn!("read {handle} failed: {err:?}");
                    StatusCode::Failure
                })?;

            if num_read == 0 {
                if total_read == 0 {
                    return Err(StatusCode::Eof);
                } else {
                    break;
                }
            }

            total_read += num_read;
        }

        data.resize(total_read, 0);

        log::debug!("read {handle} Ok: {total_read} bytes read");
        Ok(russh_sftp::protocol::Data { id, data })
    }

    /// Called on SSH_FXP_WRITE
    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(open_file) = self.open_files.get_mut(&handle) else {
            log::warn!("write {handle}: Err: not found");
            return Err(StatusCode::BadMessage);
        };

        open_file
            .file
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|err| {
                log::warn!("write: seek {handle} {offset} failed: {err:?}");
                io_status(&err)
            })?;

        open_file.file.write_all(&data).await.map_err(|err| {
            log::warn!("write {handle} at {offset} failed: {err:?}");
            io_status(&err)
        })?;

        log::debug!("write {handle} Ok: {} bytes at {offset}", data.len());
        Ok(ok_status(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let Some(mode) = permission_mode(&attrs)? else {
            return Ok(ok_status(id));
        };
        set_path_permissions(&path, mode).await.map_err(|error| {
            log::warn!("setstat {path}: {error}");
            io_status(&error)
        })?;
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let Some(file) = self.open_files.get(&handle) else {
            return Err(StatusCode::BadMessage);
        };
        let Some(mode) = permission_mode(&attrs)? else {
            return Ok(ok_status(id));
        };
        set_file_permissions(file, mode).await.map_err(|error| {
            log::warn!("fsetstat {handle}: {error}");
            io_status(&error)
        })?;
        Ok(ok_status(id))
    }

    async fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let Some(file) = self.open_files.get(&handle) else {
            return Err(StatusCode::BadMessage);
        };
        let metadata = file.file.metadata().await.map_err(|error| {
            log::warn!("fstat {handle}: {error}");
            io_status(&error)
        })?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: file_attributes(&file.path, &metadata)?,
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let mode = permission_mode(&attrs)?;
        tokio::fs::create_dir(&path).await.map_err(|error| {
            log::warn!("mkdir {path}: {error}");
            io_status(&error)
        })?;
        if let Some(mode) = mode {
            set_path_permissions(&path, mode).await.map_err(|error| {
                log::warn!("mkdir permissions {path}: {error}");
                io_status(&error)
            })?;
        }
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_file(&filename).await.map_err(|error| {
            log::warn!("remove {filename}: {error}");
            io_status(&error)
        })?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_dir(&path).await.map_err(|error| {
            log::warn!("rmdir {path}: {error}");
            io_status(&error)
        })?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        tokio::fs::rename(&oldpath, &newpath)
            .await
            .map_err(|error| {
                log::warn!("rename {oldpath} -> {newpath}: {error}");
                io_status(&error)
            })?;
        Ok(ok_status(id))
    }

    /// Called on SSH_FXP_LSTAT
    ///
    /// Motor OS has no symlinks, so lstat is equivalent to stat. Older SFTP
    /// clients (e.g. OpenSSH 8.9's scp) resolve the source path with LSTAT
    /// rather than STAT, so we must handle it.
    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        self.stat(id, path).await
    }

    /// Called on SSH_FXP_STAT
    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let metadata = tokio::fs::metadata(path.as_str()).await.map_err(|err| {
            log::info!("stat {path} -> Error: {err:?}.");
            StatusCode::NoSuchFile
        })?;

        log::info!("stat {path} -> Ok: {metadata:?}");

        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: file_attributes(&path, &metadata)?,
        })
    }
}

/// Resolves `path` to an absolute, lexically-normalized path without touching
/// the filesystem. Motor OS has no symlinks, so lexical normalization matches
/// what real canonicalization would produce, and unlike `fs::canonicalize` it
/// works for the `.` that SFTP clients probe right after connecting.
fn canonicalize_lexical(path: &str) -> String {
    let mut components: Vec<String> = Vec::new();

    // Relative paths are resolved against the server's current directory.
    if !path.starts_with('/') {
        if let Ok(cwd) = std::env::current_dir() {
            for component in cwd.components() {
                if let std::path::Component::Normal(c) = component {
                    components.push(c.to_string_lossy().into_owned());
                }
            }
        }
    }

    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            other => components.push(other.to_string()),
        }
    }

    if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::{SftpSession, canonicalize_lexical};
    use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
    use russh_sftp::server::Handler as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "russhd-sftp-{}-{}-{label}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn absolute_paths_are_normalized() {
        assert_eq!(canonicalize_lexical("/bin"), "/bin");
        // Trailing slash (added by sftp's GLOB_MARK) and doubled slashes.
        assert_eq!(canonicalize_lexical("/bin/"), "/bin");
        assert_eq!(canonicalize_lexical("/a//b"), "/a/b");
        // `.` and `..` segments are resolved lexically.
        assert_eq!(canonicalize_lexical("/a/./b"), "/a/b");
        assert_eq!(canonicalize_lexical("/a/b/../c"), "/a/c");
        // The root, and `..` escaping past it, both collapse to "/".
        assert_eq!(canonicalize_lexical("/"), "/");
        assert_eq!(canonicalize_lexical("/.."), "/");
        assert_eq!(canonicalize_lexical("/a/../.."), "/");
    }

    #[test]
    fn relative_paths_resolve_against_cwd() {
        let cwd = canonicalize_lexical(".");
        // "." canonicalizes to an absolute cwd, and a relative path hangs off it.
        assert!(cwd.starts_with('/'));
        assert_eq!(canonicalize_lexical("foo/bar"), format!("{cwd}/foo/bar"));
        // `..` pops the last cwd segment.
        let parent = canonicalize_lexical("..");
        assert!(cwd.starts_with(&parent));
    }

    #[test]
    fn upload_creates_truncates_and_writes_at_offsets() {
        let path = temp_path("upload");
        std::fs::write(&path, b"old data that must be truncated").unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut session = SftpSession::default();
            let opened = session
                .open(
                    1,
                    path.to_string_lossy().into_owned(),
                    OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                    FileAttributes::empty(),
                )
                .await
                .unwrap();

            let status = session
                .write(2, opened.handle.clone(), 6, b"world".to_vec())
                .await
                .unwrap();
            assert_eq!(status.id, 2);
            assert_eq!(status.status_code, StatusCode::Ok);

            session
                .write(3, opened.handle.clone(), 0, b"hello ".to_vec())
                .await
                .unwrap();
            session.close(4, opened.handle).await.unwrap();
        });

        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn upload_honors_append_and_rejects_unknown_handles() {
        let path = temp_path("append");
        std::fs::write(&path, b"first").unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut session = SftpSession::default();
            let opened = session
                .open(
                    1,
                    path.to_string_lossy().into_owned(),
                    OpenFlags::WRITE | OpenFlags::APPEND,
                    FileAttributes::empty(),
                )
                .await
                .unwrap();

            // APPEND makes the requested offset irrelevant.
            session
                .write(2, opened.handle.clone(), 0, b" second".to_vec())
                .await
                .unwrap();
            session.close(3, opened.handle).await.unwrap();

            assert!(matches!(
                session
                    .write(4, "not-an-open-handle".to_string(), 0, vec![1])
                    .await,
                Err(StatusCode::BadMessage)
            ));
        });

        assert_eq!(std::fs::read(&path).unwrap(), b"first second");
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn setstat_and_fsetstat_apply_supported_attributes() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("permissions");
        std::fs::write(&path, b"permissions").unwrap();
        let attrs = |mode| FileAttributes {
            permissions: Some(mode),
            ..FileAttributes::empty()
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut session = SftpSession::default();
            session
                .setstat(1, path.to_string_lossy().into_owned(), attrs(0o640))
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );

            let opened = session
                .open(
                    2,
                    path.to_string_lossy().into_owned(),
                    OpenFlags::WRITE,
                    FileAttributes::empty(),
                )
                .await
                .unwrap();
            session
                .fsetstat(3, opened.handle.clone(), attrs(0o750))
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o750
            );

            let with_times = FileAttributes {
                permissions: Some(0o640),
                atime: Some(1_700_000_000),
                mtime: Some(1_700_000_001),
                ..FileAttributes::empty()
            };
            session
                .fsetstat(4, opened.handle.clone(), with_times)
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );

            let unsupported = FileAttributes {
                size: Some(0),
                permissions: Some(0o600),
                ..FileAttributes::empty()
            };
            assert_eq!(
                session
                    .fsetstat(5, opened.handle.clone(), unsupported)
                    .await
                    .unwrap_err(),
                StatusCode::OpUnsupported
            );
            session.close(6, opened.handle).await.unwrap();
        });

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_handlers_cover_supported_sftp_operations() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("filesystem-operations");
        let directory = root.join("directory");
        let original = directory.join("original");
        let renamed = directory.join("renamed");
        std::fs::create_dir(&root).unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut session = SftpSession::default();
            let attrs = FileAttributes {
                permissions: Some(0o750),
                atime: Some(1_700_000_000),
                mtime: Some(1_700_000_001),
                ..FileAttributes::empty()
            };
            session
                .mkdir(1, directory.to_string_lossy().into_owned(), attrs)
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o750
            );

            std::fs::write(&original, b"contents").unwrap();
            let opened = session
                .open(
                    2,
                    original.to_string_lossy().into_owned(),
                    OpenFlags::READ,
                    FileAttributes::empty(),
                )
                .await
                .unwrap();
            let stat = session.fstat(3, opened.handle.clone()).await.unwrap();
            assert_eq!(stat.attrs.size, Some(8));
            session.close(4, opened.handle).await.unwrap();

            session
                .rename(
                    5,
                    original.to_string_lossy().into_owned(),
                    renamed.to_string_lossy().into_owned(),
                )
                .await
                .unwrap();
            assert!(!original.exists());
            session
                .remove(6, renamed.to_string_lossy().into_owned())
                .await
                .unwrap();
            session
                .rmdir(7, directory.to_string_lossy().into_owned())
                .await
                .unwrap();

            assert_eq!(
                session.fstat(8, "unknown".to_string()).await.unwrap_err(),
                StatusCode::BadMessage
            );
        });

        std::fs::remove_dir(root).unwrap();
    }
}
