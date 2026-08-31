//! SFTP server implementation.
//!
//! Protocol: https://www.ietf.org/proceedings/50/I-D/secsh-filexfer-00.txt

use russh_sftp::protocol::{
    File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[cfg(unix)]
use crate::permissions::unix_mode;
#[cfg(target_os = "motor")]
use crate::permissions::{Access, NormalizedMode};
use crate::sftp_extensions::{POSIX_RENAME, POSIX_RENAME_VERSION, decode_posix_rename};

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
    writable: bool,
    pending_permissions: Option<SavedPermissions>,
}

#[cfg(unix)]
type SavedPermissions = u32;

#[cfg(target_os = "motor")]
type SavedPermissions = moto_io::fs::RolePermissions;

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

// No-replace fallback for platforms and filesystems without an atomic
// primitive: check-then-rename, racy the same way OpenSSH's sftp-server is.
#[cfg(unix)]
fn rename_noreplace_emulated(oldpath: &str, newpath: &str) -> Result<(), StatusCode> {
    if std::fs::symlink_metadata(newpath).is_ok() {
        return Err(StatusCode::Failure);
    }
    std::fs::rename(oldpath, newpath).map_err(|error| io_status(&error))
}

#[cfg(target_os = "linux")]
fn rename_noreplace(oldpath: &str, newpath: &str) -> Result<(), StatusCode> {
    use std::ffi::CString;

    let old = CString::new(oldpath).map_err(|_| StatusCode::BadMessage)?;
    let new = CString::new(newpath).map_err(|_| StatusCode::BadMessage)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            old.as_ptr(),
            libc::AT_FDCWD,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        // Filesystems without RENAME_NOREPLACE support (NFS < 4.2, some
        // FUSE/overlayfs mounts) report EINVAL; pre-renameat2 kernels ENOSYS.
        Some(libc::EINVAL) | Some(libc::ENOSYS) => rename_noreplace_emulated(oldpath, newpath),
        _ => Err(io_status(&error)),
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn rename_noreplace(oldpath: &str, newpath: &str) -> Result<(), StatusCode> {
    rename_noreplace_emulated(oldpath, newpath)
}

#[cfg(target_os = "motor")]
fn rename_noreplace(oldpath: &str, newpath: &str) -> Result<(), StatusCode> {
    moto_rt::fs::move_noreplace(oldpath, newpath).map_err(|error| match error {
        // rt.vdso reports a missing source or destination parent as
        // InvalidFilename (rt_fs.rs move_path), not NotFound.
        moto_rt::Error::NotFound | moto_rt::Error::InvalidFilename => StatusCode::NoSuchFile,
        moto_rt::Error::NotAllowed => StatusCode::PermissionDenied,
        moto_rt::Error::NotImplemented => StatusCode::OpUnsupported,
        _ => StatusCode::Failure,
    })
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
async fn set_path_permissions(path: &str, mode: SavedPermissions) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(unix_mode(mode))).await
}

#[cfg(unix)]
async fn set_file_permissions(
    file: &OpenFile,
    permissions: SavedPermissions,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.file
        .set_permissions(std::fs::Permissions::from_mode(unix_mode(permissions)))
        .await
}

#[cfg(unix)]
async fn open_file(
    path: &str,
    pflags: OpenFlags,
    requested_mode: Option<u32>,
) -> std::io::Result<OpenFile> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let writable = pflags.intersects(OpenFlags::WRITE);
    let mut options: std::fs::OpenOptions = pflags.into();
    // Opening with TRUNCATE would destroy data before the file is narrowed.
    // Open first, restrict through the handle, and truncate only afterwards.
    if writable {
        options.truncate(false);
    }
    options.mode(0o600);
    let file = tokio::fs::OpenOptions::from(options).open(path).await?;
    let original_mode = file.metadata().await?.permissions().mode() & 0o777;
    if writable {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
        if pflags.contains(OpenFlags::TRUNCATE)
            && let Err(error) = file.set_len(0).await
        {
            let _ = file
                .set_permissions(std::fs::Permissions::from_mode(original_mode))
                .await;
            return Err(error);
        }
    }
    let mut open_file = OpenFile {
        file,
        path: path.to_owned(),
        writable,
        pending_permissions: None,
    };
    if writable {
        open_file.pending_permissions =
            Some(requested_mode.map(unix_mode).unwrap_or(original_mode));
    } else if let Some(mode) = requested_mode {
        set_file_permissions(&open_file, mode).await?;
    }
    Ok(open_file)
}

#[cfg(unix)]
async fn create_directory(path: &str, mode: Option<u32>) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let path = path.to_owned();
    let mode = unix_mode(mode.unwrap_or(0o700));
    tokio::task::spawn_blocking(move || {
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(mode).create(path)
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(unix)]
fn file_attributes(
    _path: &str,
    metadata: &std::fs::Metadata,
) -> Result<FileAttributes, StatusCode> {
    Ok(FileAttributes::from(metadata))
}

#[cfg(target_os = "motor")]
fn current_role() -> moto_io::fs::Role {
    match moto_sys::caps::ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities) {
        moto_sys::caps::ProcessRole::System => moto_io::fs::Role::System,
        moto_sys::caps::ProcessRole::Interactive => moto_io::fs::Role::Interactive,
        moto_sys::caps::ProcessRole::None => moto_io::fs::Role::None,
    }
}

#[cfg(target_os = "motor")]
fn to_motor_access(access: Access) -> moto_io::fs::AccessPermissions {
    match access {
        Access::None => moto_io::fs::AccessPermissions::None,
        Access::R => moto_io::fs::AccessPermissions::R,
        Access::Rw => moto_io::fs::AccessPermissions::Rw,
        Access::Rx => moto_io::fs::AccessPermissions::Rx,
        Access::Rwx => moto_io::fs::AccessPermissions::Rwx,
    }
}

#[cfg(target_os = "motor")]
fn from_motor_access(access: moto_io::fs::AccessPermissions) -> Access {
    match access {
        moto_io::fs::AccessPermissions::None => Access::None,
        moto_io::fs::AccessPermissions::R => Access::R,
        moto_io::fs::AccessPermissions::Rw => Access::Rw,
        moto_io::fs::AccessPermissions::Rx => Access::Rx,
        moto_io::fs::AccessPermissions::Rwx => Access::Rwx,
    }
}

#[cfg(target_os = "motor")]
fn translated_permissions(
    mut permissions: moto_io::fs::RolePermissions,
    mode: u32,
    directory: bool,
) -> moto_io::fs::RolePermissions {
    use moto_io::fs::Role;

    let normalized = NormalizedMode::from_posix(mode, directory);
    let owner = to_motor_access(normalized.owner);
    let public = to_motor_access(normalized.public);
    match current_role() {
        Role::System => {
            permissions.system = owner;
            permissions.interactive = public;
            permissions.none = public;
        }
        Role::Interactive => {
            permissions.interactive = owner;
            permissions.none = public;
        }
        Role::None => permissions.none = owner,
    }
    permissions
}

#[cfg(target_os = "motor")]
fn new_permissions(mode: u32, directory: bool) -> moto_io::fs::RolePermissions {
    translated_permissions(
        moto_io::fs::RolePermissions::all(moto_io::fs::AccessPermissions::Rwx),
        mode,
        directory,
    )
}

#[cfg(target_os = "motor")]
fn staging_permissions() -> moto_io::fs::RolePermissions {
    use moto_io::fs::{AccessPermissions, Role, RolePermissions};

    match current_role() {
        Role::System => RolePermissions::new(
            AccessPermissions::Rw,
            AccessPermissions::None,
            AccessPermissions::None,
        ),
        Role::Interactive => RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rw,
            AccessPermissions::None,
        ),
        Role::None => RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rwx,
            AccessPermissions::Rw,
        ),
    }
}

#[cfg(target_os = "motor")]
fn narrow_lower_roles(
    mut permissions: moto_io::fs::RolePermissions,
) -> moto_io::fs::RolePermissions {
    use moto_io::fs::{AccessPermissions, Role};

    match current_role() {
        Role::System => {
            permissions.interactive = AccessPermissions::None;
            permissions.none = AccessPermissions::None;
        }
        Role::Interactive => permissions.none = AccessPermissions::None,
        Role::None => {}
    }
    permissions
}

#[cfg(target_os = "motor")]
fn motor_io<T>(operation: impl Future<Output = moto_rt::Result<T>>) -> std::io::Result<T> {
    moto_async::LocalRuntime::new()
        .block_on(operation)
        .map_err(|error| std::io::Error::other(error.to_string()))
}

#[cfg(target_os = "motor")]
fn path_permissions(path: &str) -> std::io::Result<moto_io::fs::RolePermissions> {
    motor_io(async {
        let client = moto_io::fs::FsClient::connect()?;
        let (entry_id, _) = client.stat(&canonicalize_lexical(path)).await?;
        client.metadata(entry_id).await?.permissions()
    })
}

#[cfg(target_os = "motor")]
async fn set_path_permissions(path: &str, permissions: SavedPermissions) -> std::io::Result<()> {
    motor_io(async {
        let client = moto_io::fs::FsClient::connect()?;
        let (entry_id, _) = client.stat(&canonicalize_lexical(path)).await?;
        client.set_all_permissions(entry_id, permissions).await
    })
}

#[cfg(target_os = "motor")]
async fn set_file_permissions(
    file: &OpenFile,
    permissions: SavedPermissions,
) -> std::io::Result<()> {
    set_path_permissions(&file.path, permissions).await
}

#[cfg(target_os = "motor")]
fn create_motor_entry(
    path: &str,
    kind: moto_io::fs::EntryKind,
    permissions: moto_io::fs::RolePermissions,
) -> std::io::Result<()> {
    use std::path::Path;

    let absolute = canonicalize_lexical(path);
    let path = Path::new(&absolute);
    let parent = path.parent().and_then(Path::to_str).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid SFTP path")
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid SFTP file name")
        })?;
    motor_io(async {
        let client = moto_io::fs::FsClient::connect()?;
        let (parent_id, parent_kind) = client.stat(parent).await?;
        if parent_kind != moto_io::fs::EntryKind::Directory {
            return Err(moto_rt::Error::InvalidArgument);
        }
        client
            .create_entry_with_permissions(parent_id, kind, name, permissions)
            .await
            .map(|_| ())
    })
}

#[cfg(target_os = "motor")]
async fn open_file(
    path: &str,
    pflags: OpenFlags,
    requested_mode: Option<u32>,
) -> std::io::Result<OpenFile> {
    let writable = pflags.intersects(OpenFlags::WRITE);
    let mut original = match path_permissions(path) {
        Ok(permissions) => Some(permissions),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) if !std::path::Path::new(path).exists() => None,
        Err(error) => return Err(error),
    };
    if original.is_some() && pflags.contains(OpenFlags::CREATE | OpenFlags::EXCLUDE) {
        return Err(std::io::ErrorKind::AlreadyExists.into());
    }

    let mut actual_flags = pflags;
    if writable {
        if let Some(permissions) = original {
            set_path_permissions(path, narrow_lower_roles(permissions)).await?;
        } else if pflags.contains(OpenFlags::CREATE) {
            match create_motor_entry(path, moto_io::fs::EntryKind::File, staging_permissions()) {
                Ok(()) => actual_flags.remove(OpenFlags::CREATE | OpenFlags::EXCLUDE),
                Err(_error)
                    if !pflags.contains(OpenFlags::EXCLUDE)
                        && std::path::Path::new(path).exists() =>
                {
                    let permissions = path_permissions(path)?;
                    set_path_permissions(path, narrow_lower_roles(permissions)).await?;
                    original = Some(permissions);
                }
                Err(error) => return Err(error),
            }
        }
    }
    let options: std::fs::OpenOptions = actual_flags.into();
    let opened = tokio::fs::OpenOptions::from(options).open(path).await;
    let file = match opened {
        Ok(file) => file,
        Err(error) => {
            if let Some(permissions) = original {
                let _ = set_path_permissions(path, permissions).await;
            }
            return Err(error);
        }
    };
    let mut open_file = OpenFile {
        file,
        path: path.to_owned(),
        writable,
        pending_permissions: None,
    };
    if writable {
        open_file.pending_permissions = Some(match (requested_mode, original) {
            (Some(mode), Some(permissions)) => translated_permissions(permissions, mode, false),
            (Some(mode), None) => new_permissions(mode, false),
            (None, Some(permissions)) => permissions,
            (None, None) => staging_permissions(),
        });
    } else if let Some(mode) = requested_mode {
        let existing = path_permissions(path)?;
        set_file_permissions(&open_file, translated_permissions(existing, mode, false)).await?;
    }
    Ok(open_file)
}

#[cfg(target_os = "motor")]
async fn create_directory(path: &str, mode: Option<u32>) -> std::io::Result<()> {
    create_motor_entry(
        path,
        moto_io::fs::EntryKind::Directory,
        new_permissions(mode.unwrap_or(0o700), true),
    )
}

#[cfg(target_os = "motor")]
fn file_attributes(path: &str, metadata: &std::fs::Metadata) -> Result<FileAttributes, StatusCode> {
    use moto_io::fs::Role;

    let permissions = path_permissions(path).map_err(|error| {
        log::warn!("stat permissions for {path}: {error}");
        io_status(&error)
    })?;
    let directory = metadata.is_dir();
    let (owner, public) = match current_role() {
        Role::System => {
            let lower = from_motor_access(permissions.interactive)
                .intersect(from_motor_access(permissions.none), directory);
            (from_motor_access(permissions.system), lower)
        }
        Role::Interactive => (
            from_motor_access(permissions.interactive),
            from_motor_access(permissions.none),
        ),
        Role::None => (from_motor_access(permissions.none), Access::None),
    };
    let mut attrs = FileAttributes::from(metadata);
    let kind = if directory { 0o040000 } else { 0o100000 };
    attrs.permissions = Some(kind | NormalizedMode { owner, public }.reported_posix());
    Ok(attrs)
}

#[cfg(unix)]
fn updated_permissions(
    _current: SavedPermissions,
    mode: u32,
    _directory: bool,
) -> SavedPermissions {
    unix_mode(mode)
}

#[cfg(target_os = "motor")]
fn updated_permissions(current: SavedPermissions, mode: u32, directory: bool) -> SavedPermissions {
    translated_permissions(current, mode, directory)
}

async fn apply_path_mode(path: &str, mode: u32, directory: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    let permissions = unix_mode(mode);
    #[cfg(unix)]
    let _ = directory;
    #[cfg(target_os = "motor")]
    let permissions = translated_permissions(path_permissions(path)?, mode, directory);
    set_path_permissions(path, permissions).await
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
        let mut response = Version::new();
        response
            .extensions
            .insert(POSIX_RENAME.to_owned(), POSIX_RENAME_VERSION.to_owned());
        Ok(response)
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
            if let Some(permissions) = open_file.pending_permissions {
                set_file_permissions(&open_file, permissions)
                    .await
                    .map_err(|err| {
                        log::warn!("close: permissions '{handle}' failed: {err:?}");
                        io_status(&err)
                    })?;
            }
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
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if !pflags.intersects(OpenFlags::READ | OpenFlags::WRITE) {
            log::warn!("open: {filename}: missing read/write flag in 0x{pflags:x}");
            return Err(StatusCode::BadMessage);
        }

        let requested_mode = permission_mode(&attrs)?;
        let file = open_file(&filename, pflags, requested_mode)
            .await
            .map_err(|error| {
                log::warn!("open: {filename}: {error}");
                io_status(&error)
            })?;

        let handle = format!("{:x}", self.new_id());
        assert!(self.open_files.insert(handle.clone(), file,).is_none());

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
        let mut deferred = false;
        for file in self
            .open_files
            .values_mut()
            .filter(|file| file.writable && file.path == path)
        {
            let current = file.pending_permissions.ok_or(StatusCode::Failure)?;
            file.pending_permissions = Some(updated_permissions(current, mode, false));
            deferred = true;
        }
        if deferred {
            return Ok(ok_status(id));
        }
        let metadata = tokio::fs::metadata(&path).await.map_err(|error| {
            log::warn!("setstat metadata {path}: {error}");
            io_status(&error)
        })?;
        apply_path_mode(&path, mode, metadata.is_dir())
            .await
            .map_err(|error| {
                log::warn!("setstat {path}: {error}");
                io_status(&error)
            })?;
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        mut attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let Some(file) = self.open_files.get_mut(&handle) else {
            return Err(StatusCode::BadMessage);
        };
        // OpenSSH scp pins each in-place upload to its last acknowledged byte.
        let size = attrs.size.take();
        let mode = permission_mode(&attrs)?;
        if let Some(size) = size {
            file.file.set_len(size).await.map_err(|error| {
                log::warn!("fsetstat size {handle}: {error}");
                io_status(&error)
            })?;
        }
        if let Some(mode) = mode {
            if file.writable {
                let current = file.pending_permissions.ok_or(StatusCode::Failure)?;
                file.pending_permissions = Some(updated_permissions(current, mode, false));
            } else {
                #[cfg(unix)]
                let current = 0;
                #[cfg(target_os = "motor")]
                let current = path_permissions(&file.path).map_err(|error| io_status(&error))?;
                let permissions = updated_permissions(current, mode, false);
                set_file_permissions(file, permissions)
                    .await
                    .map_err(|error| {
                        log::warn!("fsetstat permissions {handle}: {error}");
                        io_status(&error)
                    })?;
            }
        }
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
        create_directory(&path, mode).await.map_err(|error| {
            log::warn!("mkdir {path}: {error}");
            io_status(&error)
        })?;
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
        // The no-replace rename is a synchronous filesystem call; keep it off
        // the single-threaded runtime like the tokio::fs-based handlers.
        let (old, new) = (oldpath.clone(), newpath.clone());
        tokio::task::spawn_blocking(move || rename_noreplace(&old, &new))
            .await
            .map_err(|error| {
                log::warn!("rename {oldpath} -> {newpath}: {error}");
                StatusCode::Failure
            })?
            .inspect_err(|error| {
                log::warn!("rename {oldpath} -> {newpath}: {error}");
            })?;
        Ok(ok_status(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        if request != POSIX_RENAME {
            return Err(StatusCode::OpUnsupported);
        }
        let (oldpath, newpath) = decode_posix_rename(data).map_err(|error| {
            log::warn!("invalid {POSIX_RENAME} request: {error}");
            StatusCode::BadMessage
        })?;
        // motor-fs's replacing move deletes an existing empty-directory
        // destination whatever the source kind is; POSIX rename fails
        // mismatched kinds (EISDIR/ENOTDIR), and the kernel enforces that on
        // the other platforms.
        #[cfg(target_os = "motor")]
        if let Ok(new_metadata) = tokio::fs::metadata(&newpath).await {
            let old_metadata = tokio::fs::metadata(&oldpath).await.map_err(|error| {
                log::warn!("{POSIX_RENAME} {oldpath} -> {newpath}: {error}");
                io_status(&error)
            })?;
            if old_metadata.is_dir() != new_metadata.is_dir() {
                log::warn!("{POSIX_RENAME} {oldpath} -> {newpath}: kind mismatch");
                return Err(StatusCode::Failure);
            }
        }
        tokio::fs::rename(&oldpath, &newpath)
            .await
            .map_err(|error| {
                log::warn!("{POSIX_RENAME} {oldpath} -> {newpath}: {error}");
                io_status(&error)
            })?;
        Ok(ok_status(id).into())
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
    if !path.starts_with('/')
        && let Ok(cwd) = std::env::current_dir()
    {
        for component in cwd.components() {
            if let std::path::Component::Normal(c) = component {
                components.push(c.to_string_lossy().into_owned());
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
    use crate::sftp_extensions::{POSIX_RENAME, POSIX_RENAME_VERSION, encode_posix_rename};
    use russh_sftp::protocol::{FileAttributes, OpenFlags, Packet, StatusCode};
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
    fn server_advertises_posix_rename() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let version = runtime
            .block_on(SftpSession::default().init(3, Default::default()))
            .unwrap();
        assert_eq!(
            version.extensions.get(POSIX_RENAME).map(String::as_str),
            Some(POSIX_RENAME_VERSION)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn standard_rename_refuses_replacement_and_posix_rename_replaces() {
        let root = temp_path("rename-semantics");
        let source = root.join("source");
        let target = root.join("target");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&target, b"target").unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut session = SftpSession::default();
            assert_eq!(
                session
                    .rename(
                        1,
                        source.to_string_lossy().into_owned(),
                        target.to_string_lossy().into_owned(),
                    )
                    .await
                    .unwrap_err(),
                StatusCode::Failure
            );
            assert_eq!(std::fs::read(&source).unwrap(), b"source");
            assert_eq!(std::fs::read(&target).unwrap(), b"target");

            let data = encode_posix_rename(&source.to_string_lossy(), &target.to_string_lossy());
            let Packet::Status(status) = session
                .extended(2, POSIX_RENAME.to_owned(), data)
                .await
                .unwrap()
            else {
                panic!("POSIX rename returned an unexpected packet");
            };
            assert_eq!(status.status_code, StatusCode::Ok);
            assert!(!source.exists());
            assert_eq!(std::fs::read(&target).unwrap(), b"source");

            assert_eq!(
                session
                    .extended(3, "unknown@example.com".to_owned(), Vec::new())
                    .await
                    .unwrap_err(),
                StatusCode::OpUnsupported
            );
            assert_eq!(
                session
                    .extended(4, POSIX_RENAME.to_owned(), vec![0])
                    .await
                    .unwrap_err(),
                StatusCode::BadMessage
            );

            assert_eq!(
                session
                    .rename(
                        5,
                        root.join("missing").to_string_lossy().into_owned(),
                        root.join("elsewhere").to_string_lossy().into_owned(),
                    )
                    .await
                    .unwrap_err(),
                StatusCode::NoSuchFile
            );

            // A file must not replace a directory, even an empty one.
            let file = root.join("file");
            let dir = root.join("dir");
            std::fs::write(&file, b"file").unwrap();
            std::fs::create_dir(&dir).unwrap();
            let data = encode_posix_rename(&file.to_string_lossy(), &dir.to_string_lossy());
            assert!(
                session
                    .extended(6, POSIX_RENAME.to_owned(), data)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&file).unwrap(), b"file");
            assert!(dir.is_dir());
        });

        std::fs::remove_dir_all(root).unwrap();
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
                    attrs(0o750),
                )
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );

            let with_times = FileAttributes {
                atime: Some(1_700_000_000),
                mtime: Some(1_700_000_001),
                ..FileAttributes::empty()
            };
            session
                .fsetstat(3, opened.handle.clone(), with_times)
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );

            let size = FileAttributes {
                size: Some(4),
                ..FileAttributes::empty()
            };
            session
                .fsetstat(4, opened.handle.clone(), size)
                .await
                .unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"perm");

            let unsupported = FileAttributes {
                uid: Some(1000),
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
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o750
            );

            session
                .setstat(7, path.to_string_lossy().into_owned(), attrs(0o640))
                .await
                .unwrap();
            let opened = session
                .open(
                    8,
                    path.to_string_lossy().into_owned(),
                    OpenFlags::WRITE,
                    attrs(0o750),
                )
                .await
                .unwrap();
            session
                .setstat(9, path.to_string_lossy().into_owned(), attrs(0o640))
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            session.close(10, opened.handle).await.unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );

            let opened = session
                .open(
                    11,
                    path.to_string_lossy().into_owned(),
                    OpenFlags::READ,
                    FileAttributes::empty(),
                )
                .await
                .unwrap();
            session
                .fsetstat(12, opened.handle.clone(), attrs(0o750))
                .await
                .unwrap();
            session.close(13, opened.handle).await.unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o750
            );
        });

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn writable_open_defers_restrictive_modes_until_close() {
        use std::os::unix::fs::PermissionsExt;

        let attrs = |mode| FileAttributes {
            permissions: Some(mode),
            ..FileAttributes::empty()
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for (label, requested, final_mode) in [("exec", 0o755, 0o755), ("read", 0o400, 0o400)] {
            let path = temp_path(label);
            runtime.block_on(async {
                let mut session = SftpSession::default();
                let opened = session
                    .open(
                        1,
                        path.to_string_lossy().into_owned(),
                        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                        attrs(requested),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                session
                    .write(2, opened.handle.clone(), 0, b"complete".to_vec())
                    .await
                    .unwrap();
                session.close(3, opened.handle).await.unwrap();
            });
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                final_mode
            );
            std::fs::remove_file(path).unwrap();
        }

        let abandoned = temp_path("abandoned");
        runtime.block_on(async {
            let mut session = SftpSession::default();
            session
                .open(
                    1,
                    abandoned.to_string_lossy().into_owned(),
                    OpenFlags::WRITE | OpenFlags::CREATE,
                    attrs(0o755),
                )
                .await
                .unwrap();
        });
        assert_eq!(
            std::fs::metadata(&abandoned).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_file(abandoned).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_handlers_cover_supported_sftp_operations() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("filesystem-operations");
        let directory = root.join("directory");
        let original = directory.join("original");
        let renamed = directory.join("renamed");
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
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
                .setstat(
                    7,
                    directory.to_string_lossy().into_owned(),
                    FileAttributes {
                        permissions: Some(0o500),
                        ..FileAttributes::empty()
                    },
                )
                .await
                .unwrap();
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o500
            );
            session
                .rmdir(8, directory.to_string_lossy().into_owned())
                .await
                .unwrap();

            assert_eq!(
                session.fstat(9, "unknown".to_string()).await.unwrap_err(),
                StatusCode::BadMessage
            );
        });

        std::fs::remove_dir(root).unwrap();
    }
}
