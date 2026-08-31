use std::future::Future;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;

use rand::RngExt as _;

use russh_sftp::client::RawSftpSession;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, Packet, StatusCode};

use super::local;
use super::sftp::SftpConnection;
use crate::sftp_extensions::{POSIX_RENAME, encode_posix_rename};

const PACKET_SIZE: usize = 261_120;
const MAX_DEPTH: usize = 64;

pub async fn upload_file(
    connection: &SftpConnection,
    source: &Path,
    target: &str,
) -> Result<(), Error> {
    let sftp = &connection.raw;
    let mut source_file = std::fs::File::open(source)?;
    if !source_file.metadata()?.is_file() {
        return Err(Error::Message(
            "local source is not a regular file".to_owned(),
        ));
    }
    let mode = local::file_mode(source, false)?;
    let existing = existing_remote_file(connection, target).await?;
    let staging = remote_staging_path(target)?;
    // Prefer a staging file installed by an atomic rename. Without
    // posix-rename an existing target cannot be replaced that way, and a
    // read-only parent directory refuses the staging file; both fall back to
    // an OpenSSH-style in-place overwrite.
    let staging_handle = if existing.is_some() && !connection.posix_rename {
        None
    } else {
        match sftp
            .open(
                staging.clone(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                attributes(0o600, false),
            )
            .await
        {
            Ok(handle) => Some(handle.handle),
            Err(SftpError::Status(status))
                if status.status_code == StatusCode::PermissionDenied && existing.is_some() =>
            {
                None
            }
            Err(error) => return Err(error.into()),
        }
    };
    let staged = staging_handle.is_some();
    let handle = match staging_handle {
        Some(handle) => handle,
        None => {
            sftp.open(
                target.to_owned(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                FileAttributes::empty(),
            )
            .await?
            .handle
        }
    };
    let result = async {
        let chunk_size = limited_packet(connection.limits.write_len);
        let mut offset = 0_u64;
        loop {
            let mut data = vec![0; chunk_size];
            let read = source_file.read(&mut data)?;
            if read == 0 {
                break;
            }
            data.truncate(read);
            sftp.write(handle.clone(), offset, data).await?;
            offset = offset
                .checked_add(read as u64)
                .ok_or_else(|| Error::Message("file offset overflow".to_owned()))?;
        }
        if staged {
            // Replacing keeps the target's mode, the way an in-place
            // overwrite would; only a new file gets the source's.
            sftp.fsetstat(
                handle.clone(),
                attributes(existing.flatten().unwrap_or(mode), false),
            )
            .await?;
        }
        Ok::<(), Error>(())
    }
    .await;
    let close = sftp.close(handle).await;
    if let Err(error) = result {
        if staged {
            let _ = sftp.remove(staging).await;
        }
        return Err(error);
    }
    if let Err(error) = close {
        if staged {
            let _ = sftp.remove(staging).await;
        }
        return Err(error.into());
    }
    if staged && let Err(error) = install_remote_file(connection, &staging, target).await {
        let _ = sftp.remove(staging).await;
        return Err(error);
    }
    Ok(())
}

pub async fn download_file(
    connection: &SftpConnection,
    source: &str,
    target: &Path,
) -> Result<(), Error> {
    let sftp = &connection.raw;
    let attrs = sftp.stat(source).await?.attrs;
    if !attrs.is_regular() {
        return Err(Error::Message(
            "remote source is not a regular file".to_owned(),
        ));
    }
    let existing = existing_local_file(target)?;
    let handle = sftp
        .open(source.to_owned(), OpenFlags::READ, FileAttributes::empty())
        .await?
        .handle;
    // Like the upload side: a staging file installed by a rename, falling
    // back to an in-place overwrite when a read-only parent directory
    // refuses the staging file.
    let staging = local_staging_path(target)?;
    let (mut target_file, staging) = match local::create_file(&staging, 0o600) {
        Ok(file) => (file, Some(staging)),
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied && existing.is_some() =>
        {
            let opened = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(target);
            match opened {
                Ok(file) => (file, None),
                Err(error) => {
                    let _ = sftp.close(handle).await;
                    return Err(error.into());
                }
            }
        }
        Err(error) => {
            let _ = sftp.close(handle).await;
            return Err(error.into());
        }
    };
    let result = async {
        let chunk_size = limited_packet(connection.limits.read_len) as u32;
        let mut offset = 0_u64;
        loop {
            match sftp.read(handle.clone(), offset, chunk_size).await {
                Ok(data) => {
                    if data.data.is_empty() {
                        return Err(Error::Message(
                            "remote returned an empty data packet".to_owned(),
                        ));
                    }
                    target_file.write_all(&data.data)?;
                    offset = offset
                        .checked_add(data.data.len() as u64)
                        .ok_or_else(|| Error::Message("file offset overflow".to_owned()))?;
                }
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => break,
                Err(error) => return Err(error.into()),
            }
        }
        target_file.flush()?;
        Ok::<(), Error>(())
    }
    .await;
    let close = sftp.close(handle).await;
    drop(target_file);
    if let Err(error) = result {
        if let Some(staging) = &staging {
            let _ = std::fs::remove_file(staging);
        }
        return Err(error);
    }
    if let Err(error) = close {
        if let Some(staging) = &staging {
            let _ = std::fs::remove_file(staging);
        }
        return Err(error.into());
    }
    if let Some(staging) = &staging {
        // Replacing keeps the target's mode; only a new file gets the
        // remote's.
        let mode = existing.unwrap_or(attrs.permissions.unwrap_or(0o644));
        if let Err(error) = local::set_mode(staging, mode, false) {
            let _ = std::fs::remove_file(staging);
            return Err(error.into());
        }
        if let Err(error) = std::fs::rename(staging, target) {
            let _ = std::fs::remove_file(staging);
            return Err(error.into());
        }
    }
    Ok(())
}

pub fn upload_tree<'a>(
    connection: &'a SftpConnection,
    source: &'a Path,
    target: &'a str,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    upload_tree_at(connection, source, target, 0)
}

fn upload_tree_at<'a>(
    connection: &'a SftpConnection,
    source: &'a Path,
    target: &'a str,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    Box::pin(async move {
        let sftp = &connection.raw;
        check_depth(depth)?;
        let metadata = source.symlink_metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Message(
                "symbolic links are not supported".to_owned(),
            ));
        }
        if metadata.is_file() {
            return upload_file(connection, source, target).await;
        }
        if !metadata.is_dir() {
            return Err(Error::Message("unsupported local file type".to_owned()));
        }
        let final_mode = local::file_mode(source, true)?;
        let created = ensure_remote_dir(sftp, target).await?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Message("local file name is not UTF-8".to_owned()))?;
            validate_component(&name)?;
            let remote = remote_join(target, &name);
            upload_tree_at(connection, &entry.path(), &remote, depth + 1).await?;
        }
        // Only a directory this transfer created gets the source's mode;
        // merging must not rewrite the permissions of an existing one.
        if created {
            sftp.setstat(target.to_owned(), attributes(final_mode, true))
                .await?;
        }
        Ok(())
    })
}

pub fn download_tree<'a>(
    connection: &'a SftpConnection,
    source: &'a str,
    target: &'a Path,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    download_tree_at(connection, source, target, 0)
}

fn download_tree_at<'a>(
    connection: &'a SftpConnection,
    source: &'a str,
    target: &'a Path,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    Box::pin(async move {
        let sftp = &connection.raw;
        check_depth(depth)?;
        let attrs = sftp.lstat(source).await?.attrs;
        if attrs.is_regular() {
            return download_file(connection, source, target).await;
        }
        if !attrs.is_dir() {
            return Err(Error::Message("unsupported remote file type".to_owned()));
        }
        let created = ensure_local_dir(target)?;
        let handle = sftp.opendir(source.to_owned()).await?.handle;
        let result = async {
            loop {
                match sftp.readdir(handle.clone()).await {
                    Ok(names) => {
                        for entry in names.files {
                            if entry.filename == "." || entry.filename == ".." {
                                continue;
                            }
                            validate_component(&entry.filename)?;
                            let remote = remote_join(source, &entry.filename);
                            let local = target.join(&entry.filename);
                            download_tree_at(connection, &remote, &local, depth + 1).await?;
                        }
                    }
                    Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => {
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok::<(), Error>(())
        }
        .await;
        let close = sftp.close(handle).await;
        result?;
        close?;
        // Matches the upload side: existing directories keep their mode.
        if created {
            local::set_mode(target, attrs.permissions.unwrap_or(0o755), true)?;
        }
        Ok(())
    })
}

/// Replaces `newpath` atomically via posix-rename@openssh.com. The caller
/// must have negotiated the extension (`connection.posix_rename`).
pub async fn posix_rename(
    connection: &SftpConnection,
    oldpath: &str,
    newpath: &str,
) -> Result<(), Error> {
    let data = encode_posix_rename(oldpath, newpath);
    match connection.raw.extended(POSIX_RENAME, data).await? {
        Packet::Status(status) if status.status_code == StatusCode::Ok => Ok(()),
        Packet::Status(status) => Err(SftpError::Status(status).into()),
        _ => Err(SftpError::UnexpectedPacket.into()),
    }
}

async fn install_remote_file(
    connection: &SftpConnection,
    staging: &str,
    target: &str,
) -> Result<(), Error> {
    if connection.posix_rename {
        posix_rename(connection, staging, target).await
    } else {
        // The target was absent when the transfer started (upload_file falls
        // back to an in-place overwrite otherwise), so the no-replace rename
        // only fails if it appeared concurrently.
        connection
            .raw
            .rename(staging.to_owned(), target.to_owned())
            .await?;
        Ok(())
    }
}

/// The state of an existing regular-file transfer target: None when absent,
/// Some(mode) otherwise, with the mode itself None when the server did not
/// report one. Any other existing kind fails before data is transferred.
async fn existing_remote_file(
    connection: &SftpConnection,
    target: &str,
) -> Result<Option<Option<u32>>, Error> {
    match connection.raw.stat(target.to_owned()).await {
        Ok(attrs) => existing_file_mode(&attrs.attrs).map(Some).map_err(|()| {
            Error::Message(format!(
                "remote target '{target}' exists and is not a regular file"
            ))
        }),
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The permissions attribute is optional and its file-type bits may be
/// absent too, so an entry counts as a regular file unless the type bits
/// name another kind; the mode is None when the server reported none.
fn existing_file_mode(attrs: &FileAttributes) -> Result<Option<u32>, ()> {
    match attrs.permissions.map(|mode| mode & 0o170000) {
        None | Some(0) | Some(0o100000) => Ok(attrs.permissions.map(|mode| mode & 0o777)),
        Some(_) => Err(()),
    }
}

fn existing_local_file(target: &Path) -> Result<Option<u32>, Error> {
    match target.symlink_metadata() {
        Ok(metadata) if metadata.is_file() => Ok(Some(local::file_mode(target, false)?)),
        Ok(_) => Err(Error::Message(format!(
            "local target '{}' exists and is not a regular file",
            target.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

// Both ensure helpers create first — the fresh-tree path costs one round
// trip, and two concurrent transfers cannot both pass an existence check —
// and treat an existing directory as a merge target, reporting whether the
// directory was created. New directories start at 0700 so the transfer can
// write into them; the caller stamps the final mode.
async fn ensure_remote_dir(sftp: &RawSftpSession, path: &str) -> Result<bool, Error> {
    let mkdir_error = match sftp.mkdir(path.to_owned(), attributes(0o700, true)).await {
        Ok(_) => return Ok(true),
        Err(error) => error,
    };
    match sftp.lstat(path.to_owned()).await {
        // lstat: a symlink planted at the target is refused, not silently
        // traversed, matching the local side.
        Ok(attrs) if attrs.attrs.is_dir() => Ok(false),
        Ok(_) => Err(Error::Message(format!(
            "remote target '{path}' exists and is not a directory"
        ))),
        Err(_) => Err(mkdir_error.into()),
    }
}

fn ensure_local_dir(path: &Path) -> Result<bool, Error> {
    let create_error = match local::create_dir(path, 0o700) {
        Ok(()) => return Ok(true),
        Err(error) => error,
    };
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() => Ok(false),
        Ok(_) => Err(Error::Message(format!(
            "local target '{}' exists and is not a directory",
            path.display()
        ))),
        Err(_) => Err(create_error.into()),
    }
}

pub fn remote_join(parent: &str, child: &str) -> String {
    if parent == "/" {
        format!("/{child}")
    } else {
        format!("{}/{child}", parent.trim_end_matches('/'))
    }
}

pub fn basename(path: &str) -> Result<&str, Error> {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Message("path has no file name".to_owned()))
}

fn validate_component(value: &str) -> Result<(), Error> {
    let mut components = Path::new(value).components();
    if value.is_empty()
        || value.contains('/')
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(Error::Message(format!("unsafe directory entry '{value}'")));
    }
    Ok(())
}

fn attributes(mode: u32, directory: bool) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(mode & 0o777);
    if directory {
        attrs.set_dir(true);
    } else {
        attrs.set_regular(true);
    }
    attrs
}

fn limited_packet(limit: Option<u64>) -> usize {
    limit
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(PACKET_SIZE)
        .clamp(1, PACKET_SIZE)
}

fn check_depth(depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        Err(Error::Message("recursive copy exceeds depth 64".to_owned()))
    } else {
        Ok(())
    }
}

fn remote_staging_path(target: &str) -> Result<String, Error> {
    let name = basename(target)?;
    let id = rand::rng().random::<u128>();
    let staging = format!(".{name}.motor-scp-{id:032x}");
    let parent = target
        .trim_end_matches('/')
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent });
    Ok(parent.map_or(staging.clone(), |parent| remote_join(parent, &staging)))
}

fn local_staging_path(target: &Path) -> Result<PathBuf, Error> {
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Message("local path has no UTF-8 file name".to_owned()))?;
    let id = rand::rng().random::<u128>();
    Ok(target.with_file_name(format!(".{name}.motor-scp-{id:032x}")))
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Sftp(SftpError),
    Message(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Sftp(error) => error.fmt(f),
            Self::Message(message) => message.fmt(f),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<SftpError> for Error {
    fn from(error: SftpError) -> Self {
        Self::Sftp(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_remote_components() {
        for safe in ["file", "two words", "..hidden"] {
            validate_component(safe).unwrap();
        }
        for unsafe_name in ["", ".", "..", "a/b", "/absolute"] {
            assert!(validate_component(unsafe_name).is_err());
        }
    }

    #[test]
    fn joins_and_names_remote_paths() {
        assert_eq!(remote_join("/", "file"), "/file");
        assert_eq!(remote_join("dir/", "file"), "dir/file");
        assert_eq!(basename("dir/file/").unwrap(), "file");
    }

    #[test]
    fn honors_smaller_packet_limits() {
        assert_eq!(limited_packet(None), PACKET_SIZE);
        assert_eq!(limited_packet(Some(100)), 100);
        assert_eq!(limited_packet(Some(0)), 1);
    }

    #[test]
    fn existing_local_transfer_target_must_be_a_directory() {
        let root = std::env::temp_dir().join(format!(
            "russhd-transfer-{}-{}",
            std::process::id(),
            rand::rng().random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        assert!(!ensure_local_dir(&root).unwrap());

        let file = root.join("file");
        std::fs::write(&file, b"file").unwrap();
        assert!(matches!(ensure_local_dir(&file), Err(Error::Message(_))));

        let created = root.join("created");
        assert!(ensure_local_dir(&created).unwrap());
        assert!(created.is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_file_mode_tolerates_optional_permissions() {
        let mut attrs = FileAttributes::empty();
        assert_eq!(existing_file_mode(&attrs), Ok(None));
        attrs.permissions = Some(0o644);
        assert_eq!(existing_file_mode(&attrs), Ok(Some(0o644)));
        attrs.permissions = Some(0o100600);
        assert_eq!(existing_file_mode(&attrs), Ok(Some(0o600)));
        for other_kind in [0o040755, 0o120777, 0o140644] {
            attrs.permissions = Some(other_kind);
            assert_eq!(existing_file_mode(&attrs), Err(()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_local_file_reports_mode_absence_and_kind() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "russhd-transfer-existing-{}-{}",
            std::process::id(),
            rand::rng().random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        assert!(matches!(existing_local_file(&root), Err(Error::Message(_))));

        let file = root.join("file");
        std::fs::write(&file, b"file").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(existing_local_file(&file).unwrap(), Some(0o640));

        assert_eq!(existing_local_file(&root.join("missing")).unwrap(), None);
        std::fs::remove_dir_all(root).unwrap();
    }
}
