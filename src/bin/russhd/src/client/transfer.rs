use std::future::Future;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;

use rand::RngExt as _;

use russh_sftp::client::RawSftpSession;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};

use super::local;

const PACKET_SIZE: usize = 261_120;
const MAX_DEPTH: usize = 64;

pub async fn upload_file(
    sftp: &RawSftpSession,
    source: &Path,
    target: &str,
    write_limit: Option<u64>,
) -> Result<(), Error> {
    let mut source_file = std::fs::File::open(source)?;
    if !source_file.metadata()?.is_file() {
        return Err(Error::Message(
            "local source is not a regular file".to_owned(),
        ));
    }
    let mode = local::file_mode(source, false)?;
    let staging = remote_staging_path(target)?;
    let attrs = attributes(0o600, false);
    let handle = sftp
        .open(
            staging.clone(),
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
            attrs,
        )
        .await?
        .handle;
    let result = async {
        let chunk_size = limited_packet(write_limit);
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
        sftp.fsetstat(handle.clone(), attributes(mode, false))
            .await?;
        Ok::<(), Error>(())
    }
    .await;
    let close = sftp.close(handle).await;
    if let Err(error) = result {
        let _ = sftp.remove(staging).await;
        return Err(error);
    }
    if let Err(error) = close {
        let _ = sftp.remove(staging).await;
        return Err(error.into());
    }
    if let Err(error) = sftp.rename(staging.clone(), target.to_owned()).await {
        let _ = sftp.remove(staging).await;
        return Err(error.into());
    }
    Ok(())
}

pub async fn download_file(
    sftp: &RawSftpSession,
    source: &str,
    target: &Path,
    read_limit: Option<u64>,
) -> Result<(), Error> {
    let attrs = sftp.stat(source).await?.attrs;
    if !attrs.is_regular() {
        return Err(Error::Message(
            "remote source is not a regular file".to_owned(),
        ));
    }
    let handle = sftp
        .open(source.to_owned(), OpenFlags::READ, FileAttributes::empty())
        .await?
        .handle;
    let staging = local_staging_path(target)?;
    let mut target_file = match local::create_file(&staging, 0o600) {
        Ok(file) => file,
        Err(error) => {
            let _ = sftp.close(handle).await;
            return Err(error.into());
        }
    };
    let result = async {
        let chunk_size = limited_packet(read_limit) as u32;
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
        let _ = std::fs::remove_file(&staging);
        return Err(error);
    }
    if let Err(error) = close {
        let _ = std::fs::remove_file(&staging);
        return Err(error.into());
    }
    if let Err(error) = local::set_mode(&staging, attrs.permissions.unwrap_or(0o644), false) {
        let _ = std::fs::remove_file(&staging);
        return Err(error.into());
    }
    if let Err(error) = std::fs::rename(&staging, target) {
        let _ = std::fs::remove_file(&staging);
        return Err(error.into());
    }
    Ok(())
}

pub fn upload_tree<'a>(
    sftp: &'a RawSftpSession,
    source: &'a Path,
    target: &'a str,
    write_limit: Option<u64>,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    upload_tree_at(sftp, source, target, write_limit, 0)
}

fn upload_tree_at<'a>(
    sftp: &'a RawSftpSession,
    source: &'a Path,
    target: &'a str,
    write_limit: Option<u64>,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    Box::pin(async move {
        check_depth(depth)?;
        let metadata = source.symlink_metadata()?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Message(
                "symbolic links are not supported".to_owned(),
            ));
        }
        if metadata.is_file() {
            return upload_file(sftp, source, target, write_limit).await;
        }
        if !metadata.is_dir() {
            return Err(Error::Message("unsupported local file type".to_owned()));
        }
        let final_mode = local::file_mode(source, true)?;
        sftp.mkdir(target.to_owned(), attributes(0o700, true))
            .await?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Message("local file name is not UTF-8".to_owned()))?;
            validate_component(&name)?;
            let remote = remote_join(target, &name);
            upload_tree_at(sftp, &entry.path(), &remote, write_limit, depth + 1).await?;
        }
        sftp.setstat(target.to_owned(), attributes(final_mode, true))
            .await?;
        Ok(())
    })
}

pub fn download_tree<'a>(
    sftp: &'a RawSftpSession,
    source: &'a str,
    target: &'a Path,
    read_limit: Option<u64>,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    download_tree_at(sftp, source, target, read_limit, 0)
}

fn download_tree_at<'a>(
    sftp: &'a RawSftpSession,
    source: &'a str,
    target: &'a Path,
    read_limit: Option<u64>,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>> {
    Box::pin(async move {
        check_depth(depth)?;
        let attrs = sftp.lstat(source).await?.attrs;
        if attrs.is_regular() {
            return download_file(sftp, source, target, read_limit).await;
        }
        if !attrs.is_dir() {
            return Err(Error::Message("unsupported remote file type".to_owned()));
        }
        local::create_dir(target, 0o700)?;
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
                            download_tree_at(sftp, &remote, &local, read_limit, depth + 1).await?;
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
        local::set_mode(target, attrs.permissions.unwrap_or(0o755), true)?;
        Ok(())
    })
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
}
