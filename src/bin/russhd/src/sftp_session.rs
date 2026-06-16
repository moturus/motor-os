//! SFTP server implementation.
//!
//! Protocol: https://www.ietf.org/proceedings/50/I-D/secsh-filexfer-00.txt

use russh_sftp::protocol::{File, FileAttributes, Handle, Name, Status, StatusCode, Version};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[derive(Default)]
pub struct SftpSession {
    version: Option<u32>,

    // Handle: u64 as hex.
    open_files: HashMap<String, tokio::fs::File>,
    // Handle: u64 as hex -> open directory, read incrementally by readdir.
    open_dirs: HashMap<String, tokio::fs::ReadDir>,
    next_id: u64,
}

impl SftpSession {
    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
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
        if self.open_files.remove(&handle).is_some() || self.open_dirs.remove(&handle).is_some() {
            log::info!("close {handle}: Ok");
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".to_string(),
                language_tag: "en-US".to_string(),
            })
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
                        Ok(metadata) => FileAttributes::from(&metadata),
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
        pflags: russh_sftp::protocol::OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if pflags.bits() != russh_sftp::protocol::OpenFlags::READ.bits() {
            log::warn!("open: {filename}: unsupported flags 0x{pflags:x}");
            return Err(self.unimplemented());
        }

        let file = tokio::fs::File::open(filename.as_str())
            .await
            .map_err(|err| {
                log::warn!("open: {filename}: Err: {err:?}");
                StatusCode::NoSuchFile
            })?;

        let handle = format!("{:x}", self.new_id());
        assert!(self.open_files.insert(handle.clone(), file).is_none());

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
        let Some(file) = self.open_files.get_mut(&handle) else {
            log::warn!("read {handle}: Err: not found");
            return Err(StatusCode::BadMessage);
        };

        file.seek(std::io::SeekFrom::Start(offset))
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
            let num_read = file
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
            attrs: FileAttributes::from(&metadata),
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
    use super::canonicalize_lexical;

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
}
