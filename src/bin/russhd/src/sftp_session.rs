//! SFTP server implementation.
//!
//! Protocol: https://www.ietf.org/proceedings/50/I-D/secsh-filexfer-00.txt

use russh_sftp::protocol::{FileAttributes, Handle, Name, Status, StatusCode, Version};
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[derive(Default)]
pub struct SftpSession {
    version: Option<u32>,

    // Handle: u64 as hex.
    open_files: HashMap<String, tokio::fs::File>,
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
        if self.open_files.remove(&handle).is_some() {
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

    async fn opendir(&mut self, _id: u32, path: String) -> Result<Handle, Self::Error> {
        log::info!("opendir: {}", path);
        Err(StatusCode::OpUnsupported)
    }

    async fn readdir(&mut self, _id: u32, handle: String) -> Result<Name, Self::Error> {
        log::info!("readdir: {}", handle);
        Err(StatusCode::OpUnsupported)
    }

    async fn realpath(&mut self, _id: u32, path: String) -> Result<Name, Self::Error> {
        log::info!("realpath: {}", path);
        Err(StatusCode::OpUnsupported)
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
