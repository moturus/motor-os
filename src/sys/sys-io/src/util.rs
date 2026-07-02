use async_fs::FileSystem;
use std::rc::Rc;

pub fn map_err_into_native(err: std::io::Error) -> moto_rt::Error {
    match err.kind() {
        std::io::ErrorKind::NotFound => moto_rt::Error::NotFound,
        std::io::ErrorKind::PermissionDenied => moto_rt::Error::NotAllowed,
        std::io::ErrorKind::ConnectionRefused => moto_rt::Error::NotConnected,
        std::io::ErrorKind::ConnectionReset => moto_rt::Error::NotConnected,
        std::io::ErrorKind::HostUnreachable => moto_rt::Error::NotConnected,
        std::io::ErrorKind::NetworkUnreachable => moto_rt::Error::NotConnected,
        std::io::ErrorKind::ConnectionAborted => moto_rt::Error::NotConnected,
        std::io::ErrorKind::NotConnected => moto_rt::Error::NotConnected,
        std::io::ErrorKind::AddrInUse => moto_rt::Error::AlreadyInUse,
        std::io::ErrorKind::AddrNotAvailable => todo!(),
        std::io::ErrorKind::NetworkDown => moto_rt::Error::NotConnected,
        std::io::ErrorKind::BrokenPipe => moto_rt::Error::NotConnected,
        std::io::ErrorKind::AlreadyExists => moto_rt::Error::AlreadyInUse,
        std::io::ErrorKind::WouldBlock => moto_rt::Error::NotReady,
        std::io::ErrorKind::NotADirectory => moto_rt::Error::NotADirectory,
        std::io::ErrorKind::IsADirectory => todo!(),
        std::io::ErrorKind::DirectoryNotEmpty => moto_rt::Error::FileTooLarge,
        std::io::ErrorKind::ReadOnlyFilesystem => todo!(),
        std::io::ErrorKind::FilesystemLoop => todo!(),
        std::io::ErrorKind::StaleNetworkFileHandle => todo!(),
        std::io::ErrorKind::InvalidInput => moto_rt::Error::InvalidArgument,
        std::io::ErrorKind::InvalidData => moto_rt::Error::InvalidData,
        std::io::ErrorKind::TimedOut => moto_rt::Error::TimedOut,
        std::io::ErrorKind::WriteZero => todo!(),
        std::io::ErrorKind::StorageFull => todo!(),
        std::io::ErrorKind::NotSeekable => todo!(),
        std::io::ErrorKind::QuotaExceeded => todo!(),
        std::io::ErrorKind::FileTooLarge => todo!(),
        std::io::ErrorKind::ResourceBusy => todo!(),
        std::io::ErrorKind::ExecutableFileBusy => todo!(),
        std::io::ErrorKind::Deadlock => todo!(),
        std::io::ErrorKind::CrossesDevices => todo!(),
        std::io::ErrorKind::TooManyLinks => todo!(),
        std::io::ErrorKind::InvalidFilename => todo!(),
        std::io::ErrorKind::ArgumentListTooLong => todo!(),
        std::io::ErrorKind::Interrupted => moto_rt::Error::InternalError,
        std::io::ErrorKind::Unsupported => moto_rt::Error::NotImplemented,
        std::io::ErrorKind::UnexpectedEof => moto_rt::Error::UnexpectedEof,
        std::io::ErrorKind::OutOfMemory => moto_rt::Error::OutOfMemory,
        std::io::ErrorKind::Other => moto_rt::Error::Unknown,
        _ => moto_rt::Error::Unknown,
    }
}

pub fn map_native_error(err: moto_rt::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(err as u16 as i32)
}

#[allow(unused)]
pub async fn stat(
    fs: Rc<moto_async::LocalMutex<crate::runtime::fs::FS>>,
    filename: &str,
) -> std::io::Result<Option<(async_fs::EntryId, async_fs::EntryKind)>> {
    if !filename.starts_with('/') {
        return Err(std::io::ErrorKind::InvalidFilename.into());
    }
    let paths: Vec<&str> = filename.split('/').collect();
    assert!(paths[0].is_empty());

    let mut fs_mut = fs.lock().await;

    let mut parent_id = async_fs::ROOT_ID;
    let mut entry_kind = async_fs::EntryKind::File;

    for &path in &paths[1..] {
        let trimmed = path.trim();
        if trimmed != path || trimmed.is_empty() {
            return Err(std::io::ErrorKind::InvalidFilename.into());
        }

        let Some((entry_id, kind)) = fs_mut.stat(async_fs::Role::System, parent_id, path).await?
        else {
            return Ok(None);
        };

        parent_id = entry_id;
        entry_kind = kind;
    }

    Ok(Some((parent_id, entry_kind)))
}

#[allow(unused)]
pub async fn create_file(
    fs: Rc<moto_async::LocalMutex<crate::runtime::fs::FS>>,
    filename: &str,
) -> std::io::Result<async_fs::EntryId> {
    let Some((dir, file)) = filename.rsplit_once('/') else {
        return Err(std::io::ErrorKind::InvalidFilename.into());
    };

    let Ok(Some((dir_id, entry_kind))) = stat(fs.clone(), dir).await else {
        return Err(std::io::ErrorKind::InvalidFilename.into());
    };

    if !matches!(entry_kind, async_fs::EntryKind::Directory) {
        return Err(std::io::ErrorKind::InvalidFilename.into());
    };

    let mut fs_mut = fs.lock().await;
    fs_mut
        .create_entry(
            async_fs::Role::System,
            dir_id,
            async_fs::EntryKind::File,
            file,
            [async_fs::AccessPermissions::Rwx; 3],
        )
        .await
}

#[allow(unused)]
pub async fn write_file(
    fs: &Rc<moto_async::LocalMutex<crate::runtime::fs::FS>>,
    file_id: async_fs::EntryId,
    offset: u64,
    bytes: &[u8],
) -> std::io::Result<usize> {
    assert!(bytes.len() <= 4096);
    // We need to split the write in two if it writes across a block.

    let total_len = bytes.len() as u64;
    let first_len = total_len.min(((offset + 4095) & !4095) - offset);

    let mut fs_mut = fs.lock().await;

    assert_eq!(
        first_len as usize,
        fs_mut
            .write(
                async_fs::Role::System,
                file_id,
                offset,
                &bytes[..(first_len as usize)]
            )
            .await?
    );

    let second_len = total_len - first_len;
    if second_len > 0 {
        assert_eq!(
            second_len as usize,
            fs_mut
                .write(
                    async_fs::Role::System,
                    file_id,
                    offset + first_len,
                    &bytes[(first_len as usize)..]
                )
                .await?
        );
    }

    Ok(total_len as usize)
}
