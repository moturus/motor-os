use crate::config::{MAX_FILE_BYTES, Result};
use std::path::Path;

fn check_metadata(is_file: bool, size: u64, none_can_read: bool) -> Result<()> {
    if !is_file {
        return Err("configuration and key must be regular files");
    }
    if size > MAX_FILE_BYTES as u64 {
        return Err("config and key files are limited to 64 KiB each");
    }
    if none_can_read {
        return Err("configuration and key must not be readable by the None role");
    }
    Ok(())
}

fn decode(bytes: Vec<u8>) -> Result<String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err("config and key files are limited to 64 KiB each");
    }
    String::from_utf8(bytes).map_err(|_| "configuration and key must be UTF-8")
}

#[cfg(unix)]
pub(crate) fn read(path: &Path) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let file = std::fs::File::open(path).map_err(|_| "cannot open configuration or key file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect configuration or key file")?;
    // Host tests map None access to the POSIX other-read bit.
    check_metadata(
        metadata.is_file(),
        metadata.len(),
        metadata.permissions().mode() & 0o004 != 0,
    )?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read configuration or key file")?;
    decode(bytes)
}

#[cfg(target_os = "motor")]
pub(crate) fn read(path: &Path) -> Result<String> {
    use moto_sdk::io::fs::{AccessPermissions, EntryKind, FsClient};

    let path = std::path::absolute(path).map_err(|_| "cannot resolve configuration or key path")?;
    let path = path
        .to_str()
        .ok_or("configuration or key path is not UTF-8")?;
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().map_err(|_| "cannot connect to filesystem service")?;
        let (entry, kind) = client
            .stat(path)
            .await
            .map_err(|_| "cannot find configuration or key file")?;
        let metadata = client
            .metadata(entry)
            .await
            .map_err(|_| "cannot inspect configuration or key file")?;
        let permissions = metadata
            .permissions()
            .map_err(|_| "invalid file permissions")?;
        check_metadata(
            kind == EntryKind::File,
            metadata.size,
            permissions.none != AccessPermissions::None,
        )?;
        // Read the checked entry, so a concurrent rename cannot replace it
        // between the permission check and the read. Include one overflow byte.
        let mut bytes = vec![0; MAX_FILE_BYTES + 1];
        let size = client
            .read(entry, 0, &mut bytes)
            .await
            .map_err(|_| "cannot read configuration or key file")?;
        bytes.truncate(size);
        decode(bytes)
    })
}
