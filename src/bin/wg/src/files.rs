use crate::config::{MAX_FILE_BYTES, Result};
use std::path::Path;

pub(crate) fn check_metadata(is_file: bool, size: u64, none_can_read: bool) -> Result<()> {
    if !is_file {
        return Err("configuration must be a regular file");
    }
    if size > MAX_FILE_BYTES as u64 {
        return Err("configuration is limited to 64 KiB");
    }
    if none_can_read {
        return Err("configuration must not be readable by the None role");
    }
    Ok(())
}

pub(crate) fn decode(bytes: Vec<u8>) -> Result<String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err("configuration is limited to 64 KiB");
    }
    String::from_utf8(bytes).map_err(|_| "configuration must be UTF-8")
}

#[cfg(unix)]
pub(crate) fn read(path: &Path) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;

    let file = std::fs::File::open(path).map_err(|_| "cannot open configuration file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect configuration file")?;
    // Host tests map None access to the POSIX other-read bit.
    check_metadata(
        metadata.is_file(),
        metadata.len(),
        metadata.permissions().mode() & 0o004 != 0,
    )?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read configuration file")?;
    decode(bytes)
}

#[cfg(target_os = "motor")]
pub(crate) fn read(path: &Path) -> Result<String> {
    Ok(crate::motor_files::read(path)?.text)
}
