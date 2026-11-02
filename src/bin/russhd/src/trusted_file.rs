//! Reads a credential file only if it and its path pass the checks of OpenSSH's
//! StrictModes, in each platform's own terms. Every failure is a fixed reason
//! that quotes nothing from the file.

use std::path::{Path, PathBuf};

/// The largest credential file russhd reads.
pub const MAX_BYTES: usize = 1024 * 1024;

pub type Reason = &'static str;

/// Who besides the trusted roles may read a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readers {
    Anyone,
    TrustedOnly,
}

/// Where the path checks stop for a file under this directory; a file outside
/// it is checked through the filesystem root. OpenSSH stops at the home
/// directory too: what lies above it is not the user's to secure.
#[cfg(target_os = "motor")]
pub fn default_trust_root() -> Option<PathBuf> {
    Some(PathBuf::from("/user"))
}

#[cfg(unix)]
pub fn default_trust_root() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// `Ok(None)` means the file does not exist.
#[cfg(target_os = "motor")]
pub fn read(
    path: &Path,
    trust_root: Option<&Path>,
    readers: Readers,
) -> Result<Option<Vec<u8>>, Reason> {
    use moto_sdk::io::fs::{EntryKind, FsClient};

    let text = path.to_str().ok_or("the path is not UTF-8")?;
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().map_err(|_| "cannot reach the filesystem")?;
        let (id, kind) = match client.stat(text).await {
            Ok(entry) => entry,
            Err(moto_sdk::rt::Error::NotFound) => return Ok(None),
            Err(_) => return Err("cannot look up the file"),
        };
        if kind != EntryKind::File {
            return Err("not a regular file");
        }
        let metadata = client
            .metadata(id)
            .await
            .map_err(|_| "cannot read the file's metadata")?;
        let none = metadata
            .permissions()
            .map_err(|_| "the file has invalid permissions")?
            .none;
        if none.can_write() {
            return Err("None can write the file");
        }
        if readers == Readers::TrustedOnly && none.can_read() {
            return Err("None can read the file");
        }
        for ancestor in path.ancestors().skip(1) {
            let name = ancestor.to_str().ok_or("the path is not UTF-8")?;
            let (id, kind) = client
                .stat(name)
                .await
                .map_err(|_| "cannot look up a path component")?;
            if kind != EntryKind::Directory {
                return Err("a path component is not a directory");
            }
            let permissions = client
                .metadata(id)
                .await
                .map_err(|_| "cannot read a path component's metadata")?
                .permissions()
                .map_err(|_| "a path component has invalid permissions")?;
            if permissions.none.can_write() {
                return Err("None can write a path component");
            }
            if Some(ancestor) == trust_root {
                break;
            }
        }
        if metadata.size > MAX_BYTES as u64 {
            return Err("the file exceeds 1 MiB");
        }
        let mut bytes = vec![0; metadata.size as usize];
        let mut filled = 0;
        while filled < bytes.len() {
            match client.read(id, filled as u64, &mut bytes[filled..]).await {
                Ok(0) | Err(_) => return Err("cannot read the file"),
                Ok(size) => filled += size,
            }
        }
        Ok(Some(bytes))
    })
}

/// `Ok(None)` means the file does not exist.
#[cfg(unix)]
pub fn read(
    path: &Path,
    trust_root: Option<&Path>,
    readers: Readers,
) -> Result<Option<Vec<u8>>, Reason> {
    use std::io::{ErrorKind, Read};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    fn check_writers(metadata: &std::fs::Metadata) -> Result<(), Reason> {
        if metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() } {
            return Err("an untrusted user owns the path");
        }
        if metadata.mode() & 0o022 != 0 {
            return Err("group or other can write the path");
        }
        Ok(())
    }

    // O_NONBLOCK: a FIFO has to fail the kind check, not stall on open.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot open the file"),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "cannot read the file's metadata")?;
    if !metadata.is_file() {
        return Err("not a regular file");
    }
    check_writers(&metadata)?;
    if readers == Readers::TrustedOnly && metadata.mode() & 0o077 != 0 {
        return Err("group or other can read the file");
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| "cannot read a path component's metadata")?;
        if !metadata.is_dir() {
            return Err("a path component is not a directory");
        }
        check_writers(&metadata)?;
        if Some(ancestor) == trust_root {
            break;
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read the file")?;
    if bytes.len() > MAX_BYTES {
        return Err("the file exceeds 1 MiB");
    }
    Ok(Some(bytes))
}
