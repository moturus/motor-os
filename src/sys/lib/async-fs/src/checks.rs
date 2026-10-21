use crate::{Metadata, Role};
use std::io::{ErrorKind, Result};

pub const MAX_FILENAME_LEN: usize = 255;

/// The permission required by an operation; execute also gates directory listing.
#[derive(Clone, Copy)]
pub enum Need {
    Read,
    Write,
    Execute,
}

/// Check already-fetched metadata without performing filesystem I/O.
#[inline]
pub fn check_access(metadata: &Metadata, role: Role, need: Need) -> Result<()> {
    let access = metadata.access(role)?;
    let allowed = match need {
        Need::Read => access.can_read(),
        Need::Write => access.can_write(),
        Need::Execute => access.can_execute(),
    };
    if allowed {
        Ok(())
    } else {
        Err(ErrorKind::PermissionDenied.into())
    }
}

/// Leaf-name rules shared by the filesystems.
pub fn validate_filename(filename: &str) -> Result<()> {
    if filename.len() > MAX_FILENAME_LEN || filename.contains('/') || filename.starts_with("..") {
        return Err(ErrorKind::InvalidFilename.into());
    }
    if filename.trim().len() != filename.len() {
        return Err(ErrorKind::InvalidFilename.into());
    }
    Ok(())
}
