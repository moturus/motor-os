//! Checks and permission setters for paths that Lorry reads or owns. None of
//! them follows a final symbolic link.

use std::fs::{self, File, Metadata};
use std::io;
use std::path::Path;

use crate::diagnostic::{Error, Result};

/// Whether anything, even a broken symbolic link, exists at `path`.
pub(crate) fn entry_exists(path: &Path, context: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(inspect_error(path, context, error)),
    }
}

pub(crate) fn require_real_directory(path: &Path, context: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| inspect_error(path, context, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "{context} `{}` is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn require_real_file(path: &Path, context: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| inspect_error(path, context, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::failure(format!(
            "{context} `{}` is not a real regular file",
            path.display()
        )));
    }
    Ok(())
}

/// Accepts a missing `path` or a real regular file.
pub(crate) fn require_real_file_if_present(path: &Path, context: &str) -> Result<()> {
    if entry_exists(path, context)? {
        require_real_file(path, context)
    } else {
        Ok(())
    }
}

/// Creates the directory `path` unless something exists there, then requires
/// a real directory.
pub(crate) fn create_real_directory(path: &Path, context: &str) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to create {context} `{}`: {error}",
                path.display()
            )));
        }
    }
    require_real_directory(path, context)
}

/// Requires `path` to still name the real regular file that `file` opened.
pub(crate) fn verify_open_file(file: &File, path: &Path, context: &str) -> Result<()> {
    require_real_file(path, context)?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file
            .metadata()
            .map_err(|error| inspect_error(path, context, error))?;
        let visible =
            fs::symlink_metadata(path).map_err(|error| inspect_error(path, context, error))?;
        if opened.dev() != visible.dev() || opened.ino() != visible.ino() {
            return Err(Error::failure(format!(
                "{context} `{}` changed while it was being acquired",
                path.display()
            )));
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file;
    Ok(())
}

/// The device and file numbers of `path`, whose `metadata` the caller read.
#[cfg(unix)]
pub(crate) fn path_identity(_path: &Path, metadata: &Metadata) -> Result<(u128, u128)> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev() as u128, metadata.ino() as u128))
}

#[cfg(target_os = "motor")]
pub(crate) fn path_identity(path: &Path, _metadata: &Metadata) -> Result<(u128, u128)> {
    let path = utf8(path)?;
    let attr = moto_rt::fs::stat(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect Motor file identity `{path}`: {error}"
        ))
    })?;
    Ok((0, attr.entry_id))
}

#[cfg(not(any(unix, target_os = "motor")))]
pub(crate) fn path_identity(path: &Path, _metadata: &Metadata) -> Result<(u128, u128)> {
    Err(Error::failure(format!(
        "file identity is unsupported on this platform: `{}`",
        path.display()
    )))
}

/// The device and file numbers of the open `file`.
#[cfg(unix)]
pub(crate) fn file_identity(_file: &File, metadata: &Metadata) -> Result<(u128, u128)> {
    path_identity(Path::new(""), metadata)
}

#[cfg(target_os = "motor")]
pub(crate) fn file_identity(file: &File, _metadata: &Metadata) -> Result<(u128, u128)> {
    use std::os::fd::AsRawFd;
    let attr = moto_rt::fs::get_file_attr(file.as_raw_fd()).map_err(|error| {
        Error::failure(format!(
            "failed to inspect open Motor file identity: {error}"
        ))
    })?;
    Ok((0, attr.entry_id))
}

#[cfg(not(any(unix, target_os = "motor")))]
pub(crate) fn file_identity(_file: &File, _metadata: &Metadata) -> Result<(u128, u128)> {
    Err(Error::failure(
        "file identity is unsupported on this platform",
    ))
}

/// Makes `file` owner-only: readable and writable, or readable and
/// executable with `executable`.
pub(crate) fn set_file_mode(_file: &File, _path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o700 } else { 0o600 };
        _file
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| permission_error(_path, error))?;
    }
    #[cfg(target_os = "motor")]
    {
        use std::os::fd::AsRawFd;
        let permissions = if executable {
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC
        } else {
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE
        };
        moto_rt::fs::set_file_perm(_file.as_raw_fd(), permissions)
            .map_err(|error| permission_error(_path, error))?;
    }
    Ok(())
}

/// Makes the directory `path` owner-only.
pub(crate) fn set_directory_private(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))
            .map_err(|error| permission_error(_path, error))?;
    }
    #[cfg(target_os = "motor")]
    {
        moto_rt::fs::set_perm(
            utf8(_path)?,
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE | moto_rt::fs::PERM_EXEC,
        )
        .map_err(|error| permission_error(_path, error))?;
    }
    Ok(())
}

#[cfg(target_os = "motor")]
fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| Error::failure(format!("path is not valid UTF-8: `{}`", path.display())))
}

fn inspect_error(path: &Path, context: &str, error: io::Error) -> Error {
    Error::failure(format!(
        "failed to inspect {context} `{}`: {error}",
        path.display()
    ))
}

fn permission_error(path: &Path, error: impl std::fmt::Display) -> Error {
    Error::failure(format!(
        "failed to set permissions of `{}`: {error}",
        path.display()
    ))
}
