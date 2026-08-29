use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

pub fn create_file(path: &Path, mode: u32) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
    }
    #[cfg(target_os = "motor")]
    {
        create_motor_file(path, mode)?;
        match OpenOptions::new().write(true).open(path) {
            Ok(file) => Ok(file),
            Err(error) => {
                let _ = std::fs::remove_file(path);
                Err(error)
            }
        }
    }
}

pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        if !path.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(path)?;
        }
        let metadata = path.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH configuration path is not a directory",
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(target_os = "motor")]
    {
        ensure_motor_dir(path)
    }
}

pub fn create_dir(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(mode).create(path)
    }
    #[cfg(target_os = "motor")]
    {
        create_motor_entry(
            path,
            moto_io::fs::EntryKind::Directory,
            permissions(mode, true),
        )
    }
}

pub fn safe_identity(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = path.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private key is accessible by another user",
            ));
        }
        Ok(())
    }
    #[cfg(target_os = "motor")]
    {
        use moto_io::fs::{AccessPermissions, EntryKind, FsClient, Role};

        let path = absolute_utf8(path)?;
        motor_io(async {
            let client = FsClient::connect()?;
            let (entry, kind) = client.stat(&path).await?;
            if kind != EntryKind::File {
                return Err(moto_rt::Error::InvalidArgument);
            }
            let permissions = client.metadata(entry).await?.permissions()?;
            if permissions.get(Role::None) != AccessPermissions::None {
                return Err(moto_rt::Error::NotAllowed);
            }
            Ok(())
        })
    }
}

pub fn file_mode(path: &Path, directory: bool) -> io::Result<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = directory;
        Ok(path.metadata()?.permissions().mode() & 0o777)
    }
    #[cfg(target_os = "motor")]
    {
        use crate::permissions::{Access, NormalizedMode};
        use moto_io::fs::{AccessPermissions, FsClient, Role};

        let path = absolute_utf8(path)?;
        let permissions = motor_io(async {
            let client = FsClient::connect()?;
            let (entry, _) = client.stat(&path).await?;
            client.metadata(entry).await?.permissions()
        })?;
        let access = |value| match value {
            AccessPermissions::None => Access::None,
            AccessPermissions::R => Access::R,
            AccessPermissions::Rw => Access::Rw,
            AccessPermissions::Rx => Access::Rx,
            AccessPermissions::Rwx => Access::Rwx,
        };
        let (owner, public) = match current_role() {
            Role::System => (
                access(permissions.system),
                access(permissions.interactive).intersect(access(permissions.none), directory),
            ),
            Role::Interactive => (access(permissions.interactive), access(permissions.none)),
            Role::None => (access(permissions.none), Access::None),
        };
        Ok(NormalizedMode { owner, public }.reported_posix())
    }
}

pub fn set_mode(path: &Path, mode: u32, directory: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = directory;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777))
    }
    #[cfg(target_os = "motor")]
    {
        let path = absolute_utf8(path)?;
        motor_io(async {
            let client = moto_io::fs::FsClient::connect()?;
            let (entry, _) = client.stat(&path).await?;
            client
                .set_all_permissions(entry, permissions(mode, directory))
                .await
        })
    }
}

#[cfg(target_os = "motor")]
fn current_role() -> moto_io::fs::Role {
    match moto_sys::caps::ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities) {
        moto_sys::caps::ProcessRole::System => moto_io::fs::Role::System,
        moto_sys::caps::ProcessRole::Interactive => moto_io::fs::Role::Interactive,
        moto_sys::caps::ProcessRole::None => moto_io::fs::Role::None,
    }
}

#[cfg(target_os = "motor")]
fn permissions(mode: u32, directory: bool) -> moto_io::fs::RolePermissions {
    use moto_io::fs::{AccessPermissions, Role, RolePermissions};

    let access = |bits| match (bits, directory) {
        (0, _) => AccessPermissions::None,
        (4, _) => AccessPermissions::R,
        (6, false) => AccessPermissions::Rw,
        (5, _) => AccessPermissions::Rx,
        (_, true) => AccessPermissions::Rwx,
        _ => AccessPermissions::Rw,
    };
    let owner = access((mode >> 6) & 7);
    let public = access(mode & 7);
    match current_role() {
        Role::System => RolePermissions::new(owner, public, public),
        Role::Interactive => RolePermissions::new(AccessPermissions::Rwx, owner, public),
        Role::None => RolePermissions::new(AccessPermissions::Rwx, AccessPermissions::Rwx, owner),
    }
}

#[cfg(target_os = "motor")]
fn create_motor_file(path: &Path, mode: u32) -> io::Result<()> {
    create_motor_entry(path, moto_io::fs::EntryKind::File, permissions(mode, false))
}

#[cfg(target_os = "motor")]
fn ensure_motor_dir(path: &Path) -> io::Result<()> {
    use moto_io::fs::{EntryKind, FsClient};

    if !path.exists() {
        create_motor_entry(path, EntryKind::Directory, permissions(0o700, true))?;
    }
    let path = absolute_utf8(path)?;
    motor_io(async {
        let client = FsClient::connect()?;
        let (entry, kind) = client.stat(&path).await?;
        if kind != EntryKind::Directory {
            return Err(moto_rt::Error::InvalidArgument);
        }
        client
            .set_all_permissions(entry, permissions(0o700, true))
            .await
    })
}

#[cfg(target_os = "motor")]
fn create_motor_entry(
    path: &Path,
    kind: moto_io::fs::EntryKind,
    permissions: moto_io::fs::RolePermissions,
) -> io::Result<()> {
    use moto_io::fs::{EntryKind, FsClient};

    if path.exists() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| io::Error::other("invalid path"))?;
    let name = absolute
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| io::Error::other("path is not UTF-8"))?;
    let parent = absolute_utf8(parent)?;
    motor_io(async {
        let client = FsClient::connect()?;
        let (parent, parent_kind) = client.stat(&parent).await?;
        if parent_kind != EntryKind::Directory {
            return Err(moto_rt::Error::InvalidArgument);
        }
        client
            .create_entry_with_permissions(parent, kind, name, permissions)
            .await
            .map(|_| ())
    })
}

#[cfg(target_os = "motor")]
fn absolute_utf8(path: &Path) -> io::Result<String> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("path is not UTF-8"))
}

#[cfg(target_os = "motor")]
fn motor_io<T>(operation: impl Future<Output = moto_rt::Result<T>>) -> io::Result<T> {
    moto_async::LocalRuntime::new()
        .block_on(operation)
        .map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("russhd-local-{}-{name}", std::process::id()))
    }

    #[test]
    fn creates_private_files_without_overwrite() {
        let path = path("file");
        let _ = std::fs::remove_file(&path);
        let mut file = create_file(&path, 0o600).unwrap();
        file.write_all(b"secret").unwrap();
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            create_file(&path, 0o600).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn secures_existing_directory() {
        let path = path("dir");
        let _ = std::fs::remove_dir(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        ensure_private_dir(&path).unwrap();
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::remove_dir(path).unwrap();
    }
}
