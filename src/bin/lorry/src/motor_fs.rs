//! Role-independent source modes and workspace sharing on Motor OS.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;

use moto_sdk::async_runtime::LocalRuntime;
use moto_sdk::io::fs::{AccessPermissions as Access, FsClient, Role};

use crate::diagnostic::{Error, Result};

// Source walks query many entries. Keep one connection per scanning thread.
thread_local! {
    static CLIENT: RefCell<Option<(LocalRuntime, Rc<FsClient>)>> = const { RefCell::new(None) };
}

fn with_client<T>(
    operation: impl AsyncFnOnce(Rc<FsClient>) -> moto_sdk::rt::Result<T>,
) -> Result<T> {
    CLIENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            let mut runtime = LocalRuntime::try_new().map_err(failure)?;
            let client = runtime
                .block_on(async { FsClient::connect() })
                .map_err(failure)?;
            *slot = Some((runtime, client));
        }
        let (runtime, client) = slot.as_mut().unwrap();
        runtime.block_on(operation(client.clone())).map_err(failure)
    })
}

fn failure(error: impl std::fmt::Display) -> Error {
    Error::failure(format!("Motor filesystem permissions: {error}"))
}

pub(crate) fn none_executable(entry: u128) -> Result<bool> {
    with_client(async move |client| {
        let metadata = client.metadata(entry).await?;
        Ok(metadata
            .access(Role::None)
            .map_err(|_| moto_sdk::rt::Error::InvalidData)?
            .can_execute())
    })
}

/// Mutable state is shared only below /none. Public source objects elsewhere
/// retain None's read-only storage policy, including their executable flag.
pub(crate) fn source_mode(entry: u128, path: &Path, executable: bool) -> Result<()> {
    let writable = std::fs::canonicalize(path)?.starts_with("/none");
    with_client(async move |client| {
        let mut permissions = client
            .metadata(entry)
            .await?
            .permissions()
            .map_err(|_| moto_sdk::rt::Error::InvalidData)?;
        let own = if crate::role::Role::current() == crate::role::Role::None {
            Role::None
        } else {
            Role::Interactive
        };
        let desired = if executable { Access::Rwx } else { Access::Rw };
        let old = permissions.get(own);
        // Adding x while retaining w needs the permitted rw -> rx -> rwx path.
        if executable && old == Access::Rw {
            client.set_permissions(entry, Access::Rx).await?;
            permissions = client
                .metadata(entry)
                .await?
                .permissions()
                .map_err(|_| moto_sdk::rt::Error::InvalidData)?;
        }
        match own {
            Role::None => permissions.none = desired,
            Role::Interactive => {
                permissions.interactive = desired;
                if writable {
                    permissions.none = desired;
                } else if permissions.none.can_read() {
                    permissions.none = if executable { Access::Rx } else { Access::R };
                }
            }
            Role::System => unreachable!(),
        }
        client.set_all_permissions(entry, permissions).await
    })
}

pub(crate) fn directory_mode(path: &Path) -> Result<()> {
    let path = std::fs::canonicalize(path)?;
    if !path.starts_with("/none") {
        return Ok(());
    }
    let path = path
        .to_str()
        .ok_or_else(|| Error::failure("workspace path is not Unicode"))?;
    with_client(async move |client| {
        let (entry, _) = client.stat(path).await?;
        let mut permissions = client
            .metadata(entry)
            .await?
            .permissions()
            .map_err(|_| moto_sdk::rt::Error::InvalidData)?;
        if permissions.none != Access::Rwx {
            permissions.none = Access::Rwx;
            client.set_all_permissions(entry, permissions).await?;
        }
        Ok(())
    })
}

/// Share only directories this operation creates. Existing ancestors may be
/// intentionally read/execute-only, even when a workspace below them is writable.
pub(crate) fn create_dir_all(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => directory_mode(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Check ancestors as well as the root before spawning a None build child.
pub(crate) fn require_workspace(root: &Path) -> Result<()> {
    let root = std::fs::canonicalize(root)?;
    if !root.starts_with("/none") {
        return Err(Error::failure(format!(
            "workspace `{}` cannot be built as None",
            root.display()
        ))
        .with_help(
            "put the workspace under /none, with sources readable and its root writable by None",
        ));
    }
    for path in root.ancestors() {
        let text = path
            .to_str()
            .ok_or_else(|| Error::failure("workspace path is not Unicode"))?;
        let permissions = with_client(async move |client| {
            let (entry, _) = client.stat(text).await?;
            client
                .metadata(entry)
                .await?
                .permissions()
                .map_err(|_| moto_sdk::rt::Error::InvalidData)
        })?;
        if !permissions.none.can_execute() || (path == root && !permissions.none.can_write()) {
            return Err(Error::failure(format!("workspace `{}` is not accessible to None at `{}`", root.display(), path.display()))
                .with_help("give None traversal of the workspace's parents and read/write/execute access to the workspace directory"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/motor-new.rs"]
mod tests;
