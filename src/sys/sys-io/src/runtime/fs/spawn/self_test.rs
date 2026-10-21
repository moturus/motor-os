//! Deterministic native coverage of writers queued before construction locks.

use super::{ConstructionLock, FsRuntime};
use crate::runtime::fs;
use crate::self_test::st_assert_eq;
use async_fs::{AccessPermissions, EntryId, EntryKind, FileSystem, Role, RolePermissions};
use moto_ipc::io_channel;
use moto_sys_io::api_fs;
use std::task::Poll;

/// A construction reference on an executable for tests outside this module,
/// released on drop.
pub(in crate::runtime::fs) struct HeldExecutable {
    _lock: ConstructionLock,
}

pub(in crate::runtime::fs) fn hold_executable(
    runtime: &FsRuntime,
    entry: EntryId,
) -> HeldExecutable {
    HeldExecutable {
        _lock: ConstructionLock::new(runtime, entry),
    }
}

pub(in crate::runtime::fs) async fn quarantined_read(
    runtime: &FsRuntime,
    entry: EntryId,
) -> Result<(), String> {
    let mut page = [0; 4096];
    st_assert_eq!(
        super::read_range(runtime, Role::System, entry, 0, &mut page)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    Ok(())
}

pub(in crate::runtime::fs) async fn queued_mutations(runtime: &FsRuntime) -> Result<(), String> {
    for path in ["/", "/none/tmp"] {
        let (id, _) = fs::mounts::stat_path(&runtime.mounts, Role::System, path)
            .await
            .map_err(|err| err.to_string())?;
        check_mount(runtime, id).await?;
    }
    Ok(())
}

async fn check_mount(runtime: &FsRuntime, parent: EntryId) -> Result<(), String> {
    let name = format!(
        ".spawn-lock-test-{}",
        moto_rt::time::Instant::now().as_u64()
    );
    let parent = runtime.resolve(parent).map_err(|err| err.to_string())?;
    let dir = parent
        .write()
        .await
        .map_err(|err| err.to_string())?
        .create_entry(
            Role::System,
            parent.local,
            EntryKind::Directory,
            &name,
            RolePermissions::new(
                AccessPermissions::Rwx,
                AccessPermissions::None,
                AccessPermissions::None,
            ),
        )
        .await
        .map_err(|err| err.to_string())?;
    let dir = parent.export(dir).map_err(|err| err.to_string())?;

    let result = check_mutations(runtime, dir).await;
    // Clean up even when a broken handler changed, renamed, or deleted a file.
    let cleanup = async {
        let directory = runtime.resolve(dir)?;
        let mut fs = directory.write().await?;
        while let Some(entry) = fs.get_first_entry(Role::System, directory.local).await? {
            directory.check_local(entry)?;
            fs.delete_entry(Role::System, entry).await?;
        }
        fs.delete_entry(Role::System, directory.local).await
    }
    .await
    .map_err(|err| err.to_string());
    result.and(cleanup)
}

async fn check_mutations(runtime: &FsRuntime, dir: EntryId) -> Result<(), String> {
    let directory = runtime.resolve(dir).map_err(|err| err.to_string())?;
    let (entry, other) = {
        let mut fs = directory.write().await.map_err(|err| err.to_string())?;
        let mut entries = Vec::new();
        for name in ["executable", "other"] {
            let entry = fs
                .create_entry(
                    Role::System,
                    directory.local,
                    EntryKind::File,
                    name,
                    RolePermissions::all(AccessPermissions::Rwx),
                )
                .await
                .map_err(|err| err.to_string())?;
            directory
                .check_local(entry)
                .map_err(|err| err.to_string())?;
            fs.write(Role::System, entry, 0, b"original")
                .await
                .map_err(|err| err.to_string())?;
            entries.push(directory.export(entry).map_err(|err| err.to_string())?);
        }
        (entries[0], entries[1])
    };

    let listener = io_channel::listen("sys-io-exec-lock-test");
    let (client, mut replies) =
        io_channel::connect("sys-io-exec-lock-test").map_err(|err| err.to_string())?;
    let (server, _requests) = listener.await.map_err(|err| err.to_string())?;
    let server = runtime
        .channel_budget
        .admit_fs(server)
        .map_err(|_| "self-test channel budget exhausted")?;

    let wire_entry = runtime.entry_ids.encode(entry);
    let wire_other = runtime.entry_ids.encode(other);
    let wire_dir = runtime.entry_ids.encode(dir);
    for case in 0..10 {
        let (name, mut msg) = match case {
            0 => ("truncate", api_fs::resize_msg_encode(wire_entry, 0)),
            1 => (
                "chmod",
                api_fs::set_permissions_msg_encode(wire_entry, AccessPermissions::Rw),
            ),
            2 => (
                "chmod-all",
                api_fs::set_all_permissions_msg_encode(
                    wire_entry,
                    RolePermissions::all(AccessPermissions::Rw),
                ),
            ),
            3 | 4 => {
                let page = client
                    .alloc_page(u64::MAX)
                    .await
                    .map_err(|err| err.to_string())?;
                page.bytes_mut().fill(b'x');
                if case == 3 {
                    ("write", api_fs::write_msg_encode(wire_entry, 0, 1, page))
                } else {
                    let tail = client
                        .alloc_page(u64::MAX)
                        .await
                        .map_err(|err| err.to_string())?;
                    tail.bytes_mut().fill(b'x');
                    (
                        "write-multi",
                        api_fs::write_multi_msg_encode(wire_entry, 0, 4097, vec![page, tail]),
                    )
                }
            }
            5..=7 => {
                let page = client
                    .alloc_page(u64::MAX)
                    .await
                    .map_err(|err| err.to_string())?;
                match case {
                    5 => (
                        "rename",
                        api_fs::move_entry_req_encode(wire_entry, wire_dir, "renamed", page),
                    ),
                    6 => (
                        "rename-noreplace",
                        api_fs::move_noreplace_req_encode(wire_entry, wire_dir, "renamed", page),
                    ),
                    _ => (
                        "rename-onto",
                        api_fs::move_entry_req_encode(wire_other, wire_dir, "executable", page),
                    ),
                }
            }
            8 => (
                "copy",
                api_fs::copy_file_range_req_encode(wire_other, wire_entry, 0, 8),
            ),
            _ => ("delete", api_fs::delete_entry_msg_encode(wire_entry)),
        };
        msg.id = case;

        // Hold the metadata reader while the real handler queues for writing.
        // Its first poll must reach the write-lock wait, not finish the request.
        let reader = directory.read().await.map_err(|err| err.to_string())?;
        let mut mutation = core::pin::pin!(fs::on_msg(
            msg,
            server.clone(),
            runtime.clone(),
            Role::System,
            true,
            true,
        ));
        let waiting =
            core::future::poll_fn(|cx| Poll::Ready(mutation.as_mut().poll(cx).is_pending())).await;
        drop(reader);
        // Match build's read-guard release and synchronous lock acquisition.
        let lock = ConstructionLock::new(runtime, entry);
        if waiting {
            mutation.await;
        }
        let response = replies.recv().await.map_err(|err| err.to_string())?;
        drop(lock);
        if !waiting || response.status() != Err(moto_rt::Error::NotAllowed) {
            return Err(format!(
                "{name}: queued={waiting}, response={:?}",
                response.status()
            ));
        }
    }

    let entry = runtime.resolve(entry).map_err(|err| err.to_string())?;
    let reader = entry.read().await.map_err(|err| err.to_string())?;
    let metadata = reader
        .metadata(Role::System, entry.local)
        .await
        .map_err(|err| err.to_string())?;
    st_assert_eq!(metadata.size, 8);
    st_assert_eq!(
        metadata
            .access(Role::System)
            .map_err(|err| err.to_string())?,
        AccessPermissions::Rwx
    );
    let mut bytes = [0; 8];
    st_assert_eq!(
        reader
            .read(Role::System, entry.local, 0, &mut bytes)
            .await
            .map_err(|err| err.to_string())?,
        8
    );
    st_assert_eq!(&bytes, b"original");
    Ok(())
}
