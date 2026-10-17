//! Deterministic native coverage of writers queued before construction locks.

use super::{ConstructionLock, FsRuntime};
use crate::runtime::fs;
use crate::self_test::st_assert_eq;
use async_fs::{AccessPermissions, EntryId, EntryKind, FileSystem, Role, RolePermissions};
use moto_ipc::io_channel;
use moto_sys_io::api_fs;
use std::task::Poll;

pub(in crate::runtime::fs) async fn queued_mutations(runtime: &FsRuntime) -> Result<(), String> {
    let name = format!(
        ".spawn-lock-test-{}",
        moto_rt::time::Instant::now().as_u64()
    );
    let dir = runtime
        .fs
        .write()
        .await
        .create_entry(
            Role::System,
            async_fs::ROOT_ID,
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

    let result = check_mutations(runtime, dir).await;
    // Clean up even when a broken handler changed, renamed, or deleted a file.
    let cleanup = async {
        let mut fs = runtime.fs.write().await;
        while let Some(entry) = fs.get_first_entry(Role::System, dir).await? {
            fs.delete_entry(Role::System, entry).await?;
        }
        fs.delete_entry(Role::System, dir).await
    }
    .await
    .map_err(|err| err.to_string());
    result.and(cleanup)
}

async fn check_mutations(runtime: &FsRuntime, dir: EntryId) -> Result<(), String> {
    let (entry, other) = {
        let mut fs = runtime.fs.write().await;
        let mut entries = Vec::new();
        for name in ["executable", "other"] {
            let entry = fs
                .create_entry(
                    Role::System,
                    dir,
                    EntryKind::File,
                    name,
                    RolePermissions::all(AccessPermissions::Rwx),
                )
                .await
                .map_err(|err| err.to_string())?;
            fs.write(Role::System, entry, 0, b"original")
                .await
                .map_err(|err| err.to_string())?;
            entries.push(entry);
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

    for case in 0..10 {
        let (name, mut msg) = match case {
            0 => ("truncate", api_fs::resize_msg_encode(entry, 0)),
            1 => (
                "chmod",
                api_fs::set_permissions_msg_encode(entry, AccessPermissions::Rw),
            ),
            2 => (
                "chmod-all",
                api_fs::set_all_permissions_msg_encode(
                    entry,
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
                    ("write", api_fs::write_msg_encode(entry, 0, 1, page))
                } else {
                    let tail = client
                        .alloc_page(u64::MAX)
                        .await
                        .map_err(|err| err.to_string())?;
                    tail.bytes_mut().fill(b'x');
                    (
                        "write-multi",
                        api_fs::write_multi_msg_encode(entry, 0, 4097, vec![page, tail]),
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
                        api_fs::move_entry_req_encode(entry, dir, "renamed", page),
                    ),
                    6 => (
                        "rename-noreplace",
                        api_fs::move_noreplace_req_encode(entry, dir, "renamed", page),
                    ),
                    _ => (
                        "rename-onto",
                        api_fs::move_entry_req_encode(other, dir, "executable", page),
                    ),
                }
            }
            8 => (
                "copy",
                api_fs::copy_file_range_req_encode(other, entry, 0, 8),
            ),
            _ => ("delete", api_fs::delete_entry_msg_encode(entry)),
        };
        msg.id = case;

        // Hold the metadata reader while the real handler queues for writing.
        // Its first poll must reach the write-lock wait, not finish the request.
        let reader = runtime.fs.read().await;
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

    let reader = runtime.fs.read().await;
    let metadata = reader
        .metadata(Role::System, entry)
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
            .read(Role::System, entry, 0, &mut bytes)
            .await
            .map_err(|err| err.to_string())?,
        8
    );
    st_assert_eq!(&bytes, b"original");
    Ok(())
}
