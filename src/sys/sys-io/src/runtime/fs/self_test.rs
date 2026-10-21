//! Native request-level mount regressions on isolated, bounded filesystems.
use super::*;
use moto_ipc::io_channel;
use moto_sys_io::api_fs::{MountInfo, MountKind};

pub(super) const TESTS: &[crate::self_test::SelfTest] = &[
    ("fs::mount_requests", run),
    ("fs::mount_records", records),
    ("fs::replace_without_traverse", replace_without_traverse),
];

pub(super) fn memfs(cap: u64) -> Result<FS> {
    Ok(FS::MemFs(memfs::MemFs::new(memfs::MemFsConfig {
        max_size: cap,
        free_cache_cap: 16384,
        root_mode: RolePermissions::all(AccessPermissions::Rwx),
    })?))
}

pub(super) fn runtime() -> Result<FsRuntime> {
    let exec_locks: Rc<RefCell<spawn::ExecLocks>> = Default::default();
    Ok(FsRuntime {
        mounts: Rc::new(RefCell::new(mounts::MountTable::new(memfs(1 << 20)?))),
        free_caches: Default::default(),
        entry_ids: Rc::new(entry_ids::EntryIds::new()),
        fs_stats: Default::default(),
        locks: Default::default(),
        channel_budget: Default::default(),
        exec_locks: exec_locks.clone(),
        spawn_stats: Default::default(),
        pager: Rc::new(spawn::pager::Pager::new(exec_locks)),
    })
}

fn ensure(condition: bool, what: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(what.to_owned()))
    }
}

fn run() -> std::result::Result<(), String> {
    moto_async::LocalRuntime::new()
        .block_on(requests())
        .map_err(|err| err.to_string())
}

async fn requests() -> Result<()> {
    let runtime = runtime()?;
    let root = runtime.root()?;
    let shadowed = root
        .write()
        .await?
        .create_entry(
            Role::System,
            0,
            EntryKind::Directory,
            "mounted",
            RolePermissions::all(AccessPermissions::Rwx),
        )
        .await?;
    root.check_local(shadowed)?;
    let child = memfs(8192)?;
    if let FS::MemFs(fs) = &child {
        runtime.free_caches.add(fs.free_block_cache());
    }
    let id = runtime.mounts.borrow_mut().insert(
        child,
        MountKind::MemFs,
        mounts::MountPoint {
            mount: 0,
            shadowed,
            path: "/mounted".into(),
        },
    )?;
    let mounted = runtime.resolve(mounts::join(id, 0))?;
    let local = mounted
        .write()
        .await?
        .create_entry(
            Role::None,
            0,
            EntryKind::File,
            "file",
            RolePermissions::all(AccessPermissions::Rwx),
        )
        .await?;
    let entry = mounted.export(local)?;
    let wire = runtime.entry_ids.encode(entry);
    let source = root
        .write()
        .await?
        .create_entry(
            Role::System,
            0,
            EntryKind::File,
            "source",
            RolePermissions::all(AccessPermissions::Rwx),
        )
        .await?;
    let source = root.export(source)?;
    ensure(
        move_entry(&runtime, Role::System, entry, 0, "mounted", true)
            .await
            .unwrap_err()
            .raw_os_error()
            == Some(moto_rt::E_NOT_ALLOWED as i32),
        "replacement root precedence",
    )?;
    ensure(
        move_entry(&runtime, Role::System, mounted.id, 0, "elsewhere", false)
            .await
            .unwrap_err()
            .raw_os_error()
            == Some(moto_rt::E_NOT_ALLOWED as i32),
        "source root protection",
    )?;
    ensure(
        move_entry(&runtime, Role::System, source, mounted.id, "source", false)
            .await
            .unwrap_err()
            .kind()
            == ErrorKind::CrossesDevices,
        "cross-mount rename",
    )?;
    let root_file = runtime.resolve(source)?;
    root.write()
        .await?
        .write(Role::System, root_file.local, 0, &[7; 4096])
        .await?;
    ensure(
        copy_file_range(&runtime, Role::System, source, 5, entry, 11, 4000).await? == 4000,
        "unaligned cross-mount copy",
    )?;
    let mut bytes = [0; 4000];
    ensure(
        mounted
            .read()
            .await?
            .read(Role::None, local, 11, &mut bytes)
            .await?
            == 4000
            && bytes.iter().all(|byte| *byte == 7),
        "copy data",
    )?;

    let listener = io_channel::listen("sys-io-mount-test");
    let (client, mut responses) =
        io_channel::connect("sys-io-mount-test").map_err(map_native_error)?;
    let (server, _requests) = listener.await.map_err(map_native_error)?;
    let server = runtime
        .channel_budget
        .admit_fs(server)
        .map_err(|_| std::io::Error::other("self-test channel budget"))?;
    async fn request(
        runtime: &FsRuntime,
        server: &channel_budget::ClientSender,
        responses: &mut io_channel::Receiver,
        mut msg: io_channel::Msg,
    ) -> Result<io_channel::Msg> {
        msg.id = 1;
        on_msg(msg, server.clone(), runtime.clone(), Role::None, true, true).await;
        responses.recv().await.map_err(map_native_error)
    }

    // Every request allocates its task: keep it within frusa's 4 KiB slabs.
    let (tickets, _) = moto_async::channel(1);
    let task = request_task(
        api_fs::flush_msg_encode(),
        server.clone(),
        runtime.clone(),
        Role::None,
        true,
        true,
        tickets,
    );
    ensure(
        core::mem::size_of_val(&task) <= 4096,
        "request task exceeds frusa's largest slab",
    )?;
    drop(task);

    // Alias locks share one canonical identity in either wire-codec mode.
    let alias = runtime.entry_ids.encode(shadowed);
    let canonical = runtime.entry_ids.encode(mounted.id);
    let response = request(
        &runtime,
        &server,
        &mut responses,
        api_fs::file_lock_msg_encode(alias, 1, moto_rt::fs::TRY_LOCK_EXCLUSIVE),
    )
    .await?;
    response.status().map_err(map_native_error)?;
    let response = request(
        &runtime,
        &server,
        &mut responses,
        api_fs::file_lock_msg_encode(canonical, 2, moto_rt::fs::TRY_LOCK_EXCLUSIVE),
    )
    .await?;
    ensure(
        response.status() == Err(moto_rt::Error::NotReady),
        "alias lock conflict",
    )?;
    request(
        &runtime,
        &server,
        &mut responses,
        api_fs::file_lock_msg_encode(canonical, 1, moto_rt::fs::UNLOCK),
    )
    .await?
    .status()
    .map_err(map_native_error)?;

    // A single-block quota failure is atomic; a multi-page request reports
    // its complete prefix when a later block cannot be allocated.
    let before = mounted.read().await?.metadata(Role::None, local).await?;
    let used_before = mounts::info(&runtime.mounts, 1).await?.used;
    let mut bytes_before = [0; 4096];
    mounted
        .read()
        .await?
        .read(Role::None, local, 0, &mut bytes_before)
        .await?;
    let page = client
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;
    page.bytes_mut().fill(9);
    let response = request(
        &runtime,
        &server,
        &mut responses,
        api_fs::write_msg_encode(wire, 4096, 4096, page),
    )
    .await?;
    ensure(
        response.status() == Err(moto_rt::Error::StorageFull),
        "classic quota error",
    )?;
    ensure(
        mounted
            .read()
            .await?
            .metadata(Role::None, local)
            .await?
            .size
            == before.size,
        "failed write size atomicity",
    )?;
    let mut bytes_after = [0; 4096];
    mounted
        .read()
        .await?
        .read(Role::None, local, 0, &mut bytes_after)
        .await?;
    ensure(
        bytes_after == bytes_before && mounts::info(&runtime.mounts, 1).await?.used == used_before,
        "failed write data/quota atomicity",
    )?;
    root.write()
        .await?
        .write(Role::System, root_file.local, 4096, &[13; 4096])
        .await?;
    ensure(
        copy_file_range(&runtime, Role::None, source, 0, entry, 0, 8192).await? == 4096,
        "cross-mount copy prefix on later quota failure",
    )?;
    root.read()
        .await?
        .read(Role::None, root_file.local, 4096, &mut bytes_after)
        .await?;
    ensure(
        bytes_after.iter().all(|byte| *byte == 13),
        "copy preserved source",
    )?;
    let pages = client
        .alloc_pages(2, u64::MAX)
        .await
        .map_err(map_native_error)?;
    for page in &pages {
        page.bytes_mut().fill(11);
    }
    let response = request(
        &runtime,
        &server,
        &mut responses,
        api_fs::write_multi_msg_encode(wire, 0, 8192, pages),
    )
    .await?;
    ensure(
        api_fs::write_multi_resp_decode(response).map_err(map_native_error)? == 4096,
        "write prefix",
    )?;
    let readahead = runtime.fs_stats.readahead_spawns.get();
    for len in [4096, 8192] {
        let response = request(
            &runtime,
            &server,
            &mut responses,
            api_fs::read_msg_encode(wire, 0, len),
        )
        .await?;
        // Recover every returned page just as a client would.
        if len == 4096 {
            let (_, page) =
                api_fs::read_resp_decode(response, &client).map_err(map_native_error)?;
            drop(page);
        } else {
            let (_, pages) =
                api_fs::read_multi_resp_decode(response, &client).map_err(map_native_error)?;
            drop(pages);
        }
    }
    ensure(
        runtime.fs_stats.readahead_spawns.get() == readahead,
        "memfs spawned readahead",
    )?;
    for cursor in [0, 1] {
        let response = request(
            &runtime,
            &server,
            &mut responses,
            api_fs::get_mounts_req_encode(cursor),
        )
        .await?;
        let (record, next) =
            api_fs::get_mounts_resp_decode(response, &client).map_err(map_native_error)?;
        ensure(
            record.id == cursor && next == if cursor == 1 { api_fs::MOUNTS_END } else { 1 },
            "mount cursor",
        )?;
    }
    for cursor in [2, api_fs::MOUNTS_END] {
        let response = request(
            &runtime,
            &server,
            &mut responses,
            api_fs::get_mounts_req_encode(cursor),
        )
        .await?;
        ensure(
            response.status() == Err(moto_rt::Error::InvalidArgument),
            "invalid mount cursor",
        )?;
    }
    // The table's paths exceed one channel page, and retain spaces, quotes,
    // newlines and UTF-8 without depending on a text delimiter.
    for index in 0..8 {
        let path = format!("/m{index}/'雪\n/{}/{}", "x/".repeat(390), "tail");
        runtime.mounts.borrow_mut().insert(
            memfs(8192)?,
            MountKind::MemFs,
            mounts::MountPoint {
                mount: 0,
                shadowed: 100 + index,
                path,
            },
        )?;
    }
    let mut path_bytes = 0;
    for cursor in 0..10 {
        let response = request(
            &runtime,
            &server,
            &mut responses,
            api_fs::get_mounts_req_encode(cursor),
        )
        .await?;
        let (record, next) =
            api_fs::get_mounts_resp_decode(response, &client).map_err(map_native_error)?;
        path_bytes += record.path.len();
        ensure(
            record.path == runtime.mounts.borrow().find(record.id).unwrap().path(),
            "paginated mount path",
        )?;
        ensure(
            next == if cursor == 9 {
                api_fs::MOUNTS_END
            } else {
                cursor + 1
            },
            "long table cursor",
        )?;
    }
    ensure(
        path_bytes > io_channel::PAGE_SIZE,
        "pagination fixture too small",
    )?;

    // Simulate an admitted pressure exception; size is checked under the
    // mutation guard, and freeing drains the cache before its reply.
    for command in api_fs::CMD_STAT..=api_fs::CMD_GET_MOUNTS {
        if command == api_fs::CMD_FILE_LOCK {
            continue;
        }
        let mut msg = api_fs::resize_msg_encode(wire, 0);
        msg.command = command;
        ensure(
            served_under_pressure(&msg, &runtime)
                == matches!(command, api_fs::CMD_RESIZE | api_fs::CMD_DELETE_ENTRY),
            "pressure command classification",
        )?;
    }
    for operation in [
        moto_rt::fs::UNLOCK,
        moto_rt::fs::TRY_LOCK_EXCLUSIVE,
        moto_rt::fs::TRY_LOCK_SHARED,
    ] {
        ensure(
            served_under_pressure(&api_fs::file_lock_msg_encode(wire, 3, operation), &runtime)
                == (operation == moto_rt::fs::UNLOCK),
            "pressure lock classification",
        )?;
    }
    let err = on_cmd_resize(
        api_fs::resize_msg_encode(wire, 8192),
        &server,
        runtime.clone(),
        Role::None,
        true,
    )
    .await
    .unwrap_err();
    ensure(
        err.kind() == ErrorKind::OutOfMemory,
        "pressure resize growth",
    )?;
    on_cmd_resize(
        api_fs::resize_msg_encode(wire, 0),
        &server,
        runtime.clone(),
        Role::None,
        true,
    )
    .await?;
    responses
        .recv()
        .await
        .map_err(map_native_error)?
        .status()
        .map_err(map_native_error)?;
    if let FS::MemFs(fs) = &*mounted.read().await? {
        ensure(
            fs.cached_free_bytes() == 0,
            "pressure shrink must return pages",
        )?;
    }
    on_cmd_delete_entry(
        api_fs::delete_entry_msg_encode(wire),
        &server,
        runtime.clone(),
        Role::None,
        true,
    )
    .await?;
    responses
        .recv()
        .await
        .map_err(map_native_error)?
        .status()
        .map_err(map_native_error)?;
    ensure(
        mounted
            .read()
            .await?
            .stat(Role::None, 0, "file")
            .await?
            .is_none(),
        "pressure delete",
    )?;
    // Keep an alias's origin across the multi-read dispatch and lock wait.
    let writer = mounted.write().await?;
    let mut pending = core::pin::pin!(on_cmd_read(
        api_fs::read_msg_encode(alias, 0, 8192),
        &server,
        runtime.clone(),
        Role::None,
    ));
    ensure(
        core::future::poll_fn(|cx| std::task::Poll::Ready(pending.as_mut().poll(cx).is_pending()))
            .await,
        "multi-read should wait for the mount lock",
    )?;
    ensure(
        root.check_local(1 << 112).unwrap_err().kind() == ErrorKind::InvalidData,
        "quarantine alias origin",
    )?;
    drop(writer);
    ensure(
        pending.await.unwrap_err().kind() == ErrorKind::InvalidData,
        "multi-read rechecks alias origin after waiting",
    )?;
    Ok(())
}

/// A replacing rename needs only `w` on the destination directory, as in the
/// backends, while mount roots and running executables there stay protected.
fn replace_without_traverse() -> std::result::Result<(), String> {
    moto_async::LocalRuntime::new()
        .block_on(replacements())
        .map_err(|err| err.to_string())
}

async fn replacements() -> Result<()> {
    let runtime = runtime()?;
    let root = runtime.root()?;
    let all = RolePermissions::all(AccessPermissions::Rwx);
    let mut fs = root.write().await?;
    let dir = fs
        .create_entry(
            Role::System,
            0,
            EntryKind::Directory,
            "w-only",
            RolePermissions::all(AccessPermissions::Rw),
        )
        .await?;
    let mut targets = Vec::new();
    for (name, kind) in [
        ("existing", EntryKind::File),
        ("running", EntryKind::File),
        ("point", EntryKind::Directory),
    ] {
        targets.push(fs.create_entry(Role::System, dir, kind, name, all).await?);
    }
    let mut sources = Vec::new();
    for name in ["a", "b", "c", "d"] {
        sources.push(
            fs.create_entry(Role::None, 0, EntryKind::File, name, all)
                .await?,
        );
    }
    drop(fs);

    // Mount 0's local IDs are its internal IDs.
    move_entry(&runtime, Role::None, sources[0], dir, "absent", true).await?;
    move_entry(&runtime, Role::None, sources[1], dir, "existing", true).await?;
    ensure(
        root.read().await?.lookup_unchecked(dir, "existing").await?
            == Some((sources[1], EntryKind::File)),
        "replaced entry",
    )?;

    let not_allowed = |result: Result<()>| {
        result.err().and_then(|err| err.raw_os_error()) == Some(moto_rt::E_NOT_ALLOWED as i32)
    };
    let held = spawn::self_test::hold_executable(&runtime, targets[1]);
    let replaced = move_entry(&runtime, Role::None, sources[2], dir, "running", true).await;
    drop(held);
    ensure(not_allowed(replaced), "running executable replaced")?;
    runtime.mounts.borrow_mut().insert(
        memfs(1 << 20)?,
        MountKind::MemFs,
        mounts::MountPoint {
            mount: 0,
            shadowed: targets[2],
            path: "/w-only/point".into(),
        },
    )?;
    ensure(
        not_allowed(move_entry(&runtime, Role::None, sources[3], dir, "point", true).await),
        "mount root replaced",
    )
}

fn records() -> std::result::Result<(), String> {
    use crate::self_test::{st_assert, st_assert_eq};
    let mut bytes = [0; io_channel::PAGE_SIZE];
    for path in [
        "/".to_owned(),
        "/odd ' \" \t\n雪".into(),
        format!("/{}", "x".repeat(1023)),
    ] {
        for corrupted in [false, true] {
            let record = MountInfo {
                id: (1 << 24) - 1,
                kind: MountKind::MemFs,
                path: path.clone(),
                corrupted,
                used: (!corrupted).then_some(0),
                entries: None,
                cap: (!corrupted).then_some(u64::MAX),
            };
            let len = record.encode(&mut bytes).map_err(|err| err.to_string())?;
            st_assert_eq!(MountInfo::decode(&bytes[..len]).unwrap(), record);
            st_assert!(MountInfo::decode(&bytes[..len - 1]).is_err());
            st_assert!(MountInfo::decode(&bytes[..len + 1]).is_err());
            bytes[5] = 255;
            st_assert!(MountInfo::decode(&bytes[..len]).is_err());
        }
    }
    let mut malformed = api_fs::get_mounts_req_encode(0);
    malformed.payload.args_64_mut()[0] = 1 << 32;
    st_assert_eq!(
        api_fs::get_mounts_req_decode(malformed),
        Err(moto_rt::Error::InvalidArgument)
    );
    Ok(())
}
