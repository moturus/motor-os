//! Mounted memfs namespace, cross-device operations, and bounded memory use.
use moto_io::fs::{EntryId, EntryKind, FsClient, MountInfo, MountKind};
use moto_sys_io::api_fs;
use std::io::ErrorKind;

const RAM_DIR: &str = "/none/tmp/systest-mounts";
const DISK_DIR: &str = "/user/tmp/systest-mounts";

async fn memfs_mount(client: &std::rc::Rc<FsClient>) -> Result<MountInfo, String> {
    client
        .mounts()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .find(|mount| mount.path == "/none/tmp" && mount.kind == MountKind::MemFs)
        .ok_or_else(|| "missing /none/tmp memfs mount".into())
}

pub fn run_all_tests() {
    namespace();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("mounts-none")
        .env(
            moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
            format!("0x{:x}", moto_sys::caps::CAP_FS_WRITE),
        )
        .output()
        .unwrap();
    assert!(child.status.success(), "{child:?}");
    memory();
    println!("mounts: ALL PASS");
}

pub fn none_role() {
    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let mount = memfs_mount(&client).await.unwrap();
        assert!(mount.cap.is_some());
        let (root, _) = client.stat("/none/tmp").await.unwrap();
        let dir = client
            .create_entry(root, EntryKind::Directory, "systest-mounts-none")
            .await
            .unwrap();
        let file = client
            .create_entry(dir, EntryKind::File, "file")
            .await
            .unwrap();
        assert_eq!(client.get_first_entry(dir).await.unwrap(), Some(file));
        client
            .file_lock(file, 1, moto_rt::fs::TRY_LOCK_EXCLUSIVE)
            .await
            .unwrap();
        assert_eq!(
            client
                .file_lock(file, 2, moto_rt::fs::TRY_LOCK_EXCLUSIVE)
                .await,
            Err(moto_rt::Error::NotReady)
        );
        client
            .file_lock(file, 1, moto_rt::fs::UNLOCK)
            .await
            .unwrap();
        assert!(
            client
                .set_permissions(root, moto_io::fs::AccessPermissions::Rwx)
                .await
                .is_err()
        );
        client.delete_entry(file).await.unwrap();
        client.delete_entry(dir).await.unwrap();
    });
    println!("mounts: None-role listing, creation and locks PASS");
}

fn namespace() {
    use std::io::{Read, Seek, Write};
    assert!(!std::fs::exists("/none/tmp/.shadowed-by-memfs").unwrap());
    assert!(
        std::fs::read_dir("/none/tmp")
            .unwrap()
            .all(|entry| { entry.unwrap().file_name() != ".shadowed-by-memfs" })
    );
    std::fs::create_dir(RAM_DIR).unwrap();
    std::fs::create_dir(DISK_DIR).unwrap();
    let pattern: Vec<u8> = (0..100_003).map(|i| (i * 17 + i / 256) as u8).collect();
    let ram = format!("{RAM_DIR}/file");
    let disk = format!("{DISK_DIR}/file");
    std::fs::write(&disk, &pattern).unwrap();
    assert_eq!(std::fs::copy(&disk, &ram).unwrap(), pattern.len() as u64);
    assert_eq!(std::fs::read(&ram).unwrap(), pattern);
    std::fs::remove_file(&disk).unwrap();
    assert_eq!(std::fs::copy(&ram, &disk).unwrap(), pattern.len() as u64);
    assert_eq!(std::fs::read(&disk).unwrap(), pattern);
    for (from, to) in [(&ram, &disk), (&disk, &ram)] {
        assert_eq!(
            std::fs::rename(from, to).unwrap_err().kind(),
            ErrorKind::CrossesDevices
        );
        assert_eq!(std::fs::read(from).unwrap(), pattern);
        assert_eq!(std::fs::read(to).unwrap(), pattern);
    }
    std::fs::create_dir(format!("{RAM_DIR}/sub")).unwrap();
    assert_eq!(
        std::fs::rename(format!("{RAM_DIR}/sub"), format!("{DISK_DIR}/sub"))
            .unwrap_err()
            .kind(),
        ErrorKind::CrossesDevices
    );
    assert!(std::fs::exists(format!("{RAM_DIR}/sub")).unwrap());
    assert!(!std::fs::exists(format!("{DISK_DIR}/sub")).unwrap());
    // Fixtures for copies at or past a source's end (checked below).
    for (from, to) in [(RAM_DIR, DISK_DIR), (DISK_DIR, RAM_DIR)] {
        for len in [0, 8192] {
            std::fs::write(format!("{from}/eof-source-{len}"), vec![5; len]).unwrap();
            std::fs::write(format!("{to}/eof-target-{len}"), [6; 8192]).unwrap();
        }
    }
    assert_eq!(
        std::fs::remove_dir("/none/tmp").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::rename("/none/tmp", format!("{DISK_DIR}/mount"))
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::rename("/none/tmp", "/none/systest-moved-mount")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::rename(format!("{RAM_DIR}/sub"), "/none/tmp")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::rename(DISK_DIR, "/none/tmp").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );

    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let mount = memfs_mount(&client).await.unwrap();
        assert!(mount.id != 0 && !mount.corrupted);
        assert!(mount.used.is_some() && mount.entries.is_some() && mount.cap.is_some());
        let ram_bytes =
            (moto_sys::stats::MemoryStats::get().unwrap().available / (1 << 20) + 10) << 20;
        assert_eq!(
            mount.cap,
            Some(
                (ram_bytes & !((16 << 20) - 1))
                    .saturating_sub(16 << 20)
                    .max(8 << 20)
            )
        );
        let (tmp, kind) = client.stat("/none/tmp").await.unwrap();
        assert_eq!(kind, EntryKind::Directory);
        assert_eq!(client.name(tmp).await.unwrap(), "tmp");
        let (none, _) = client.stat("/none").await.unwrap();
        let mut next = client.get_first_entry(none).await.unwrap();
        let mut seen = false;
        while let Some(id) = next {
            if client.name(id).await.unwrap() == "tmp" {
                assert_eq!(id, tmp);
                assert_eq!(
                    client.metadata(id).await.unwrap().kind(),
                    EntryKind::Directory
                );
                seen = true;
            }
            next = client.get_next_entry(id).await.unwrap();
        }
        assert!(seen);
        // The component and whole-path protocol operations agree on identity.
        let (sender, mut receiver) = moto_ipc::io_channel::connect(api_fs::FS_URL).unwrap();
        let page = sender.alloc_page(u64::MAX).await.unwrap();
        sender
            .send(api_fs::stat_msg_encode(none, "tmp", page))
            .await
            .unwrap();
        assert_eq!(
            api_fs::stat_resp_decode(receiver.recv().await.unwrap())
                .unwrap()
                .0,
            tmp
        );
        sender
            .send(api_fs::get_mounts_req_encode(u32::MAX))
            .await
            .unwrap();
        assert_eq!(
            receiver.recv().await.unwrap().status(),
            Err(moto_rt::Error::InvalidArgument)
        );
        let (src, _) = client.stat(&disk).await.unwrap();
        let (dst, _) = client.stat(&ram).await.unwrap();
        assert_eq!(
            client
                .copy_file_range(src, dst, 17, u32::MAX as u64)
                .await
                .unwrap(),
            32768
        );
        assert_eq!(
            client.copy_file_range(dst, dst, 0, 65536).await.unwrap(),
            32768
        );
        // A copy at or past the source's end copies nothing and leaves the
        // destination alone: same size, no write (same modified time) and no
        // memfs storage, for empty and block-aligned sources both ways.
        for (from, to) in [(RAM_DIR, DISK_DIR), (DISK_DIR, RAM_DIR)] {
            for len in [0, 8192] {
                let (source, _) = client
                    .stat(&format!("{from}/eof-source-{len}"))
                    .await
                    .unwrap();
                let (target, _) = client
                    .stat(&format!("{to}/eof-target-{len}"))
                    .await
                    .unwrap();
                let before = client.metadata(target).await.unwrap();
                let used = memfs_mount(&client).await.unwrap().used;
                // Any write would stamp a later modified time.
                std::thread::sleep(std::time::Duration::from_millis(2));
                for offset in [len, 1 << 20] {
                    assert_eq!(
                        client
                            .copy_file_range(source, target, offset, 4096)
                            .await
                            .unwrap(),
                        0
                    );
                }
                let after = client.metadata(target).await.unwrap();
                assert_eq!(after.size, before.size);
                assert_eq!(after.modified.as_nanos(), before.modified.as_nanos());
                assert_eq!(memfs_mount(&client).await.unwrap().used, used);
            }
        }
        client.flush().await.unwrap();
    });
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&ram)
        .unwrap();
    file.seek(std::io::SeekFrom::Start(4095)).unwrap();
    file.write_all(b"boundary").unwrap();
    file.seek(std::io::SeekFrom::Start(4095)).unwrap();
    let mut read = [0; 8];
    file.read_exact(&mut read).unwrap();
    assert_eq!(&read, b"boundary");
    drop(file);
    std::fs::remove_dir_all(RAM_DIR).unwrap();
    std::fs::remove_dir_all(DISK_DIR).unwrap();
    println!("mounts: namespace and cross-device operations PASS");
}

fn check(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn metric(name: &str) -> Result<u64, String> {
    let provider =
        moto_stats::Collector::provider_by_name("sys-io").ok_or("missing sys-io provider")?;
    let desc = moto_stats::Collector::describe(&provider)
        .map_err(|err| err.to_string())?
        .into_iter()
        .find(|desc| desc.name == name)
        .ok_or_else(|| format!("missing metric {name}"))?;
    moto_stats::Collector::read(&provider, desc.id, moto_stats::SCOPE_GLOBAL)
        .map_err(|err| err.to_string())
}

fn free_pages() -> Result<u64, String> {
    moto_sys::stats::AdmissionStats::get()
        .map(|stats| stats.free_for_admission())
        .map_err(|err| err.to_string())
}

pub(super) async fn delete_held_entries(
    client: &std::rc::Rc<FsClient>,
    entries: impl IntoIterator<Item = EntryId>,
) -> moto_rt::Result<()> {
    let mut result = Ok(());
    for entry in entries {
        if let Err(err) = client.delete_entry(entry).await
            && result.is_ok()
        {
            result = Err(err);
        }
    }
    result
}

fn memory() {
    let result = moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().map_err(|err| err.to_string())?;
        let baseline = memfs_mount(&client).await?;
        let cap = baseline.cap.ok_or("missing memfs capacity")?;
        if cap > 1 << 30 {
            println!("mounts: memory acceptance skipped: cap {cap} exceeds 1 GiB");
            return Ok(());
        }
        let ram = (moto_sys::stats::MemoryStats::get()
            .map_err(|err| err.to_string())?
            .available
            / (1 << 20)
            + 10)
            << 20;
        let cache_cap = if ram >= 256 << 20 {
            (ram / 20).max(16 << 20)
        } else if ram >= 128 << 20 {
            8 << 20
        } else if ram >= 64 << 20 {
            4 << 20
        } else {
            2 << 20
        };
        let (root, _) = client
            .stat("/none/tmp")
            .await
            .map_err(|err| err.to_string())?;
        println!("mounts: initial used {:?}, entries {:?}, cache {}, admission-free {} pages",
            baseline.used, baseline.entries, metric("fs.memfs.cached_free_bytes")?, free_pages()?);
        let dir = client
            .create_entry(root, EntryKind::Directory, "systest-mounts")
            .await
            .map_err(|err| err.to_string())?;
        let mut held = [None; 4];
        let buffer = [37; 32768];
        let test = async {
            let working = memfs_mount(&client).await?;
            // More than the cache cap, without an allocation proportional to it
            // in the test process. Repeat to exercise release and zeroed reuse.
            let workload = (64 << 20).min(cap / 2).max(cache_cap + 32768);
            for _ in 0..3 {
                let file = client
                    .create_entry(dir, EntryKind::File, "cache")
                    .await
                    .map_err(|err| err.to_string())?;
                held[0] = Some(file);
                let mut offset = 0;
                while offset < workload {
                    let count = client
                        .write(file, offset, &buffer)
                        .await
                        .map_err(|err| err.to_string())?;
                    check(count != 0, "zero cache workload write")?;
                    offset += count as u64;
                }
                client
                    .delete_entry(file)
                    .await
                    .map_err(|err| err.to_string())?;
                held[0] = None;
                check(
                    metric("fs.memfs.cached_free_bytes")? <= cache_cap,
                    "free cache exceeds cap",
                )?;
                let after = memfs_mount(&client).await?;
                check(after.used == working.used && after.entries == working.entries, "cache cycle leaked live storage")?;
                println!("mounts: cache cycle admission-free {} pages", free_pages()?);
            }
            let small = client
                .create_entry(dir, EntryKind::File, "small")
                .await
                .map_err(|err| err.to_string())?;
            held[0] = Some(small);
            client
                .write(small, 0, b"small")
                .await
                .map_err(|err| err.to_string())?;
            let big = client
                .create_entry(dir, EntryKind::File, "big")
                .await
                .map_err(|err| err.to_string())?;
            held[1] = Some(big);
            let refused_before = metric("fs.reserve_refused")?;
            let mut size = 0;
            loop {
                match client.write(big, size, &buffer).await {
                    Ok(count) => {
                        check(count > 0, "zero big-file write")?;
                        size += count as u64;
                        check(size <= cap, "unbounded memfs write")?;
                    }
                    Err(moto_rt::Error::StorageFull) => break,
                    Err(err) => return Err(format!("memfs fill: {err}")),
                }
            }
            // Probe admission before metrics queries can release incidental
            // buffers or observe later allocator housekeeping.
            let creation = client.create_entry(dir, EntryKind::File, "refused").await;
            if let Ok(entry) = &creation {
                held[2] = Some(*entry);
            }
            check(
                creation == Err(moto_rt::Error::StorageFull),
                "creation admitted below reserve",
            )?;
            check(
                !moto_sys::memory_pressure(),
                "memfs fill reached kernel pressure",
            )?;
            check(
                metric("fs.reserve_refused")? > refused_before,
                "fill stopped at quota instead of the memory reserve",
            )?;
            client
                .delete_entry(small)
                .await
                .map_err(|err| err.to_string())?;
            held[0] = None;
            let (disk_dir, _) = client.stat("/user/tmp").await
                .map_err(|err| err.to_string())?;
            let disk_probe = client.create_entry(disk_dir, EntryKind::File, "systest-memfs-disk-probe")
                .await.map_err(|err| err.to_string())?;
            held[3] = Some(disk_probe);
            let probe = b"root remains usable";
            check(
                client.write(disk_probe, 0, probe).await
                    .map_err(|err| err.to_string())? == probe.len(),
                "short disk service write",
            )?;
            client.delete_entry(disk_probe).await.map_err(|err| err.to_string())?;
            held[3] = None;
            client
                .delete_entry(big)
                .await
                .map_err(|err| err.to_string())?;
            held[1] = None;
            let after = memfs_mount(&client).await?;
            check(after.used == working.used && after.entries == working.entries, "fill/delete leaked live storage")?;
            let recovered = client
                .create_entry(dir, EntryKind::File, "recovered")
                .await
                .map_err(|err| err.to_string())?;
            held[0] = Some(recovered);
            client
                .write(recovered, 0, &buffer)
                .await
                .map_err(|err| err.to_string())?;
            client
                .delete_entry(recovered)
                .await
                .map_err(|err| err.to_string())?;
            held[0] = None;
            println!("mounts: reserve refused after {size} bytes; recovery PASS, admission-free {} pages", free_pages()?);
            Ok(())
        }
        .await;
        // Lookup can be refused under pressure; retain every created ID and
        // attempt all cleanup even when an earlier deletion fails.
        let cleanup = delete_held_entries(&client, held.into_iter().flatten().chain([dir]))
            .await
            .map_err(|err| err.to_string());
        if let Err(err) = &cleanup {
            eprintln!("mounts: cleanup failed: {err}");
        }
        test?;
        cleanup?;
        let after = memfs_mount(&client).await?;
        check(
            after.used == baseline.used && after.entries == baseline.entries,
            "memfs live storage leaked",
        )?;
        check(
            metric("fs.memfs.cached_free_bytes")? <= cache_cap,
            "cache cap after recovery",
        )?;
        Ok::<_, String>(())
    });
    result.unwrap();
}
