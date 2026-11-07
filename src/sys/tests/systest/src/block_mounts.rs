use moto_sdk::io::fs::{AccessPermissions, EntryKind, FsClient, MountKind, RolePermissions};

fn denied<T>(result: Result<T, moto_rt::Error>) {
    assert!(matches!(result, Err(moto_rt::Error::NotAllowed)));
}

pub fn read_only_root() {
    const PROBE: &str = "/none/cfg/ro-probe";
    assert_eq!(std::fs::read(PROBE).unwrap(), b"read-only fixture\n");
    assert!(
        std::fs::read_dir("/none/cfg")
            .unwrap()
            .any(|entry| { entry.unwrap().file_name() == "ro-probe" })
    );
    assert_eq!(
        std::fs::write(PROBE, b"changed").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let mounts = client.mounts().await.unwrap();
        assert!(mounts[0].read_only && mounts[0].kind == MountKind::MotorFs);
        let logs = mounts
            .iter()
            .find(|mount| mount.path == "/system/logs")
            .unwrap();
        assert_eq!(logs.kind, MountKind::MemFs);
        assert!(!logs.read_only);
        assert_eq!(logs.cap, Some(16 << 20));
        let (probe, _) = client.stat(PROBE).await.unwrap();
        let (parent, _) = client.stat("/none/cfg").await.unwrap();
        let (tmp, _) = client.stat("/none/tmp").await.unwrap();
        let writable = client
            .create_entry(tmp, EntryKind::File, "writable")
            .await
            .unwrap();
        denied(client.create_entry(parent, EntryKind::File, "new").await);
        denied(
            client
                .create_entry(parent, EntryKind::Directory, "new")
                .await,
        );
        denied(
            client
                .create_entry_with_permissions(
                    parent,
                    EntryKind::File,
                    "new",
                    RolePermissions::all(AccessPermissions::Rw),
                )
                .await,
        );
        denied(client.write(probe, 0, b"changed").await);
        denied(client.write(probe, 0, &[7; 8192]).await);
        denied(client.resize(probe, 0).await);
        denied(client.delete_entry(probe).await);
        denied(client.set_permissions(probe, AccessPermissions::R).await);
        denied(
            client
                .set_all_permissions(probe, RolePermissions::all(AccessPermissions::R))
                .await,
        );
        for (source, target) in [(probe, tmp), (writable, parent), (probe, parent)] {
            denied(client.move_entry(source, target, "moved").await);
            denied(client.move_noreplace(source, target, "moved").await);
        }
        denied(client.copy_file_range(writable, probe, 0, 1).await);
        assert_eq!(
            client
                .copy_file_range(probe, writable, 0, 17)
                .await
                .unwrap(),
            17
        );
        client
            .file_lock(probe, 1, moto_rt::fs::TRY_LOCK_SHARED)
            .await
            .unwrap();
        client
            .file_lock(probe, 1, moto_rt::fs::UNLOCK)
            .await
            .unwrap();
        client.flush().await.unwrap();
        client.delete_entry(writable).await.unwrap();
    });
    let output = std::process::Command::new("/system/bin/sysbox")
        .args(["echo", "read-only-exec"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"read-only-exec\n");
    assert_eq!(std::fs::read(PROBE).unwrap(), b"read-only fixture\n");
    if moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_SYS != 0 {
        crate::logging::read_only_root_rotation();
    }
    println!("block mounts: read-only root PASS");
}

pub fn partition(phase: &str) {
    let path = "/user/data/persist";
    let bytes: Vec<u8> = (0..16401).map(|offset| (offset % 251) as u8).collect();
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let mounts = client.mounts().await.unwrap();
        if phase == "unconfigured" {
            assert_eq!(
                mounts
                    .iter()
                    .filter(|mount| mount.kind == MountKind::MotorFs)
                    .count(),
                1
            );
            assert!(!std::fs::exists("/user/data/label").unwrap());
            return;
        }
        let mount = mounts
            .iter()
            .find(|mount| mount.path == "/user/data")
            .unwrap();
        assert_eq!(mount.id, 5);
        assert_eq!(
            mount.source,
            Some(moto_sdk::io::fs::MountBlockSource {
                device: 0,
                partition: Some(4)
            })
        );
        assert_eq!(mount.read_only, phase == "read-only");
        assert_eq!(std::fs::read("/user/data/label").unwrap(), b"virtio0p4\n");
        let (parent, _) = client.stat("/user/data").await.unwrap();
        assert_eq!(
            client
                .metadata(parent)
                .await
                .unwrap()
                .permissions()
                .unwrap()
                .none,
            AccessPermissions::Rx
        );
        if phase == "write" {
            std::fs::write(path, &bytes).unwrap();
            std::fs::write("/user/root-persist", &bytes).unwrap();
            let (source, _) = client.stat("/user/root-persist").await.unwrap();
            let copied = client
                .create_entry(parent, EntryKind::File, "copy")
                .await
                .unwrap();
            assert_eq!(
                client
                    .copy_file_range(source, copied, 0, bytes.len() as u64)
                    .await
                    .unwrap(),
                bytes.len() as u64
            );
            assert_eq!(std::fs::read("/user/data/copy").unwrap(), bytes);
            assert_eq!(
                std::fs::rename(path, "/user/moved").unwrap_err().kind(),
                std::io::ErrorKind::CrossesDevices
            );
        } else {
            assert_eq!(phase, "read-only");
            assert_eq!(std::fs::read(path).unwrap(), bytes);
            assert_eq!(std::fs::read("/user/root-persist").unwrap(), bytes);
            assert_eq!(
                std::fs::write(path, b"bad").unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied
            );
            let (source, _) = client.stat(path).await.unwrap();
            let (other, _) = client.stat("/user/root-persist").await.unwrap();
            let (user, _) = client.stat("/user").await.unwrap();
            for (file, parent) in [(source, user), (other, parent)] {
                denied(client.move_entry(file, parent, "moved").await);
                denied(client.move_noreplace(file, parent, "moved").await);
            }
        }
        let copy = "/none/tmp/from-disk";
        std::fs::copy(path, copy).unwrap();
        assert_eq!(std::fs::read(copy).unwrap(), bytes);
        std::fs::remove_file(copy).unwrap();
        client.flush().await.unwrap();
    });
    println!("block mounts: partition {phase} PASS");
}

pub fn devices(phase: &str) {
    assert!(matches!(phase, "write" | "read-only"));
    let sources = [
        ("/user/data", 0, Some(4), "virtio0p4\n"),
        ("/user/data/nested", 1, Some(1), "virtio1p1\n"),
        ("/user/bare", 2, None, "virtio2\n"),
    ];
    let contents = |index: usize| {
        (0..32781)
            .map(|offset| ((offset + index * 17) % 251) as u8)
            .collect::<Vec<_>>()
    };
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let mounts = client.mounts().await.unwrap();
        assert_eq!(mounts.len(), 8);
        for (index, (path, device, partition, label)) in sources.iter().enumerate() {
            let mount = mounts.iter().find(|mount| mount.path == *path).unwrap();
            assert_eq!(mount.id, 5 + index as u32);
            assert_eq!(mount.kind, MountKind::MotorFs);
            assert_eq!(
                mount.source,
                Some(moto_sdk::io::fs::MountBlockSource {
                    device: *device,
                    partition: *partition,
                })
            );
            assert_eq!(mount.read_only, phase == "read-only" && *device == 2);
            assert_eq!(
                std::fs::read(format!("{path}/label")).unwrap(),
                label.as_bytes()
            );
            let file = format!("{path}/device-persist");
            if phase == "write" {
                std::fs::write(&file, contents(index)).unwrap();
            } else {
                assert_eq!(std::fs::read(&file).unwrap(), contents(index));
            }
            if mount.read_only {
                assert_eq!(
                    std::fs::write(&file, b"bad").unwrap_err().kind(),
                    std::io::ErrorKind::PermissionDenied
                );
            }
        }
        // Every pair crosses either an owner or a filesystem on the same owner.
        for (index, (from, ..)) in sources.iter().enumerate() {
            let file = format!("{from}/device-persist");
            for (other, (to, ..)) in sources.iter().enumerate() {
                if index == other {
                    continue;
                }
                let copied = format!("{to}/from-{index}");
                if phase == "write" {
                    std::fs::copy(&file, &copied).unwrap();
                }
                assert_eq!(std::fs::read(&copied).unwrap(), contents(index));
                let (source, _) = client.stat(&file).await.unwrap();
                let (target, _) = client.stat(to).await.unwrap();
                let error = if phase == "read-only" && (index == 2 || other == 2) {
                    moto_rt::Error::NotAllowed
                } else {
                    moto_rt::Error::CrossesDevices
                };
                assert_eq!(client.move_entry(source, target, "moved").await, Err(error));
                assert_eq!(
                    client.move_noreplace(source, target, "moved").await,
                    Err(error)
                );
            }
            let copied = format!("/none/tmp/from-{index}");
            std::fs::copy(&file, &copied).unwrap();
            assert_eq!(std::fs::read(&copied).unwrap(), contents(index));
            std::fs::remove_file(copied).unwrap();
        }
        client.flush().await.unwrap();
    });
    let original = std::env::current_exe().unwrap();
    let digest = |program: &std::path::Path| {
        let output = std::process::Command::new(program)
            .args(["cold-spawn-child", "digest"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stdout.starts_with(b"image-ok "));
        output.stdout
    };
    let expected = digest(&original);
    for (path, ..) in sources {
        let program = std::path::Path::new(path).join("paging-probe");
        if phase == "write" {
            std::fs::copy(&original, &program).unwrap();
            moto_rt::fs::set_perm(
                program.to_str().unwrap(),
                moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC,
            )
            .unwrap();
        }
        assert_eq!(digest(&program), expected);
    }
    println!("block mounts: devices {phase} PASS");
}

pub fn stress() {
    use std::io::{Read, Seek, SeekFrom, Write};
    std::fs::create_dir_all(crate::DISK_TEMP_DIR).unwrap();
    // Exercise the unchanged refusal floor with all disk owners/caches present.
    crate::mounts::memory();
    let barrier = std::sync::Barrier::new(5);
    std::thread::scope(|scope| {
        for (index, path) in ["/user", "/user/data", "/user/data/nested", "/user/bare"]
            .into_iter()
            .enumerate()
        {
            let barrier = &barrier;
            scope.spawn(move || {
                let name = format!("{path}/concurrent-io");
                let mut file = std::fs::OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&name)
                    .unwrap();
                let mut bytes = vec![0; 65536];
                barrier.wait();
                for round in 0..8 {
                    let value = (index * 19 + round) as u8;
                    bytes.fill(value);
                    file.seek(SeekFrom::Start(0)).unwrap();
                    for _ in 0..64 {
                        file.write_all(&bytes).unwrap();
                    }
                    file.sync_all().unwrap();
                    file.seek(SeekFrom::Start(0)).unwrap();
                    for _ in 0..64 {
                        bytes.fill(!value);
                        file.read_exact(&mut bytes).unwrap();
                        assert!(bytes.iter().all(|byte| *byte == value));
                    }
                }
                drop(file);
                std::fs::remove_file(name).unwrap();
            });
        }
        scope.spawn(|| {
            let bytes = vec![37; 32768];
            barrier.wait();
            for _ in 0..8 {
                let mut file = std::fs::File::create("/none/tmp/concurrent-memory").unwrap();
                for _ in 0..1024 {
                    file.write_all(&bytes).unwrap();
                }
                drop(file);
                std::fs::remove_file("/none/tmp/concurrent-memory").unwrap();
            }
        });
    });
    println!("block mounts: concurrent I/O and memfs pressure PASS");
}
