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
