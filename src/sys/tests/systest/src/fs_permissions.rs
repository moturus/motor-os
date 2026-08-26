use moto_io::fs::{AccessPermissions, EntryId, EntryKind, FsClient, Role, RolePermissions};

const NONE_CHILD: &str = "fs-permissions-none-child";

fn expect_denied<T>(result: moto_rt::Result<T>) {
    assert_eq!(result.err(), Some(moto_rt::Error::NotAllowed));
}

fn parse_entry_id(value: &str) -> EntryId {
    value.parse().unwrap()
}

pub fn is_none_child(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some(NONE_CHILD)
}

pub fn run_none_child(args: &[String]) -> ! {
    use moto_sys::caps::ProcessRole;

    assert_eq!(13, args.len());
    assert_eq!(
        ProcessRole::None,
        ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities)
    );

    let root = &args[2];
    let no_read = parse_entry_id(&args[3]);
    let read_only = parse_entry_id(&args[4]);
    let rx_dir = parse_entry_id(&args[5]);
    let rx_child = parse_entry_id(&args[6]);
    let r_dir = parse_entry_id(&args[7]);
    let rw_dir = parse_entry_id(&args[8]);
    let source_denied_file = parse_entry_id(&args[9]);
    let source_denied_dst = parse_entry_id(&args[10]);
    let destination_denied_file = parse_entry_id(&args[11]);
    let destination_denied_dst = parse_entry_id(&args[12]);

    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let mut buf = [0_u8; 16];

        expect_denied(client.read(no_read, 0, &mut buf).await);
        assert_ne!(0, client.read(read_only, 0, &mut buf).await.unwrap());
        expect_denied(client.write(read_only, 0, b"no").await);
        expect_denied(client.resize(read_only, 0).await);

        assert_eq!(
            Some(rx_child),
            client.get_first_entry(rx_dir).await.unwrap()
        );
        expect_denied(
            client
                .create_entry(rx_dir, EntryKind::File, "create-denied")
                .await,
        );
        expect_denied(client.delete_entry(rx_child).await);

        expect_denied(client.get_first_entry(r_dir).await);
        expect_denied(client.stat(&format!("{root}/r/child")).await);

        // Write on a directory is sufficient for mutation; execute is only
        // needed for lookup and enumeration.
        expect_denied(client.get_first_entry(rw_dir).await);
        let created = client
            .create_entry(rw_dir, EntryKind::File, "created-by-none")
            .await
            .unwrap();
        client.delete_entry(created).await.unwrap();

        expect_denied(
            client
                .move_entry(source_denied_file, source_denied_dst, "moved")
                .await,
        );
        expect_denied(
            client
                .move_entry(destination_denied_file, destination_denied_dst, "moved")
                .await,
        );
    });

    std::process::exit(0)
}

async fn create_file(
    client: &std::rc::Rc<FsClient>,
    parent: EntryId,
    name: &str,
    contents: &[u8],
) -> EntryId {
    let id = client
        .create_entry(parent, EntryKind::File, name)
        .await
        .unwrap();
    assert_eq!(contents.len(), client.write(id, 0, contents).await.unwrap());
    id
}

pub fn run_all_tests() {
    use moto_sys::caps::{MOTOR_OS_CAPS_ENV_KEY, ProcessRole};
    use std::io::Write;

    assert_eq!(
        ProcessRole::Interactive,
        ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities)
    );

    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = crate::temp_path(&format!(
        "systest-process-role-fs-{}-{started}",
        moto_sys::ProcessStaticPage::get().pid
    ));
    std::fs::create_dir(&root).unwrap();

    // std's readonly API narrows the Interactive byte. It cannot widen it
    // again, so replacement is the recovery mechanism.
    let sealed = root.join("sealed");
    std::fs::write(&sealed, b"sealed").unwrap();
    let mut permissions = std::fs::metadata(&sealed).unwrap().permissions();
    assert!(!permissions.readonly());
    permissions.set_readonly(true);
    std::fs::set_permissions(&sealed, permissions.clone()).unwrap();
    assert!(std::fs::metadata(&sealed).unwrap().permissions().readonly());

    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let (sealed_id, EntryKind::File) = client.stat(sealed.to_str().unwrap()).await.unwrap()
        else {
            panic!("sealed entry is not a file")
        };
        let metadata = client.metadata(sealed_id).await.unwrap();
        assert_eq!(
            AccessPermissions::Rwx,
            metadata.access(Role::System).unwrap()
        );
        assert_eq!(
            AccessPermissions::R,
            metadata.access(Role::Interactive).unwrap()
        );
        assert_eq!(AccessPermissions::R, metadata.access(Role::None).unwrap());
        expect_denied(
            client
                .set_permissions(sealed_id, AccessPermissions::Rwx)
                .await,
        );
    });

    permissions.set_readonly(false);
    assert_eq!(
        std::io::ErrorKind::PermissionDenied,
        std::fs::set_permissions(&sealed, permissions)
            .unwrap_err()
            .kind()
    );

    let replacement = root.join("replacement");
    let sealed_contents = std::fs::read(&sealed).unwrap();
    std::fs::write(&replacement, &sealed_contents).unwrap();
    std::fs::remove_file(&sealed).unwrap();
    std::fs::rename(&replacement, &sealed).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&sealed)
        .unwrap()
        .write_all(b"!")
        .unwrap();
    assert_eq!(b"sealed!", std::fs::read(&sealed).unwrap().as_slice());

    let ids = moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let (root_id, EntryKind::Directory) = client.stat(root.to_str().unwrap()).await.unwrap()
        else {
            panic!("test root is not a directory")
        };

        let exact = RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rw,
            AccessPermissions::R,
        );
        let exact_id = client
            .create_entry_with_permissions(root_id, EntryKind::File, "exact", exact)
            .await
            .unwrap();
        let exact_metadata = client.metadata(exact_id).await.unwrap();
        assert_eq!(
            AccessPermissions::Rwx,
            exact_metadata.access(Role::System).unwrap()
        );
        assert_eq!(
            AccessPermissions::Rw,
            exact_metadata.access(Role::Interactive).unwrap()
        );
        assert_eq!(
            AccessPermissions::R,
            exact_metadata.access(Role::None).unwrap()
        );

        let executable = RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rx,
            AccessPermissions::R,
        );
        let executable_id = client
            .create_entry_with_permissions(root_id, EntryKind::File, "exact-executable", executable)
            .await
            .unwrap();
        expect_denied(client.write(executable_id, 0, b"no").await);
        expect_denied(client.resize(executable_id, 1).await);

        let unauthorized = RolePermissions::all(AccessPermissions::R);
        expect_denied(
            client
                .create_entry_with_permissions(
                    root_id,
                    EntryKind::File,
                    "exact-unauthorized",
                    unauthorized,
                )
                .await,
        );
        assert_eq!(
            client
                .stat(&format!("{}/exact-unauthorized", root.display()))
                .await
                .unwrap_err(),
            moto_rt::Error::NotFound
        );

        let non_monotonic = RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::R,
            AccessPermissions::Rw,
        );
        expect_denied(
            client
                .create_entry_with_permissions(
                    root_id,
                    EntryKind::File,
                    "exact-non-monotonic",
                    non_monotonic,
                )
                .await,
        );
        assert_eq!(
            client
                .stat(&format!("{}/exact-non-monotonic", root.display()))
                .await
                .unwrap_err(),
            moto_rt::Error::NotFound
        );

        let finalized = create_file(&client, root_id, "self-finalized", b"#!/bin/sh\n").await;
        client
            .set_permissions(finalized, AccessPermissions::Rx)
            .await
            .unwrap();
        assert_eq!(
            AccessPermissions::Rx,
            client
                .metadata(finalized)
                .await
                .unwrap()
                .access(Role::Interactive)
                .unwrap()
        );
        expect_denied(
            client
                .set_permissions(finalized, AccessPermissions::Rw)
                .await,
        );

        let no_read = create_file(&client, root_id, "no-read", b"secret").await;
        client
            .set_permissions(no_read, AccessPermissions::None)
            .await
            .unwrap();
        let read_only = create_file(&client, root_id, "read-only", b"readable").await;
        client
            .set_permissions(read_only, AccessPermissions::R)
            .await
            .unwrap();

        let rx_dir = client
            .create_entry(root_id, EntryKind::Directory, "rx")
            .await
            .unwrap();
        let rx_child = create_file(&client, rx_dir, "child", b"child").await;
        client
            .set_permissions(rx_dir, AccessPermissions::Rx)
            .await
            .unwrap();

        let r_dir = client
            .create_entry(root_id, EntryKind::Directory, "r")
            .await
            .unwrap();
        create_file(&client, r_dir, "child", b"child").await;
        client
            .set_permissions(r_dir, AccessPermissions::R)
            .await
            .unwrap();

        let rw_dir = client
            .create_entry(root_id, EntryKind::Directory, "rw")
            .await
            .unwrap();
        client
            .set_permissions(rw_dir, AccessPermissions::Rw)
            .await
            .unwrap();

        let source_denied = client
            .create_entry(root_id, EntryKind::Directory, "source-denied")
            .await
            .unwrap();
        let source_denied_file = create_file(&client, source_denied, "move", b"move").await;
        let source_denied_dst = client
            .create_entry(root_id, EntryKind::Directory, "source-destination")
            .await
            .unwrap();
        client
            .set_permissions(source_denied, AccessPermissions::Rx)
            .await
            .unwrap();

        let destination_source = client
            .create_entry(root_id, EntryKind::Directory, "destination-source")
            .await
            .unwrap();
        let destination_denied_file =
            create_file(&client, destination_source, "move", b"move").await;
        let destination_denied_dst = client
            .create_entry(root_id, EntryKind::Directory, "destination-denied")
            .await
            .unwrap();
        client
            .set_permissions(destination_denied_dst, AccessPermissions::Rx)
            .await
            .unwrap();

        [
            no_read,
            read_only,
            rx_dir,
            rx_child,
            r_dir,
            rw_dir,
            source_denied_file,
            source_denied_dst,
            destination_denied_file,
            destination_denied_dst,
        ]
    });

    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg(NONE_CHILD)
        .arg(root.to_str().unwrap())
        .env(MOTOR_OS_CAPS_ENV_KEY, "0x0");
    for id in ids {
        command.arg(id.to_string());
    }
    assert_eq!(Some(0), command.status().unwrap().code());

    println!("fs_permissions::run_all_tests PASS");
}
