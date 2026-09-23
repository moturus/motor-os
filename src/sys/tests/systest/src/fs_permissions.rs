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
        assert_eq!(
            RolePermissions::new(
                AccessPermissions::Rwx,
                AccessPermissions::Rwx,
                AccessPermissions::Rw,
            ),
            client
                .metadata(created)
                .await
                .unwrap()
                .permissions()
                .unwrap()
        );
        let created_dir = client
            .create_entry(rw_dir, EntryKind::Directory, "directory-by-none")
            .await
            .unwrap();
        assert_eq!(
            RolePermissions::all(AccessPermissions::Rwx),
            client
                .metadata(created_dir)
                .await
                .unwrap()
                .permissions()
                .unwrap()
        );
        client.delete_entry(created).await.unwrap();
        client.delete_entry(created_dir).await.unwrap();

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

    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let (root_id, EntryKind::Directory) = client.stat(root.to_str().unwrap()).await.unwrap()
        else {
            panic!("test root is not a directory")
        };
        assert_eq!(
            RolePermissions::new(
                AccessPermissions::Rwx,
                AccessPermissions::Rwx,
                AccessPermissions::Rx,
            ),
            client
                .metadata(root_id)
                .await
                .unwrap()
                .permissions()
                .unwrap()
        );
        let default_file = client
            .create_entry(root_id, EntryKind::File, "interactive-default")
            .await
            .unwrap();
        assert_eq!(
            RolePermissions::new(
                AccessPermissions::Rwx,
                AccessPermissions::Rw,
                AccessPermissions::R,
            ),
            client
                .metadata(default_file)
                .await
                .unwrap()
                .permissions()
                .unwrap()
        );
        client.delete_entry(default_file).await.unwrap();
    });

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

    // Motor OS permissions are role-based, so the Unix-specific Clippy
    // concern about making a file world-writable does not apply here.
    #[allow(clippy::permissions_set_readonly_false)]
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
        expect_denied(
            client
                .set_permissions(finalized, AccessPermissions::Rwx)
                .await,
        );
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
        client
            .set_permissions(finalized, AccessPermissions::Rwx)
            .await
            .unwrap();
        assert_eq!(
            AccessPermissions::Rwx,
            client
                .metadata(finalized)
                .await
                .unwrap()
                .access(Role::Interactive)
                .unwrap()
        );
        assert_eq!(client.write(finalized, 0, b"ok").await.unwrap(), 2);

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
            .set_all_permissions(
                rw_dir,
                RolePermissions::new(
                    AccessPermissions::Rwx,
                    AccessPermissions::Rw,
                    AccessPermissions::Rw,
                ),
            )
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
        .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{:x}", crate::IO_CAPS));
    for id in ids {
        command.arg(id.to_string());
    }
    assert_eq!(Some(0), command.status().unwrap().code());

    println!("fs_permissions::run_all_tests PASS");
}

const WRITE_CAP_CHILD: &str = "fs-write-cap-child";
const WRITE_CAP_DATA: &[u8] = b"fs-write-cap fixture";

pub fn is_write_cap_child(args: &[String]) -> bool {
    args.len() == 4 && args[1] == WRITE_CAP_CHILD
}

async fn stat_file(client: &std::rc::Rc<FsClient>, path: &str) -> EntryId {
    let (id, EntryKind::File) = client.stat(path).await.unwrap() else {
        panic!("{path} is not a file")
    };
    id
}

/// Checks one request's outcome, then shows the connection still serves reads.
async fn expect_outcome(
    client: &std::rc::Rc<FsClient>,
    data: EntryId,
    allowed: bool,
    result: moto_rt::Result<()>,
) {
    if allowed {
        result.unwrap();
    } else {
        expect_denied(result);
    }
    let mut buf = [0_u8; 4];
    assert_eq!(4, client.read(data, 0, &mut buf).await.unwrap());
}

/// Every known request outside sys-io's read allowlist. Role permissions allow
/// all of them, so with `allowed` they are the positive control.
async fn write_requests(client: &std::rc::Rc<FsClient>, root: &str, allowed: bool) {
    use moto_rt::fs::{LOCK_EXCLUSIVE, LOCK_SHARED, TRY_LOCK_EXCLUSIVE, TRY_LOCK_SHARED, UNLOCK};

    let (root_id, _) = client.stat(root).await.unwrap();
    let data = stat_file(client, &format!("{root}/data")).await;
    let victim = stat_file(client, &format!("{root}/victim")).await;
    let copy_dst = stat_file(client, &format!("{root}/copy-dst")).await;
    let permissions = client.metadata(data).await.unwrap().permissions().unwrap();
    let first = client.get_first_entry(root_id).await.unwrap().unwrap();
    client.name(first).await.unwrap();
    client.get_next_entry(first).await.unwrap();

    let multi_page = [0x55_u8; 2 * moto_sys::sys_mem::PAGE_SIZE_SMALL as usize];
    let role =
        moto_sys::caps::ProcessRole::from_caps(moto_sys::ProcessStaticPage::get().capabilities);
    let role_access = permissions.get(match role {
        moto_sys::caps::ProcessRole::None => Role::None,
        moto_sys::caps::ProcessRole::Interactive => Role::Interactive,
        moto_sys::caps::ProcessRole::System => Role::System,
    });
    // Each request is followed by a read on the same connection.
    macro_rules! request {
        ($call:expr) => {
            let result = $call.await.map(drop);
            expect_outcome(client, data, allowed, result).await;
        };
    }
    request!(client.write(data, 0, b"x"));
    request!(client.write(data, 0, &multi_page));
    request!(client.resize(data, WRITE_CAP_DATA.len() as u64));
    request!(client.create_entry(root_id, EntryKind::File, "created"));
    request!(client.create_entry(root_id, EntryKind::Directory, "created-dir"));
    request!(client.create_entry_with_permissions(
        root_id,
        EntryKind::File,
        "created-p",
        permissions
    ));
    request!(client.copy_file_range(data, copy_dst, 0, 4));
    request!(client.set_permissions(data, role_access));
    request!(client.set_all_permissions(data, permissions));
    request!(client.move_entry(victim, root_id, "moved"));
    request!(client.move_noreplace(victim, root_id, "moved-again"));
    request!(client.delete_entry(victim));
    request!(client.flush());
    for operation in [
        LOCK_SHARED,
        LOCK_EXCLUSIVE,
        TRY_LOCK_SHARED,
        TRY_LOCK_EXCLUSIVE,
    ] {
        request!(client.file_lock(data, 1, operation));
        request!(client.file_lock(data, 1, UNLOCK));
    }
}

/// Denied page-carrying requests must release their donated pages: more of
/// them than the channel holds, then a valid request, all under a deadline,
/// since a leaked page makes the next allocation wait forever.
async fn donated_pages_released(client: &std::rc::Rc<FsClient>, root: &str) {
    use futures::FutureExt;
    use moto_ipc::io_channel::CHANNEL_PAGE_COUNT;
    use moto_sys_io::api_fs::{WRITE_MAX_BYTES, WRITE_MAX_PAGES};

    let requests = async {
        let (root_id, _) = client.stat(root).await.unwrap();
        let data = stat_file(client, &format!("{root}/data")).await;
        let permissions = client.metadata(data).await.unwrap().permissions().unwrap();
        for _ in 0..=CHANNEL_PAGE_COUNT {
            expect_denied(client.write(data, 0, b"x").await);
            expect_denied(client.create_entry(root_id, EntryKind::File, "p").await);
            expect_denied(
                client
                    .create_entry(root_id, EntryKind::Directory, "p")
                    .await,
            );
            expect_denied(
                client
                    .create_entry_with_permissions(root_id, EntryKind::File, "p", permissions)
                    .await,
            );
            expect_denied(client.move_entry(data, root_id, "p").await);
            expect_denied(client.move_noreplace(data, root_id, "p").await);
        }
        let fill = [0x55_u8; WRITE_MAX_BYTES];
        for _ in 0..=CHANNEL_PAGE_COUNT / WRITE_MAX_PAGES {
            expect_denied(client.write(data, 0, &fill).await);
        }
        client.stat(root).await.unwrap();
    };
    let mut requests = core::pin::pin!(requests.fuse());
    let mut deadline =
        core::pin::pin!(moto_async::sleep(std::time::Duration::from_secs(10)).fuse());
    futures::select! {
        () = requests => {}
        () = deadline => panic!("denied requests leaked donated pages"),
    }
}

/// Write-intent opens fail in rt.vdso before any lookup, create, or truncate;
/// a read-only open still works.
fn open_requests(root: &str, allowed: bool) {
    use std::fs::OpenOptions;
    use std::io::Read;

    let data = format!("{root}/data");
    let missing = format!("{root}/missing");
    let mut contents = Vec::new();
    std::fs::File::open(&data)
        .unwrap()
        .read_to_end(&mut contents)
        .unwrap();
    assert!(!contents.is_empty());

    for (options, path) in [
        (OpenOptions::new().write(true).clone(), &data),
        (OpenOptions::new().append(true).clone(), &data),
        (OpenOptions::new().write(true).truncate(true).clone(), &data),
        (
            OpenOptions::new().write(true).create(true).clone(),
            &missing,
        ),
        (
            OpenOptions::new().write(true).create_new(true).clone(),
            &missing,
        ),
    ] {
        let result = options.open(path);
        if allowed {
            result.unwrap();
            let _ = std::fs::remove_file(&missing);
        } else {
            let error = result.unwrap_err();
            assert_eq!(std::io::ErrorKind::PermissionDenied, error.kind());
            assert_eq!(Some(moto_rt::E_NOT_ALLOWED.into()), error.raw_os_error());
        }
    }
}

pub fn run_write_cap_child(args: &[String]) -> ! {
    let allowed = args[2] == "allow";
    assert_eq!(
        allowed,
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_FS_WRITE != 0
    );
    let root = &args[3];
    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        write_requests(&client, root, allowed).await;
        if !allowed {
            donated_pages_released(&client, root).await;
        }
    });
    open_requests(root, allowed);
    std::process::exit(0)
}

/// Names, contents, and permissions of the fixture's entries.
fn write_cap_snapshot(root: &std::path::Path) -> Vec<(String, Vec<u8>, RolePermissions)> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let mut snapshot = Vec::new();
        for name in names {
            let path = root.join(&name);
            let id = stat_file(&client, path.to_str().unwrap()).await;
            let permissions = client.metadata(id).await.unwrap().permissions().unwrap();
            snapshot.push((name, std::fs::read(&path).unwrap(), permissions));
        }
        snapshot
    })
}

/// Without `CAP_FS_WRITE`, sys-io refuses every request that is not a read,
/// whatever `role_caps` add, and leaves the fixture unchanged.
pub fn test_write_capability(role_caps: u64) {
    use moto_sys::caps::{CAP_FS_WRITE, CAP_SPAWN, MOTOR_OS_CAPS_ENV_KEY, ProcessRole};

    let root = crate::temp_path(&format!(
        "systest-fs-write-cap-{:016x}",
        std::random::random::<u64>(..)
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("data"), WRITE_CAP_DATA).unwrap();
    std::fs::write(root.join("victim"), b"victim").unwrap();
    std::fs::write(root.join("copy-dst"), b"copy-destination").unwrap();
    let before = write_cap_snapshot(&root);

    let restricted = role_caps | CAP_SPAWN;
    for (caps, mode) in [(restricted, "deny"), (restricted | CAP_FS_WRITE, "allow")] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([WRITE_CAP_CHILD, mode, root.to_str().unwrap()])
            .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
            .status()
            .unwrap();
        assert_eq!(Some(0), status.code(), "{mode} child");
        if mode == "deny" {
            assert_eq!(before, write_cap_snapshot(&root));
        }
    }

    std::fs::remove_dir_all(root).unwrap();
    println!(
        "fs_permissions::test_write_capability({:?}) PASS",
        ProcessRole::from_caps(role_caps)
    );
}

const STDOUT_WRITER_CHILD: &str = "fs-write-cap-stdout-writer";
const STDOUT_RELAY_HELPER: &str = "fs-write-cap-stdout-relay-helper";
const STDOUT_DENIED_EXIT: i32 = 13;

pub fn is_stdout_writer_child(args: &[String]) -> bool {
    args.len() == 3 && args[1] == STDOUT_WRITER_CHILD
}

/// Writes `args[2]` to stdout; a denied write exits with `STDOUT_DENIED_EXIT`.
/// It bypasses `std::io::Stdout`, which reports every write error on this
/// platform as success.
pub fn run_stdout_writer_child(args: &[String]) -> ! {
    let bytes = args[2].as_bytes();
    match moto_rt::fs::write(moto_rt::FD_STDOUT, bytes) {
        Ok(written) => {
            assert_eq!(bytes.len(), written);
            std::process::exit(0)
        }
        Err(moto_rt::Error::NotAllowed) => std::process::exit(STDOUT_DENIED_EXIT),
        Err(err) => panic!("stdout write failed: {err:?}"),
    }
}

pub fn is_stdout_relay_helper(args: &[String]) -> bool {
    args.len() == 3 && args[1] == STDOUT_RELAY_HELPER
}

/// Holds `CAP_FS_WRITE` and a file-backed stdout, which its child, spawned with
/// the mask in `args[2]`, inherits through this process's relay.
pub fn run_stdout_relay_helper(args: &[String]) -> ! {
    assert_ne!(
        0,
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_FS_WRITE
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([STDOUT_WRITER_CHILD, "relayed\n"])
        .env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, &args[2])
        .stdout(std::process::Stdio::inherit())
        .status()
        .unwrap();
    std::process::exit(status.code().unwrap())
}

/// An explicit file given as stdout is written by the child's own connection,
/// so a restricted child cannot write it; an inherited file-backed stream is
/// written by the authorized parent's relay.
pub fn test_write_capability_stdio() {
    use moto_sys::caps::{CAP_INTERACTIVE, CAP_NET, CAP_SPAWN, MOTOR_OS_CAPS_ENV_KEY};
    use std::process::{Command, Stdio};

    let restricted = format!("0x{:x}", CAP_SPAWN | CAP_INTERACTIVE | CAP_NET);
    let dir = crate::temp_path(&format!(
        "systest-fs-write-cap-stdio-{:016x}",
        std::random::random::<u64>(..)
    ));
    std::fs::create_dir(&dir).unwrap();
    let exe = std::env::current_exe().unwrap();

    let direct = dir.join("direct");
    let status = Command::new(&exe)
        .args([STDOUT_WRITER_CHILD, "direct\n"])
        .env(MOTOR_OS_CAPS_ENV_KEY, &restricted)
        .stdout(Stdio::from(std::fs::File::create(&direct).unwrap()))
        .status()
        .unwrap();
    assert_eq!(Some(STDOUT_DENIED_EXIT), status.code());
    assert!(std::fs::read(&direct).unwrap().is_empty());

    let output = Command::new(&exe)
        .args([STDOUT_WRITER_CHILD, "piped\n"])
        .env(MOTOR_OS_CAPS_ENV_KEY, &restricted)
        .output()
        .unwrap();
    assert_eq!(Some(0), output.status.code());
    assert_eq!(b"piped\n", output.stdout.as_slice());

    let relayed = dir.join("relayed");
    let status = Command::new(&exe)
        .args([STDOUT_RELAY_HELPER, &restricted])
        .stdout(Stdio::from(std::fs::File::create(&relayed).unwrap()))
        .status()
        .unwrap();
    assert_eq!(Some(0), status.code());
    assert_eq!(b"relayed\n", std::fs::read(&relayed).unwrap().as_slice());

    std::fs::remove_dir_all(dir).unwrap();
    println!("fs_permissions::test_write_capability_stdio PASS");
}
