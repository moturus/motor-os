use moto_io::fs::{AccessPermissions, EntryKind, FsClient, RolePermissions};
use std::path::Path;
use std::process::{Command, Output};

const SYSBOX: &str = "/system/bin/sysbox";
const CHMOD: &str = "/system/bin/chmod";

fn run_sysbox(args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("chmod")
        .args(args)
        .output()
        .unwrap()
}

fn write_file(root: &Path, name: &str) -> std::path::PathBuf {
    let path = root.join(name);
    std::fs::write(&path, name.as_bytes()).unwrap();
    path
}

fn listed_mode(root: &Path, name: &str) -> String {
    let output = Command::new(SYSBOX)
        .args(["ls", root.to_str().unwrap(), "-l"])
        .output()
        .unwrap();
    assert!(output.status.success(), "ls failed: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let field = stdout
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let permissions = fields.next()?;
            let _size = fields.next()?;
            (fields.next() == Some(name)).then_some(permissions)
        })
        .unwrap_or_else(|| panic!("missing {name:?} in ls output {stdout:?}"));
    assert_eq!(10, field.len());
    field[1..].to_owned()
}

fn assert_mode(root: &Path, name: &str, mode: &str) {
    assert_eq!(mode, listed_mode(root, name));
}

pub fn run_all_tests() {
    let root = crate::temp_path(&format!(
        "systest-sysbox-chmod-{}",
        moto_sys::ProcessStaticPage::get().pid
    ));
    std::fs::create_dir(&root).unwrap();

    // Exercise the IPC operation directly, including trusted Interactive
    // authority and rollback when a higher role is changed.
    let ipc = write_file(&root, "ipc");
    moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let (entry_id, EntryKind::File) = client.stat(ipc.to_str().unwrap()).await.unwrap() else {
            panic!("IPC fixture is not a file")
        };
        let exact = RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rw,
            AccessPermissions::R,
        );
        client.set_all_permissions(entry_id, exact).await.unwrap();
        assert_eq!(
            exact,
            client
                .metadata(entry_id)
                .await
                .unwrap()
                .permissions()
                .unwrap()
        );

        let forbidden = RolePermissions::new(
            AccessPermissions::Rx,
            AccessPermissions::R,
            AccessPermissions::None,
        );
        assert_eq!(
            Some(moto_rt::Error::NotAllowed),
            client.set_all_permissions(entry_id, forbidden).await.err()
        );
        assert_eq!(
            exact,
            client
                .metadata(entry_id)
                .await
                .unwrap()
                .permissions()
                .unwrap()
        );
    });
    assert_mode(&root, "ipc", "rwxrw-r--");

    // Across these fresh files, every legal permission triplet appears in both
    // the Interactive and None positions where monotonicity permits it.
    let modes = [
        "rwxrwxrwx",
        "rwxrwxrw-",
        "rwxrwxr-x",
        "rwxrwxr--",
        "rwxrwx---",
        "rwxrw----",
        "rwxr-x---",
        "rwxr-----",
        "rwx------",
    ];
    for (index, mode) in modes.into_iter().enumerate() {
        let name = format!("mode-{index}");
        let path = write_file(&root, &name);
        let output = run_sysbox(&[mode, path.to_str().unwrap()]);
        assert!(output.status.success(), "chmod {mode} failed: {output:?}");
        assert_mode(&root, &name, mode);
    }

    let shim = write_file(&root, "shim");
    let output = Command::new(CHMOD)
        .args(["rwxr-xr--", shim.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "chmod shim failed: {output:?}");
    assert_mode(&root, "shim", "rwxr-xr--");

    let multi_a = write_file(&root, "multi-a");
    let multi_b = write_file(&root, "multi-b");
    let output = run_sysbox(&[
        "rwxrw-r--",
        multi_a.to_str().unwrap(),
        multi_b.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "multi-path chmod failed: {output:?}"
    );
    assert_mode(&root, "multi-a", "rwxrw-r--");
    assert_mode(&root, "multi-b", "rwxrw-r--");

    // A missing middle operand makes the invocation fail, but both valid paths
    // are still attempted.
    let partial_a = write_file(&root, "partial-a");
    let partial_b = write_file(&root, "partial-b");
    let missing = root.join("missing");
    let output = run_sysbox(&[
        "rwxr-----",
        partial_a.to_str().unwrap(),
        missing.to_str().unwrap(),
        partial_b.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert_mode(&root, "partial-a", "rwxr-----");
    assert_mode(&root, "partial-b", "rwxr-----");

    let invalid = write_file(&root, "invalid");
    for mode in [
        "",
        "rwx",
        "rwxrwxrwxr",
        "-rwxrwxrwx",
        "755",
        "+x",
        "-w-rwxrwx",
        "rwxr--rwx",
        "r--rwx---",
    ] {
        let output = run_sysbox(&[mode, invalid.to_str().unwrap()]);
        assert!(!output.status.success(), "invalid mode {mode:?} succeeded");
        assert_mode(&root, "invalid", "rwxrwxrwx");
    }

    // The all-empty mode is syntactically valid and starts with '-'. This
    // Interactive process cannot narrow System, so the filesystem—not option
    // parsing—rejects it.
    let output = run_sysbox(&["---------", invalid.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("invalid mode"), "{stderr}");
    assert!(!stderr.contains("usage:"), "{stderr}");
    assert_mode(&root, "invalid", "rwxrwxrwx");

    let help = run_sysbox(&["--help"]);
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stderr)
            .unwrap()
            .contains("System/Interactive/None")
    );

    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_chmod::run_all_tests PASS");
}
