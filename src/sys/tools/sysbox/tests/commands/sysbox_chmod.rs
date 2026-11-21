use moto_sdk::io::fs::{AccessPermissions, EntryKind, FsClient, RolePermissions};
use std::path::Path;
use std::process::{Command, Output};

const SYSBOX: &str = env!("CARGO_BIN_EXE_sysbox");
const CHMOD: &str = "/user/bin/chmod";

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
            // Files list a size between the two; directories do not.
            let mut fields = line.split_whitespace();
            let permissions = fields.next()?;
            (fields.last() == Some(name)).then_some(permissions)
        })
        .unwrap_or_else(|| panic!("missing {name:?} in ls output {stdout:?}"));
    assert_eq!(10, field.len());
    field[1..].to_owned()
}

fn assert_mode(root: &Path, name: &str, mode: &str) {
    assert_eq!(mode, listed_mode(root, name));
}

fn create_dir(root: &Path, name: &str) -> std::path::PathBuf {
    let path = root.join(name);
    std::fs::create_dir(&path).unwrap();
    path
}

fn chmod_ok(args: &[&str]) {
    let output = run_sysbox(args);
    assert!(output.status.success(), "chmod {args:?} failed: {output:?}");
}

/// Each case starts from a fresh file in the first mode, applies the
/// symbolic mode, and expects either the resulting mode or an error.
fn symbolic_tests(root: &Path) {
    let cases = [
        ("rwxrw-r--", "n+w", Ok("rwxrw-rw-")),
        ("rwxrw-rw-", "n-w", Ok("rwxrw-r--")),
        ("rwxrw-rw-", "n-r", Ok("rwxrw----")),
        ("rwxrw-rw-", "i-w", Ok("rwxr--r--")),
        ("rwxr-xr-x", "in-x", Ok("rwxr--r--")),
        ("rwxrw-r--", "in-rwx", Ok("rwx------")),
        ("rwxr-xr--", "n=rx", Ok("rwxr-xr-x")),
        ("rwxrw-r--", "n=", Ok("rwxrw----")),
        ("rwxr-xr-x", "in+w", Ok("rwxrwxrwx")),
        ("rwxrw-r--", "n+", Ok("rwxrw-r--")),
        (
            "rwxrw----",
            "n+w",
            Err("n+w would give invalid mode rwxrw--w-"),
        ),
        (
            "rwxr-xr-x",
            "n+w",
            Err("n+w would give invalid mode rwxr-xrwx"),
        ),
        (
            "rwxrw-r--",
            "n=w",
            Err("n=w would give invalid mode rwxrw--w-"),
        ),
        ("rwxrw-r--", "s-x", Err("NotAllowed")),
        ("rwxrw-r--", "i+x", Err("NotAllowed")),
    ];
    for (index, (start, mode, expected)) in cases.into_iter().enumerate() {
        let name = format!("symbolic-{index}");
        let path = write_file(root, &name);
        chmod_ok(&[start, path.to_str().unwrap()]);
        let output = run_sysbox(&[mode, path.to_str().unwrap()]);
        match expected {
            Ok(result) => {
                assert!(output.status.success(), "{start} {mode}: {output:?}");
                assert_mode(root, &name, result);
            }
            Err(message) => {
                assert!(!output.status.success(), "{start} {mode} succeeded");
                let stderr = String::from_utf8(output.stderr).unwrap();
                assert!(stderr.contains(message), "{start} {mode}: {stderr}");
                assert_mode(root, &name, start);
            }
        }
    }
}

fn recursive_tests(root: &Path) {
    // The command this feature was written for, on fresh Interactive
    // entries: directories start rwxrwxr-x and files rwxrw-r--.
    let tree = create_dir(root, "tree");
    let sub = create_dir(&tree, "sub");
    let deeper = create_dir(&sub, "deeper");
    write_file(&tree, "a");
    write_file(&sub, "b");
    write_file(&deeper, "c");
    write_file(root, "beside");
    chmod_ok(&["-r", "n+w", tree.to_str().unwrap()]);
    assert_mode(root, "tree", "rwxrwxrwx");
    assert_mode(&tree, "a", "rwxrw-rw-");
    assert_mode(&tree, "sub", "rwxrwxrwx");
    assert_mode(&sub, "b", "rwxrw-rw-");
    assert_mode(&sub, "deeper", "rwxrwxrwx");
    assert_mode(&deeper, "c", "rwxrw-rw-");
    assert_mode(root, "beside", "rwxrw-r--");

    // Without -r only the directory itself changes; -r on a file is allowed.
    let flat = create_dir(root, "flat");
    write_file(&flat, "inside");
    chmod_ok(&["n+w", flat.to_str().unwrap()]);
    assert_mode(root, "flat", "rwxrwxrwx");
    assert_mode(&flat, "inside", "rwxrw-r--");
    let single = write_file(root, "single");
    chmod_ok(&["-r", "n+w", single.to_str().unwrap()]);
    assert_mode(root, "single", "rwxrw-rw-");

    // Changing a child needs Interactive w on its directory. Removing it must
    // wait until the contents are done; restoring it must come first.
    let ordering = create_dir(root, "ordering");
    let inner = create_dir(&ordering, "inner");
    write_file(&inner, "file");
    chmod_ok(&["-r", "rwxr-x---", ordering.to_str().unwrap()]);
    assert_mode(root, "ordering", "rwxr-x---");
    assert_mode(&ordering, "inner", "rwxr-x---");
    assert_mode(&inner, "file", "rwxr-x---");
    chmod_ok(&["-r", "i+w", ordering.to_str().unwrap()]);
    assert_mode(root, "ordering", "rwxrwx---");
    assert_mode(&ordering, "inner", "rwxrwx---");
    assert_mode(&inner, "file", "rwxrwx---");

    // An entry the mode cannot apply to fails the command, but the walk
    // still changes everything else.
    let mixed = create_dir(root, "mixed");
    write_file(&mixed, "good");
    let exec = write_file(&mixed, "exec");
    chmod_ok(&["rwxr-xr-x", exec.to_str().unwrap()]);
    let output = run_sysbox(&["-r", "n+w", mixed.to_str().unwrap()]);
    assert!(!output.status.success(), "mixed chmod succeeded");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("exec': n+w would give invalid mode"),
        "{stderr}"
    );
    assert_mode(root, "mixed", "rwxrwxrwx");
    assert_mode(&mixed, "good", "rwxrw-rw-");
    assert_mode(&mixed, "exec", "rwxr-xr-x");

    let missing = root.join("missing");
    assert!(!run_sysbox(&["-r", "n+w", missing.to_str().unwrap()])
        .status
        .success());
}

pub fn run_all_tests() {
    if moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_INTERACTIVE == 0 {
        return;
    }
    // A panic aborts systest without cleanup: unseal and remove what an
    // earlier run left behind before starting over.
    let root = crate::temp_path("systest-sysbox-chmod");
    let _ = crate::set_directory_access(&root.join("protected"), AccessPermissions::Rwx);
    for directory in ["ordering", "ordering/inner"] {
        let _ = crate::set_directory_access(&root.join(directory), AccessPermissions::Rwx);
    }
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();

    // Exercise the IPC operation directly, including trusted Interactive
    // authority and rollback when a higher role is changed.
    let ipc = write_file(&root, "ipc");
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
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
        "rwxrw-rw-",
        "rwxrw-r--",
        "rwxrw----",
        "rwxr-xr-x",
        "rwxr-xr--",
        "rwxr-x---",
        "rwxr--r--",
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

    symbolic_tests(&root);
    recursive_tests(&root);

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
        "n",
        "N+w",
        "q+w",
        "n+q",
        "n+-w",
        "n+w,i+w",
    ] {
        let output = run_sysbox(&[mode, invalid.to_str().unwrap()]);
        assert!(!output.status.success(), "invalid mode {mode:?} succeeded");
        assert_mode(&root, "invalid", "rwxrw-r--");
    }

    // The all-empty mode is syntactically valid and starts with '-'. This
    // Interactive process cannot narrow System, so the filesystem—not option
    // parsing—rejects it.
    let output = run_sysbox(&["---------", invalid.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("invalid mode"), "{stderr}");
    assert!(!stderr.contains("usage:"), "{stderr}");
    assert_mode(&root, "invalid", "rwxrw-r--");

    let protected = root.join("protected");
    std::fs::create_dir(&protected).unwrap();
    let protected_file = write_file(&protected, "entry");
    crate::set_directory_access(&protected, AccessPermissions::Rx).unwrap();
    let output = run_sysbox(&["rwxr-xr--", protected_file.to_str().unwrap()]);
    assert!(
        !output.status.success(),
        "protected chmod succeeded: {output:?}"
    );
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("NotAllowed"),
        "protected chmod did not report PermissionDenied"
    );
    assert_mode(&protected, "entry", "rwxrw-r--");
    std::fs::write(&protected_file, b"ordinary write").unwrap();
    assert_eq!(
        b"ordinary write",
        std::fs::read(&protected_file).unwrap().as_slice()
    );
    crate::set_directory_access(&protected, AccessPermissions::Rwx).unwrap();

    let help = run_sysbox(&["--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stderr).unwrap();
    assert!(help.contains("System/Interactive/None"));
    assert!(help.contains("chmod [-r] MODE PATH..."));

    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_chmod::run_all_tests PASS");
}
