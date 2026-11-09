//! Tests for `sysbox ls` argument parsing.

use std::path::Path;
use std::process::{Command, Output};

const SYSBOX: &str = "/system/bin/sysbox";

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("ls")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn assert_lists(output: Output, marker: &str) {
    assert!(
        output.status.success(),
        "ls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Debug rt.vdso startup records intentionally use the child's stderr.
    #[cfg(not(debug_assertions))]
    assert!(output.stderr.is_empty(), "ls diagnostic: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.split_whitespace().any(|field| field == marker),
        "ls did not list {marker:?}: {stdout:?}"
    );
}

pub fn run_test() {
    let root = crate::temp_path(&format!(
        "systest-sysbox-ls-{}",
        moto_sys::ProcessStaticPage::get().pid
    ));
    let _ = std::fs::remove_dir_all(&root);
    let directory = root.join("-lh");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("marker.txt"), b"marker").unwrap();

    // After `--`, an option-looking operand is a directory, not `-l` and `-h`.
    assert_lists(run(&root, &["--", "-lh"]), "marker.txt");
    // Options before the delimiter still apply to that directory.
    assert_lists(run(&root, &["-l", "--", "-lh"]), "marker.txt");

    // A file operand lists itself, named as it was typed, as ls(1) does.
    assert_lists(run(&root, &["--", "-lh/marker.txt"]), "-lh/marker.txt");
    assert_lists(
        run(&root, &["-l", "--", "-lh/marker.txt"]),
        "-lh/marker.txt",
    );

    // An inaccessible operand is ls(1)'s "serious trouble": stderr and status 2.
    let output = run(&root, &["missing-entry"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "ls of a missing path: {output:?}"
    );
    assert!(output.stdout.is_empty(), "ls of a missing path: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("error reading directory"),
        "ls of a missing path: {output:?}"
    );

    test_operands_kept_as_typed(&root);

    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_ls::run_test PASS");
}

/// The exact stdout of a successful `ls`, with the status checked.
#[track_caller]
fn stdout_of(output: Output) -> String {
    assert!(output.status.success(), "ls failed: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

/// Operands reach the file system as typed: no trimming, no skipping, and no
/// wildcard expansion of their own (the shell owns globbing).
fn test_operands_kept_as_typed(root: &Path) {
    let names = ["has space.txt", "*.md", "a.md", "trimmed"];
    let directory = root.join("typed");
    std::fs::create_dir_all(&directory).unwrap();
    for name in names {
        std::fs::write(directory.join(name), name).unwrap();
    }

    // A file operand lists itself under the name it was given, so a trimmed
    // or re-expanded operand would print a different name or fail.
    for name in names {
        assert_eq!(
            stdout_of(run(&directory, &[name])),
            format!("{name} \n"),
            "ls of {name:?}"
        );
        let long = stdout_of(run(&directory, &["-l", name]));
        assert!(
            long.ends_with(&format!(" {name}\n")),
            "ls -l of {name:?}: {long:?}"
        );
    }

    // Motor OS paths cannot have surrounding whitespace, so these operands
    // name nothing: they must fail rather than be trimmed to `trimmed` or `.`.
    for operand in ["", "  ", " trimmed", "trimmed "] {
        let output = run(&directory, &[operand]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "ls of {operand:?}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "ls of {operand:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains(&format!("error reading directory '{operand}'")),
            "ls of {operand:?}: {output:?}"
        );
    }

    // A lone `-` is an operand, not an empty option group.
    let output = run(&directory, &["-"]);
    assert_eq!(output.status.code(), Some(2), "ls of \"-\": {output:?}");
    std::fs::write(directory.join("-"), b"dash").unwrap();
    assert_eq!(stdout_of(run(&directory, &["-"])), "- \n");
}
