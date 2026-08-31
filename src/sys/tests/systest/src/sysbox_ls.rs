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

    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_ls::run_test PASS");
}
