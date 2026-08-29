//! Tests for `sysbox cat`.

use std::process::{Command, Output};

const SYSBOX: &str = "/system/bin/sysbox";

fn run(args: &[&str]) -> Output {
    Command::new(SYSBOX).arg("cat").args(args).output().unwrap()
}

pub fn run_test() {
    let root = crate::temp_path(&format!(
        "systest-sysbox-cat-{}",
        moto_sys::ProcessStaticPage::get().pid
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let readable = root.join("readable");
    std::fs::write(&readable, b"cat fixture\n").unwrap();
    let output = run(&[readable.to_str().unwrap()]);
    assert!(output.status.success(), "cat failed: {output:?}");
    assert_eq!(b"cat fixture\n", output.stdout.as_slice());

    let missing = root.join("missing");
    let output = run(&[missing.to_str().unwrap()]);
    assert!(!output.status.success(), "cat of missing file succeeded");
    assert!(
        output.stdout.is_empty(),
        "cat diagnostic on stdout: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("error reading file"),
        "missing cat diagnostic: {output:?}"
    );

    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_cat::run_test PASS");
}
