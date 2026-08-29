//! Tests for the user-facing `which` command.

use std::process::{Command, Output};

const WHICH: &str = "/system/bin/which";

fn run(command: &str) -> Output {
    Command::new(WHICH).arg(command).output().unwrap()
}

fn assert_found(command: &str, expected: &str) {
    let output = run(command);
    assert!(
        output.status.success(),
        "which {command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

pub fn run_test() {
    assert_found("ls", "/system/bin/ls\n");
    assert_found("red", "/user/bin/red\n");

    let missing = run("nonexisting-command");
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stdout.is_empty(), "unexpected output: {missing:?}");

    println!("sysbox_which::run_test PASS");
}
