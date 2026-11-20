//! Tests for `sysbox caps`.

use moto_sys::caps::*;
use std::process::{Command, Output, Stdio};

#[allow(dead_code)]
#[path = "../../src/commands/caps.rs"]
mod command;

const SYSBOX: &str = env!("CARGO_BIN_EXE_sysbox");

fn run(args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("caps")
        .args(args)
        .output()
        .unwrap()
}

fn assert_caps(args: &[&str], pid: u64, caps: u64) {
    let output = run(args);
    assert!(output.status.success(), "caps {args:?} failed: {output:?}");
    let expected = format!("PID {pid}: capabilities: {}\n", command::format_caps(caps));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

fn assert_fails(args: &[&str]) {
    let output = run(args);
    assert_eq!(output.status.code(), Some(1), "caps {args:?}: {output:?}");
    assert!(output.stdout.is_empty(), "caps {args:?}: {output:?}");
    assert!(!output.stderr.is_empty(), "caps {args:?}: {output:?}");
}

fn test_format() {
    let format = command::format_caps;
    assert_eq!(format(0x304), "0x304 = CAP_SPAWN | CAP_NET | CAP_FS_WRITE");
    assert_eq!(format(0), "0x0 = (none)");
    assert_eq!(format(CAP_SYS | 0xc00), "0xc01 = CAP_SYS | 0xc00");
    assert_eq!(
        format(0x3ff),
        "0x3ff = CAP_SYS | CAP_IO_MANAGER | CAP_SPAWN | CAP_LOG | CAP_SHUTDOWN \
         | CAP_SPAWN_DETACHED | CAP_INTERACTIVE | CAP_VSOCK | CAP_NET | CAP_FS_WRITE"
    );
}

// A sleeping child with an explicit mask, reported by its PID.
fn test_child(caps: u64) {
    let mut child = Command::new(SYSBOX)
        .args(["sleep", "60"])
        .env(MOTOR_OS_CAPS_ENV_KEY, format!("{caps:#x}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id() as u64;
    assert_caps(&[&pid.to_string()], pid, caps);
    child.kill().unwrap();
    child.wait().unwrap();
}

pub fn run_test() {
    test_format();

    let page = moto_sys::ProcessStaticPage::get();
    // Without a PID, caps reports its parent: this test process.
    assert_caps(&[], page.pid, page.capabilities);
    assert_caps(&[&page.pid.to_string()], page.pid, page.capabilities);

    test_child(0);
    test_child(page.capabilities & (CAP_SPAWN | CAP_NET | CAP_FS_WRITE));

    assert_fails(&["not-a-pid"]);
    assert_fails(&["1", "2"]);
    assert_fails(&[&u64::MAX.to_string()]);

    println!("sysbox_caps::run_test PASS");
}
