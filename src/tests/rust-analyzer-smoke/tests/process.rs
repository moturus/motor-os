use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

use rust_analyzer_smoke::process::{MAX_STDERR_LEN, ServerProcess};

fn spawn(mode: &str) -> ServerProcess {
    ServerProcess::spawn(
        Command::new(env!("CARGO_BIN_EXE_rust-analyzer-smoke"))
            .arg("--fake-child")
            .arg(mode),
    )
    .unwrap()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[test]
fn reads_message_and_reaps_clean_child() {
    let mut child = spawn("message");
    assert_eq!(child.read_until(deadline()).unwrap()["ready"], true);
    assert!(child.wait_until(deadline()).unwrap().success());
}

#[test]
fn reports_partial_frame() {
    let mut child = spawn("partial");
    assert_eq!(
        child.read_until(deadline()).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert!(child.wait_until(deadline()).unwrap().success());
}

#[test]
fn drains_and_bounds_stderr_concurrently() {
    let mut child = spawn("stderr");
    assert_eq!(child.read_until(deadline()).unwrap()["ready"], true);
    assert!(child.wait_until(deadline()).unwrap().success());
    let stderr = child.stderr_tail();
    assert_eq!(stderr.len(), MAX_STDERR_LEN);
    assert!(stderr.ends_with("stderr-tail-marker"));
}

#[test]
fn timeout_kills_and_reaps_child() {
    let mut child = spawn("hang");
    let error = child
        .read_until(Instant::now() + Duration::from_millis(100))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(!child.wait_until(deadline()).unwrap().success());
}
