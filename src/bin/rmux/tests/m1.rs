//! M1 end-to-end: rmux as a byte pump between the console and one shell.
//!
//! `pane`'s unit tests drive a pane directly; these drive the *binary*, over
//! its own stdin and stdout, which is the only way to reach the half M1 adds —
//! the event loop, the console reader, and the exit code the pane's child
//! chose. No pty is involved: that is what the conformance harness needs
//! (details.md §9.1), and it is not needed to prove that a pipe is a pipe.

use std::io::Write;
use std::process::Command;
use std::process::Stdio;

const RMUX: &str = env!("CARGO_BIN_EXE_rmux");

/// A scratch directory this test alone uses.
///
/// rmux is a server plus clients now, and a client attaches to whichever
/// server the port file names (details.md §4.2). Tests run in parallel, so
/// without a directory apiece they would all attach to the *same* session and
/// read each other's output. `$TMPDIR` is what decides where the port file
/// goes on the host, which is exactly the knob needed.
fn private_tmpdir() -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rmux-m1-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run rmux with `input` typed at its console, and return what it painted on
/// stdout plus its exit code.
fn rmux(input: &str) -> (String, i32) {
    let tmpdir = private_tmpdir();
    let mut child = Command::new(RMUX)
        .env("TMPDIR", &tmpdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rmux");

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).unwrap();
    // The console is over; rmux passes that on by closing the pane's stdin.
    drop(stdin);

    let out = child.wait_with_output().unwrap();
    // Every script here ends with `exit`, so the session ends and the server
    // with it -- but the directory is ours to tidy either way.
    let _ = std::fs::remove_dir_all(&tmpdir);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn rmux_runs_a_shell_and_relays_what_it_prints() {
    let (out, code) = rmux("echo $((21+21))\nexit\n");
    assert!(out.contains("42"), "{out:?}");
    assert_eq!(code, 0);
}

#[test]
fn rmux_exits_with_the_status_its_shell_chose() {
    let (_, code) = rmux("exit 5\n");
    assert_eq!(code, 5);
}

#[test]
fn a_panes_stderr_is_painted_on_the_console_like_the_rest_of_it() {
    // Both of a pane's pipes are the same terminal to the program in it, so
    // both end up on the console — never on rmux's own stderr, which belongs to
    // rmux's own complaints.
    let (out, _) = rmux("echo oops >&2\nexit\n");
    assert!(out.contains("oops"), "{out:?}");
}

#[test]
fn what_a_pane_printed_last_is_painted_before_rmux_leaves() {
    // A pane's waiter reports the exit only once its output has been drained
    // (details.md §4.5), so the last thing a program printed is in the grid by
    // the time rmux stops -- and stopping without painting it throws that
    // away, which is the same loss the drain exists to prevent, one layer up.
    // This failed about three runs in five before the final render was added,
    // so the loop is the test.
    for _ in 0..5 {
        let (out, code) = rmux("echo la\"\"st\nexit\n");
        assert!(out.contains("last"), "{out:?}");
        assert_eq!(code, 0);
    }
}

#[test]
fn rmux_refuses_a_command_it_does_not_have() {
    // The surface is fixed (§4.1, §7.3) and nothing outside it is planned, so
    // an unknown verb is a usage message rather than a guess.
    for args in [
        vec!["frobnicate"],
        vec!["new", "-x", "boom"],
        vec!["ls", "extra"],
    ] {
        let tmpdir = private_tmpdir();
        let out = Command::new(RMUX)
            .env("TMPDIR", &tmpdir)
            .args(&args)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&tmpdir);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn ls_with_no_server_running_says_nothing_and_succeeds() {
    // There are no sessions, and saying so is the answer -- starting a server
    // to be told it has none would be worse.
    let tmpdir = private_tmpdir();
    let out = Command::new(RMUX)
        .env("TMPDIR", &tmpdir)
        .arg("ls")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&tmpdir);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}
