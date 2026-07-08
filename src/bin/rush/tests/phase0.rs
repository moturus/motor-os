//! Phase 0 golden tests.
//!
//! These lock in rush's *current* observable behavior plus the Phase 0
//! correctness fixes (diagnostics to stderr, 127/126 exit codes, `exit`
//! semantics), so the lex/parse/exec rewrite in later phases cannot silently
//! regress them. Expected values follow the POSIX standard (cross-checked
//! against `dash`/`bash` on the host where they agree); shell-specific quirks
//! are deliberately avoided, and where rush is still incomplete the gap is
//! called out in a comment.
//!
//! The shell binary is located via Cargo's `CARGO_BIN_EXE_<name>` env var, so
//! these run the real `rush` executable end to end.

use std::io::Write;
use std::process::{Command, Stdio};

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Run `rush -c <script>` and capture stdout, stderr, and the exit status.
fn run_c(script: &str) -> Run {
    let out = Command::new(RUSH)
        .arg("-c")
        .arg(script)
        .output()
        .expect("failed to spawn rush");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Feed `input` to `rush -piped` on stdin and return the exit status.
///
/// `-piped` runs the interactive loop over a pipe, which — unlike `-c` — does
/// not abort on a non-zero command, so it is currently the only way to exercise
/// two sequential commands (real `;` sequencing arrives in Phase 2).
fn run_piped_status(input: &str) -> i32 {
    let mut child = Command::new(RUSH)
        .arg("-piped")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn rush -piped");
    {
        let mut stdin = child.stdin.take().unwrap();
        // Ignore write errors: the shell may `exit` before draining stdin.
        let _ = stdin.write_all(input.as_bytes());
    }
    child.wait().unwrap().code().unwrap_or(-1)
}

/// A unique temp path per test, cleaned up by the caller.
fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rush_phase0_{}_{}", std::process::id(), tag))
}

#[test]
fn simple_command_stdout() {
    let r = run_c("echo hello");
    assert_eq!(r.stdout, "hello\n");
    assert_eq!(r.stderr, "");
    assert_eq!(r.code, 0);
}

#[test]
fn true_and_false_exit_codes() {
    assert_eq!(run_c("true").code, 0);
    assert_eq!(run_c("false").code, 1);
}

#[test]
fn command_not_found_is_127_on_stderr() {
    let r = run_c("nonexistent_cmd_xyz");
    assert_eq!(r.code, 127, "POSIX: command not found -> 127");
    assert_eq!(r.stdout, "", "diagnostics must not pollute stdout");
    assert!(
        r.stderr.contains("command not found"),
        "stderr was: {:?}",
        r.stderr
    );
    assert!(
        r.stderr.contains("nonexistent_cmd_xyz"),
        "error should name the command; stderr was: {:?}",
        r.stderr
    );
}

#[test]
fn and_list_short_circuits() {
    // false && X : X does not run, status is the failing command's.
    let r = run_c("false && echo NOPE");
    assert_eq!(r.stdout, "");
    assert_eq!(r.code, 1);

    // true && X : X runs.
    let r = run_c("true && echo YES");
    assert_eq!(r.stdout, "YES\n");
    assert_eq!(r.code, 0);
}

#[test]
fn quoting_double_and_single() {
    assert_eq!(run_c("echo \"a b\"").stdout, "a b\n");
    assert_eq!(run_c("echo 'x y'").stdout, "x y\n");
}

#[test]
fn exit_with_explicit_status() {
    assert_eq!(run_c("exit 5").code, 5);
    assert_eq!(run_c("exit 0").code, 0);
}

#[test]
fn exit_status_taken_modulo_256() {
    // POSIX: exit status is the argument mod 256. 300 & 0xff == 44.
    assert_eq!(run_c("exit 300").code, 44);
}

#[test]
fn exit_with_bad_argument() {
    let r = run_c("exit foo");
    // A non-numeric operand is an error: every POSIX shell exits 2 with a
    // diagnostic on stderr. We use the common "numeric argument required"
    // wording (not dash's shell-specific "Illegal number").
    assert_eq!(r.code, 2);
    assert_eq!(r.stdout, "");
    assert!(
        r.stderr.contains("numeric argument required"),
        "stderr was: {:?}",
        r.stderr
    );
}

#[test]
fn bare_exit_uses_last_status() {
    // A bare `exit` must exit with $? (the previous command's status).
    // Verified over `-piped` because `-c` cannot yet run two commands in
    // sequence (no `;` until Phase 2).
    assert_eq!(run_piped_status("false\nexit\n"), 1);
    assert_eq!(run_piped_status("true\nexit\n"), 0);
}

#[test]
fn inline_env_assignment_reaches_child() {
    let r = run_c("FOO=phase0bar env");
    assert_eq!(r.code, 0);
    assert!(
        r.stdout.lines().any(|l| l == "FOO=phase0bar"),
        "stdout was: {:?}",
        r.stdout
    );
}

#[test]
fn stdout_redirect_truncate_and_append() {
    let path = temp_path("redir");
    let _ = std::fs::remove_file(&path);

    let r = run_c(&format!("echo hi > {}", path.display()));
    assert_eq!(r.code, 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hi\n");

    let r = run_c(&format!("echo more >> {}", path.display()));
    assert_eq!(r.code, 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hi\nmore\n");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn cd_error_goes_to_stderr() {
    let r = run_c("cd /no_such_dir_rush_phase0");
    // Full `cd` (exit status, $HOME, etc.) is Phase 5; here we only assert the
    // diagnostic is routed to stderr and does not leak onto stdout.
    assert_eq!(r.stdout, "");
    assert!(r.stderr.contains("cd"), "stderr was: {:?}", r.stderr);
}
