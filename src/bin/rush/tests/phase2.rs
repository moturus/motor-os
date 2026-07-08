//! Phase 2 golden tests: end-to-end sequencing that the new parser + executor
//! unlock via `-c`, which the flat model could not express.
//!
//! These lock in `;` and `&` list separators and `||` short-circuiting (the
//! `&&` case is already covered by `phase0::and_list_short_circuits`), plus the
//! Phase 2 boundaries that are deferred to Phase 3 (multi-stage pipelines).
//! Expected values match `dash`/`bash` where they agree.

use std::process::Command;

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

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

#[test]
fn semicolon_runs_both_commands() {
    let r = run_c("echo a; echo b");
    assert_eq!(r.stdout, "a\nb\n");
    assert_eq!(r.code, 0);
}

#[test]
fn list_continues_past_a_failure() {
    // Unlike `&&`, a `;` (or newline) does not short-circuit on failure.
    let r = run_c("false; echo after");
    assert_eq!(r.stdout, "after\n");
    assert_eq!(r.code, 0, "status is that of the last command");
}

#[test]
fn list_status_is_the_last_command() {
    assert_eq!(run_c("true; false").code, 1);
    assert_eq!(run_c("false; true").code, 0);
}

#[test]
fn or_list_short_circuits() {
    // false || X : X runs.
    let r = run_c("false || echo rescued");
    assert_eq!(r.stdout, "rescued\n");
    assert_eq!(r.code, 0);

    // true || X : X does not run.
    let r = run_c("true || echo NOPE");
    assert_eq!(r.stdout, "");
    assert_eq!(r.code, 0);
}

#[test]
fn and_or_chain_is_left_associative() {
    // (false && echo A) || echo B : A skipped, B runs.
    let r = run_c("false && echo A || echo B");
    assert_eq!(r.stdout, "B\n");
    assert_eq!(r.code, 0);
}

#[test]
fn ampersand_separates_commands() {
    // `&` runs synchronously in Phase 2 (real background is Phase 7) but still
    // acts as a command separator.
    let r = run_c("echo one & echo two");
    assert_eq!(r.stdout, "one\ntwo\n");
    assert_eq!(r.code, 0);
}

#[test]
fn a_syntax_error_exits_2() {
    let r = run_c("echo a ;; echo b");
    assert_eq!(r.code, 2);
    assert_eq!(r.stdout, "");
    assert!(
        r.stderr.contains("syntax error"),
        "stderr was: {:?}",
        r.stderr
    );
}

#[test]
fn multi_stage_pipeline_is_deferred_cleanly() {
    // Phase 2 boundary: parses, but the executor refuses rather than panicking.
    // Real pipelines arrive in Phase 3.
    let r = run_c("echo a | cat");
    assert_eq!(r.stdout, "");
    assert!(
        r.stderr.contains("not yet supported"),
        "stderr was: {:?}",
        r.stderr
    );
    assert_ne!(r.code, 0);
}
