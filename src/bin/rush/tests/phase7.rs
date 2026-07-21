//! Phase 7 golden tests: signals, traps, background jobs and `wait` (M3).
//!
//! Every expectation here was cross-checked against `dash` on the Linux host
//! (status *and* stdout), except where a comment marks a deliberate divergence.
//! Diagnostics on stderr are matched loosely, since their wording carries the
//! shell's own name.
//!
//! These run on the Unix host, which — unlike Motor OS — can actually deliver a
//! signal, so they exercise the real handler path. What Motor OS does with the
//! same code is covered by the VM self-check (`phase7-vmcheck.sh`) and spelled
//! out in `rush-to-sh-plan.md` §7: traps stay stored but only `^C` can fire one,
//! and `kill` can only terminate.

#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_c(script: &str) -> Run {
    let out = Command::new(RUSH)
        .args(["-c", script])
        // Start from a clean slate so host env vars (PS1, ENV, …) can't leak in.
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("failed to run rush");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: shell_status(out.status),
    }
}

/// The status a shell would report for `rush` itself — `128 + signo` when a
/// signal killed it, which is exactly what these tests assert when a default
/// signal action is expected to take the shell down.
fn shell_status(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

fn out(script: &str) -> String {
    run_c(script).stdout
}

fn code(script: &str) -> i32 {
    run_c(script).code
}

// ---- background execution ---------------------------------------------------

#[test]
fn background_runs_concurrently() {
    // The whole point of `&`: two 0.4s sleeps must overlap. A generous ceiling —
    // the failure this guards against is serialization, which would take 0.8s+.
    let start = std::time::Instant::now();
    assert_eq!(out("sleep 0.4 & sleep 0.4 & wait; echo done"), "done\n");
    assert!(
        start.elapsed() < std::time::Duration::from_millis(700),
        "background jobs did not overlap: {:?}",
        start.elapsed()
    );
}

#[test]
fn async_list_status_is_zero() {
    // POSIX §2.9.3: the shell does not wait, so the status is 0 even though the
    // command itself fails.
    assert_eq!(out("sh -c 'exit 3' & echo st=$?; wait"), "st=0\n");
}

#[test]
fn bang_pid_is_unset_before_any_background() {
    assert_eq!(out(r#"echo "[$!]""#), "[]\n");
}

#[test]
fn bang_pid_names_the_last_background_job() {
    assert_eq!(out("sleep 0.05 & p=$!; wait $p; echo ok"), "ok\n");
}

#[test]
fn background_stdin_is_empty_not_the_terminal() {
    // POSIX §2.9.3: an asynchronous job's stdin is /dev/null, so it cannot steal
    // input meant for the shell. `read` therefore hits EOF at once.
    assert_eq!(out("sh -c 'read x; echo \"got=[$x]\"' & wait"), "got=[]\n");
}

// ---- wait -------------------------------------------------------------------

#[test]
fn wait_reports_the_jobs_status() {
    assert_eq!(out("sh -c 'exit 7' & wait $!; echo st=$?"), "st=7\n");
}

#[test]
fn wait_with_no_args_is_zero() {
    assert_eq!(out("sh -c 'exit 3' & wait; echo st=$?"), "st=0\n");
}

#[test]
fn wait_for_unknown_pid_is_127() {
    assert_eq!(out("wait 999999; echo st=$?"), "st=127\n");
}

#[test]
fn wait_for_a_non_number_is_a_usage_error() {
    let run = run_c("wait abc");
    assert_eq!(run.code, 2);
    assert!(!run.stderr.is_empty());
}

#[test]
fn wait_remembers_a_finished_jobs_status() {
    // dash reports the same status to repeated `wait`s; only `jobs` forgets.
    assert_eq!(
        out("sh -c 'exit 4' & wait $!; echo a=$?; wait $!; echo b=$?"),
        "a=4\nb=4\n"
    );
}

#[test]
fn wait_by_job_spec() {
    assert_eq!(out("sh -c 'exit 5' & wait %1; echo st=$?"), "st=5\n");
}

// ---- jobs -------------------------------------------------------------------

#[test]
fn jobs_lists_a_running_job() {
    // dash's format, with the command text rush keeps and dash (non-interactive)
    // leaves blank — a documented divergence.
    let stdout = out("sleep 0.3 & jobs; wait");
    assert_eq!(stdout, "[1] + Running                    sleep 0.3\n");
}

#[test]
fn jobs_reports_a_finished_job_then_forgets_it() {
    // dash's rule: `jobs` reports a Done job once and discards it, so the second
    // `jobs` is silent and a later `wait` no longer knows the pid (127).
    assert_eq!(
        out("sh -c 'exit 3' & wait; jobs; echo ---; jobs; wait $!; echo st=$?"),
        "[1] + Done(3)                    sh -c exit 3\n---\nst=127\n"
    );
}

#[test]
fn jobs_marks_the_two_most_recent() {
    // Newest first, `+` then `-` — as dash prints them.
    let stdout = out("sleep 0.3 & sleep 0.3 & jobs; wait");
    let markers: Vec<&str> = stdout.lines().map(|l| &l[..5]).collect();
    assert_eq!(markers, vec!["[2] +", "[1] -"]);
}

#[test]
fn jobs_p_lists_pids_only() {
    assert_eq!(out("sleep 0.05 & jobs -p; wait").lines().count(), 1);
}

// ---- traps ------------------------------------------------------------------

#[test]
fn trap_runs_on_a_signal() {
    assert_eq!(
        out("trap 'echo caught' INT; kill -INT $$; echo after"),
        "caught\nafter\n"
    );
}

#[test]
fn trap_lists_canonical_names() {
    // A number or a `SIG`-prefixed name is stored under the bare name, and the
    // listing is re-readable input (dash prints exactly this).
    assert_eq!(
        out("trap 'echo hi' 2 SIGUSR1; trap"),
        "trap -- 'echo hi' INT\ntrap -- 'echo hi' USR1\n"
    );
}

#[test]
fn trap_empty_action_ignores_the_signal() {
    assert_eq!(
        out("trap '' INT; kill -INT $$; echo survived"),
        "survived\n"
    );
}

#[test]
fn trap_dash_restores_the_default_action() {
    // The default action for INT kills the shell: 128 + 2.
    let run = run_c("trap 'echo t' INT; trap - INT; kill -INT $$; echo notreached");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, 130);
}

#[test]
fn trap_on_an_unknown_condition_is_an_error() {
    let run = run_c("trap 'echo x' NOPE");
    assert_eq!(run.code, 1);
    assert!(run.stderr.contains("bad trap"));
}

#[test]
fn trap_on_an_uncatchable_signal_is_accepted_and_inert() {
    // No one may catch KILL; dash accepts the trap silently all the same.
    assert_eq!(code("trap 'echo k' KILL"), 0);
}

#[test]
fn trap_preserves_the_status_around_the_action() {
    // The action sees `$?` as it was, and cannot change what the next command
    // sees (here: the `kill`'s own success).
    assert_eq!(
        out("trap 'echo in=$?' USR1; false; kill -USR1 $$; echo after=$?"),
        "in=0\nafter=0\n"
    );
}

// ---- the EXIT trap ----------------------------------------------------------

#[test]
fn exit_trap_runs_and_keeps_the_exit_status() {
    let run = run_c("trap 'echo bye' EXIT; exit 5");
    assert_eq!(run.stdout, "bye\n");
    assert_eq!(run.code, 5);
}

#[test]
fn exit_trap_sees_the_last_status_and_cannot_change_it() {
    let run = run_c("trap 'echo bye:$?' EXIT; false");
    assert_eq!(run.stdout, "bye:1\n");
    assert_eq!(run.code, 1);
}

#[test]
fn exit_trap_set_in_a_subshell_fires_at_its_boundary() {
    assert_eq!(
        out("(trap 'echo sub' EXIT; true); echo after"),
        "sub\nafter\n"
    );
}

#[test]
fn exit_trap_inherited_by_a_subshell_stays_the_parents() {
    // The subshell gets a copy, but running it is the parent's job — so this
    // prints `after` first, then the trap at shell exit.
    assert_eq!(out("trap 'echo E' EXIT; (true); echo after"), "after\nE\n");
}

#[test]
fn subshell_exit_trap_shadows_the_parents_without_consuming_it() {
    assert_eq!(
        out("trap 'echo E' EXIT; (trap 'echo S' EXIT; true); echo mid"),
        "S\nmid\nE\n"
    );
}

#[test]
fn exit_trap_output_inside_a_command_substitution_is_captured() {
    assert_eq!(
        out("x=$(trap 'echo t' EXIT; echo v); echo \"x=[$x]\""),
        "x=[v\nt]\n"
    );
}

#[test]
fn exit_trap_fires_once_when_the_shell_exits() {
    assert_eq!(out("trap 'echo once' EXIT; true"), "once\n");
}

// ---- signals interrupting a wait -------------------------------------------

#[test]
fn a_trap_interrupts_a_foreground_command() {
    // The killer runs asynchronously and signals the shell 0.2s into a 3s sleep;
    // the trap must run then, not when the sleep finishes.
    //
    // The redirections on the sleep are load-bearing: rush exits from the trap
    // while that child is still running, and an orphan holding the shell's
    // stdout/stderr keeps this harness's capture pipes open until it finishes —
    // so without them the elapsed time below measures the orphan, not rush.
    // (dash leaves the same orphan, and takes the same 3s when piped.)
    let start = std::time::Instant::now();
    let run = run_c(
        "trap 'echo term; exit 9' TERM; sh -c \"sleep 0.2; kill -TERM $$\" & sleep 3 >/dev/null 2>&1; echo notreached",
    );
    assert_eq!(run.stdout, "term\n");
    assert_eq!(run.code, 9);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "the trap waited for the foreground command: {:?}",
        start.elapsed()
    );
}

#[test]
fn wait_interrupted_by_a_trap_returns_128_plus_signo() {
    // POSIX §2.14 `wait`; dash reports 138 for USR1 (128 + 10).
    assert_eq!(
        out(
            "trap 'echo trapped' USR1; sleep 2 & sh -c \"sleep 0.2; kill -USR1 $$\" & wait; echo st=$?"
        ),
        "trapped\nst=138\n"
    );
}

// ---- kill -------------------------------------------------------------------

#[test]
fn kill_zero_checks_that_a_process_exists() {
    assert_eq!(out("kill -0 $$; echo st=$?"), "st=0\n");
}

#[test]
fn kill_reports_an_unknown_pid() {
    let run = run_c("kill 999999");
    assert_eq!(run.code, 1);
    assert!(run.stderr.contains("no such process"));
}

#[test]
fn kill_accepts_a_job_spec() {
    assert_eq!(out("sleep 5 & kill %1; wait %1; echo st=$?"), "st=143\n");
}

#[test]
fn kill_accepts_signal_names_and_numbers() {
    for spec in ["-9", "-KILL", "-SIGKILL", "-s KILL", "-s 9"] {
        let script = format!("sleep 5 & kill {spec} $!; wait $!; echo st=$?");
        assert_eq!(out(&script), "st=137\n", "kill {spec}");
    }
}

#[test]
fn kill_rejects_an_unknown_signal() {
    let run = run_c("kill -NOPE 1");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("invalid signal"));
}

#[test]
fn kill_l_lists_signal_names() {
    let stdout = out("kill -l");
    assert!(stdout.contains("INT"), "{stdout}");
    assert!(stdout.contains("TERM"), "{stdout}");
    // Names only: `EXIT` is a trap condition, not a signal one can send.
    assert!(!stdout.contains("EXIT"), "{stdout}");
}

#[test]
fn a_signal_killed_child_reports_128_plus_signo() {
    // POSIX §2.8.2 — dash also reports 137 (it additionally prints `Killed`,
    // which rush does not: a documented divergence).
    assert_eq!(out("sh -c 'kill -9 $$'; echo st=$?"), "st=137\n");
}

// ---- fg / bg ----------------------------------------------------------------

#[test]
fn fg_waits_for_a_job_in_the_foreground() {
    // A documented divergence: dash refuses `fg` without job control, but with
    // no suspend/resume to offer, waiting is the half of `fg` that still means
    // something. It echoes the command first, as job control shells do.
    assert_eq!(
        out("sh -c 'exit 6' & fg; echo st=$?"),
        "sh -c exit 6\nst=6\n"
    );
}

#[test]
fn fg_on_an_unknown_job_fails() {
    let run = run_c("fg %9");
    assert_eq!(run.code, 1);
    assert!(run.stderr.contains("no such job"));
}

#[test]
fn bg_always_fails_because_nothing_can_be_stopped() {
    // There is no `^Z` and no SIGTSTP on either platform (§0.1), so no job is
    // ever in the state `bg` exists to leave. dash's `bg` fails here too.
    let run = run_c("sleep 0.05 & bg");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("no job control"));
}

// ---- backgrounding what cannot fork ----------------------------------------

#[test]
fn a_backgrounded_builtin_still_records_a_job() {
    // With no `fork`, a builtin cannot run concurrently: it runs in place and is
    // recorded as an already-finished job, so `$!` and `wait` still work.
    assert_eq!(out("echo hi & wait $!; echo st=$?"), "hi\nst=0\n");
}

#[test]
fn a_backgrounded_compound_command_runs_isolated() {
    // `&` on a compound command delivers the subshell's isolation (the variable
    // does not leak) even though it cannot deliver concurrency.
    assert_eq!(out("{ x=inner; } & wait; echo \"x=[$x]\""), "x=[]\n");
}

#[test]
fn an_interactive_shell_reaps_background_jobs_it_was_never_asked_to_wait_for() {
    // Nothing else reaps in an interactive session — `wait`/`jobs` might never be
    // run — so without a poll at the prompt every `&` leaked a zombie (and, on
    // Motor OS, its handle and pump threads) for the life of the shell.
    let mut child = Command::new(RUSH)
        .arg("--piped")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn rush");
    // Three quick jobs, a pause for them to die, then ask the OS what is left.
    // `ps --ppid <rush>` lists rush's children; a `Z` state is an unreaped one.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"sleep 0.05 &\nsleep 0.05 &\nsleep 0.05 &\nsleep 0.5\nps -o stat= --ppid $$\nexit\n")
        .expect("failed to write stdin");
    let out = child.wait_with_output().expect("failed to wait for rush");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let zombies = stdout.lines().filter(|l| l.trim_start().starts_with('Z')).count();
    assert_eq!(zombies, 0, "unreaped background jobs:\n{stdout}");
}

#[test]
fn a_missing_background_command_is_reported_and_waitable() {
    // dash forks before it discovers the command is missing, so `$!` is still
    // set and `wait` reports 127. rush records the same finished job.
    let run = run_c("no_such_command_xyz & wait $!; echo st=$?");
    assert_eq!(run.stdout, "st=127\n");
    assert!(run.stderr.contains("not found"));
}
