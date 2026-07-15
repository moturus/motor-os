//! Phase 6 golden tests: shell options, invocation, startup files, prompts.
//!
//! Every expectation here was cross-checked against `dash` on the Linux host
//! (status *and* stdout), except where a comment marks a deliberate divergence
//! — `-o pipefail` and `-h`, which dash lacks, and the `$-` letter order, which
//! POSIX leaves unspecified. Diagnostics on stderr are matched loosely, since
//! their wording carries the shell's own name.

use std::io::Write;
use std::process::{Command, Stdio};

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Run `rush <args…>` with `stdin` fed in, from a clean environment.
fn run_args(args: &[&str], stdin: &str) -> Run {
    let mut child = Command::new(RUSH)
        .args(args)
        // Start from a clean slate so host env vars (PS1, ENV, …) can't leak in.
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rush");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .expect("failed to write stdin");
    let out = child.wait_with_output().expect("failed to wait for rush");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn run_c(script: &str) -> Run {
    run_args(&["-c", script], "")
}

fn out(script: &str) -> String {
    run_c(script).stdout
}

/// A unique temp path per test, cleaned up by the caller.
fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rush_phase6_{}_{}", std::process::id(), tag))
}

// ---- set -e (errexit) -------------------------------------------------------

#[test]
fn errexit_exits_on_a_failing_command() {
    let run = run_c("set -e; false; echo done");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, 1);
}

#[test]
fn errexit_ignores_a_failure_in_a_condition_context() {
    // POSIX §2.8.1: -e does not apply to a command whose value is being tested —
    // an `if`/`while` condition, a non-final `&&`/`||` operand, or a `!` pipeline.
    for script in [
        "set -e; false && echo x; echo done",
        "set -e; ! true; echo done",
        "set -e; if false; then :; fi; echo done",
        "set -e; while false; do :; done; echo done",
        "set -e; until true; do :; done; echo done",
        "set -e; false || true; echo done",
    ] {
        let run = run_c(script);
        assert_eq!(run.stdout, "done\n", "{script}");
        assert_eq!(run.code, 0, "{script}");
    }
}

#[test]
fn errexit_suppression_reaches_inside_a_compound_condition() {
    // The suppression is a context, not a single-command exemption: the `false`
    // nested inside these still must not exit the shell.
    for script in [
        "set -e; ! { false; }; echo done",
        "set -e; if { false; }; then :; fi; echo done",
        "set -e; { true; false; } && echo x; echo done",
        "set -e; f() { if false; then :; fi; }; f; echo done",
    ] {
        let run = run_c(script);
        assert_eq!(run.stdout, "done\n", "{script}");
        assert_eq!(run.code, 0, "{script}");
    }
}

#[test]
fn errexit_fires_on_the_last_command_of_an_and_or_list() {
    for script in ["set -e; true && false; echo done", "set -e; false || false; echo done"] {
        let run = run_c(script);
        assert_eq!(run.stdout, "", "{script}");
        assert_eq!(run.code, 1, "{script}");
    }
}

#[test]
fn errexit_fires_from_inside_compound_commands_and_functions() {
    for script in [
        "set -e; { false; }; echo done",
        "set -e; (false); echo done",
        "set -e; for i in 1; do false; done; echo done",
        "set -e; case x in x) false;; esac; echo done",
        "set -e; f() { false; echo NO; }; f; echo done",
        "set -e; f() { if false; then :; fi; false; }; f; echo done",
    ] {
        let run = run_c(script);
        assert_eq!(run.stdout, "", "{script}");
        assert_eq!(run.code, 1, "{script}");
    }
}

#[test]
fn errexit_uses_the_last_stage_of_a_pipeline() {
    assert_eq!(run_c("set -e; false | true; echo done").stdout, "done\n");
    assert_eq!(run_c("set -e; true | false; echo done").code, 1);
}

#[test]
fn errexit_and_command_substitution() {
    // An assignment's status is its last command substitution's, so this exits…
    let run = run_c("set -e; x=$(false); echo done");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, 1);
    // …but a substitution feeding a *successful* command does not: the failure
    // stays inside the substitution's subshell.
    let run = run_c("set -e; echo A$(false)B; echo done");
    assert_eq!(run.stdout, "AB\ndone\n");
    assert_eq!(run.code, 0);
}

#[test]
fn errexit_runs_the_exit_trap() {
    let run = run_c("trap 'echo EXITTRAP' EXIT; set -e; false; echo done");
    assert_eq!(run.stdout, "EXITTRAP\n");
    assert_eq!(run.code, 1);
}

#[test]
fn assignment_takes_the_status_of_its_command_substitution() {
    // POSIX §2.9.1, and the mechanism `set -e` above depends on.
    assert_eq!(out("x=$(false); echo $?"), "1\n");
    assert_eq!(out("x=$(true); echo $?"), "0\n");
    assert_eq!(out("x=plain; echo $?"), "0\n");
}

// ---- set -u (nounset) -------------------------------------------------------

#[test]
fn nounset_aborts_on_an_unset_parameter() {
    for script in [
        "set -u; echo $FOO; echo done",
        "set -u; echo ${FOO}; echo done",
        "set -u; echo ${#FOO}; echo done",
        "set -u; echo $1; echo done",
        "set -u; x=${FOO}; echo done",
        // Trimming does not give the unset case a meaning, so -u still fires.
        "set -u; echo ${FOO#a}; echo done",
        "set -u; echo ${FOO%a}; echo done",
    ] {
        let run = run_c(script);
        assert_eq!(run.stdout, "", "{script}");
        assert_eq!(run.code, 2, "{script}");
        assert!(run.stderr.contains("parameter not set"), "{script}: {}", run.stderr);
    }
}

#[test]
fn nounset_allows_what_posix_exempts() {
    // A modifier that handles "unset" suppresses the error; a *null* value is
    // not unset; and `$@`/`$*` with no positional parameters is fine.
    for (script, want) in [
        ("set -u; echo \"${FOO:-d}\"; echo done", "d\ndone\n"),
        ("set -u; echo ${FOO+set}; echo done", "\ndone\n"),
        ("set -u; echo ${FOO=assigned}; echo done", "assigned\ndone\n"),
        ("set -u; FOO=; echo $FOO; echo done", "\ndone\n"),
        ("set -u; echo $@; echo done", "\ndone\n"),
        ("set -u; echo $*; echo done", "\ndone\n"),
        // Arithmetic treats an unset variable as 0 rather than an error.
        ("set -u; echo $((FOO+1)); echo done", "1\ndone\n"),
    ] {
        let run = run_c(script);
        assert_eq!(run.stdout, want, "{script}");
        assert_eq!(run.code, 0, "{script}");
    }
}

#[test]
fn nounset_is_reported_but_survivable_when_interactive() {
    // An interactive shell reports and carries on where a script would abort.
    let run = run_args(&["--piped"], "set -u\necho $FOO\necho done\n");
    assert!(run.stdout.contains("done"), "{}", run.stdout);
    assert!(run.stderr.contains("parameter not set"), "{}", run.stderr);
}

#[test]
fn error_if_unset_modifier_aborts() {
    // `${x?}` — a Phase 3 limit (diagnose but continue) that Phase 6 closes by
    // routing it through the same fatal-error path as `set -u`.
    let run = run_c("echo ${FOO?}; echo done");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("parameter not set"), "{}", run.stderr);

    let run = run_c("echo ${FOO?custom msg}; echo done");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("custom msg"), "{}", run.stderr);

    // dash distinguishes the `:?` wording, and a null value only trips `:?`.
    let run = run_c("echo ${FOO:?}; echo done");
    assert!(run.stderr.contains("parameter not set or null"), "{}", run.stderr);
    assert_eq!(run_c("FOO=; echo ${FOO?}; echo done").code, 0);
}

// ---- set -x (xtrace) --------------------------------------------------------

#[test]
fn xtrace_writes_expanded_commands_to_stderr() {
    let run = run_c("set -x; echo \"a b\"");
    assert_eq!(run.stdout, "a b\n");
    // Words are traced expanded and unquoted, as dash does.
    assert_eq!(run.stderr, "+ echo a b\n");
}

#[test]
fn xtrace_covers_assignments_pipelines_and_loop_bodies() {
    assert_eq!(run_c("set -x; a=1 b=2").stderr, "+ a=1 b=2\n");
    assert_eq!(run_c("set -x; a=1 echo hi").stderr, "+ a=1 echo hi\n");
    assert_eq!(run_c("set -x; echo a | cat").stderr, "+ echo a\n+ cat\n");
    assert_eq!(
        run_c("set -x; for i in 1 2; do echo $i; done").stderr,
        "+ echo 1\n+ echo 2\n"
    );
    assert_eq!(run_c("set -x; if true; then echo y; fi").stderr, "+ true\n+ echo y\n");
}

#[test]
fn xtrace_uses_ps4() {
    let run = run_c("PS4='TRACE> '; set -x; echo hi");
    assert_eq!(run.stderr, "TRACE> echo hi\n");
    // PS4 is expanded, not printed literally.
    let run = run_c("V=9; PS4='[$V] '; set -x; echo hi");
    assert_eq!(run.stderr, "[9] echo hi\n");
}

#[test]
fn xtrace_can_be_turned_off() {
    // `set +x` is itself traced — it is still an xtrace shell as it runs — but
    // nothing after it is. (dash behaves identically.)
    assert_eq!(run_c("set -x; set +x; echo hi").stderr, "+ set +x\n");
    assert_eq!(run_c("set +x; echo hi").stderr, "");
}

// ---- set -f (noglob), -C (noclobber), -a (allexport), -n (noexec) -----------

#[test]
fn noglob_disables_pathname_expansion() {
    let run = run_c("set -f; echo /*");
    assert_eq!(run.stdout, "/*\n");
    assert_eq!(run_c("set -f; set +f; echo $-").stdout, "\n");
}

#[test]
fn noclobber_protects_existing_files() {
    let path = temp_path("noclobber");
    let p = path.display();
    std::fs::write(&path, "original\n").unwrap();

    // `>` on an existing regular file fails (status 2, as in dash) and leaves it.
    let run = run_c(&format!("set -C; echo new > {p}"));
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("File exists"), "{}", run.stderr);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "original\n");

    // `>|` overrides noclobber.
    assert_eq!(run_c(&format!("set -C; echo new >| {p}")).code, 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\n");

    // `>>` appends, and a non-existent target is created.
    assert_eq!(run_c(&format!("set -C; echo more >> {p}")).code, 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new\nmore\n");

    std::fs::remove_file(&path).unwrap();
    assert_eq!(run_c(&format!("set -C; echo fresh > {p}")).code, 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh\n");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn noclobber_exempts_non_regular_files() {
    // POSIX only protects existing *regular* files, so `> /dev/null` still works.
    let run = run_c("set -C; echo x > /dev/null && echo ok");
    assert_eq!(run.stdout, "ok\n");
}

#[test]
fn allexport_exports_every_assignment() {
    let script = format!("set -a; FOO=bar; {RUSH} -c 'echo got=$FOO'");
    assert_eq!(out(&script), "got=bar\n");
    // …and only while it is on.
    let script = format!("set -a; FOO=bar; set +a; BAZ=qux; {RUSH} -c 'echo [$FOO][$BAZ]'");
    assert_eq!(out(&script), "[bar][]\n");
}

#[test]
fn noexec_parses_without_executing() {
    let run = run_c("set -n; echo hi; echo there");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, 0);
}

#[test]
fn noexec_is_ignored_when_interactive() {
    // Otherwise a typo would wedge the session: `set +n` could never run.
    let run = run_args(&["--piped"], "set -n\necho still-running\n");
    assert!(run.stdout.contains("still-running"), "{}", run.stdout);
}

// ---- set -o pipefail --------------------------------------------------------

#[test]
fn pipefail_reports_the_last_failing_stage() {
    // A rush extension over dash: POSIX.1-2024 added `pipefail`, dash has none.
    assert_eq!(run_c("false | true").code, 0);
    assert_eq!(run_c("set -o pipefail; false | true").code, 1);
    assert_eq!(run_c("set -o pipefail; true | true").code, 0);
    assert_eq!(run_c("set -o pipefail; set +o pipefail; false | true").code, 0);
    // The *last* failing stage wins, not the first.
    assert_eq!(run_c("set -o pipefail; sh -c 'exit 3' | sh -c 'exit 4'").code, 4);
    assert_eq!(run_c("set -o pipefail; sh -c 'exit 3' | true").code, 3);
}

// ---- $- and the set -o listings --------------------------------------------

#[test]
fn dollar_dash_reports_the_enabled_options() {
    assert_eq!(out("echo $-"), "\n");
    assert_eq!(out("set -e; echo $-"), "e\n");
    assert_eq!(out("set -f; echo $-"), "f\n");
    // Canonical table order — dash prints "ufe" here; POSIX leaves order open.
    assert_eq!(out("set -efu; echo $-"), "efu\n");
    assert_eq!(out("set -efu; set +f; echo $-"), "eu\n");
    // `pipefail` has no option letter, so it never appears.
    assert_eq!(out("set -o pipefail; echo $-"), "\n");
}

#[test]
fn dollar_dash_reports_invocation_options() {
    assert_eq!(run_args(&["-e", "-c", "echo $-"], "").stdout, "e\n");
    assert_eq!(run_args(&["-ec", "echo $-"], "").stdout, "e\n");
    assert_eq!(run_args(&["-o", "noglob", "-c", "echo $-"], "").stdout, "f\n");
    // An interactive stdin shell reports both `s` and `i`.
    let run = run_args(&["--piped"], "echo [$-]\n");
    assert!(run.stdout.contains("[is]"), "{}", run.stdout);
}

#[test]
fn set_o_lists_options() {
    let run = run_c("set -e; set -o");
    assert!(run.stdout.starts_with("Current option settings\n"), "{}", run.stdout);
    assert!(run.stdout.contains("errexit         on\n"), "{}", run.stdout);
    assert!(run.stdout.contains("noglob          off\n"), "{}", run.stdout);
}

#[test]
fn set_plus_o_lists_reinputtable_options() {
    let run = run_c("set -e; set +o");
    assert!(run.stdout.contains("set -o errexit\n"), "{}", run.stdout);
    assert!(run.stdout.contains("set +o noglob\n"), "{}", run.stdout);
}

#[test]
fn set_o_accepts_long_names() {
    assert_eq!(out("set -o errexit; echo $-"), "e\n");
    assert_eq!(out("set -o noglob; set +o noglob; echo $-"), "\n");
}

#[test]
fn set_rejects_an_unknown_option_fatally() {
    // A special builtin's usage error aborts a non-interactive shell.
    let run = run_c("set -Q; echo done");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, 2);
    let run = run_c("set -o bogus; echo done");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, 2);
}

#[test]
fn set_options_do_not_disturb_positional_parameters() {
    // Only operands (or a bare `--`) touch them.
    assert_eq!(run_args(&["-c", "set -e; echo $#", "N", "a", "b"], "").stdout, "2\n");
    assert_eq!(run_args(&["-c", "set --; echo $#", "N", "a", "b"], "").stdout, "0\n");
    assert_eq!(out("set -- x y z; echo $# $1 $3"), "3 x z\n");
}

#[test]
fn subshell_option_changes_do_not_leak() {
    assert_eq!(out("(set -f); echo [$-]"), "[]\n");
    assert_eq!(out("x=$(set -f; echo hi); echo $x [$-]"), "hi []\n");
}

// ---- invocation -------------------------------------------------------------

#[test]
fn dash_c_sets_positional_parameters_from_operands() {
    // The headline break from rush's old parsing, which joined the operands into
    // the command string: `rush -c 'echo $1' NAME hello` printed "$1 NAME hello".
    assert_eq!(run_args(&["-c", "echo $1", "NAME", "hello"], "").stdout, "hello\n");
    assert_eq!(run_args(&["-c", "echo $0 $1 $2", "NAME", "a", "b"], "").stdout, "NAME a b\n");
    assert_eq!(run_args(&["-c", "echo $#", "NAME", "a", "b"], "").stdout, "2\n");
    // With no `name` operand, `$0` stays the shell's own name.
    assert!(run_args(&["-c", "echo $0"], "").stdout.contains("rush"));
}

#[test]
fn dash_c_accepts_a_leading_double_dash() {
    // The form libc's system()/popen() emit — `--` ends the options, and the
    // command string is the operand after it.
    assert_eq!(run_args(&["-c", "--", "echo hi"], "").stdout, "hi\n");
    assert_eq!(run_args(&["-c", "echo hi"], "").stdout, "hi\n");
}

#[test]
fn options_may_be_clustered_and_negated() {
    assert_eq!(run_args(&["-xc", "echo hi"], "").stderr, "+ echo hi\n");
    assert_eq!(run_args(&["-cx", "echo hi"], "").stderr, "+ echo hi\n");
    assert_eq!(run_args(&["+x", "-c", "echo hi"], "").stdout, "hi\n");
}

#[test]
fn script_operands_set_positional_parameters() {
    let path = temp_path("script_args.sh");
    std::fs::write(&path, "echo \"$0|$1|$#\"\n").unwrap();
    let p = path.display().to_string();
    let run = run_args(&[&p, "WORLD", "x"], "");
    assert_eq!(run.stdout, format!("{p}|WORLD|2\n"));
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn stdin_mode_reads_the_script_from_stdin() {
    // `-s`, explicitly and by default (no operands).
    assert_eq!(run_args(&["-s", "ARG1"], "echo \"[$1]\"\n").stdout, "[ARG1]\n");
    assert_eq!(run_args(&[], "echo from-stdin\n").stdout, "from-stdin\n");
}

#[test]
fn a_var_assignment_operand_names_a_file() {
    // The old parser treated `rush FOO=bar` as a *command*; POSIX says it names
    // a script file, so this must fail to open it.
    let run = run_args(&["FOO=bar"], "");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("FOO=bar"), "{}", run.stderr);
}

#[test]
fn an_unreadable_script_operand_exits_2() {
    let run = run_args(&["/nonexistent/script.sh"], "");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("cannot open"), "{}", run.stderr);
}

#[test]
fn an_illegal_option_is_a_usage_error() {
    for args in [vec!["-z"], vec!["--version"], vec!["-o", "bogus", "-c", "echo hi"]] {
        let run = run_args(&args, "");
        assert_eq!(run.code, 2, "{args:?}");
        assert!(run.stderr.contains("illegal option"), "{args:?}: {}", run.stderr);
    }
    // `-c` with no command string.
    assert_eq!(run_args(&["-c"], "").code, 2);
}

#[test]
fn dash_h_is_the_hashall_option_not_usage() {
    // Deliberate: POSIX reserves `-h` for command hashing, so rush's old
    // "-h prints usage" is gone. rush accepts it as a no-op (dash rejects it).
    let run = run_args(&["-h", "-c", "echo hi"], "");
    assert_eq!(run.stdout, "hi\n");
    assert_eq!(run.code, 0);
}

// ---- startup files and prompts ---------------------------------------------

#[test]
fn interactive_shell_sources_env() {
    let path = temp_path("env.sh");
    std::fs::write(&path, "echo SOURCED; FROM_ENV=yes\n").unwrap();

    let mut child = Command::new(RUSH)
        .arg("--piped")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("ENV", path.display().to_string())
        .env("PS1", "") // keep the prompt out of the captured stdout
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"echo got=$FROM_ENV\nexit\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SOURCED"), "{stdout}");
    assert!(stdout.contains("got=yes"), "{stdout}");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn non_interactive_shell_ignores_env() {
    let path = temp_path("env_noninteractive.sh");
    std::fs::write(&path, "echo SHOULD_NOT_RUN\n").unwrap();
    let out = Command::new(RUSH)
        .args(["-c", "echo body"])
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("ENV", path.display().to_string())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "body\n");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_missing_env_file_is_not_an_error() {
    let run = run_args(&["--piped"], "echo alive\nexit\n");
    assert!(run.stdout.contains("alive"), "{}", run.stdout);
}

#[test]
fn prompt_variables_have_defaults_and_are_expandable() {
    // PS2/PS4 match dash; PS1 is rush's colored prompt (a documented divergence).
    assert_eq!(out("echo \"[$PS2]\""), "[> ]\n");
    assert_eq!(out("echo \"[$PS4]\""), "[+ ]\n");
    assert!(out("echo \"$PS1\"").contains("rush"));
    // An inherited value wins over the default.
    let out = Command::new(RUSH)
        .args(["-c", "echo \"[$PS2]\""])
        .env("PS2", "inherited> ")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[inherited> ]\n");
}

#[test]
fn allexport_does_not_export_the_shells_own_defaults() {
    // The prompt defaults are the shell's own, not a user assignment, so `set -a`
    // must leave them unexported — as in dash. (Asked via `export -p` rather
    // than a child's `$PS1`: a child would just set its own defaults again.)
    let run = run_args(&["-a", "-c", "export -p"], "");
    assert!(!run.stdout.contains("PS1"), "{}", run.stdout);
    assert!(!run.stdout.contains("PS2"), "{}", run.stdout);
    // …while a real assignment under `-a` still exports.
    let run = run_args(&["-a", "-c", "FOO=bar; export -p"], "");
    assert!(run.stdout.contains("export FOO='bar'"), "{}", run.stdout);
}

#[test]
fn ps1_drives_the_interactive_prompt() {
    let run = run_args(&["--piped"], "PS1='myprompt$ '\necho hi\n");
    assert!(run.stdout.contains("myprompt$ "), "{}", run.stdout);
}

#[test]
fn ps2_drives_the_continuation_prompt() {
    let run = run_args(&["--piped"], "PS1=\nPS2='cont> '\nfor i in 1 2\ndo\necho $i\ndone\n");
    assert!(run.stdout.contains("cont> "), "{}", run.stdout);
    assert!(run.stdout.contains('1') && run.stdout.contains('2'), "{}", run.stdout);
}

#[test]
fn pwd_is_maintained() {
    // POSIX requires the shell to set PWD at startup and keep it through `cd`.
    let run = run_c("echo \"$PWD\"");
    assert_eq!(run.stdout.trim_end(), std::env::current_dir().unwrap().to_str().unwrap());
    assert_eq!(out("cd /; echo $PWD"), "/\n");
    assert_eq!(out("cd /tmp; cd /; echo $OLDPWD"), "/tmp\n");
}

// ---- I/O errors -------------------------------------------------------------

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "needs /dev/full")]
fn a_builtin_reports_a_failed_write() {
    // A builtin whose output cannot be written has not succeeded. Losing the
    // output *and* reporting success is what let a broken `>>` on Motor OS
    // destroy data invisibly. /dev/full accepts opens and fails every write, so
    // it reproduces that here. dash prints the same and exits 1.
    for cmd in ["echo hi", "printf x", "pwd"] {
        let run = run_c(&format!("{cmd} > /dev/full"));
        assert_eq!(run.code, 1, "{cmd}");
        assert!(run.stderr.contains("I/O error"), "{cmd}: {}", run.stderr);
    }
    // A working redirection is of course still silent and successful.
    let run = run_c("echo hi > /dev/null");
    assert_eq!(run.code, 0);
    assert_eq!(run.stderr, "");
}

#[test]
fn append_redirection_appends() {
    // Guards the `>>` path end-to-end. This passed on Linux while silently
    // losing every append on Motor OS, where `OpenOptions::append(true)` yielded
    // a non-writable file (fixed in rt.vdso's file_open) and the failed writes
    // went unreported (fixed above) — so assert the *contents*, not the status.
    let path = temp_path("append");
    let p = path.display();
    let run = run_c(&format!("echo one > {p}; echo two >> {p}; printf 'three\\n' >> {p}"));
    assert_eq!(run.code, 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\nthree\n");
    // `>>` also creates a missing file.
    std::fs::remove_file(&path).unwrap();
    run_c(&format!("echo fresh >> {p}"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "fresh\n");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn verbose_echoes_input() {
    // `-v` echoes what the shell reads. rush reads a script whole (no incremental
    // reader), so it echoes it in one piece — dash interleaves line by line.
    let path = temp_path("verbose.sh");
    std::fs::write(&path, "echo one\necho two\n").unwrap();
    let run = run_args(&["-v", &path.display().to_string()], "");
    assert_eq!(run.stdout, "one\ntwo\n");
    assert_eq!(run.stderr, "echo one\necho two\n");
    std::fs::remove_file(&path).unwrap();

    // Like dash, a `-c` string is not echoed: it was never "read" as input.
    assert_eq!(run_c("set -v; echo hi").stderr, "");
}
