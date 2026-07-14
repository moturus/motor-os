//! Phase 5 golden tests (milestone M2: POSIX builtins).
//!
//! Each case runs `rush -c <script>` and asserts on stdout / exit status. The
//! expectations were cross-checked against `dash` on the Linux host; where rush
//! deliberately diverges (see the module-level notes in `src/builtins.rs`) the
//! test documents why.

use std::process::Command;

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

struct Run {
    stdout: String,
    code: i32,
}

fn run_c(script: &str) -> Run {
    let out = Command::new(RUSH)
        .arg("-c")
        .arg(script)
        // Start from a clean slate so host env vars don't mask the assertions.
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("failed to spawn rush");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn out(script: &str) -> String {
    run_c(script).stdout
}

// ---- export -----------------------------------------------------------------

#[test]
fn exported_var_reaches_child_but_bare_assignment_does_not() {
    let script = format!(
        "export EXPORTED=yes; LOCAL=no; {RUSH} -c 'echo exp=$EXPORTED local=$LOCAL'"
    );
    let run = run_c(&script);
    assert_eq!(run.stdout, "exp=yes local=\n");
    assert_eq!(run.code, 0);
}

#[test]
fn export_of_existing_shell_var_promotes_it() {
    let script = format!("VAR=promoted; export VAR; {RUSH} -c 'echo $VAR'");
    assert_eq!(run_c(&script).stdout, "promoted\n");
}

#[test]
fn export_p_lists_exports_in_reusable_form() {
    let run = run_c("export A=1; export B='x y'; export -p");
    assert!(run.stdout.contains("export A='1'\n"), "{}", run.stdout);
    assert!(run.stdout.contains("export B='x y'\n"), "{}", run.stdout);
    assert_eq!(run.code, 0);
}

#[test]
fn export_rejects_invalid_identifier_fatally() {
    // A bad variable name is a special-builtin usage error: fatal (exit 2), and
    // the shell stops (`echo after` never runs) — matching dash.
    let run = run_c("export 1bad=x; echo after");
    assert_eq!(run.code, 2);
    assert!(!run.stdout.contains("after"), "{}", run.stdout);
}

// ---- echo -------------------------------------------------------------------

#[test]
fn echo_basic_and_n() {
    assert_eq!(out("echo hello world"), "hello world\n");
    assert_eq!(out("echo -n hi; echo X"), "hiX\n");
}

#[test]
fn echo_interprets_escapes() {
    // dash's XSI echo always interprets backslash escapes.
    assert_eq!(out("echo 'a\\tb'"), "a\tb\n");
    assert_eq!(out("echo 'a\\nb'"), "a\nb\n");
    // `\c` stops output (and suppresses the trailing newline).
    assert_eq!(out("echo 'a\\cb'"), "a");
}

// ---- printf -----------------------------------------------------------------

#[test]
fn printf_conversions() {
    assert_eq!(out("printf '%s=%d\\n' x 42"), "x=42\n");
    assert_eq!(out("printf '%x %X %o\\n' 255 255 8"), "ff FF 10\n");
    assert_eq!(out("printf '100%%\\n'"), "100%\n");
    assert_eq!(out("printf '%b\\n' 'a\\tb'"), "a\tb\n");
}

#[test]
fn printf_width_precision_and_flags() {
    assert_eq!(out("printf '%5d|%-5d|%05d\\n' 7 7 7"), "    7|7    |00007\n");
    assert_eq!(out("printf '%+d %+d\\n' 5 -5"), "+5 -5\n");
    assert_eq!(out("printf '%.3s\\n' abcdef"), "abc\n");
}

#[test]
fn printf_recycles_format_over_extra_args() {
    assert_eq!(out("printf '[%s]' a b c"), "[a][b][c]");
    assert_eq!(out("printf '%s:%s\\n' a 1 b 2"), "a:1\nb:2\n");
    // Missing operands render as empty / zero.
    assert_eq!(out("printf '%s-%s\\n' only"), "only-\n");
}

#[test]
fn printf_number_bases() {
    assert_eq!(out("printf '%d\\n' 0xff"), "255\n");
    assert_eq!(out("printf '%d\\n' 010"), "8\n");
    // A leading quote yields the next character's code.
    assert_eq!(out("printf '%d\\n' '\"A'"), "65\n");
}

// ---- test / [ ---------------------------------------------------------------

#[test]
fn test_string_and_numeric() {
    assert_eq!(out("[ abc = abc ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ abc != abd ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ -z '' ] && echo y"), "y\n");
    assert_eq!(out("[ -n x ] && echo y"), "y\n");
    assert_eq!(out("[ 3 -lt 5 ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ 5 -ge 5 ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ 2 -lt 2 ] && echo y || echo n"), "n\n");
}

#[test]
fn test_negation_grouping_and_logic() {
    assert_eq!(out("[ ! -z x ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ \\( a = a \\) ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ 1 -eq 1 -a 2 -eq 2 ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ 1 -eq 2 -o 3 -eq 3 ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ ] && echo y || echo n"), "n\n");
    assert_eq!(out("[ x ] && echo y || echo n"), "y\n");
}

#[test]
fn test_bad_integer_is_error_status() {
    // Behavior (not the message) matches dash: `[` errors (status 2), so `||`
    // runs.
    assert_eq!(out("[ x -eq 1 ] && echo y || echo n"), "n\n");
}

#[test]
fn test_file_predicates() {
    assert_eq!(out("[ -e / ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ -d / ] && echo y || echo n"), "y\n");
    assert_eq!(out("[ -f /nonexistent_xyz ] && echo y || echo n"), "n\n");
}

// ---- read -------------------------------------------------------------------

#[test]
fn read_splits_on_ifs_with_remainder() {
    assert_eq!(out("echo 'a b c' | { read x y z; echo \"$x|$y|$z\"; }"), "a|b|c\n");
    // The last variable absorbs the remainder.
    assert_eq!(out("echo 'a b c d' | { read x y; echo \"$x|$y\"; }"), "a|b c d\n");
    // Custom IFS.
    assert_eq!(out("printf '1:2:3\\n' | { IFS=: read a b c; echo \"$a-$b-$c\"; }"), "1-2-3\n");
    // Fewer fields than vars leaves the tail empty.
    assert_eq!(out("echo a | { read x y z; echo \"$x|$y|$z\"; }"), "a||\n");
}

#[test]
fn read_raw_vs_backslash() {
    // `-r` keeps a backslash literal; plain `read` consumes it as an escape.
    assert_eq!(out("printf '%s\\n' 'a\\b' | { read -r x; printf '[%s]\\n' \"$x\"; }"), "[a\\b]\n");
    assert_eq!(out("printf '%s\\n' 'a\\b' | { read x; printf '[%s]\\n' \"$x\"; }"), "[ab]\n");
    // Without -r, a backslash-escaped space is literal (not a field split).
    assert_eq!(out("printf 'a\\\\ b c\\n' | { read x y; echo \"$x|$y\"; }"), "a b|c\n");
}

#[test]
fn while_read_loop_over_a_pipe() {
    // The defining M2 idiom: a `while read` loop consuming a pipe.
    assert_eq!(
        out("printf '1\\n2\\n3\\n' | while read n; do echo \"got $n\"; done"),
        "got 1\ngot 2\ngot 3\n"
    );
    assert_eq!(
        out("i=0; printf 'a\\nb\\nc\\n' | while read x; do i=$((i+1)); echo \"$i:$x\"; done"),
        "1:a\n2:b\n3:c\n"
    );
}

// ---- cd / pwd ---------------------------------------------------------------

#[test]
fn cd_pwd_and_oldpwd() {
    assert_eq!(out("cd /; pwd"), "/\n");
    // `cd -` returns to (and prints) the previous directory.
    assert_eq!(out("cd /; cd /tmp; cd - "), "/\n");
    assert_eq!(out("cd /tmp; cd /; echo $OLDPWD"), "/tmp\n");
}

// ---- set / shift ------------------------------------------------------------

#[test]
fn set_positional_parameters() {
    assert_eq!(out("set -- a b c; echo $# $1 $3"), "3 a c\n");
    assert_eq!(out("set -- a b; set --; echo $#"), "0\n");
    assert_eq!(out("set one two three; echo $2"), "two\n");
}

#[test]
fn shift_drops_positional_parameters() {
    assert_eq!(out("set -- a b c; shift; echo $# $1"), "2 b\n");
    assert_eq!(out("set -- a b c d; shift 2; echo $1"), "c\n");
}

#[test]
fn shift_past_end_is_fatal() {
    let run = run_c("set -- a; shift 5; echo after");
    assert_eq!(run.code, 2);
    assert!(!run.stdout.contains("after"), "{}", run.stdout);
}

// ---- unset ------------------------------------------------------------------

#[test]
fn unset_variable_and_function() {
    assert_eq!(out("x=5; unset x; echo \"[$x]\""), "[]\n");
    assert_eq!(out("f() { echo hi; }; unset -f f; type f 2>/dev/null; echo done"), "done\n");
}

#[test]
fn unset_readonly_is_fatal() {
    let run = run_c("readonly r=1; unset r; echo after");
    assert_eq!(run.code, 2);
    assert!(!run.stdout.contains("after"), "{}", run.stdout);
}

// ---- readonly ---------------------------------------------------------------

#[test]
fn readonly_prevents_reassignment_fatally() {
    // The assignment is rejected (X keeps its value) and the shell aborts.
    let run = run_c("readonly X=5; X=6; echo $X");
    assert_eq!(run.code, 2);
    assert!(!run.stdout.contains('6'), "{}", run.stdout);
}

#[test]
fn readonly_p_lists() {
    let run = run_c("readonly A=1; readonly -p");
    assert!(run.stdout.contains("readonly A='1'\n"), "{}", run.stdout);
}

// ---- getopts ----------------------------------------------------------------

#[test]
fn getopts_simple_flags() {
    // getopts does not shift; `$1` is still `-a` (OPTIND now points past the
    // options).
    assert_eq!(
        out("set -- -a -b foo; while getopts ab opt; do echo \"opt=$opt\"; done; echo rest=$1 idx=$OPTIND"),
        "opt=a\nopt=b\nrest=-a idx=3\n"
    );
}

#[test]
fn getopts_option_with_argument() {
    assert_eq!(
        out("set -- -o out.txt -v file; while getopts o:v opt; do case $opt in o) echo out=$OPTARG;; v) echo verbose;; esac; done"),
        "out=out.txt\nverbose\n"
    );
}

#[test]
fn getopts_combined_flags() {
    assert_eq!(out("set -- -ab; while getopts ab o; do echo $o; done"), "a\nb\n");
}

// ---- type / command ---------------------------------------------------------

#[test]
fn type_classifies_names() {
    assert_eq!(out("type echo"), "echo is a shell builtin\n");
    assert_eq!(out("type if"), "if is a shell keyword\n");
    assert_eq!(out("f(){ :; }; type f"), "f is a shell function\n");
}

#[test]
fn type_not_found_is_127() {
    let run = run_c("type nosuchcmd_zzz");
    assert_eq!(run.code, 127);
}

#[test]
fn command_v_and_bypass() {
    assert_eq!(out("command -v echo"), "echo\n");
    // `command` runs the builtin, bypassing a same-named function.
    assert_eq!(out("echo() { printf CUSTOM; }; command echo hi"), "hi\n");
    assert_eq!(run_c("command -v nosuchcmd_zzz").code, 127);
}

// ---- eval / . (source) ------------------------------------------------------

#[test]
fn eval_runs_in_current_shell() {
    assert_eq!(out("eval 'x=5; echo $x'"), "5\n");
    // eval builds a variable name dynamically.
    assert_eq!(out("n=x; eval \"$n=hello\"; echo $x"), "hello\n");
    assert_eq!(out("for v in A B C; do eval \"$v=1\"; done; echo \"$A$B$C\""), "111\n");
}

#[test]
fn dot_sources_a_file() {
    let script = "echo 'echo sourced; MYVAR=42' > /tmp/rush_p5_src.sh; \
                  . /tmp/rush_p5_src.sh; echo \"var=$MYVAR\"; rm -f /tmp/rush_p5_src.sh";
    assert_eq!(out(script), "sourced\nvar=42\n");
}

#[test]
fn dot_return_leaves_the_sourced_file() {
    let script = "printf 'echo one\\nreturn 3\\necho two\\n' > /tmp/rush_p5_ret.sh; \
                  . /tmp/rush_p5_ret.sh; echo \"rc=$?\"; rm -f /tmp/rush_p5_ret.sh";
    assert_eq!(out(script), "one\nrc=3\n");
}

// ---- : / true / false -------------------------------------------------------

#[test]
fn colon_true_false() {
    assert_eq!(out(": ; echo $?"), "0\n");
    assert_eq!(out("true; echo $?; false; echo $?"), "0\n1\n");
}

// ---- alias ------------------------------------------------------------------

#[test]
fn alias_defines_lists_and_expands() {
    // rush expands aliases at execution time (a documented divergence from
    // dash's parse-time behavior), so `ll` runs even in a `-c` string.
    assert_eq!(out("alias ll='echo LL'; ll"), "LL\n");
    assert_eq!(out("alias a=b; alias a"), "a='b'\n");
    assert_eq!(out("alias g='echo G'; unalias g; g 2>/dev/null; echo done"), "done\n");
}

// ---- trap -------------------------------------------------------------------

#[test]
fn trap_exit_fires_once() {
    assert_eq!(out("trap 'echo cleanup' EXIT; echo main"), "main\ncleanup\n");
    assert_eq!(out("trap 'echo bye' EXIT; exit 0"), "bye\n");
}

// ---- pipelines with builtins ------------------------------------------------

#[test]
fn builtins_in_pipelines() {
    assert_eq!(out("printf 'apple\\nbanana\\napricot\\n' | grep ^a | wc -l"), "2\n");
    assert_eq!(out("echo hi | cat"), "hi\n");
    assert_eq!(out("printf 'a\\nb\\nc\\n' | wc -l"), "3\n");
}

// ---- realistic scripting ----------------------------------------------------

#[test]
fn recursive_function_with_arithmetic() {
    assert_eq!(out("f() { if [ \"$1\" -le 0 ]; then echo done; else echo \"$1\"; f $(($1-1)); fi; }; f 3"),
        "3\n2\n1\ndone\n");
}

#[test]
fn getopts_argument_shifting_script() {
    let script = "verbose=0; out=default; \
        set -- -v -o result.txt file1 file2; \
        while getopts vo: opt; do \
          case $opt in v) verbose=1;; o) out=$OPTARG;; esac; \
        done; \
        shift $((OPTIND - 1)); \
        echo \"verbose=$verbose out=$out files=$*\"";
    assert_eq!(out(script), "verbose=1 out=result.txt files=file1 file2\n");
}
