//! Phase 4 golden tests (milestone M2 groundwork): compound commands and
//! functions — `if`/`for`/`while`/`until`/`case`, brace groups, subshells,
//! function definitions and calls, and the `break`/`continue`/`return`
//! control-flow builtins. Expected values match `dash`/`bash` where they agree.

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
        .output()
        .expect("failed to spawn rush");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn tmp(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rush_phase4_{}_{}", std::process::id(), tag))
}

/// Run `body` as a script file with positional parameters `args` (`$1`, `$2`,
/// …). Script mode sets the positional parameters; the `-c` form does not until
/// Phase 6, so tests that need `$1` use a file.
fn run_script_args(tag: &str, body: &str, args: &[&str]) -> String {
    let path = tmp(tag);
    std::fs::write(&path, body).unwrap();
    let out = Command::new(RUSH)
        .arg(path.to_str().unwrap())
        .args(args)
        .output()
        .expect("failed to spawn rush");
    let _ = std::fs::remove_file(&path);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ---- if / then / elif / else -----------------------------------------------

#[test]
fn if_then_else() {
    assert_eq!(run_c("if true; then echo yes; fi").stdout, "yes\n");
    assert_eq!(run_c("if false; then echo yes; else echo no; fi").stdout, "no\n");
    assert_eq!(
        run_c("if false; then echo a; elif true; then echo b; else echo c; fi").stdout,
        "b\n"
    );
}

#[test]
fn if_status_is_the_taken_branch() {
    // No branch runs → status 0.
    assert_eq!(run_c("if false; then true; fi; echo $?").stdout, "0\n");
    // The taken branch's status propagates.
    assert_eq!(run_c("if true; then false; fi; echo $?").stdout, "1\n");
}

// ---- for -------------------------------------------------------------------

#[test]
fn for_over_word_list() {
    assert_eq!(run_c("for x in a b c; do echo $x; done").stdout, "a\nb\nc\n");
    // Globs and expansions expand in the word list.
    assert_eq!(run_c("for n in 1 2 3; do echo $((n*n)); done").stdout, "1\n4\n9\n");
}

#[test]
fn for_without_in_uses_positional_params() {
    // `for x` with no `in` clause iterates over the positional parameters.
    let out = run_script_args("for_params", "for x; do echo $x; done", &["one", "two"]);
    assert_eq!(out, "one\ntwo\n");
}

#[test]
fn for_empty_list_runs_body_zero_times() {
    assert_eq!(run_c("for x in; do echo $x; done; echo end").stdout, "end\n");
}

// ---- while / until ---------------------------------------------------------

#[test]
fn while_loop() {
    assert_eq!(
        run_c("i=1; while [ $i -le 3 ]; do echo $i; i=$((i+1)); done").stdout,
        "1\n2\n3\n"
    );
}

#[test]
fn until_loop() {
    assert_eq!(
        run_c("i=0; until [ $i -ge 3 ]; do echo $i; i=$((i+1)); done").stdout,
        "0\n1\n2\n"
    );
}

// ---- break / continue ------------------------------------------------------

#[test]
fn break_and_continue() {
    assert_eq!(
        run_c("for i in 1 2 3 4 5; do if [ $i -eq 3 ]; then continue; fi; if [ $i -eq 5 ]; then break; fi; echo $i; done").stdout,
        "1\n2\n4\n"
    );
}

#[test]
fn break_n_exits_multiple_loops() {
    // `break 2` leaves both loops.
    assert_eq!(
        run_c("for i in 1 2; do for j in a b; do echo $i$j; break 2; done; done").stdout,
        "1a\n"
    );
}

#[test]
fn break_continue_outside_loop_are_noops() {
    // dash/bash treat these as silent no-ops that keep executing.
    assert_eq!(run_c("break; echo survived").stdout, "survived\n");
    assert_eq!(run_c("continue; echo survived").stdout, "survived\n");
    // A `break` inside a function without its own loop does not break the
    // caller's loop.
    assert_eq!(
        run_c("f() { break; echo in; }; for i in 1 2; do f; echo out$i; done").stdout,
        "in\nout1\nin\nout2\n"
    );
}

#[test]
fn continue_n_targets_outer_loop() {
    assert_eq!(
        run_c("for i in 1 2 3; do for j in a b; do if [ $j = a ]; then continue 2; fi; echo $i$j; done; echo unreached; done").stdout,
        ""
    );
}

// ---- case ------------------------------------------------------------------

#[test]
fn case_matches_patterns() {
    let script = "for f in a.txt b.log c.txt d; do \
        case $f in *.txt) echo txt:$f;; *.log) echo log:$f;; *) echo other:$f;; esac; \
        done";
    assert_eq!(
        run_c(script).stdout,
        "txt:a.txt\nlog:b.log\ntxt:c.txt\nother:d\n"
    );
}

#[test]
fn case_alternation_and_no_match() {
    assert_eq!(run_c("case yes in y|yes|yeah) echo hit;; esac").stdout, "hit\n");
    // No match → status 0, no output.
    let r = run_c("case zzz in a) echo a;; esac; echo done=$?");
    assert_eq!(r.stdout, "done=0\n");
}

#[test]
fn case_quoted_pattern_is_literal() {
    // A quoted `*` in a pattern matches only a literal asterisk.
    assert_eq!(run_c("case '*' in \"*\") echo literal;; esac").stdout, "literal\n");
    assert_eq!(run_c("case abc in \"*\") echo lit;; *) echo glob;; esac").stdout, "glob\n");
}

// ---- brace group & subshell ------------------------------------------------

#[test]
fn brace_group_runs_in_current_environment() {
    // A brace group does not isolate variables.
    assert_eq!(run_c("{ x=inside; }; echo $x").stdout, "inside\n");
}

#[test]
fn subshell_isolates_state() {
    // Variable and cwd changes inside ( … ) do not leak out.
    assert_eq!(run_c("x=out; (x=in; echo $x); echo $x").stdout, "in\nout\n");
}

#[test]
fn compound_redirection() {
    let path = tmp("loop_out");
    let _ = std::fs::remove_file(&path);
    let script = format!("for i in 1 2 3; do echo line$i; done > {}", path.display());
    run_c(&script);
    let contents = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    assert_eq!(contents, "line1\nline2\nline3\n");
}

// ---- functions -------------------------------------------------------------

#[test]
fn function_definition_and_call() {
    assert_eq!(
        run_c("greet() { echo hello $1; }; greet world; greet there").stdout,
        "hello world\nhello there\n"
    );
}

#[test]
fn function_positional_params_are_scoped() {
    // $1 inside the function is its own argument; the outer $1 is restored.
    let out = run_script_args(
        "fn_params",
        "f() { echo in=$1; }; echo out=$1; f X; echo out=$1",
        &["OUT"],
    );
    assert_eq!(out, "out=OUT\nin=X\nout=OUT\n");
}

#[test]
fn function_return_status() {
    assert_eq!(run_c("f() { return 3; }; f; echo $?").stdout, "3\n");
    // `return` with no argument uses $?.
    assert_eq!(run_c("f() { false; return; }; f; echo $?").stdout, "1\n");
}

#[test]
fn recursive_function() {
    let fact = "fact() { if [ $1 -le 1 ]; then echo 1; else echo $(( $1 * $(fact $(($1-1))) )); fi; }; fact 5";
    assert_eq!(run_c(fact).stdout, "120\n");
}

#[test]
fn control_flow_exit_status() {
    // The shell's exit status is the last command's — including a function's
    // `return` value and a negated pipeline.
    assert_eq!(run_c("f() { return 4; }; f").code, 4);
    assert_eq!(run_c("if false; then exit 9; fi").code, 0);
    assert_eq!(run_c("for i in 1 2; do :; done").code, 0);
    assert_eq!(run_c("! true").code, 1);
}

// ---- pipeline negation -----------------------------------------------------

#[test]
fn bang_negates_pipeline() {
    assert_eq!(run_c("! true; echo $?").stdout, "1\n");
    assert_eq!(run_c("! false; echo $?").stdout, "0\n");
    assert_eq!(run_c("if ! false; then echo neg; fi").stdout, "neg\n");
}

// ---- nesting ---------------------------------------------------------------

#[test]
fn nested_constructs() {
    let script = "for i in 1 2 3; do \
        if [ $((i % 2)) -eq 0 ]; then echo even $i; else echo odd $i; fi; \
        done";
    assert_eq!(run_c(script).stdout, "odd 1\neven 2\nodd 3\n");
}

#[test]
fn function_with_loop_and_case() {
    let script = "classify() { for a in \"$@\"; do case $a in [0-9]) echo digit $a;; *) echo word $a;; esac; done; }; classify 5 hi 3";
    assert_eq!(run_c(script).stdout, "digit 5\nword hi\ndigit 3\n");
}

// ---- multi-line via a script file ------------------------------------------

#[test]
fn multiline_script_file() {
    let path = tmp("script.sh");
    let script = "\
i=0
while [ $i -lt 3 ]
do
    echo count $i
    i=$((i + 1))
done
";
    std::fs::write(&path, script).unwrap();
    let out = Command::new(RUSH).arg(path.to_str().unwrap()).output().expect("spawn");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "count 0\ncount 1\ncount 2\n"
    );
}
