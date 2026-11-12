//! Input that several commands share: a file redirected onto a compound
//! command, the staged input of a pipeline stage, or a here-document. Each
//! command must find it at the shell's position, and an external command must
//! not consume what it never reads.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const RUSH: &str = env!("CARGO_BIN_EXE_rush");
const INPUT: &str = "first\nsecond\nthird\nfourth\n";

struct InputFile(PathBuf);

impl InputFile {
    fn new(name: &str) -> Self {
        #[cfg(target_os = "motor")]
        let (root, pid) = (
            PathBuf::from("/none/tmp"),
            moto_sys::ProcessStaticPage::get().pid,
        );
        #[cfg(not(target_os = "motor"))]
        let (root, pid) = (std::env::temp_dir(), u64::from(std::process::id()));
        let path = root.join(format!("rush-shared-input-{pid}-{name}"));
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        fs::write(&path, INPUT).unwrap();
        Self(path)
    }
}

impl Drop for InputFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).unwrap();
    }
}

/// Where a test's compound command gets `INPUT` from.
#[derive(Clone, Copy)]
enum Input {
    Pipeline,
    File,
    Heredoc,
}

/// Run `body`, a compound command whose `$1` is the Rush executable, with
/// `INPUT` as its standard input.
fn check(name: &str, input: Input, body: &str, expected: &str) {
    let file = matches!(input, Input::File).then(|| InputFile::new(name));
    let script = match input {
        Input::Pipeline => format!(r#"printf '%s' '{INPUT}' | {body}"#),
        Input::File => format!(r#"{body} < "$2""#),
        Input::Heredoc => format!("{body} <<EOF\n{INPUT}EOF\n"),
    };
    let mut command = Command::new(RUSH);
    command.args(["-c", &script, "shared-input", RUSH]);
    if let Some(file) = &file {
        command.arg(&file.0);
    }
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "{name}: {:?}", output.stderr);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        expected,
        "{name}"
    );
}

/// A loop over the input that runs `child` between its `read`s.
fn check_loop(name: &str, input: Input, child: &str, expected: &str) {
    // The child is the Rush executable, so it really spawns a process instead
    // of taking Rush's in-process path for shell scripts or builtins.
    let body = format!(
        r#"while IFS= read -r item; do
            printf 'loop:%s\n' "$item"
            "$1" -c '{child}' || exit $?
        done"#
    );
    check(name, input, &body, expected);
}

const NO_READ_OUTPUT: &str = "loop:first\nloop:second\nloop:third\nloop:fourth\n";

#[test]
fn pipeline_input_survives_a_child_that_reads_nothing() {
    check_loop("pipeline-no-read", Input::Pipeline, ":", NO_READ_OUTPUT);
}

#[test]
fn redirected_input_survives_a_child_that_reads_nothing() {
    check_loop("redirect-no-read", Input::File, ":", NO_READ_OUTPUT);
}

// The shell reads one line and a child reads the rest.
const READ_REST: &str = r#"{
        IFS= read -r item
        printf 'shell:%s\n' "$item"
        "$1" -c 'while IFS= read -r item; do printf "child:%s\n" "$item"; done'
    }"#;
const READ_REST_OUTPUT: &str = "shell:first\nchild:second\nchild:third\nchild:fourth\n";

#[test]
fn pipeline_input_reaches_a_child_at_the_shells_position() {
    check(
        "pipeline-read-rest",
        Input::Pipeline,
        READ_REST,
        READ_REST_OUTPUT,
    );
}

#[test]
fn redirected_input_reaches_a_child_at_the_shells_position() {
    check(
        "redirect-read-rest",
        Input::File,
        READ_REST,
        READ_REST_OUTPUT,
    );
}

#[test]
fn heredoc_input_reaches_a_child_at_the_shells_position() {
    check(
        "heredoc-read-rest",
        Input::Heredoc,
        READ_REST,
        READ_REST_OUTPUT,
    );
}

// A here-document read by builtins alone, then with a child in between. The
// loop is bounded, so a position that fails to advance fails the test instead
// of hanging it.
const BUILTINS: &str = r#"{ IFS= read -r a; IFS= read -r b; printf '%s %s\n' "$a" "$b"; }"#;
const BOUNDED_LOOP: &str = r#"for round in 1 2 3 4 5 6; do
        IFS= read -r item || break
        printf 'loop:%s\n' "$item"
        "$1" -c ':' || exit $?
    done"#;

#[test]
fn heredoc_input_advances_across_builtins() {
    check(
        "heredoc-builtins",
        Input::Heredoc,
        BUILTINS,
        "first second\n",
    );
}

#[test]
fn heredoc_input_survives_a_child_that_reads_nothing() {
    check(
        "heredoc-no-read",
        Input::Heredoc,
        BOUNDED_LOOP,
        NO_READ_OUTPUT,
    );
}

// What a child reads is taken from the shell only on the Unix host, where the
// two share one file offset. On Motor OS the child reads through its own copy
// of the offset and the shell sees those bytes again: a documented limit.
#[cfg(unix)]
const READ_ONE: &str = r#"IFS= read -r item || exit $?; printf "child:%s\n" "$item""#;
#[cfg(unix)]
const READ_ONE_OUTPUT: &str = "loop:first\nchild:second\nloop:third\nchild:fourth\n";

#[cfg(unix)]
#[test]
fn pipeline_input_advances_only_by_what_the_child_reads() {
    check_loop(
        "pipeline-read-one",
        Input::Pipeline,
        READ_ONE,
        READ_ONE_OUTPUT,
    );
}

#[cfg(unix)]
#[test]
fn redirected_input_advances_only_by_what_the_child_reads() {
    check_loop("redirect-read-one", Input::File, READ_ONE, READ_ONE_OUTPUT);
}
