//! Tests for `sysbox wc`.
//!
//! Every expected string here is what the Linux `wc` this was written against
//! (uutils coreutils 0.8.0) printed for the same fixture, including the column
//! widths, which are the part of `wc` that is easy to get subtly wrong.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SYSBOX: &str = "/sys/sysbox";

const THREE: &str = "hello world\nsecond line here\nthird\n";

fn build_files(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join("three.txt"), THREE).unwrap();
    std::fs::write(root.join("one.txt"), b"one\n").unwrap();
    std::fs::write(root.join("empty.txt"), b"").unwrap();
    std::fs::write(root.join("notrail.txt"), b"no trailing newline").unwrap();
    std::fs::write(root.join("tabs.txt"), b"a\tb\nlonger line here\n").unwrap();
    // "café naïve" and "你好": 20 bytes, 14 characters, widest line 10 columns.
    std::fs::write(root.join("utf8.txt"), "café naïve\n你好\n").unwrap();
    // Six wide characters are twelve columns, more than the eight below them.
    std::fs::write(root.join("cjk.txt"), "你好你好你好\nabcdefgh\n").unwrap();
    std::fs::write(root.join("names0"), b"one.txt\0three.txt\0").unwrap();
    std::fs::write(root.join("names0bad"), b"one.txt\0missing.txt\0").unwrap();
    std::fs::write(root.join("names0empty"), b"\0").unwrap();
}

fn run(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(SYSBOX)
        .arg("wc")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run_stdin(cwd: &Path, args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(SYSBOX)
        .arg("wc")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[track_caller]
fn expect(output: &std::process::Output, stdout: &str) {
    assert!(
        output.status.success(),
        "wc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
}

/// The counts themselves, and the order they are printed in: lines, words,
/// characters, bytes, longest line, whatever order the options came in.
fn test_counts(root: &Path) {
    expect(&run(root, &["three.txt"]), " 3  6 35 three.txt\n");
    expect(&run(root, &["-l", "three.txt"]), "3 three.txt\n");
    expect(&run(root, &["-w", "three.txt"]), "6 three.txt\n");
    expect(&run(root, &["-c", "three.txt"]), "35 three.txt\n");
    expect(&run(root, &["-m", "three.txt"]), "35 three.txt\n");
    expect(&run(root, &["-L", "three.txt"]), "16 three.txt\n");
    expect(
        &run(root, &["-L", "-c", "-m", "-w", "-l", "three.txt"]),
        " 3  6 35 35 16 three.txt\n",
    );
    expect(
        &run(root, &["-lwcmL", "three.txt"]),
        " 3  6 35 35 16 three.txt\n",
    );
    expect(
        &run(root, &["--lines", "--words", "--bytes", "three.txt"]),
        " 3  6 35 three.txt\n",
    );

    expect(&run(root, &["empty.txt"]), "0 0 0 empty.txt\n");
    // A last line with no newline is still a line to count words in.
    expect(&run(root, &["notrail.txt"]), " 0  3 19 notrail.txt\n");

    println!("sysbox_wc::test_counts PASS");
}

/// Characters are not bytes, and a column is not a character: a tab reaches
/// the next stop and an East Asian character takes two.
fn test_wide_and_tabs(root: &Path) {
    expect(&run(root, &["-m", "-c", "utf8.txt"]), "14 20 utf8.txt\n");
    expect(&run(root, &["-L", "utf8.txt"]), "10 utf8.txt\n");
    expect(&run(root, &["-L", "cjk.txt"]), "12 cjk.txt\n");
    expect(&run(root, &["-L", "tabs.txt"]), "16 tabs.txt\n");

    println!("sysbox_wc::test_wide_and_tabs PASS");
}

/// The counts are padded to the width of the largest they could be — the
/// inputs' sizes added up — except when one count of one input needs none.
fn test_column_widths(root: &Path) {
    expect(
        &run(root, &["one.txt", "three.txt"]),
        " 1  1  4 one.txt\n 3  6 35 three.txt\n 4  7 39 total\n",
    );
    expect(
        &run(root, &["-l", "one.txt", "three.txt"]),
        " 1 one.txt\n 3 three.txt\n 4 total\n",
    );
    expect(
        &run(root, &["-c", "one.txt", "three.txt"]),
        " 4 one.txt\n35 three.txt\n39 total\n",
    );

    // Standard input has no size to look at: seven columns, and the counts of
    // a single count of a single input still need none.
    expect(
        &run_stdin(root, &[], THREE.as_bytes()),
        "      3       6      35\n",
    );
    expect(&run_stdin(root, &["-l"], THREE.as_bytes()), "3\n");
    expect(
        &run_stdin(root, &["-"], THREE.as_bytes()),
        "      3       6      35 -\n",
    );
    expect(
        &run_stdin(root, &["three.txt", "-"], b"one\n"),
        "      3       6      35 three.txt\n      1       1       4 -\n      4       7      39 total\n",
    );

    println!("sysbox_wc::test_column_widths PASS");
}

fn test_totals(root: &Path) {
    expect(
        &run(root, &["--total=always", "three.txt"]),
        " 3  6 35 three.txt\n 3  6 35 total\n",
    );
    expect(
        &run(root, &["--total=never", "one.txt", "three.txt"]),
        " 1  1  4 one.txt\n 3  6 35 three.txt\n",
    );
    expect(
        &run(root, &["--total=only", "one.txt", "three.txt"]),
        "4 7 39\n",
    );
    expect(
        &run(root, &["--total", "only", "one.txt", "three.txt"]),
        "4 7 39\n",
    );
    // auto is the default: a total for more than one input, and none for one.
    expect(
        &run(root, &["--total=auto", "three.txt"]),
        " 3  6 35 three.txt\n",
    );

    println!("sysbox_wc::test_totals PASS");
}

fn test_files0_from(root: &Path) {
    let expected = " 1  1  4 one.txt\n 3  6 35 three.txt\n 4  7 39 total\n";
    expect(&run(root, &["--files0-from=names0"]), expected);
    expect(&run(root, &["--files0-from", "names0"]), expected);
    expect(
        &run_stdin(root, &["--files0-from=-"], b"one.txt\0three.txt\0"),
        expected,
    );

    // A name that cannot be counted is reported, and the rest still are.
    let output = run(root, &["--files0-from=names0bad"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "1 1 4 one.txt\n1 1 4 total\n"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing.txt: No such file or directory")
    );

    // The list itself can be wrong in two ways.
    let output = run(root, &["--files0-from=missing"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("cannot open 'missing' for reading: No such file or directory"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = run(root, &["--files0-from=names0empty"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("names0empty:1: invalid zero-length file name"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Operands and a list are two ways of saying the same thing.
    let output = run(root, &["--files0-from=names0", "three.txt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("extra operand 'three.txt'"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    println!("sysbox_wc::test_files0_from PASS");
}

fn test_errors(root: &Path) {
    // A missing file has no row of its own, and does not stop the others.
    let output = run(root, &["-l", "missing.txt", "one.txt"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "1 one.txt\n1 total\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "wc: missing.txt: No such file or directory\n"
    );

    let output = run(root, &["missing.txt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());

    // A directory is reported, with the row of zeros Linux prints for it.
    let output = run(root, &["."]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "      0       0       0 .\n"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Is a directory"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // An option `wc` does not have, and a value it does not take.
    let output = run(root, &["-x", "three.txt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid option -- 'x'"));

    let output = run(root, &["--nope", "three.txt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized option '--nope'"));

    let output = run(root, &["--total=bogus", "three.txt"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid argument 'bogus'"));

    // After `--`, a leading dash is a file name.
    let output = run(root, &["--", "-x"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("wc: -x: No such file or directory"));

    println!("sysbox_wc::test_errors PASS");
}

fn test_help_and_version(root: &Path) {
    let output = run(root, &["--help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for option in ["--bytes", "--chars", "--files0-from", "--lines", "--total"] {
        assert!(stdout.contains(option), "no {option} in help");
    }
    assert_eq!(run(root, &["-h"]).stdout, output.stdout);

    let output = run(root, &["--version"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("wc (sysbox)"));
    assert_eq!(run(root, &["-V"]).stdout, output.stdout);

    println!("sysbox_wc::test_help_and_version PASS");
}

/// Counting does not depend on where the reads happen to land: a file large
/// enough to arrive in several pieces, with multi-byte characters straddling
/// the boundaries, counts the same as it would whole.
fn test_large_input(root: &Path) {
    let path = root.join("large.txt");
    let mut text = String::new();
    // 8 bytes of characters per line, so a 64 KiB read boundary lands inside
    // a multi-byte character rather than tidily between two.
    for _ in 0..20_000 {
        text.push_str("aé你b\n");
    }
    std::fs::write(&path, &text).unwrap();

    let bytes = text.len();
    let chars = text.chars().count();
    // Every count is padded to the width of the file's size, the largest any
    // of them could be; the widest line is five columns, not four characters.
    let width = bytes.to_string().len();
    let expected = format!(
        "{:>width$} {:>width$} {chars:>width$} {bytes:>width$} {:>width$} large.txt\n",
        20_000, 20_000, 5
    );
    expect(
        &run(root, &["-l", "-w", "-m", "-c", "-L", "large.txt"]),
        &expected,
    );

    std::fs::remove_file(&path).unwrap();
    println!("sysbox_wc::test_large_input PASS");
}

pub fn run_test() {
    let root: PathBuf = std::env::temp_dir().join("systest-sysbox-wc");
    build_files(&root);

    test_counts(&root);
    test_wide_and_tabs(&root);
    test_column_widths(&root);
    test_totals(&root);
    test_files0_from(&root);
    test_errors(&root);
    test_help_and_version(&root);
    test_large_input(&root);

    std::fs::remove_dir_all(&root).unwrap();
    println!("sysbox_wc::run_test PASS");
}
