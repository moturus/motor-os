//! Tests for `sysbox head`.
//!
//! Every expected output here is what GNU `head` (coreutils 9.7) printed for
//! the same fixture and arguments.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SYSBOX: &str = "/system/bin/sysbox";

fn numbered(lines: usize) -> String {
    (1..=lines).map(|n| format!("{n}\n")).collect()
}

fn build_files(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::write(root.join("twelve"), numbered(12)).unwrap();
    std::fs::write(root.join("three"), "l1\nl2\nl3\n").unwrap();
    std::fs::write(root.join("notrail"), "x1\nx2").unwrap();
    std::fs::write(root.join("empty"), "").unwrap();
    std::fs::write(root.join("zero"), b"a\0b\0c\0d").unwrap();
    std::fs::write(root.join("with space"), "spaced\n").unwrap();
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("head")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run_stdin(cwd: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(SYSBOX)
        .arg("head")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Feed the input while the output drains, or a large one fills both pipes.
    // `head` may stop reading once it has what it needs; a short write then is
    // the pipe closing, not a failure.
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    output
}

#[track_caller]
fn expect(output: &Output, stdout: &str) {
    assert!(
        output.status.success(),
        "head failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
}

#[track_caller]
fn expect_failure(output: &Output, stdout: &str, stderr: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
    assert_eq!(messages(&output.stderr), stderr);
}

/// What the command itself wrote to stderr: in a debug build, the runtime
/// writes its log records ("12:345: DEBUG ...") there, too.
fn messages(stderr: &[u8]) -> String {
    let is_log_record = |line: &str| {
        line.split_once(": ").is_some_and(|(stamp, _)| {
            stamp.split(':').count() == 2
                && stamp
                    .split(':')
                    .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    String::from_utf8_lossy(stderr)
        .lines()
        .filter(|line| !is_log_record(line))
        .map(|line| format!("{line}\n"))
        .collect()
}

fn test_counts(root: &Path) {
    expect(&run(root, &["twelve"]), &numbered(10));
    expect(&run(root, &["-n", "2", "twelve"]), "1\n2\n");
    expect(&run(root, &["-n2", "twelve"]), "1\n2\n");
    expect(&run(root, &["--lines=3", "twelve"]), "1\n2\n3\n");
    expect(&run(root, &["--lines", "+1", "twelve"]), "1\n");
    expect(&run(root, &["-4", "twelve"]), "1\n2\n3\n4\n");
    expect(&run(root, &["-n", "0", "twelve"]), "");
    expect(&run(root, &["-n", "20", "three"]), "l1\nl2\nl3\n");
    expect(&run(root, &["-c", "4", "three"]), "l1\nl");
    expect(&run(root, &["--bytes=1", "three"]), "l");
    expect(&run(root, &["-3c", "three"]), "l1\n");
    expect(&run(root, &["-c", "1K", "three"]), "l1\nl2\nl3\n");
    expect(&run(root, &["-n", "1", "-c", "2", "three"]), "l1");
    expect(&run(root, &["-c", "2", "-n", "1", "three"]), "l1\n");
    expect(&run(root, &["notrail"]), "x1\nx2");
    expect(&run(root, &["empty"]), "");
    expect(&run(root, &["-z", "-n", "2", "zero"]), "a\0b\0");

    println!("sysbox_head::test_counts PASS");
}

/// A leading '-' on the count prints all but the last lines or bytes.
fn test_all_but_last(root: &Path) {
    expect(&run(root, &["-n", "-10", "twelve"]), "1\n2\n");
    expect(&run(root, &["-n-1", "three"]), "l1\nl2\n");
    expect(&run(root, &["-n", "-0", "three"]), "l1\nl2\nl3\n");
    expect(&run(root, &["-n", "-5", "three"]), "");
    // A last line with no newline is still a line.
    expect(&run(root, &["-n", "-1", "notrail"]), "x1\n");
    expect(&run(root, &["-c", "-2", "three"]), "l1\nl2\nl");
    expect(&run(root, &["--bytes=-100", "three"]), "");
    expect(&run(root, &["-c", "-1", "empty"]), "");
    expect(&run(root, &["-z", "-n", "-1", "zero"]), "a\0b\0c\0");

    println!("sysbox_head::test_all_but_last PASS");
}

fn test_headers(root: &Path) {
    expect(
        &run(root, &["-n", "1", "three", "notrail"]),
        "==> three <==\nl1\n\n==> notrail <==\nx1\n",
    );
    expect(
        &run(root, &["-q", "-n", "1", "three", "notrail"]),
        "l1\nx1\n",
    );
    expect(
        &run(root, &["-v", "-n", "1", "three"]),
        "==> three <==\nl1\n",
    );
    expect(
        &run(root, &["-n", "1", "notrail", "three"]),
        "==> notrail <==\nx1\n\n==> three <==\nl1\n",
    );
    expect(
        &run_stdin(root, &["-n", "1", "three", "-"], b"in\n"),
        "==> three <==\nl1\n\n==> standard input <==\nin\n",
    );

    println!("sysbox_head::test_headers PASS");
}

fn test_stdin(root: &Path) {
    let input = numbered(12);
    expect(&run_stdin(root, &[], input.as_bytes()), &numbered(10));
    expect(&run_stdin(root, &["-n", "-11"], input.as_bytes()), "1\n");
    expect(
        &run_stdin(root, &["-c", "3", "-"], input.as_bytes()),
        "1\n2",
    );

    // Standard input named twice reads on where the first one stopped.
    let from_file = Command::new(SYSBOX)
        .args(["head", "-q", "-n", "1", "-", "-"])
        .current_dir(root)
        .stdin(std::fs::File::open(root.join("three")).unwrap())
        .output()
        .unwrap();
    expect(&from_file, "l1\nl2\n");
    // From a pipe, too, where GNU `head` loses the rest of what it read.
    expect(
        &run_stdin(root, &["-q", "-n", "1", "-", "-"], b"a\nb\nc\n"),
        "a\nb\n",
    );

    println!("sysbox_head::test_stdin PASS");
}

/// Withholding nothing holds nothing back: input leaves as it arrives, with
/// no line ended and the writer still holding the pipe open.
fn test_withholding_nothing(root: &Path) {
    // More than an output buffer holds, and no newline.
    const LEN: usize = 128 * 1024;
    for count in [["-n", "-0"], ["-c", "-0"]] {
        let mut child = Command::new(SYSBOX)
            .arg("head")
            .args(count)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut first = [0_u8; 1];
            stdout.read_exact(&mut first).unwrap();
            sender.send(()).unwrap();
            let mut rest = Vec::new();
            stdout.read_to_end(&mut rest).unwrap();
            1 + rest.len()
        });

        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&[b'x'; LEN]).unwrap();
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .is_ok(),
            "head {count:?} held its input back until the end"
        );
        drop(stdin);
        assert_eq!(reader.join().unwrap(), LEN);
        assert!(child.wait().unwrap().success());
    }

    println!("sysbox_head::test_withholding_nothing PASS");
}

/// Inputs larger than one read, so that what is held back crosses reads.
fn test_large_input(root: &Path) {
    let input = numbered(100_000);
    let path = root.join("large");
    std::fs::write(&path, &input).unwrap();

    let output = run(root, &["-n", "-99998", "large"]);
    expect(&output, "1\n2\n");
    let output = run(root, &["-c", "-588888", "large"]);
    expect(&output, &input[..input.len() - 588_888]);
    let output = run(root, &["-n", "70000", "large"]);
    expect(&output, &numbered(70_000));
    let output = run_stdin(root, &["-c", "-1"], input.as_bytes());
    expect(&output, &input[..input.len() - 1]);
    let output = run_stdin(root, &["-n", "-1"], input.as_bytes());
    expect(&output, &numbered(99_999));

    std::fs::remove_file(&path).unwrap();
    println!("sysbox_head::test_large_input PASS");
}

/// A failed input is reported and skipped; the rest are still printed.
fn test_errors(root: &Path) {
    expect_failure(
        &run(root, &["-n", "1", "three", "missing", "notrail"]),
        "==> three <==\nl1\n\n==> notrail <==\nx1\n",
        "head: cannot open 'missing' for reading: No such file or directory\n",
    );
    expect_failure(
        &run(root, &["-n", "1", "dir", "three"]),
        "==> dir <==\n\n==> three <==\nl1\n",
        "head: error reading 'dir': Is a directory\n",
    );
    expect_failure(
        &run(root, &["-n", "abc", "three"]),
        "",
        "head: invalid number of lines: 'abc'\n",
    );
    expect_failure(
        &run(root, &["-c", "1x", "three"]),
        "",
        "head: invalid number of bytes: '1x'\n",
    );
    expect_failure(
        &run(root, &["-x", "three"]),
        "",
        "head: invalid option -- 'x'\nTry 'head --help' for more information.\n",
    );
    expect_failure(
        &run(root, &["-n"]),
        "",
        "head: option requires an argument -- 'n'\nTry 'head --help' for more information.\n",
    );

    println!("sysbox_head::test_errors PASS");
}

/// `/system/bin/head` is the name people type: a rush shim over `sysbox
/// head`, which has to keep an argument with a space in it whole.
fn test_bin_shim(root: &Path) {
    let output = Command::new("/system/bin/head")
        .args(["-n", "1", "three", "with space"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    expect(&output, "==> three <==\nl1\n\n==> with space <==\nspaced\n");

    println!("sysbox_head::test_bin_shim PASS");
}

pub fn run_test() {
    let root: PathBuf = std::env::temp_dir().join("systest-sysbox-head");
    build_files(&root);

    test_counts(&root);
    test_all_but_last(&root);
    test_headers(&root);
    test_stdin(&root);
    test_large_input(&root);
    test_withholding_nothing(&root);
    test_errors(&root);
    test_bin_shim(&root);

    std::fs::remove_dir_all(&root).unwrap();
    println!("sysbox_head::run_test PASS");
}
