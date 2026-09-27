//! Tests for `sysbox tail`.
//!
//! Every expected output here is what GNU `tail` (coreutils 9.7) printed for
//! the same fixture and arguments.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SYSBOX: &str = "/system/bin/sysbox";

fn numbered(lines: std::ops::RangeInclusive<usize>) -> String {
    lines.map(|n| format!("{n}\n")).collect()
}

fn build_files(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root.join("dir")).unwrap();
    std::fs::write(root.join("twelve"), numbered(1..=12)).unwrap();
    std::fs::write(root.join("three"), "l1\nl2\nl3\n").unwrap();
    std::fs::write(root.join("notrail"), "x1\nx2").unwrap();
    std::fs::write(root.join("empty"), "").unwrap();
    std::fs::write(root.join("blank"), "\n\n\n").unwrap();
    std::fs::write(root.join("zero"), b"a\0b\0c\0d").unwrap();
    std::fs::write(root.join("with space"), "spaced\n").unwrap();
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("tail")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run_stdin(cwd: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(SYSBOX)
        .arg("tail")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Feed the input while the output drains, or a large one fills both pipes.
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
        "tail failed: {}",
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

/// The same arguments read the same from a file, which is read from its end,
/// and from a pipe, which is not.
#[track_caller]
fn expect_both(root: &Path, args: &[&str], file: &str, stdout: &str) {
    let mut with_file = args.to_vec();
    with_file.push(file);
    expect(&run(root, &with_file), stdout);
    let input = std::fs::read(root.join(file)).unwrap();
    expect(&run_stdin(root, args, &input), stdout);
}

fn test_from_end(root: &Path) {
    expect_both(root, &[], "twelve", &numbered(3..=12));
    expect_both(root, &["-n", "2"], "twelve", "11\n12\n");
    expect_both(root, &["-n2"], "twelve", "11\n12\n");
    expect_both(root, &["--lines=-3"], "twelve", "10\n11\n12\n");
    expect_both(root, &["-n", "0"], "twelve", "");
    expect_both(root, &["-n", "20"], "three", "l1\nl2\nl3\n");
    expect_both(root, &["-n", "1"], "notrail", "x2");
    expect_both(root, &["-n", "2"], "blank", "\n\n");
    expect_both(root, &["-n", "1"], "empty", "");
    expect_both(root, &["-c", "4"], "three", "\nl3\n");
    expect_both(root, &["--bytes=1K"], "three", "l1\nl2\nl3\n");
    expect_both(root, &["-z", "-n", "2"], "zero", "c\0d");
    expect_both(root, &["-c", "2", "-n", "1"], "three", "l3\n");

    println!("sysbox_tail::test_from_end PASS");
}

/// A leading '+' counts from the start instead: +NUM begins at line NUM.
fn test_from_start(root: &Path) {
    expect_both(root, &["-n", "+11"], "twelve", "11\n12\n");
    expect_both(root, &["-n", "+0"], "three", "l1\nl2\nl3\n");
    expect_both(root, &["-n", "+1"], "three", "l1\nl2\nl3\n");
    expect_both(root, &["-n", "+9"], "three", "");
    expect_both(root, &["-c", "+4"], "three", "l2\nl3\n");
    expect_both(root, &["--bytes=+100"], "three", "");
    expect_both(root, &["-z", "-n", "+3"], "zero", "c\0d");

    println!("sysbox_tail::test_from_start PASS");
}

/// `tail -NUM` and `tail +NUM`, with `b`, `c` or `l`, before one file at most.
fn test_obsolete(root: &Path) {
    expect(&run(root, &["-2", "twelve"]), "11\n12\n");
    expect(&run(root, &["+11", "twelve"]), "11\n12\n");
    expect(&run(root, &["-3c", "three"]), "l3\n");
    expect(&run(root, &["+7c", "three"]), "l3\n");
    expect(&run(root, &["-1l", "three"]), "l3\n");
    expect(&run(root, &["-2", "--", "three"]), "l2\nl3\n");
    expect(&run_stdin(root, &["-1"], b"a\nb\n"), "b\n");
    expect_failure(
        &run(root, &["-2", "three", "twelve"]),
        "",
        "tail: option used in invalid context -- 2\n",
    );
    // With two files, "+2" is a file name.
    expect_failure(
        &run(root, &["+2", "three", "notrail"]),
        "==> three <==\nl1\nl2\nl3\n\n==> notrail <==\nx1\nx2",
        "tail: cannot open '+2' for reading: No such file or directory\n",
    );

    println!("sysbox_tail::test_obsolete PASS");
}

fn test_headers(root: &Path) {
    expect(
        &run(root, &["-n", "1", "three", "notrail"]),
        "==> three <==\nl3\n\n==> notrail <==\nx2",
    );
    expect(
        &run(root, &["-q", "-n", "1", "three", "twelve"]),
        "l3\n12\n",
    );
    expect(
        &run(root, &["-v", "-n", "1", "three"]),
        "==> three <==\nl3\n",
    );
    expect(
        &run_stdin(root, &["-n", "1", "three", "-"], b"in\n"),
        "==> three <==\nl3\n\n==> standard input <==\nin\n",
    );

    println!("sysbox_tail::test_headers PASS");
}

/// Inputs larger than one read, from a file and from a pipe.
fn test_large_input(root: &Path) {
    let input = numbered(1..=100_000);
    std::fs::write(root.join("large"), &input).unwrap();

    expect_both(root, &["-n", "2"], "large", "99999\n100000\n");
    expect_both(root, &["-n", "70000"], "large", &numbered(30_001..=100_000));
    expect_both(root, &["-n", "+99999"], "large", "99999\n100000\n");
    expect_both(root, &["-c", "588888"], "large", &input[7..]);
    expect_both(root, &["-c", "+588889"], "large", &input[588_888..]);

    std::fs::remove_file(root.join("large")).unwrap();
    println!("sysbox_tail::test_large_input PASS");
}

/// Nothing to print from the end is nothing to read: `tail -n 0` returns
/// while the writer still holds the pipe open.
fn test_zero_count(root: &Path) {
    for count in [["-n", "0"], ["-c", "0"]] {
        let mut child = Command::new(SYSBOX)
            .arg("tail")
            .args(count)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        // It may be gone already, which is the point.
        let _ = stdin.write_all(b"no newline yet");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "tail {count:?} waited for its input to end"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        drop(stdin);
        expect(&child.wait_with_output().unwrap(), "");
    }
    // Nor are there headers, or files to open.
    expect(&run(root, &["-n", "0", "three", "missing"]), "");

    println!("sysbox_tail::test_zero_count PASS");
}

/// A failed input is reported and skipped; the rest are still printed.
fn test_errors(root: &Path) {
    expect_failure(
        &run(root, &["-n", "1", "three", "missing", "notrail"]),
        "==> three <==\nl3\n\n==> notrail <==\nx2",
        "tail: cannot open 'missing' for reading: No such file or directory\n",
    );
    expect_failure(
        &run(root, &["-n", "1", "dir", "three"]),
        "==> dir <==\n\n==> three <==\nl3\n",
        "tail: error reading 'dir': Is a directory\n",
    );
    expect_failure(
        &run(root, &["-n", "abc", "three"]),
        "",
        "tail: invalid number of lines: 'abc'\n",
    );
    expect_failure(
        &run(root, &["-f", "three"]),
        "",
        "tail: invalid option -- 'f'\nTry 'tail --help' for more information.\n",
    );
    expect_failure(
        &run(root, &["--follow", "three"]),
        "",
        "tail: unrecognized option '--follow'\nTry 'tail --help' for more information.\n",
    );

    println!("sysbox_tail::test_errors PASS");
}

/// `/system/bin/tail` is the name people type: a rush shim over `sysbox
/// tail`, which has to keep an argument with a space in it whole.
fn test_bin_shim(root: &Path) {
    let output = Command::new("/system/bin/tail")
        .args(["-n", "1", "three", "with space"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    expect(&output, "==> three <==\nl3\n\n==> with space <==\nspaced\n");

    println!("sysbox_tail::test_bin_shim PASS");
}

pub fn run_test() {
    let root: PathBuf = std::env::temp_dir().join("systest-sysbox-tail");
    build_files(&root);

    test_from_end(&root);
    test_from_start(&root);
    test_obsolete(&root);
    test_headers(&root);
    test_large_input(&root);
    test_zero_count(&root);
    test_errors(&root);
    test_bin_shim(&root);

    std::fs::remove_dir_all(&root).unwrap();
    println!("sysbox_tail::run_test PASS");
}
