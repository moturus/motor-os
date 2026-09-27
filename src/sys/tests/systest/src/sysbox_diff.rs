//! Tests for `sysbox diff`.
//!
//! Every expected output here is what GNU `diff` (diffutils 3.12) printed for
//! the same fixture and arguments, the timestamps in headers aside.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SYSBOX: &str = "/system/bin/sysbox";

fn build_files(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).unwrap();
    let write = |name: &str, contents: &[u8]| std::fs::write(root.join(name), contents).unwrap();
    write("f1", b"a\nb\nc\nd\ne\n");
    write("f2", b"a\nB\nc\nd\ne\nf\n");
    write("f3", b"a\nb\nc\n");
    write("nonl", b"a\nb");
    write("nl", b"a\nb\n");
    write("bin1", b"x\0y");
    write("bin2", b"x\0z");
    write("spaces1", b"a  b\nHello\n");
    write("spaces2", b"a b\nhello\n");
    write("nospace", b"ab\nhello\n");
    write("with space", b"a\nB\n");
    write("ctx1", b"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n");
    write("ctx2", b"one\n2\n3\n4\n5\n6\n7\n8\n9\nten\n");

    // Two fixtures where a shortest script is not unique, so that the one
    // printed is GNU's choice: what it sets aside before searching decides
    // the first, and how much of the shared ends it searches the second.
    write("discard1", b"a\nc\nd\n");
    write("discard2", b"b\nd\nd\nc\nb\n");
    write("horizon1", b"d\nc\nc\na\nb\n");
    write("horizon2", b"a\nb\nb\n");

    for dir in ["A/sub", "A/onlyA_dir", "A/mixed", "B/sub", "B/onlyB_dir"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    write("A/same", b"1\n");
    write("B/same", b"1\n");
    write("A/chg", b"x\n");
    write("B/chg", b"y\n");
    write("A/sub/deep", b"p\n");
    write("B/sub/deep", b"q\n");
    write("A/onlyA", b"z\n");
    write("B/onlyB", b"w\n");
    write("B/mixed", b"m\n");
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(SYSBOX)
        .arg("diff")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run_stdin(cwd: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(SYSBOX)
        .arg("diff")
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

#[track_caller]
fn expect(output: &Output, status: i32, stdout: &str) {
    assert_eq!(
        output.status.code(),
        Some(status),
        "diff: {}",
        messages(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
}

#[track_caller]
fn expect_trouble(output: &Output, stdout: &str, stderr: &str) {
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), stdout);
    assert_eq!(messages(&output.stderr), stderr);
}

fn test_formats(root: &Path) {
    expect(&run(root, &["f1", "f1"]), 0, "");
    expect(
        &run(root, &["f1", "f2"]),
        1,
        "2c2\n< b\n---\n> B\n5a6\n> f\n",
    );
    expect(&run(root, &["f1", "f3"]), 1, "4,5d3\n< d\n< e\n");
    expect(
        &run(
            root,
            &["-u", "--label", "old", "--label", "new", "f1", "f2"],
        ),
        1,
        "--- old\n+++ new\n@@ -1,5 +1,6 @@\n a\n-b\n+B\n c\n d\n e\n+f\n",
    );
    expect(
        &run(root, &["-U0", "-L", "old", "-L", "new", "f1", "f2"]),
        1,
        "--- old\n+++ new\n@@ -2 +2 @@\n-b\n+B\n@@ -5,0 +6 @@\n+f\n",
    );
    expect(
        &run(root, &["-C1", "-L", "old", "-L", "new", "f1", "f2"]),
        1,
        "*** old\n--- new\n***************\n*** 1,3 ****\n  a\n! b\n  c\n--- 1,3 ----\n  a\n! B\n  c\n\
         ***************\n*** 5 ****\n--- 5,6 ----\n  e\n+ f\n",
    );
    expect(
        &run(root, &["--context", "-L", "old", "-L", "new", "f1", "f3"]),
        1,
        "*** old\n--- new\n***************\n*** 1,5 ****\n  a\n  b\n  c\n- d\n- e\n--- 1,3 ----\n",
    );

    println!("sysbox_diff::test_formats PASS");
}

/// A last line without a newline differs from the same line with one, and
/// says so wherever it is printed.
fn test_missing_newline(root: &Path) {
    expect(
        &run(root, &["nonl", "nl"]),
        1,
        "2c2\n< b\n\\ No newline at end of file\n---\n> b\n",
    );
    expect(
        &run(root, &["-u", "-L", "x", "-L", "y", "nonl", "nl"]),
        1,
        "--- x\n+++ y\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n",
    );
    // Under -w and -b, the missing newline is white space too.
    expect(&run(root, &["-w", "nonl", "nl"]), 0, "");

    println!("sysbox_diff::test_missing_newline PASS");
}

/// The script GNU `diff` picks among the shortest ones.
fn test_edit_script(root: &Path) {
    expect(
        &run(root, &["discard1", "discard2"]),
        1,
        "1,2c1,2\n< a\n< c\n---\n> b\n> d\n3a4,5\n> c\n> b\n",
    );
    expect(
        &run(root, &["-d", "discard1", "discard2"]),
        1,
        "1,2c1\n< a\n< c\n---\n> b\n3a3,5\n> d\n> c\n> b\n",
    );
    expect(
        &run(root, &["horizon1", "horizon2"]),
        1,
        "1,3d0\n< d\n< c\n< c\n4a2\n> b\n",
    );
    expect(
        &run(root, &["-u", "-L", "x", "-L", "y", "horizon1", "horizon2"]),
        1,
        "--- x\n+++ y\n@@ -1,5 +1,3 @@\n-d\n-c\n-c\n a\n b\n+b\n",
    );

    // Lines inserted into a run of equal lines go after them.
    let lines: String = (1..=2000).map(|n| format!("line {}\n", n / 7)).collect();
    let mut edited = lines.replace("line 100\n", "line 100\nline 100\n");
    edited = edited.replacen("line 250\n", "", 1);
    std::fs::write(root.join("large1"), &lines).unwrap();
    std::fs::write(root.join("large2"), &edited).unwrap();
    expect(
        &run(root, &["large1", "large2"]),
        1,
        "706a707,713\n> line 100\n> line 100\n> line 100\n> line 100\n> line 100\n> line 100\n\
         > line 100\n1750d1756\n< line 250\n",
    );

    println!("sysbox_diff::test_edit_script PASS");
}

/// Any context too large to count is as much as there is: one hunk.
fn test_huge_context(root: &Path) {
    let whole =
        "--- x\n+++ y\n@@ -1,10 +1,10 @@\n-1\n+one\n 2\n 3\n 4\n 5\n 6\n 7\n 8\n 9\n-10\n+ten\n";
    for context in ["-U18446744073709551615", "-U99999999999999999999999"] {
        expect(
            &run(root, &[context, "-L", "x", "-L", "y", "ctx1", "ctx2"]),
            1,
            whole,
        );
    }
    expect(
        &run(root, &["-U1", "-L", "x", "-L", "y", "ctx1", "ctx2"]),
        1,
        "--- x\n+++ y\n@@ -1,2 +1,2 @@\n-1\n+one\n 2\n@@ -9,2 +9,2 @@\n 9\n-10\n+ten\n",
    );

    println!("sysbox_diff::test_huge_context PASS");
}

/// Under -N an absent operand is an empty one of the other's kind, so a
/// directory against nothing is all deletions.
fn test_absent_operands(root: &Path) {
    expect(
        &run(root, &["-rN", "A", "missing"]),
        1,
        "diff -rN A/chg missing/chg\n1d0\n< x\n\
         diff -rN A/onlyA missing/onlyA\n1d0\n< z\n\
         diff -rN A/same missing/same\n1d0\n< 1\n\
         diff -rN A/sub/deep missing/sub/deep\n1d0\n< p\n",
    );
    expect(
        &run(root, &["-N", "A", "missing"]),
        1,
        "diff -N A/chg missing/chg\n1d0\n< x\n\
         Common subdirectories: A/mixed and missing/mixed\n\
         diff -N A/onlyA missing/onlyA\n1d0\n< z\n\
         Common subdirectories: A/onlyA_dir and missing/onlyA_dir\n\
         diff -N A/same missing/same\n1d0\n< 1\n\
         Common subdirectories: A/sub and missing/sub\n",
    );
    // GNU `diff` 3.12 refuses this order ("A: Is a directory"); it means the
    // same as the one above, turned around.
    expect(
        &run(root, &["-rN", "missing", "A/sub"]),
        1,
        "diff -rN missing/deep A/sub/deep\n0a1\n> p\n",
    );
    expect_trouble(
        &run(root, &["A", "missing"]),
        "",
        "diff: missing: No such file or directory\n",
    );
    expect_trouble(
        &run(root, &["-N", "missing1", "missing2"]),
        "",
        "diff: missing1: No such file or directory\ndiff: missing2: No such file or directory\n",
    );

    println!("sysbox_diff::test_absent_operands PASS");
}

/// Labels name the files wherever the pair is reported on, not only in
/// headers; directory listings and errors keep the paths.
fn test_labels(root: &Path) {
    let labeled = |args: &[&str]| {
        let mut all = vec!["-L", "OLD", "-L", "NEW"];
        all.extend_from_slice(args);
        run(root, &all)
    };
    expect(
        &labeled(&["-q", "f1", "f2"]),
        1,
        "Files OLD and NEW differ\n",
    );
    expect(
        &labeled(&["-s", "f1", "f1"]),
        0,
        "Files OLD and NEW are identical\n",
    );
    expect(
        &labeled(&["bin1", "bin2"]),
        1,
        "Binary files OLD and NEW differ\n",
    );
    expect(
        &labeled(&["-s", "-", "-"]),
        0,
        "Files OLD and NEW are identical\n",
    );
    expect(
        &labeled(&["-r", "-q", "A", "B"]),
        1,
        "Files OLD and NEW differ\n\
         File OLD is a directory while file NEW is a regular file\n\
         Only in A: onlyA\nOnly in A: onlyA_dir\nOnly in B: onlyB\nOnly in B: onlyB_dir\n\
         Files OLD and NEW differ\n",
    );

    println!("sysbox_diff::test_labels PASS");
}

fn test_reports(root: &Path) {
    expect(
        &run(root, &["-q", "f1", "f2"]),
        1,
        "Files f1 and f2 differ\n",
    );
    expect(&run(root, &["-q", "f1", "f1"]), 0, "");
    expect(
        &run(root, &["-s", "f1", "f1"]),
        0,
        "Files f1 and f1 are identical\n",
    );
    expect(
        &run(root, &["bin1", "bin2"]),
        1,
        "Binary files bin1 and bin2 differ\n",
    );
    expect(&run(root, &["bin1", "bin1"]), 0, "");
    expect(
        &run(root, &["-a", "bin1", "bin2"]),
        1,
        "1c1\n< x\0y\n\\ No newline at end of file\n---\n> x\0z\n\\ No newline at end of file\n",
    );

    println!("sysbox_diff::test_reports PASS");
}

fn test_ignoring(root: &Path) {
    expect(
        &run(root, &["spaces1", "spaces2"]),
        1,
        "1,2c1,2\n< a  b\n< Hello\n---\n> a b\n> hello\n",
    );
    expect(
        &run(root, &["-b", "spaces1", "spaces2"]),
        1,
        "2c2\n< Hello\n---\n> hello\n",
    );
    expect(&run(root, &["-bi", "spaces1", "spaces2"]), 0, "");
    expect(
        &run(root, &["-b", "spaces2", "nospace"]),
        1,
        "1c1\n< a b\n---\n> ab\n",
    );
    expect(&run(root, &["-w", "-i", "spaces1", "nospace"]), 0, "");
    expect(
        &run(root, &["--ignore-case", "spaces2", "nospace"]),
        1,
        "1c1\n< a b\n---\n> ab\n",
    );

    println!("sysbox_diff::test_ignoring PASS");
}

fn test_directories(root: &Path) {
    expect(
        &run(root, &["A", "B"]),
        1,
        "diff A/chg B/chg\n1c1\n< x\n---\n> y\n\
         File A/mixed is a directory while file B/mixed is a regular file\n\
         Only in A: onlyA\nOnly in A: onlyA_dir\nOnly in B: onlyB\nOnly in B: onlyB_dir\n\
         Common subdirectories: A/sub and B/sub\n",
    );
    expect(
        &run(root, &["-r", "A", "B"]),
        1,
        "diff -r A/chg B/chg\n1c1\n< x\n---\n> y\n\
         File A/mixed is a directory while file B/mixed is a regular file\n\
         Only in A: onlyA\nOnly in A: onlyA_dir\nOnly in B: onlyB\nOnly in B: onlyB_dir\n\
         diff -r A/sub/deep B/sub/deep\n1c1\n< p\n---\n> q\n",
    );
    expect(
        &run(root, &["-rN", "A", "B"]),
        1,
        "diff -rN A/chg B/chg\n1c1\n< x\n---\n> y\n\
         File A/mixed is a directory while file B/mixed is a regular file\n\
         diff -rN A/onlyA B/onlyA\n1d0\n< z\n\
         diff -rN A/onlyB B/onlyB\n0a1\n> w\n\
         diff -rN A/sub/deep B/sub/deep\n1c1\n< p\n---\n> q\n",
    );
    expect(
        &run(root, &["-r", "-q", "A", "B"]),
        1,
        "Files A/chg and B/chg differ\n\
         File A/mixed is a directory while file B/mixed is a regular file\n\
         Only in A: onlyA\nOnly in A: onlyA_dir\nOnly in B: onlyB\nOnly in B: onlyB_dir\n\
         Files A/sub/deep and B/sub/deep differ\n",
    );
    // A file and a directory: the file of the same name in the directory.
    expect(&run(root, &["A/chg", "B"]), 1, "1c1\n< x\n---\n> y\n");
    expect(&run(root, &["B/", "A/chg"]), 1, "1c1\n< y\n---\n> x\n");

    println!("sysbox_diff::test_directories PASS");
}

/// Unified headers carry the modification time, in GNU's format.
fn test_headers(root: &Path) {
    let output = run(root, &["-u", "f1", "f2"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    for (line, prefix) in lines.iter().zip(["--- f1\t", "+++ f2\t"]) {
        let stamp = line
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("{line}"));
        // "2026-09-26 10:11:12.123456789 +0000"
        let shape: String = stamp
            .chars()
            .map(|c| if c.is_ascii_digit() { 'N' } else { c })
            .collect();
        assert_eq!(shape, "NNNN-NN-NN NN:NN:NN.NNNNNNNNN +NNNN", "{line}");
    }
    assert_eq!(lines[2], "@@ -1,5 +1,6 @@");

    let output = run(root, &["-c", "f1", "f2"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    // "*** f1\tSat Sep 26 10:11:12 2026"
    let stamp = stdout
        .lines()
        .next()
        .unwrap()
        .strip_prefix("*** f1\t")
        .unwrap();
    assert_eq!(stamp.len(), 24, "{stamp}");

    println!("sysbox_diff::test_headers PASS");
}

fn test_stdin(root: &Path) {
    expect(
        &run_stdin(root, &["-", "f1"], b"a\nb\nc\nd\n"),
        1,
        "4a5\n> e\n",
    );
    expect(
        &run_stdin(
            root,
            &["-u", "-L", "in", "-L", "f1", "-", "f1"],
            b"a\nb\nc\nd\ne\n",
        ),
        0,
        "",
    );
    // Standard input named twice is one input, the same as itself: that is
    // the answer before it ends, however long its writer holds it open.
    let mut child = Command::new(SYSBOX)
        .args(["diff", "-s", "-", "-"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(b"a\n");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "diff - - waited for its input to end"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    drop(stdin);
    expect(
        &child.wait_with_output().unwrap(),
        0,
        "Files - and - are identical\n",
    );

    println!("sysbox_diff::test_stdin PASS");
}

fn test_errors(root: &Path) {
    expect_trouble(
        &run(root, &["f1", "missing"]),
        "",
        "diff: missing: No such file or directory\n",
    );
    // -N takes an absent file to be empty.
    expect(
        &run(root, &["-N", "f3", "missing"]),
        1,
        "1,3d0\n< a\n< b\n< c\n",
    );
    expect_trouble(
        &run(root, &["f1"]),
        "",
        "diff: missing operand after 'f1'\ndiff: Try 'diff --help' for more information.\n",
    );
    expect_trouble(
        &run(root, &["f1", "f2", "f3"]),
        "",
        "diff: extra operand 'f3'\ndiff: Try 'diff --help' for more information.\n",
    );
    expect_trouble(
        &run(root, &["-u", "-c", "f1", "f2"]),
        "",
        "diff: conflicting output style options\ndiff: Try 'diff --help' for more information.\n",
    );
    expect_trouble(
        &run(root, &["-U", "x", "f1", "f2"]),
        "",
        "diff: invalid context length 'x'\ndiff: Try 'diff --help' for more information.\n",
    );
    // GNU names only the first byte of the character.
    expect_trouble(
        &run(root, &["-é", "f1", "f2"]),
        "",
        "diff: invalid option -- 'é'\ndiff: Try 'diff --help' for more information.\n",
    );

    println!("sysbox_diff::test_errors PASS");
}

/// `/system/bin/diff` is the name people type: a rush shim over `sysbox
/// diff`, which has to keep an argument with a space in it whole.
fn test_bin_shim(root: &Path) {
    let output = Command::new("/system/bin/diff")
        .args(["f1", "with space"])
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    expect(&output, 1, "2,5c2\n< b\n< c\n< d\n< e\n---\n> B\n");

    println!("sysbox_diff::test_bin_shim PASS");
}

pub fn run_test() {
    let root: PathBuf = std::env::temp_dir().join("systest-sysbox-diff");
    build_files(&root);

    test_formats(&root);
    test_missing_newline(&root);
    test_edit_script(&root);
    test_huge_context(&root);
    test_absent_operands(&root);
    test_labels(&root);
    test_reports(&root);
    test_ignoring(&root);
    test_directories(&root);
    test_headers(&root);
    test_stdin(&root);
    test_errors(&root);
    test_bin_shim(&root);

    std::fs::remove_dir_all(&root).unwrap();
    println!("sysbox_diff::run_test PASS");
}
