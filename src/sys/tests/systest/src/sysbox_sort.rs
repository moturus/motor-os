//! Native byte sorting, order diagnostics and literal shell operands.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(root: &Path, arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new("/system/bin/sysbox")
        .arg("sort")
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[track_caller]
fn expect(output: Output, code: i32, bytes: &[u8], diagnostic: Option<&[u8]>) {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    assert_eq!(output.stdout, bytes, "{output:?}");
    let messages: Vec<_> = output
        .stderr
        .split(|byte| *byte == b'\n')
        .filter(|line| line.starts_with(b"sort:"))
        .collect();
    assert_eq!(messages, diagnostic.into_iter().collect::<Vec<_>>());
}

pub fn run_test() {
    let root = std::env::temp_dir().join("systest-sysbox-sort");
    std::fs::create_dir(&root).unwrap();
    for (args, input, output) in [
        (&[][..], &b"b\na\0z\n\nz"[..], &b"\na\0z\nb\nz\n"[..]),
        (&["-r"], b"a\nb\n", b"b\na\n"),
        (&["-u"], b"b\na\nb\na", b"a\nb\n"),
        (&["-f"], b"b\nB\na\nA\n", b"A\na\nB\nb\n"),
        (&["-fs"], b"b\nB\na\nA\n", b"a\nA\nb\nB\n"),
        (&["-fu"], b"b\nB\na\nA\n", b"a\nb\n"),
        (&["-rfs"], b"b\nB\na\nA\n", b"b\nB\na\nA\n"),
        (&[], b"", b""),
        (&[], b"\n", b"\n"),
        (&[], b"\xff\n\x80\na", b"a\n\x80\n\xff\n"),
    ] {
        expect(run(&root, args, input), 0, output, None);
    }
    expect(run(&root, &["-c"], b"a\na\nb"), 0, b"", None);
    expect(
        run(&root, &["-c"], b"a\nz\nb"),
        1,
        b"",
        Some(b"sort: -:3: disorder: b"),
    );
    expect(
        run(&root, &["-cu"], b"a\na\nb"),
        1,
        b"",
        Some(b"sort: -:2: disorder: a"),
    );
    expect(run(&root, &["-rc"], b"b\na"), 0, b"", None);
    expect(
        run(&root, &["-c"], b"\xff\n\x80"),
        1,
        b"",
        Some(b"sort: -:2: disorder: \x80"),
    );
    std::fs::write(root.join("one *"), b"z\na").unwrap();
    std::fs::write(root.join("two"), b"b\na\n").unwrap();
    expect(run(&root, &["one *", "two"], b""), 0, b"a\na\nb\nz\n", None);
    expect(
        run(&root, &["one *", "-r", "-"], b"b"),
        0,
        b"z\nb\na\n",
        None,
    );
    expect(run(&root, &["-o", "one *", "one *"], b""), 0, b"", None);
    assert_eq!(std::fs::read(root.join("one *")).unwrap(), b"a\nz\n");
    expect(run(&root, &["-oout"], b"z\na"), 0, b"", None);
    assert_eq!(std::fs::read(root.join("out")).unwrap(), b"a\nz\n");
    for flag in ["-z", "-m", "--unknown"] {
        expect(
            run(&root, &["-o", "out", flag], b""),
            2,
            b"",
            Some(format!("sort: unsupported option '{flag}'").as_bytes()),
        );
        assert_eq!(std::fs::read(root.join("out")).unwrap(), b"a\nz\n");
    }
    expect(
        run(&root, &["-o"], b""),
        2,
        b"",
        Some(b"sort: option requires an argument -- 'o'"),
    );
    expect(
        run(&root, &["-c", "-o", "out"], b""),
        2,
        b"",
        Some(b"sort: options '-co' are incompatible"),
    );
    expect(
        run(&root, &["-c", "one *", "two"], b""),
        2,
        b"",
        Some(b"sort: extra operand 'two' not allowed with -c"),
    );
    expect(
        run(&root, &["-o", "out", "missing"], b""),
        2,
        b"",
        Some(b"sort: cannot read: missing: No such file or directory"),
    );
    assert_eq!(std::fs::read(root.join("out")).unwrap(), b"a\nz\n");
    std::fs::write(root.join("-f"), b"b\na").unwrap();
    expect(run(&root, &["--", "-f"], b""), 0, b"a\nb\n", None);
    let wrapper = Command::new("/system/bin/sort")
        .arg("one *")
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    expect(wrapper, 0, b"a\nz\n", None);
    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox_sort::run_test PASS");
}
