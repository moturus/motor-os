//! Real sysbox command regressions; run against the installed native executable.
#[path = "utility-tests/cut.rs"]
mod cut;
#[path = "utility-tests/echo.rs"]
mod echo;
#[path = "utility-tests/sort-keys.rs"]
mod sort_key_flags;
#[path = "utility-tests/tr.rs"]
mod tr;
#[path = "utility-tests/uniq.rs"]
mod uniq;
#[path = "utility-tests/xargs.rs"]
mod xargs;
#[path = "utility-tests/xargs-probe.rs"]
mod xargs_probe;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(root: &Path, arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(std::env::args().nth(1).unwrap())
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || pipe.write_all(input));
        let output = child.wait_with_output().unwrap();
        if let Err(error) = writer.join().unwrap() {
            assert!(
                output.status.code() != Some(0) && error.kind() == std::io::ErrorKind::BrokenPipe,
                "{output:?}: {error}"
            );
        }
        output
    })
}

// Debug Motor runtimes deliberately log to the same stderr pipe. Recognize only
// their timestamped DEBUG records; command diagnostics and other records remain.
fn runtime_debug(line: &[u8]) -> bool {
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    let Some((stamp, source)) = line.trim_start().split_once(": DEBUG lib/rt.vdso/src/") else {
        return false;
    };
    let Some((seconds, millis)) = stamp.split_once(':') else {
        return false;
    };
    let Some((file, location)) = source.split_once(':') else {
        return false;
    };
    let Some((number, _message)) = location.split_once(": ") else {
        return false;
    };
    !seconds.is_empty()
        && seconds.bytes().all(|byte| byte.is_ascii_digit())
        && millis.len() == 3
        && millis.bytes().all(|byte| byte.is_ascii_digit())
        && file.ends_with(".rs")
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[track_caller]
fn expect(output: Output, code: i32, bytes: &[u8], diagnostic: &[u8]) {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    assert_eq!(output.stdout, bytes, "{output:?}");
    let messages: Vec<u8> = output
        .stderr
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| !(cfg!(all(target_os = "motor", debug_assertions)) && runtime_debug(line)))
        .flatten()
        .copied()
        .collect();
    assert_eq!(messages, diagnostic, "{output:?}");
}

fn sort_fields(root: &Path) {
    for (args, input, output) in [
        (&["sort", "-k2,2"][..], &b"x b\nz a"[..], &b"z a\nx b\n"[..]),
        (
            &["sort", "-t:", "-k2,2", "-n"],
            b"a:10\nb:2\nc:",
            b"c:\nb:2\na:10\n",
        ),
        (
            &["sort", "--field-separator=:", "--key=2,2", "-s"],
            b"z:a\nx:a\na:b",
            b"z:a\nx:a\na:b\n",
        ),
        (
            &["sort", "-t:", "-k2,2", "-u"],
            b"z:a\nx:a\na:b",
            b"z:a\na:b\n",
        ),
        (
            &["sort", "-t:", "-k2,2", "-k1,1"],
            b"z:a\nx:a\na:b",
            b"x:a\nz:a\na:b\n",
        ),
        (&["sort", "-k1.2,1.2"], b"x2\nz1\na3", b"z1\nx2\na3\n"),
        (&["sort", "-t\\0", "-k2,2"], b"a\0z\nz\0a", b"z\0a\na\0z\n"),
        (&["sort", "-k2,1"], b"b 2\na 1", b"a 1\nb 2\n"),
        (
            &["sort", "-k999999999999999999999999999999999", "-s"],
            b"z\na",
            b"z\na\n",
        ),
    ] {
        expect(run(root, args, input), 0, output, b"");
    }
    expect(
        run(root, &["sort", "-t:", "-k2,2", "-nc"], b"a:10\nz:2"),
        1,
        b"",
        b"sort: -:2: disorder: z:2\n",
    );
    std::fs::write(root.join("result"), b"keep").unwrap();
    expect(
        run(root, &["sort", "-oresult", "-k0"], b""),
        2,
        b"",
        b"sort: field number is zero: invalid field specification '0'\n",
    );
    assert_eq!(std::fs::read(root.join("result")).unwrap(), b"keep");
    expect(
        run(
            root,
            &["sort", "--output=result", "-t:", "-k2,2", "-n"],
            b"a:10\nb:2",
        ),
        0,
        b"",
        b"",
    );
    assert_eq!(std::fs::read(root.join("result")).unwrap(), b"b:2\na:10\n");
    println!("sysbox utility-tests: sort fields PASS");
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--probe") {
        xargs_probe::probe();
        return;
    }
    let root = std::env::temp_dir().join(format!("sysbox-utility-tests-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    eprintln!("sysbox utility test artifacts: {}", root.display());
    sort_fields(&root);
    sort_key_flags::run_test(&root);
    uniq::run_test(&root);
    cut::bytes(&root);
    cut::fields(&root);
    tr::one_set(&root);
    tr::translation(&root);
    xargs::basic(&root);
    xargs::batches(&root);
    xargs::replacement(&root);
    echo::run_test(&root);
    std::fs::remove_dir_all(root).unwrap();
    println!("sysbox utility-tests: ALL PASS");
}
