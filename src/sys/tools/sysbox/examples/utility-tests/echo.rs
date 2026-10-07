use super::{expect, run};
use std::path::Path;

pub fn run_test(root: &Path) {
    for (args, output) in [
        (&["echo"][..], &b"\n"[..]),
        (&["echo", "", "two", ""], b" two \n"),
        (&["echo", "-n", "one", "two"], b"one two"),
        (&["echo", r"a\nb"], b"a\\nb\n"),
        (&["echo", "-e", r"a\nb"], b"a\nb\n"),
        (&["echo", "-eE", r"a\nb"], b"a\\nb\n"),
        (&["echo", "-En", "-e", r"a\nb"], b"a\nb"),
        (&["echo", "--", "-n"], b"-- -n\n"),
        (&["echo", "-nx", "-n"], b"-nx -n\n"),
        (&["echo", "--help", "text"], b"--help text\n"),
        (&["echo", "-e", r"a\cb", "ignored"], b"a"),
        (
            &["echo", "-e", r"\0\0377\777\x41\xF\xg\q\"],
            b"\0\xff\xffA\x0f\\xg\\q\\\n",
        ),
        (&["echo", "-e", "é\\t字"], "é\t字\n".as_bytes()),
    ] {
        expect(run(root, args, b""), 0, output, b"");
    }
    let long = "x".repeat(40_000);
    let output = format!("{long} {long}\n");
    expect(
        run(root, &["echo", &long, &long], b""),
        0,
        output.as_bytes(),
        b"",
    );
    let output = std::process::Command::new(std::env::args().nth(1).unwrap())
        .args(["echo", "-e", r"a\nb"])
        .env("POSIXLY_CORRECT", "1")
        .output()
        .unwrap();
    expect(output, 0, b"-e a\nb\n", b"");
    if cfg!(target_os = "motor") {
        let output = std::process::Command::new("/system/bin/echo")
            .args(["-n", "wrapper"])
            .output()
            .unwrap();
        expect(output, 0, b"wrapper", b"");
        let output = std::process::Command::new("/system/bin/rush")
            .args(["-c", "echo 'a\\nb'"])
            .output()
            .unwrap();
        expect(output, 0, b"a\nb\n", b"");
    }
    println!("sysbox utility-tests: echo PASS");
}
