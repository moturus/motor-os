use super::{expect, run};
use std::path::Path;

pub fn basic(root: &Path) {
    let executable = std::env::current_exe().unwrap();
    let executable = executable.to_str().unwrap();
    for (flags, input, output) in [
        (
            &[][..],
            &b"a \"b c\" 'd e' x\\ y\n"[..],
            &b"[\"a\", \"b c\", \"d e\", \"x y\"]\n"[..],
        ),
        (
            &["-0"],
            b"a b\0'quote'\0; touch injected\0\0",
            b"[\"a b\", \"'quote'\", \"; touch injected\", \"\"]\n",
        ),
        (&[], b"", b"[]\n"),
        (&["-r"], b"", b""),
    ] {
        let args: Vec<_> = std::iter::once("xargs")
            .chain(flags.iter().copied())
            .chain([executable, "--probe", "args"])
            .collect();
        expect(run(root, &args, input), 0, output, b"");
    }
    expect(run(root, &["xargs"], b"a 'b c'\n"), 0, b"a b c\n", b"");
    expect(run(root, &["xargs"], b""), 0, b"\n", b"");
    expect(run(root, &["xargs", "-r"], b""), 0, b"", b"");
    expect(
        run(root, &["xargs", "echo"], b"a 'b c'\n"),
        0,
        b"a b c\n",
        b"",
    );
    assert!(!root.join("injected").exists());
    expect(
        run(
            root,
            &["xargs", "-0", executable, "--probe", "args"],
            b"\xff\0",
        ),
        1,
        b"",
        b"xargs: argument is not valid UTF-8\n",
    );
    for (status, code, stderr) in [
        ("7", 123, String::new()),
        (
            "255",
            124,
            format!("xargs: {executable}: exited with status 255; aborting\n"),
        ),
    ] {
        expect(
            run(
                root,
                &["xargs", executable, "--probe", "status", status],
                b"item",
            ),
            code,
            b"ran\n",
            stderr.as_bytes(),
        );
    }
    for (input, quote) in [(&b"'bad"[..], "single"), (&b"\"bad"[..], "double")] {
        expect(run(root, &["xargs", executable, "--probe", "args"], input), 1, b"", format!("xargs: unmatched {quote} quote; by default quotes are special to xargs unless you use the -0 option\n").as_bytes());
    }
    for program in ["missing-xargs-program", "./missing-xargs-program"] {
        expect(
            run(root, &["xargs", program], b"item"),
            127,
            b"",
            format!("xargs: {program}: No such file or directory\n").as_bytes(),
        );
    }
    let denied = root.join("xargs-no-execute");
    std::fs::write(&denied, b"not executable\n").unwrap();
    #[cfg(target_os = "motor")]
    moto_rt::fs::set_perm(
        denied.to_str().unwrap(),
        moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE,
    )
    .unwrap();
    expect(
        run(root, &["xargs", denied.to_str().unwrap()], b"item"),
        126,
        b"",
        format!("xargs: {}: Permission denied\n", denied.display()).as_bytes(),
    );
    let input = b"ab ".repeat(50_000);
    let output = run(root, &["xargs", executable, "--probe", "count"], &input);
    let counts: Vec<usize> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    assert_eq!(counts.len(), 2, "{output:?}");
    assert_eq!(counts.iter().sum::<usize>(), 50_000, "{output:?}");
    assert!(
        counts.iter().all(|count| count * 3 < 128 * 1024),
        "{output:?}"
    );
    let bytes = output.stdout.clone();
    expect(output, 0, &bytes, b"");
    println!("sysbox utility-tests: xargs basic PASS");
}

pub fn batches(root: &Path) {
    let executable = std::env::current_exe().unwrap();
    let executable = executable.to_str().unwrap();
    expect(run(root, &["xargs", "-n2"], b"a b c"), 0, b"a b\nc\n", b"");
    #[cfg(target_os = "motor")]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("/system/bin/xargs")
            .args(["-n2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"a b c").unwrap();
        expect(child.wait_with_output().unwrap(), 0, b"a b\nc\n", b"");
    }
    for (flags, input, output) in [
        (
            &["-n2"][..],
            &b"a b c"[..],
            &b"[\"a\", \"b\"]\n[\"c\"]\n"[..],
        ),
        (&["-d:", "-n2"], b"a b:'c':", b"[\"a b\", \"'c'\"]\n"),
        (&["-d="], b"a=b=c", b"[\"a\", \"b\", \"c\"]\n"),
        (&["--delimiter=="], b"a=b=c", b"[\"a\", \"b\", \"c\"]\n"),
        (
            &["--delimiter=\\n", "--max-args=1"],
            b"a b\nx\n",
            b"[\"a b\"]\n[\"x\"]\n",
        ),
        (&["-n", " \t+2"], b"a b c", b"[\"a\", \"b\"]\n[\"c\"]\n"),
        (
            &["-n99999999999999999999999999999999"],
            b"a b",
            b"[\"a\", \"b\"]\n",
        ),
    ] {
        let args: Vec<_> = std::iter::once("xargs")
            .chain(flags.iter().copied())
            .chain([executable, "--probe", "args"])
            .collect();
        expect(run(root, &args, input), 0, output, b"");
    }
    expect(
        run(
            root,
            &["xargs", "-n1", executable, "--probe", "status", "7"],
            b"a b c",
        ),
        123,
        b"ran\nran\nran\n",
        b"",
    );
    expect(
        run(
            root,
            &["xargs", "-n1", executable, "--probe", "status", "255"],
            b"a b",
        ),
        124,
        b"ran\n",
        format!("xargs: {executable}: exited with status 255; aborting\n").as_bytes(),
    );
    expect(
        run(root, &["xargs", "-n0", executable, "--probe", "args"], b""),
        1,
        b"",
        b"xargs: max-args must be a positive integer\n",
    );
    expect(
        run(
            root,
            &["xargs", "-n=2", executable, "--probe", "args"],
            b"a b",
        ),
        1,
        b"",
        b"xargs: max-args must be a positive integer\n",
    );
    println!("sysbox utility-tests: xargs batches PASS");
}

pub fn replacement(root: &Path) {
    let executable = std::env::current_exe().unwrap();
    let executable = executable.to_str().unwrap();
    expect(
        run(
            root,
            &["xargs", "-I%", executable, "--probe", "args", "pre%/%post"],
            b"a b\nc",
        ),
        0,
        b"[\"prea b/a bpost\"]\n[\"prec/cpost\"]\n",
        b"",
    );
    expect(
        run(
            root,
            &["xargs", "-0", "-I{}", executable, "--probe", "args", "{}"],
            b"a b\0; touch replaced\0",
        ),
        0,
        b"[\"a b\"]\n[\"; touch replaced\"]\n",
        b"",
    );
    assert!(!root.join("replaced").exists());
    expect(
        run(
            root,
            &["xargs", "-I=", executable, "--probe", "args", "pre=post"],
            b"x\ny\n",
        ),
        0,
        b"[\"prexpost\"]\n[\"preypost\"]\n",
        b"",
    );

    expect(
        run(
            root,
            &["xargs", "-I%", executable, "--probe", "args", "%"],
            b"",
        ),
        0,
        b"",
        b"",
    );
    expect(
        run(
            root,
            &["xargs", "-0t", executable, "--probe", "args"],
            b"a b\0$(echo bad)\0a'b\0",
        ),
        0,
        b"[\"a b\", \"$(echo bad)\", \"a'b\"]\n",
        format!("{executable} --probe args 'a b' '$(echo bad)' 'a'\\''b'\n").as_bytes(),
    );
    let repeated = "%".repeat(20_000);
    let input = vec![b'x'; 20_000];
    expect(
        run(
            root,
            &["xargs", "-I%", executable, "--probe", "args", &repeated],
            &input,
        ),
        1,
        b"",
        b"xargs: argument list too long\n",
    );
    expect(
        run(root, &["xargs", "-n2", "-I%", executable, "--probe", "args", "%"], b"a b\nc"),
        0, b"[\"a b\"]\n[\"c\"]\n",
        b"xargs: warning: options --max-args and --replace/-I/-i are mutually exclusive, ignoring previous --max-args value\n",
    );
    for marker in ["{}", "echo", "sysbox"] {
        expect(
            run(root, &["xargs", "-I", marker], b"word\nnext\n"),
            0,
            b"\n\n",
            b"",
        );
    }
    println!("sysbox utility-tests: xargs replacement PASS");
}
