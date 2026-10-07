use super::{expect, run};
use std::path::Path;
use std::process::{Command, Stdio};

pub fn run_test(root: &Path) {
    for (args, input, output) in [
        (&[][..], &b"b\na\na\nb\n"[..], &b"b\na\nb\n"[..]),
        (&["-c"], b"b\nb\na", b"      2 b\n      1 a\n"),
        (&["-d"], b"b\nb\na\nc\nc", b"b\nc\n"),
        (&["-u"], b"b\nb\na\nc\nc", b"a\n"),
        (&["-du"], b"b\nb\na\nc\nc", b""),
        (&["-ci"], b"Ab\naB\nx\nX", b"      2 Ab\n      2 x\n"),
        (&["--repeated", "--ignore-case"], b"b\nB\na", b"b\n"),
        (&[], b"\n\n\na\n\n", b"\na\n\n"),
        (&[], b"\xff\0x\n\xff\0x\n\x80\r", b"\xff\0x\n\x80\r\n"),
        (&[], b"", b""),
        (&[], b"a", b"a\n"),
    ] {
        let arguments: Vec<_> = std::iter::once("uniq")
            .chain(args.iter().copied())
            .collect();
        expect(run(root, &arguments, input), 0, output, b"");
    }
    let streaming = b"a\nb\n".repeat(20_000);
    expect(run(root, &["uniq"], &streaming), 0, &streaming, b"");
    let long = vec![b'x'; 70000];
    let mut input = long.clone();
    input.push(b'\n');
    input.extend(&long);
    let mut counted = b"      2 ".to_vec();
    counted.extend(&long);
    counted.push(b'\n');
    expect(run(root, &["uniq", "-c"], &input), 0, &counted, b"");
    std::fs::write(root.join("one *"), b"b\nb\na").unwrap();
    expect(run(root, &["uniq", "one *"], b""), 0, b"b\na\n", b"");
    expect(run(root, &["uniq", "one *", "-c", "out"], b""), 0, b"", b"");
    assert_eq!(
        std::fs::read(root.join("out")).unwrap(),
        b"      2 b\n      1 a\n"
    );
    expect(
        run(root, &["uniq", "-", "-"], b"b\nb\na"),
        0,
        b"b\na\n",
        b"",
    );
    std::fs::write(root.join("-c"), b"b\nb\na").unwrap();
    expect(run(root, &["uniq", "--", "-c"], b""), 0, b"b\na\n", b"");
    for flag in ["-z", "-D", "--unknown"] {
        expect(
            run(root, &["uniq", flag, "one *", "out"], b""),
            1,
            b"",
            format!("uniq: unsupported option '{flag}'\n").as_bytes(),
        );
        assert_eq!(
            std::fs::read(root.join("out")).unwrap(),
            b"      2 b\n      1 a\n"
        );
    }
    expect(
        run(root, &["uniq", "missing", "out"], b""),
        1,
        b"",
        b"uniq: missing: No such file or directory\n",
    );
    assert_eq!(
        std::fs::read(root.join("out")).unwrap(),
        b"      2 b\n      1 a\n"
    );
    std::fs::create_dir(root.join("standard input")).unwrap();
    expect(
        run(root, &["uniq", "standard input"], b""),
        1,
        b"",
        b"uniq: error reading 'standard input': Is a directory\n",
    );
    let wrapper = Command::new("/system/bin/uniq")
        .arg("one *")
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    expect(wrapper, 0, b"b\na\n", b"");
    println!("sysbox utility-tests: uniq PASS");
}
