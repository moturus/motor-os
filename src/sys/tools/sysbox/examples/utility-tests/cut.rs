use super::{expect, run};
use std::path::Path;
pub fn bytes(root: &Path) {
    for (args, input, output) in [
        (
            &["cut", "-b", "1,3-4"][..],
            &b"abcdef\nz"[..],
            &b"acd\nz\n"[..],
        ),
        (&["cut", "-c2"], b"\xc3\xa9x\na:b", b"\xa9\n:\n"),
        (&["cut", "-b", "3,1,1-2"], b"abcd", b"abc\n"),
        (
            &["cut", "--bytes=2-", "--complement"],
            b"abc\n\nxy",
            b"a\n\nx\n",
        ),
        (&["cut", "-b", "-2"], b"abcd", b"ab\n"),
        (&["cut", "-b", "18446744073709551614"], b"abc", b"\n"),
    ] {
        expect(run(root, args, input), 0, output, b"");
    }
    expect(run(root,&["cut","-b0"],b""),1,b"",b"cut: byte/character positions are numbered from 1\nTry 'cut --help' for more information.\n");
    std::fs::write(root.join("cut *"), b"abc\nxyz").unwrap();
    expect(run(root, &["cut", "-b2", "cut *"], b""), 0, b"b\ny\n", b"");
    expect(
        run(root, &["cut", "-b2", "missing-cut", "cut *"], b""),
        1,
        b"b\ny\n",
        b"cut: missing-cut: No such file or directory\n",
    );
    std::fs::create_dir(root.join("cut-directory")).unwrap();
    expect(
        run(root, &["cut", "-b1", "cut-directory"], b""),
        1,
        b"",
        b"cut: cut-directory: Is a directory\n",
    );
    for (specification, error) in [
        ("3-1", "invalid decreasing range"),
        (
            "18446744073709551615",
            "byte/character offset '18446744073709551615' is too large",
        ),
    ] {
        expect(
            run(root, &["cut", "-b", specification], b""),
            1,
            b"",
            format!("cut: {error}\nTry 'cut --help' for more information.\n").as_bytes(),
        );
    }
    println!("sysbox utility-tests: cut bytes PASS");
}
pub fn fields(root: &Path) {
    for (args, input, output) in [
        (
            &["cut", "-f2", "-d:"][..],
            &b"a:b:c\nd::f\ng"[..],
            &b"b\n\ng\n"[..],
        ),
        (&["cut", "-f2", "-d:", "-s"], b"a:b\ng\nh:i:j", b"b\ni\n"),
        (&["cut", "-f1,3", "--delimiter=:"], b"a:b:c", b"a:c\n"),
        (
            &["cut", "-f2", "-d:", "--complement"],
            b"a:b:c\nx:y",
            b"a:c\nx\n",
        ),
        (&["cut", "-f2", "-d", ""], b"a\0b\nx", b"b\nx\n"),
        (&["cut", "-f2", "-d\n"], b"a\nb\nc\n", b"b\n"),
        (&["cut", "-d=", "-f2"], b"a=b\0c\n", b"b\0c\n"),
        (
            &["cut", "--delimiter==", "--fields=2"],
            b"a=b\0c\n",
            b"b\0c\n",
        ),
        (&["cut", "-f1", "-d\n", "-s"], b"a\n", b"a\n"),
        (&["cut", "-f2", "-d\n", "-s"], b"a\n", b""),
        (&["cut", "-f1-", "-d:", "-s", "--complement"], b"a:b", b""),
    ] {
        expect(run(root, args, input), 0, output, b"");
    }
    for (args, diagnostic) in [
        (&["cut", "-f0"][..], "fields are numbered from 1"),
        (&["cut", "-f=1"], "invalid field range"),
        (&["cut", "-b=1"], "invalid byte or character range"),
        (
            &["cut", "-b1", "-d:"],
            "an input delimiter makes sense\n\tonly when operating on fields",
        ),
    ] {
        expect(
            run(root, args, b"a:b"),
            1,
            b"",
            format!("cut: {diagnostic}\nTry 'cut --help' for more information.\n").as_bytes(),
        );
    }
    println!("sysbox utility-tests: cut fields PASS");
}
