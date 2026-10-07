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
