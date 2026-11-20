use super::{expect, run};
use std::path::Path;

pub fn run_test(root: &Path) {
    for (args, input, output) in [
        (
            &["sort", "--field-separator=:", "--key=2,2n"][..],
            &b"a:10\nb:2"[..],
            &b"b:2\na:10\n"[..],
        ),
        (
            &["sort", "-t:", "-k2,2n", "-s"],
            b"c:2\nb:2\na:10",
            b"c:2\nb:2\na:10\n",
        ),
        (
            &["sort", "-t:", "-k2,2n", "-u"],
            b"b:2\nc:2\na:10",
            b"b:2\na:10\n",
        ),
        (
            &["sort", "-t:", "-k2,2n", "-k1,1r"],
            b"a:2\nb:2\nc:1",
            b"c:1\nb:2\na:2\n",
        ),
        (
            &["sort", "-t:", "-k2,2nr"],
            b"a:2\nb:10\nc:1",
            b"b:10\na:2\nc:1\n",
        ),
        (
            &["sort", "-r", "-t:", "-k2,2n"],
            b"a:2\nc:1\nb:2",
            b"c:1\nb:2\na:2\n",
        ),
        (
            &["sort", "-t:", "-k2,2h"],
            b"a:2G\nb:1000M\nc:1K",
            b"c:1K\nb:1000M\na:2G\n",
        ),
        (&["sort", "-nh", "-k1f"], b"2\n10", b"10\n2\n"),
        (
            &["sort", "-k2b,2"],
            b"z   a\nx b\ny  a",
            b"y  a\nz   a\nx b\n",
        ),
        (
            &["sort", "-t:", "-k2,2f", "-u"],
            b"z:B\nx:b\ny:A",
            b"y:A\nz:B\n",
        ),
    ] {
        expect(run(root, args, input), 0, output, b"");
    }
    for blank in [" ", "\t", "\n", "\x0b", "\x0c", "\r"] {
        let key = format!("{blank}2.{blank}1,{blank}2.{blank}0n");
        expect(
            run(root, &["sort", "-k", &key], b"a 10\nb 2"),
            0,
            b"b 2\na 10\n",
            b"",
        );
    }
    std::fs::write(root.join("key-out"), b"keep").unwrap();
    for (specification, error) in [
        ("1nh", "options '-hn' are incompatible"),
        ("1z", "unsupported key option 'z' in '1z'"),
    ] {
        expect(
            run(root, &["sort", "-o", "key-out", "-k", specification], b""),
            2,
            b"",
            format!("sort: {error}\n").as_bytes(),
        );
        assert_eq!(std::fs::read(root.join("key-out")).unwrap(), b"keep");
    }
    println!("sysbox utility-tests: sort key flags PASS");
}
