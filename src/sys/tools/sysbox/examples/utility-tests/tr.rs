use super::{expect, run};
use std::path::Path;
pub fn one_set(root: &Path) {
    for (args, input, output) in [
        (
            &["tr", "-d", "0-9"][..],
            &b"a1b2\xff3\n"[..],
            &b"ab\xff\n"[..],
        ),
        (&["tr", "-s", "[:space:]"], b"a \t\t\n\n b", b"a \t\n b"),
        (&["tr", "-cd", "[:alnum:]"], b"a_1\xff \nB!", b"a1B"),
        (&["tr", "-cs", "a"], b"bbbaaaccc", b"baaac"),
        (&["tr", "-d", r"\000-\037"], b"a\0b\t\n\xff", b"ab\xff"),
        (&["tr", "-d", ""], b"\0\xffabc", b"\0\xffabc"),
        (&["tr", "-d", "[:]"], b"[:]:]abc", b"abc"),
        (&["tr", "-d", "[="], b"x[]*=ab", b"x]*ab"),
        (&["tr", "-d", "[*]"], b"x[]*=ab", b"x=ab"),
        (&["tr", "-d", "[aa*]"], b"x[]*=ab", b"x=b"),
        (&["tr", "-d", r"[\*]"], b"x[]*=ab", b"x=ab"),
        (&["tr", "-d", "[:space:]"], b"a \t\n\r\x0b\x0cb", b"ab"),
    ] {
        expect(run(root, args, input), 0, output, b"");
    }
    expect(
        run(root, &["tr", "-d", "z-a"], b""),
        1,
        b"",
        b"tr: range-endpoints of 'z-a' are in reverse collating sequence order\n",
    );
    for (set, diagnostic) in [
        ("[::]", "missing character class name '[::]'"),
        ("[:]:]", "invalid character class ']'"),
    ] {
        expect(
            run(root, &["tr", "-d", set], b"abc"),
            1,
            b"",
            format!("tr: {diagnostic}\n").as_bytes(),
        );
    }
    for set in ["[=a=]", r"[\]*]"] {
        expect(
            run(root, &["tr", "-d", set], b"abc"),
            1,
            b"",
            b"tr: unsupported equivalence or repetition construct\n",
        );
    }
    let input = vec![b' '; 65_537];
    expect(run(root, &["tr", "-s", "[:blank:]"], &input), 0, b" ", b"");
    let input = b"abc\xff".repeat(20_000);
    expect(run(root, &["tr", "-d", ""], &input), 0, &input, b"");
    println!("sysbox utility-tests: tr one set PASS");
}
pub fn translation(root: &Path) {
    for (args, input, output) in [
        (
            &["tr", "[:lower:]", "[:upper:]"][..],
            &b"aZ\0\xffz"[..],
            &b"AZ\0\xffZ"[..],
        ),
        (&["tr", "a-c", "XY"], b"abcab\n", b"XYYXY\n"),
        (
            &["tr", "-cs", "[:alnum:]", r"\n"],
            b"a _!b\n\nC",
            b"a\nb\nC",
        ),
        (&["tr", "-ds", "a", "b"], b"abbabbbc", b"bc"),
        (&["tr", "", ""], b"abc", b"abc"),
        (&["tr", "a", "abc[:lower:]"], b"aZ", b"aZ"),
        (&["tr", "-c", "a", "[:upper:]abc"], b"\0\x01ab", b"ABac"),
    ] {
        expect(run(root, args, input), 0, output, b"");
    }
    println!("sysbox utility-tests: tr translation PASS");
}
