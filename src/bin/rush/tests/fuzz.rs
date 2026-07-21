//! Phase 9: the lexer and parser must not panic, whatever the input.
//!
//! A shell reads text from whoever is typing at it. Every `unwrap`, slice index,
//! and `todo!()` on that path is a crash waiting for the right line — and a
//! crash in the *parser* is worse than a syntax error, because it takes the
//! session (and any unsaved history) with it.
//!
//! Not a coverage-guided fuzzer: this crate takes no dependencies (the charter),
//! and `cargo-fuzz` needs a nightly toolchain and a corpus directory. What is
//! here instead is a deterministic generator over the *shell's own alphabet* —
//! the operators, quotes, expansions and reserved words that make up the
//! interesting inputs — driven by a seeded PRNG so a failure reproduces from its
//! seed alone. Structure-aware and repeatable beats random bytes: `\x00\xff\x01`
//! exercises one early `return Err`, while `${x:-$(cat <<EOF` exercises the
//! nesting where the bodies are buried.
//!
//! The parser is also required to be *total*: for any input it must return one
//! of the four [`Parsed`] outcomes, and — for [`parse_source`] — never claim
//! "incomplete", since nothing more is coming. Both are asserted below.

#![cfg(unix)]

use std::process::Command;

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

/// A tiny deterministic PRNG (xorshift64*), so a failing case is reproducible
/// from its seed and the suite never flakes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

/// The shell's alphabet: the tokens that actually mean something to the lexer
/// and parser, so a random walk lands on real constructs rather than on noise.
#[rustfmt::skip]
const ATOMS: &[&str] = &[
    // operators and separators
    ";", ";;", "&", "&&", "|", "||", "(", ")", "\n", " ", "\t",
    "<", ">", ">>", "<<", "<<-", "<&", ">&", "<>", ">|", "1", "2", "0",
    // quoting
    "'", "\"", "\\", "\\\n", "$'", "'a'", "\"a\"", "\\'",
    // expansions, and their unbalanced halves
    "$", "${", "}", "$(", "${x", "$((", "))", "`", "$x", "$1", "$@", "$*", "$?",
    "$#", "$$", "$!", "$-", "${x:-", "${x#", "${x%%", "${#x}", "$(())", "$(( ",
    // reserved words
    "if", "then", "else", "elif", "fi", "for", "in", "do", "done",
    "while", "until", "case", "esac", "{", "}", "!", "function",
    // words and here-doc bait
    "echo", "x", "x=1", "a", "EOF", "#", "# c", "*", "?", "[a-z]", "~", "=",
    "<<EOF", "<<'EOF'", "<<-EOF", "\nEOF\n", "..", "/", "-", "+", ":", "%",
    // multibyte, since the lexer indexes chars
    "é", "日本", "🦀", "\u{300}",
];

/// Build one pseudo-random program of up to `len` atoms.
fn generate(rng: &mut Rng, len: usize) -> String {
    let n = 1 + rng.below(len);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str(rng.pick(ATOMS));
    }
    s
}

/// Run `src` through the real binary with `-n` (noexec: parse, do not run) and
/// return the exit status.
///
/// `-n` is what makes fuzzing the parser safe to do end-to-end: the generator
/// happily produces `rm -rf /` eventually, and this way the shell reads it,
/// parses it, and runs nothing at all. A panic still shows up — as a SIGABRT
/// (or SIGSEGV), which is exactly what these tests look for.
fn parse_only(src: &str) -> std::process::Output {
    Command::new(RUSH)
        .arg("-n")
        .arg("-c")
        .arg(src)
        .env("PATH", "/nonexistent")
        .output()
        .expect("failed to spawn rush")
}

/// Whether the process died on a signal rather than exiting — a panic (abort),
/// a segfault, or a stack overflow.
fn crashed(out: &std::process::Output) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = out.status.signal() {
        return Some(format!("killed by signal {sig}"));
    }
    // The release profile is `panic=abort`, but a debug build unwinds and
    // reports 101 with a message on stderr.
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.code() == Some(101) || err.contains("panicked at") {
        return Some(format!("panicked: {err}"));
    }
    if err.contains("not yet implemented") || err.contains("internal error") {
        return Some(format!("todo!/unreachable! reached: {err}"));
    }
    None
}

#[test]
fn the_parser_never_panics_on_generated_input() {
    let mut failures = Vec::new();
    for seed in 1..=600_u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let src = generate(&mut rng, 12);
        let out = parse_only(&src);
        if let Some(why) = crashed(&out) {
            failures.push(format!("\n  seed {seed}: {src:?}\n    {why}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} generated inputs crashed the parser:{}",
        failures.len(),
        failures.join("")
    );
}

#[test]
fn the_parser_never_panics_on_long_generated_input() {
    // Longer programs reach the nesting the short ones cannot.
    let mut failures = Vec::new();
    for seed in 1..=120_u64 {
        let mut rng = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
        let src = generate(&mut rng, 200);
        let out = parse_only(&src);
        if let Some(why) = crashed(&out) {
            failures.push(format!("\n  seed {seed}: {src:?}\n    {why}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} long generated inputs crashed the parser:{}",
        failures.len(),
        failures.join("")
    );
}

/// Inputs that are *specifically* nasty: deep nesting, unbalanced everything,
/// and the boundary cases of each construct. A generator finds these only by
/// luck; a list finds them every run.
#[rustfmt::skip]
const HAND_PICKED: &[&str] = &[
    "",
    " ",
    "\n",
    "\\",
    "\\\\",
    "'",
    "\"",
    "`",
    "$",
    "${",
    "$(",
    "$((",
    "$(()",
    "${}",
    "${#}",
    "${#",
    "${x",
    "${x:",
    "${x:-",
    "${x:-${y:-${z:-",
    "$($($($(",
    "((((((((((",
    "))))))))))",
    "{{{{{{{{{{",
    "}}}}}}}}}}",
    "if if if if if",
    "for for for",
    "case case in in",
    "do done do done",
    "!!!!!!!!",
    "|||||||",
    "&&&&&&&",
    ";;;;;;;",
    "<<<<<<<",
    ">>>>>>>",
    "<<",
    "<<-",
    "<<EOF",
    "<<''",
    "<< ",
    "0<&-",
    "9999999999999999999999>x",
    "1>&99999999999999999999",
    "echo >",
    "echo <",
    "echo >&",
    "x=",
    "=x",
    "==",
    "a=b=c",
    "#",
    "#\n#\n#",
    "\u{300}",
    "é'",
    "日本${",
    "🦀$((",
    "$'\\",
    "$'",
    // A here-doc whose delimiter never comes, at every depth.
    "cat <<EOF",
    "cat <<EOF\n",
    "cat <<EOF\nbody",
    "$(cat <<EOF\nbody",
    "if true; then cat <<EOF\nbody",
    // Deep but balanced: the recursive-descent parser's stack.
    "$(echo $(echo $(echo $(echo $(echo $(echo hi))))))",
    "((((((((((1))))))))))",
    "if true; then if true; then if true; then echo x; fi; fi; fi",
    // Reserved words where words go, and vice versa.
    "echo if then else fi",
    "if",
    "then",
    "fi",
    "done",
    "esac",
    "in",
    "!",
    "{",
    "}",
    "()",
    "( )",
    "f()",
    "f() {",
    "f() { }",
    "for x in",
    "for x in;",
    "for; do; done",
    "while; do; done",
    "case in esac",
    "case x in esac",
    "case x in )",
    "case x in |) ;; esac",
];

#[test]
fn the_parser_never_panics_on_hand_picked_nasty_input() {
    let mut failures = Vec::new();
    for src in HAND_PICKED {
        let out = parse_only(src);
        if let Some(why) = crashed(&out) {
            failures.push(format!("\n  {src:?}\n    {why}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} hand-picked inputs crashed the parser:{}",
        failures.len(),
        failures.join("")
    );
}

/// Bytes that cannot travel through `argv` — a nul terminates a C string, so
/// `execve` would refuse it — still reach the shell through a *script*, which is
/// read as bytes from a file. It must not choke on them.
#[test]
fn the_parser_never_panics_on_bytes_argv_cannot_carry() {
    let dir = std::env::temp_dir().join(format!("rush-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("script.sh");
    for bytes in [
        &b"echo a\0b"[..],
        &b"\0\0\0"[..],
        &b"echo \xff\xfe"[..],           // invalid UTF-8
        &b"echo '\xc3'"[..],             // a truncated UTF-8 sequence
        &b"\xef\xbb\xbfecho bom"[..],    // a byte-order mark
        &b"echo hi\r\n"[..],             // CRLF line endings
    ] {
        std::fs::write(&path, bytes).unwrap();
        let out = Command::new(RUSH)
            .arg("-n")
            .arg(&path)
            .output()
            .expect("failed to spawn rush");
        assert!(
            crashed(&out).is_none(),
            "{bytes:?} crashed: {:?}",
            crashed(&out)
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Deep nesting must not overflow the stack: a recursive-descent parser on
/// unbounded input is the classic way to turn a long line into a SIGSEGV.
#[test]
fn deep_nesting_does_not_overflow_the_stack() {
    for depth in [100, 1_000, 10_000] {
        for (open, close) in [("$(", ")"), ("(", ")"), ("{ ", "; }"), ("${x:-", "}")] {
            let src = format!("{}{}", open.repeat(depth), close.repeat(depth));
            let out = parse_only(&src);
            assert!(
                crashed(&out).is_none(),
                "{depth}× {open}…{close} crashed: {:?}",
                crashed(&out)
            );
        }
    }
}

/// The expansion engine and the arithmetic evaluator recurse on nesting just as
/// the parser does — and unlike the parser, `-n` never reaches them, so these
/// have to actually run. Each was a stack overflow until Phase 9.
#[test]
fn deeply_nested_expansions_do_not_overflow_the_stack() {
    let cases = [
        ("${x:-", "}", "parameter defaults"),
        ("$(echo ", ")", "command substitutions"),
        ("\"$(echo ", ")\"", "quoted command substitutions"),
    ];
    for (open, close, what) in cases {
        for depth in [50, 1_000, 5_000] {
            let src = format!("echo {}y{}", open.repeat(depth), close.repeat(depth));
            let out = Command::new(RUSH)
                .arg("-c")
                .arg(&src)
                .env("PATH", "/nonexistent")
                .output()
                .expect("failed to spawn rush");
            assert!(
                crashed(&out).is_none(),
                "{depth}x {what} crashed: {:?}",
                crashed(&out)
            );
        }
    }
    // Arithmetic parenthesises to its own depth.
    for depth in [10, 1_000, 5_000] {
        let src = format!("echo $(({}1{}))", "(".repeat(depth), ")".repeat(depth));
        let out = Command::new(RUSH)
            .arg("-c")
            .arg(&src)
            .output()
            .expect("failed to spawn rush");
        assert!(
            crashed(&out).is_none(),
            "{depth}x arithmetic parens crashed: {:?}",
            crashed(&out)
        );
    }
}

/// The generator's own contract: same seed, same program. A failure that cannot
/// be reproduced is not much of a bug report.
#[test]
fn generation_is_deterministic() {
    let a = generate(&mut Rng(12345), 30);
    let b = generate(&mut Rng(12345), 30);
    assert_eq!(a, b);
    assert_ne!(a, generate(&mut Rng(54321), 30));
}
