//! Phase 9: the POSIX conformance corpus.
//!
//! Every other test file states what rush *should* do and checks that it does.
//! This one does not state anything: it runs each case through **both rush and
//! `dash`** and requires them to agree. dash is the plan's reference shell, so
//! it — not a hand-written expectation — is the oracle, and the corpus can be
//! extended by anyone who can think of a snippet without having to know the
//! answer first.
//!
//! Compared per case: **stdout** and **exit status**, plus whether a diagnostic
//! was produced at all. Not the diagnostic's text: every shell words its errors
//! differently and POSIX does not specify them, so demanding rush say
//! "Syntax error: Unterminated quoted string" would be testing dash's prose.
//!
//! Cases live in [`CORPUS`], grouped by the section of POSIX.1-2017 §2 they
//! exercise. A case that rush *knowingly* answers differently goes in
//! [`DIVERGENCES`] with the reason — that list is the honest inventory of where
//! rush is not dash, and the test asserts each entry still diverges, so a
//! divergence that gets fixed cannot quietly stay documented as broken.
//!
//! Requires `dash` on the host; without it the suite skips rather than fails, so
//! that a checkout on a machine without dash still builds and tests clean.

use std::process::Command;

const RUSH: &str = env!("CARGO_BIN_EXE_rush");
const DASH: &str = "/bin/dash";

/// The corpus. One shell snippet per entry, each self-contained and hermetic:
/// no network, no state outside `$TMPDIR`, and no external command that a
/// minimal host might lack (beyond the coreutils dash's own test suite assumes).
#[rustfmt::skip]
const CORPUS: &[&str] = &[
    // ---- §2.2 quoting ----
    r#"echo 'single'"#,
    r#"echo "double""#,
    r#"echo a\ b"#,
    r#"echo "a'b""#,
    r#"echo 'a"b'"#,
    r#"echo "a\"b""#,
    r#"echo 'it'\''s'"#,
    r#"echo "\$notavar""#,
    r#"echo '$notavar'"#,
    r#"echo "a\\b""#,
    r#"echo 'a\b'"#,
    r#"echo "\n""#,
    r#"echo ""; echo "empty above""#,
    r#"x=; echo "[$x]""#,
    r#"echo "a
b""#,
    r#"echo a\
b"#,
    r#"echo "$(echo nested)""#,
    r#"echo "`echo backtick`""#,

    // ---- §2.5 parameters ----
    r#"x=1; echo $x"#,
    r#"x=1; echo ${x}"#,
    r#"x=1; echo ${x}2"#,
    r#"echo $notset"#,
    r#"echo "[$notset]""#,
    r#"set -- a b c; echo $#"#,
    r#"set -- a b c; echo $1 $2 $3"#,
    r#"set -- a b c; echo "$@""#,
    r#"set -- a b c; echo "$*""#,
    r#"set -- "a b" c; for i in "$@"; do echo "[$i]"; done"#,
    r#"set -- "a b" c; for i in "$*"; do echo "[$i]"; done"#,
    r#"set -- "a b" c; for i in $@; do echo "[$i]"; done"#,
    r#"set --; echo "[$*]" "[$@]" $#"#,
    r#"true; echo $?"#,
    r#"false; echo $?"#,
    r#"(exit 42); echo $?"#,
    r#"set -- a b c; shift; echo $@"#,
    r#"set -- a b c; shift 2; echo $@"#,

    // ---- §2.6.2 parameter expansion ----
    r#"echo ${notset:-default}"#,
    r#"x=; echo ${x:-default}"#,
    r#"x=; echo ${x-default}"#,
    r#"x=set; echo ${x:-default}"#,
    r#"echo ${notset:=assigned}; echo $notset"#,
    r#"x=v; echo ${x:+plus}"#,
    r#"echo ${notset:+plus}"#,
    r#"x=; echo ${x:+plus}"#,
    r#"x=; echo ${x+plus}"#,
    r#"x=hello; echo ${#x}"#,
    r#"set -- a b; echo ${#}"#,
    r#"x=a.b.c; echo ${x#*.}"#,
    r#"x=a.b.c; echo ${x##*.}"#,
    r#"x=a.b.c; echo ${x%.*}"#,
    r#"x=a.b.c; echo ${x%%.*}"#,
    r#"x=foo.txt; echo ${x%.txt}"#,
    r#"x=/a/b/c; echo ${x##*/}"#,
    r#"x=/a/b/c; echo ${x%/*}"#,
    r#"x=abc; echo ${x#x}"#,
    r#"echo ${notset:?}"#,
    r#"x=1; echo ${x:?}"#,

    // ---- §2.6.3 command substitution ----
    r#"echo $(echo hi)"#,
    r#"echo `echo hi`"#,
    r#"echo $(echo a; echo b)"#,
    r#"echo "$(echo a; echo b)""#,
    r#"x=$(echo trailing); echo "[$x]""#,
    r#"echo "[$(printf 'a\n\n\n')]""#,
    r#"echo $(false); echo $?"#,
    r#"x=$(false); echo $?"#,
    r#"echo $(echo $(echo deep))"#,
    r#"x=$(exit 7); echo $?"#,

    // ---- §2.6.4 arithmetic ----
    r#"echo $((1+2))"#,
    r#"echo $((2*3+4))"#,
    r#"echo $((2*(3+4)))"#,
    r#"echo $((7/2))"#,
    r#"echo $((7%2))"#,
    r#"echo $((-5))"#,
    r#"echo $((1<2))"#,
    r#"echo $((2<1))"#,
    r#"echo $((1==1))"#,
    r#"echo $((1!=1))"#,
    r#"echo $((1&&0))"#,
    r#"echo $((1||0))"#,
    r#"echo $((!0))"#,
    r#"echo $((1?2:3))"#,
    r#"x=5; echo $((x+1))"#,
    r#"x=5; echo $(($x+1))"#,
    r#"echo $((0x10))"#,
    r#"echo $((010))"#,
    r#"x=2; y=3; echo $((x*y))"#,
    r#"echo $((1 << 4))"#,
    r#"echo $((255 >> 4))"#,
    r#"echo $((6 & 3))"#,
    r#"echo $((6 | 3))"#,
    r#"echo $((6 ^ 3))"#,
    r#"set -- 4; echo $(($1*2))"#,
    // An arithmetic error is an *expansion* error: fatal to a non-interactive
    // shell (POSIX 2.8.1), not something to shrug off and carry on from.
    r#"echo $((1+))"#,
    r#"echo $((1+)); echo after"#,
    r#"x=$((1/0)); echo after"#,
    r#"echo $((1/0))"#,
    r#"echo $((1%0))"#,
    r#"echo $((x=))"#,
    r#"echo $((*))"#,
    r#"if false; then echo $((1+)); fi; echo ok"#,

    // ---- §2.6.5 field splitting ----
    r#"x="a b c"; for i in $x; do echo "[$i]"; done"#,
    r#"x="a b c"; for i in "$x"; do echo "[$i]"; done"#,
    r#"IFS=:; x=a:b:c; for i in $x; do echo "[$i]"; done"#,
    r#"IFS=:; x=a::c; for i in $x; do echo "[$i]"; done"#,
    r#"IFS=; x="a b"; for i in $x; do echo "[$i]"; done"#,
    r#"x="  spaced  out  "; for i in $x; do echo "[$i]"; done"#,
    r#"set -- $(echo a b c); echo $#"#,

    // ---- §2.7 redirection ----
    r#"echo out > "$T/f"; cat "$T/f""#,
    r#"echo one > "$T/f"; echo two >> "$T/f"; cat "$T/f""#,
    r#"echo in > "$T/f"; cat < "$T/f""#,
    r#"echo x > "$T/f"; read line < "$T/f"; echo "[$line]""#,
    r#"ls /nonexistent-xyz 2>/dev/null; echo $?"#,
    r#"echo msg 2>&1 1>/dev/null"#,
    r#"{ echo out; echo err >&2; } > "$T/f" 2>&1; cat "$T/f""#,
    r#"cat <<EOT
here
EOT"#,
    r#"cat <<'EOT'
$notexpanded
EOT"#,
    r#"x=v; cat <<EOT
$x
EOT"#,
    r#"cat <<-EOT
	tab-stripped
	EOT"#,
    r#"cat <<EOT
EOT"#,
    r#"cat <<EOT1; cat <<EOT2
one
EOT1
two
EOT2"#,
    r#"cat <<EOT
backtick: `echo sub`
EOT"#,

    // ---- §2.9.2 pipelines ----
    r#"echo hi | cat"#,
    r#"echo hi | cat | cat"#,
    r#"printf 'a\nb\nc\n' | tail -1"#,
    r#"false | true; echo $?"#,
    r#"true | false; echo $?"#,
    r#"! true; echo $?"#,
    r#"! false; echo $?"#,
    r#"echo a | while read x; do echo "[$x]"; done"#,
    r#"printf '1 2\n' | { read a b; echo "$a-$b"; }"#,

    // ---- §2.9.3 lists ----
    r#"true && echo yes"#,
    r#"false && echo no"#,
    r#"false || echo yes"#,
    r#"true || echo no"#,
    r#"true && echo a || echo b"#,
    r#"false && echo a || echo b"#,
    r#"echo one; echo two"#,
    r#"{ echo a; echo b; }"#,
    r#"(echo sub)"#,
    r#"x=outer; (x=inner); echo $x"#,
    r#"x=outer; { x=inner; }; echo $x"#,

    // ---- §2.9.4 compound commands ----
    r#"if true; then echo yes; fi"#,
    r#"if false; then echo no; else echo else; fi"#,
    r#"if false; then echo a; elif true; then echo b; else echo c; fi"#,
    r#"if false; then echo a; fi; echo $?"#,
    r#"for i in 1 2 3; do echo $i; done"#,
    r#"for i in; do echo $i; done; echo done"#,
    r#"set -- a b; for i; do echo $i; done"#,
    r#"i=0; while [ $i -lt 3 ]; do echo $i; i=$((i+1)); done"#,
    r#"i=0; until [ $i -ge 3 ]; do echo $i; i=$((i+1)); done"#,
    r#"for i in 1 2 3; do [ $i = 2 ] && continue; echo $i; done"#,
    r#"for i in 1 2 3; do [ $i = 2 ] && break; echo $i; done"#,
    r#"for i in 1 2; do for j in a b; do echo $i$j; done; done"#,
    r#"for i in 1 2; do for j in a b; do break 2; done; echo never; done; echo out"#,
    r#"case abc in a*) echo match;; *) echo no;; esac"#,
    r#"case abc in xyz) echo no;; abc) echo exact;; esac"#,
    r#"case abc in a|b|abc) echo alt;; esac"#,
    r#"case abc in ???) echo three;; esac"#,
    r#"case abc in [abc]*) echo class;; esac"#,
    r#"case x in y) echo no;; esac; echo $?"#,
    r#"case "a b" in "a b") echo quoted;; esac"#,

    // ---- §2.9.5 functions ----
    r#"f() { echo in-f; }; f"#,
    r#"f() { echo "$1-$2"; }; f a b"#,
    r#"f() { return 3; }; f; echo $?"#,
    r#"f() { echo $#; }; f a b c"#,
    r#"f() { g() { echo nested; }; g; }; f"#,
    r#"f() { echo "$@"; }; f "a b" c"#,
    r#"x=global; f() { echo $x; }; f"#,
    r#"f() { x=set-in-f; }; f; echo $x"#,
    r#"set -- outer; f() { echo $1; }; f inner; echo $1"#,
    r#"f() { echo f; }; f() { echo redefined; }; f"#,
    r#"f() { for i in 1 2; do echo $i; done; }; f"#,
    r#"f() { if [ "$1" -gt 0 ]; then echo $1; f $(($1-1)); fi; }; f 3"#,

    // ---- §2.10 / §2.14 builtins ----
    r#":; echo $?"#,
    r#"echo -n no-newline; echo ""#,
    r#"printf '%s\n' hello"#,
    r#"printf '%d\n' 42"#,
    r#"printf '%s-%s\n' a b"#,
    r#"printf '%s\n' a b c"#,
    r#"printf '%5s|\n' x"#,
    r#"printf '%-5s|\n' x"#,
    r#"printf '%05d\n' 42"#,
    r#"printf '%x\n' 255"#,
    r#"printf '%c' abc; echo ""#,
    r#"printf 'a%%b\n'"#,
    r#"printf '%s\n'"#,
    r#"[ a = a ]; echo $?"#,
    r#"[ a != b ]; echo $?"#,
    r#"[ -z "" ]; echo $?"#,
    r#"[ -n x ]; echo $?"#,
    r#"[ 1 -eq 1 ]; echo $?"#,
    r#"[ 1 -lt 2 -a 2 -lt 3 ]; echo $?"#,
    r#"[ 1 -lt 2 -o 3 -lt 2 ]; echo $?"#,
    r#"[ ! 1 = 2 ]; echo $?"#,
    r#"[ ]; echo $?"#,
    r#"[ x ]; echo $?"#,
    r#"test -d /; echo $?"#,
    r#"test -f /; echo $?"#,
    r#"cd /; pwd"#,
    r#"cd /tmp; cd /; echo $OLDPWD"#,
    r#"x=1; unset x; echo "[$x]""#,
    r#"f() { echo f; }; unset -f f; f 2>/dev/null; echo $?"#,
    r#"export X=exported; sh -c 'echo $X'"#,
    r#"X=notexported; sh -c 'echo "[$X]"'"#,
    r#"readonly r=1; r=2; echo $?"#,
    r#"eval 'echo evaled'"#,
    r#"eval 'x=1; echo $x'"#,
    r#"x='echo indirect'; eval "$x""#,
    r#"set -- a b; eval 'echo $1'"#,
    r#"command echo via-command"#,
    r#"command -v echo"#,
    r#"f() { echo f; }; command -v f"#,
    r#"true; command -v nosuchcommand-xyz; echo $?"#,
    r#"printf 'x\n' | { read v; echo "[$v]"; }"#,
    r#"printf 'a b c\n' | { read x y; echo "[$x][$y]"; }"#,
    r#"printf 'a\\tb\n' | { read -r v; echo "[$v]"; }"#,
    r#"OPTIND=1; set -- -a -b arg; while getopts ab opt; do echo "opt=$opt"; done"#,

    // ---- exit status and errors ----
    r#"nosuchcommand-xyz 2>/dev/null; echo $?"#,
    r#"/nonexistent/path 2>/dev/null; echo $?"#,
    r#"exit 5"#,
    r#"(exit 3); echo $?"#,
    r#"true; exit"#,
    r#"false; exit"#,
    r#"f() { exit 4; }; f; echo never"#,

    // ---- §2.10.2 / grammar edge cases ----
    r#"echo a;echo b"#,
    r#"echo a ;; echo b"#,
    r#"if true; then echo a; fi; if true; then echo b; fi"#,
    r#"echo # a comment"#,
    r#"# only a comment"#,
    r#"echo before # trailing comment"#,
    r#"echo 'not # a comment'"#,
    r#"echo a#b"#,
    r#""#,
    r#"   "#,
    r#";"#,
    r#"echo )"#,
    r#"for"#,
    r#"echo "unterminated"#,
    r#"echo $(unterminated"#,
    r#"if true; then"#,
    r#"echo a |"#,
    r#"echo a &&"#,
    r#"cat <<EOT
unterminated heredoc"#,
    r#"echo a\"#,
];

/// Cases where rush deliberately answers differently, with the reason. Each is
/// asserted to *still* differ, so this list cannot rot into a list of bugs that
/// were quietly fixed — or hide one that was quietly introduced.
#[rustfmt::skip]
const DIVERGENCES: &[(&str, &str)] = &[
    // POSIX leaves the order unspecified; rush prints its table's canonical
    // order, dash prints its own (Phase 6, documented).
    ("set -efu; echo $-", "the order of `$-` is unspecified by POSIX"),
    // POSIX.1-2024 added pipefail; dash rejects it outright.
    ("set -o pipefail; false | true; echo $?", "rush has pipefail (POSIX.1-2024); dash does not"),
    // POSIX reserves -h for hashing; rush accepts and ignores it, dash rejects.
    ("set -h; echo ok", "rush accepts -h as a no-op; dash rejects it"),
    // rush's `clear`/`history` are documented extensions, so `command -v` finds
    // a builtin where dash finds /usr/bin/clear (or nothing).
    ("command -v clear", "`clear` is a rush builtin (the Motor image has no external one)"),
    ("command -v history", "`history` is a rush builtin extension"),
    // Aliases: rush expands at execution time, dash at parse time, so dash needs
    // a second parse unit before the alias takes effect (Phase 5, documented).
    ("alias e='echo aliased'; e", "rush expands aliases at execution time, dash at parse time"),
    // Redirections to fds above 2 are not wired (a Phase 3 limit, and one Motor
    // OS enforces: a child there takes only inherit/null/pipe as its stdio, so
    // an arbitrary fd cannot be handed to `cat >&3` at all).
    (r#"exec 3>"$T/f"; echo fd3 >&3; exec 3>&-; cat "$T/f""#, "fds > 2 are not wired (no fd passing on Motor OS)"),
];

struct Run {
    stdout: String,
    /// Whether anything was said on stderr. Not *what*: shells word errors
    /// differently and POSIX does not specify the text.
    spoke: bool,
    code: i32,
}

fn run(shell: &str, case: &str, tmp: &str) -> Run {
    let out = Command::new(shell)
        .arg("-c")
        .arg(case)
        .env("T", tmp)
        .env("LC_ALL", "C")
        .current_dir(tmp)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {shell}: {e}"));
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        spoke: !out.stderr.is_empty(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn have_dash() -> bool {
    std::path::Path::new(DASH).exists()
}

/// A scratch directory per case, so a case that writes files cannot see another's.
fn scratch(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("rush-conf-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_str().unwrap().to_string()
}

/// Compare rush against dash on `case`; returns a description of the difference.
fn diff(case: &str, tag: &str) -> Option<String> {
    let a = scratch(&format!("{tag}-rush"));
    let b = scratch(&format!("{tag}-dash"));
    let r = run(RUSH, case, &a);
    let d = run(DASH, case, &b);
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);

    let mut why = Vec::new();
    if r.stdout != d.stdout {
        why.push(format!("stdout: rush {:?} vs dash {:?}", r.stdout, d.stdout));
    }
    if r.code != d.code {
        why.push(format!("status: rush {} vs dash {}", r.code, d.code));
    }
    if r.spoke != d.spoke {
        why.push(format!(
            "stderr: rush {} vs dash {}",
            if r.spoke { "spoke" } else { "silent" },
            if d.spoke { "spoke" } else { "silent" }
        ));
    }
    if why.is_empty() {
        None
    } else {
        Some(why.join("; "))
    }
}

#[test]
fn the_corpus_agrees_with_dash() {
    if !have_dash() {
        eprintln!("skipping: {DASH} not installed");
        return;
    }
    let mut failures = Vec::new();
    for (i, case) in CORPUS.iter().enumerate() {
        if let Some(why) = diff(case, &format!("c{i}")) {
            failures.push(format!("\n  case {i}: {case:?}\n    {why}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} corpus cases disagree with dash:{}",
        failures.len(),
        CORPUS.len(),
        failures.join("")
    );
}

#[test]
fn the_documented_divergences_still_diverge() {
    if !have_dash() {
        eprintln!("skipping: {DASH} not installed");
        return;
    }
    let mut fixed = Vec::new();
    for (i, (case, reason)) in DIVERGENCES.iter().enumerate() {
        if diff(case, &format!("d{i}")).is_none() {
            fixed.push(format!("\n  {case:?} — documented as: {reason}"));
        }
    }
    assert!(
        fixed.is_empty(),
        "these no longer diverge from dash; remove them from DIVERGENCES:{}",
        fixed.join("")
    );
}
