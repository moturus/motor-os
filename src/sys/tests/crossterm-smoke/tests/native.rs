#![cfg(target_os = "motor")]
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};

const PROBE: &str = env!("CARGO_BIN_EXE_crossterm-smoke");

fn run(mode: &str, input: &[u8]) -> Output {
    let mut child = Command::new(PROBE)
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn keys_and_lone_escape_decode_without_a_terminal() {
    let output = run("keys", b"hi\r\n\x1b[A\x03q");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ready\nkey=Char('h')\nkey=Char('i')\nkey=Enter\nkey=Up\nkey=Char('c')+KeyModifiers(CONTROL)\nkey=Char('q')\nend=quit\n");

    let mut child = Command::new(PROBE)
        .arg("keys")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line, "ready\n");
    child.stdin.as_mut().unwrap().write_all(b"\x1b").unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    assert_eq!(line, "key=Esc\n");
    child.stdin.take().unwrap().write_all(b"q").unwrap();
    let lines: Vec<_> = output.lines().map(Result::unwrap).collect();
    assert_eq!(lines, ["key=Char('q')", "end=quit"]);
    assert!(child.wait().unwrap().success());
}

#[test]
fn screen_restores_on_return_and_abort() {
    for mode in ["screen", "panic"] {
        let output = run(mode, b"");
        assert_eq!(output.status.success(), mode == "screen", "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        let entered = text.find("\x1b[?1049h").unwrap();
        let left = text.find("\x1b[?1049l").unwrap();
        assert!(entered < left, "{text:?}");
        if mode == "screen" {
            assert!(text.contains("screen=restored"));
        }
    }
}

#[test]
fn nonterminal_size_never_emits_a_terminal_query() {
    let output = run("size", b"");
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("size=80x24") && text.contains("size-after=80x24"),
        "{text:?}"
    );
    for unexpected in ["resize=", "\x1b[?2048", "\x1b[6n", "\x1b[18t"] {
        assert!(!text.contains(unexpected), "{text:?}");
    }
    // Ctrl+C registration needs a live terminal; cross-test.sh retains that
    // assertion in its forced-PTY SSH check.
}
