//! Check a live serial transcript without treating its unfinished tail as EOF.
use std::process::ExitCode;

fn console_text(bytes: &[u8]) -> String {
    let mut plain = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    while pos < bytes.len() {
        if bytes[pos] == 0x1b {
            if pos + 1 == bytes.len() {
                break;
            }
            // Rush saves/restores the cursor around its position query.
            if matches!(bytes[pos + 1], b'7' | b'8') {
                pos += 2;
                continue;
            }
            if bytes[pos + 1] == b'[' {
                pos += 2;
                while pos < bytes.len() && !(0x40..=0x7e).contains(&bytes[pos]) {
                    pos += 1;
                }
                pos += usize::from(pos < bytes.len());
                continue;
            }
        }
        if bytes[pos] != b'\r' {
            plain.push(bytes[pos]);
        }
        pos += 1;
    }
    String::from_utf8_lossy(&plain).into_owned()
}

fn ready_marker(id: usize) -> String {
    format!("\nstderr-burst {id} ready\n")
}

fn prompt(id: usize) -> String {
    format!("[TTY-BURST-{id}] ")
}

fn error_line(id: usize, line: usize, lines: usize) -> String {
    format!("  caused by: stderr-burst {id} line {line} of {lines} stays whole\n")
}

/// Whether `line` begins a log record: one of sys-tty's `[kernel log: ...]`
/// notes, or the `secs:millis` stamp that every log format leads with. `None`:
/// it is an unfinished beginning of one.
fn starts_record(line: &str) -> Option<bool> {
    const NOTE: &str = "[kernel log: ";
    if line.starts_with(NOTE) {
        return Some(true);
    }
    if NOTE.starts_with(line) {
        return None;
    }
    let mut stamp = line.trim_start_matches(' ').bytes();
    let mut secs = 0;
    loop {
        match stamp.next()? {
            b'0'..=b'9' => secs += 1,
            b':' if secs != 0 => break,
            _ => return Some(false),
        }
    }
    for _ in 0..3 {
        if !stamp.next()?.is_ascii_digit() {
            return Some(false);
        }
    }
    Some(matches!(stamp.next()?, b':' | b' '))
}

/// Passes over the whole log records that begin `text`, which starts a line,
/// and whether there were any. `None`: `text` ends inside what may be one.
fn skip_records(mut text: &str) -> Option<(&str, bool)> {
    let mut skipped = false;
    loop {
        if skipped && text.is_empty() {
            return Some((text, true));
        }
        let (line, whole) = match text.split_once('\n') {
            Some((line, _)) => (line, true),
            None => (text, false),
        };
        match starts_record(line) {
            Some(true) if whole => skipped = true,
            // The line break that an interrupted chunk still owed.
            _ if whole && line.is_empty() && skipped => {}
            Some(true) | None if !whole => return None,
            _ => return Some((text, skipped)),
        }
        text = &text[line.len() + 1..];
    }
}

/// Strips `expected` from `text`, which starts a line. Sys-tty may write whole
/// log records between two screen chunks, and moves to a fresh line first when
/// the earlier chunk ended inside one. `Ok(None)`: `text` ends too early.
fn strip_expected<'a>(text: &'a str, mut expected: &str) -> Result<Option<&'a str>, ()> {
    let Some((mut text, _)) = skip_records(text) else {
        return Ok(None);
    };
    loop {
        let same = text
            .bytes()
            .zip(expected.bytes())
            .take_while(|(found, wanted)| found == wanted)
            .count();
        (text, expected) = (&text[same..], &expected[same..]);
        if expected.is_empty() {
            return Ok(Some(text));
        }
        if text.is_empty() {
            return Ok(None);
        }
        match text.strip_prefix('\n').map(skip_records) {
            Some(None) => return Ok(None),
            Some(Some((rest, true))) => text = rest,
            _ => return Err(()),
        }
    }
}

fn check(text: &str, id: usize, lines: usize) -> Result<bool, String> {
    let ready = ready_marker(id);
    let prompt = prompt(id);
    let Some(start) = text.find(&ready) else {
        return if text.contains(&prompt) {
            Err("prompt preceded the command's ready line".into())
        } else {
            Ok(false)
        };
    };
    if text[..start].contains(&prompt) {
        return Err("prompt preceded the error text".into());
    }
    let mut rest = &text[start + ready.len()..];
    for line in 1..=lines {
        rest = match strip_expected(rest, &error_line(id, line, lines)) {
            Ok(Some(rest)) => rest,
            Ok(None) => return Ok(false),
            Err(()) => {
                return Err(format!(
                    "expected intact error line {line} before the prompt; got {rest:?}"
                ));
            }
        };
    }
    rest = match strip_expected(rest, &prompt) {
        Ok(Some(rest)) => rest,
        Ok(None) => return Ok(false),
        Err(()) => {
            return Err(format!(
                "expected the next prompt immediately after the error text; got {rest:?}"
            ));
        }
    };
    // Only log records, on a fresh line, may follow the prompt.
    while !rest.is_empty() {
        rest = match rest.strip_prefix('\n').map(skip_records) {
            Some(None) => return Ok(false),
            Some(Some((rest, true))) => rest,
            _ => return Err(format!("expected nothing after the prompt; got {rest:?}")),
        };
    }
    Ok(true)
}

fn self_test() {
    let ready = format!("old prompt and echoed command{}", ready_marker(7));
    let body: String = (1..=3).map(|line| error_line(7, line, 3)).collect();
    let prompt = prompt(7);
    let valid = format!("{ready}{body}{prompt}");
    assert_eq!(check(&valid, 7, 3), Ok(true));
    for end in 0..valid.len() {
        assert_eq!(check(&valid[..end], 7, 3), Ok(false));
    }
    let first = error_line(7, 1, 3);
    let rest: String = (2..=3).map(|line| error_line(7, line, 3)).collect();
    for invalid in [
        format!("{ready}{prompt}{body}"),
        format!("{prompt}{ready}{body}"),
        format!("{ready}{first}{prompt}{}", error_line(7, 2, 3)),
        format!("{ready}{first}{}{prompt}", error_line(7, 3, 3)),
        format!("{ready}unexpected prefix {body}{prompt}"),
        format!("{ready}{body}{prompt}extra output"),
        format!("{ready}{first}rush: not a log record\n{rest}{prompt}"),
        format!("{ready}{first}\n{rest}{prompt}"),
    ] {
        assert!(check(&invalid, 7, 3).is_err(), "accepted {invalid:?}");
    }

    // Log records keep to their own lines, wherever sys-tty fits them in.
    let user = "  10:934: DEBUG sys-io/src/runtime/net/device.rs:525: VirtioDevice::receive()\n";
    let kernel = " 12:001  1: KERNEL sched.rs:10 - a kernel record\n";
    let note = "[kernel log: 3 records dropped: console backlog]\n";
    let (head, tail) = first.split_at(12);
    let whole = first.trim_end();
    for logged in [
        format!("{ready}{user}{first}{kernel}{note}{rest}{user}{prompt}"),
        format!("{ready}{head}\n{user}{tail}{rest}{prompt}"),
        format!("{ready}{head}\n{user}\n{note}{kernel}{tail}{rest}{prompt}"),
        format!("{ready}{whole}\n{user}\n{note}\n{rest}{prompt}"),
        format!("{ready}{body}{prompt}\n{user}\n{note}"),
    ] {
        assert_eq!(check(&logged, 7, 3), Ok(true), "rejected {logged:?}");
        for end in 0..logged.len() {
            assert!(check(&logged[..end], 7, 3).is_ok(), "{:?}", &logged[..end]);
        }
    }
    // A record that does not start a line is not one sys-tty wrote.
    let glued = format!("{ready}{head}{user}{tail}{rest}{prompt}");
    assert!(check(&glued, 7, 3).is_err());

    let decorated = format!(
        "\x1b[?25l{}\x1b[?25h\x1b7\x1b[6n\x1b8",
        valid.replace('\n', "\n\r")
    );
    assert_eq!(check(&console_text(decorated.as_bytes()), 7, 3), Ok(true));
    println!("console stderr checker self-test PASS");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--self-test" {
        self_test();
        return ExitCode::SUCCESS;
    }
    assert_eq!(
        args.len(),
        5,
        "usage: checker LOG BYTE_OFFSET ID LINES|ready"
    );
    let bytes = std::fs::read(&args[1]).unwrap();
    let offset: usize = args[2].parse().unwrap();
    let id = args[3].parse().unwrap();
    let text = console_text(bytes.get(offset..).unwrap_or_default());
    let result = if args[4] == "ready" {
        Ok(text.contains(&ready_marker(id)))
    } else {
        check(&text, id, args[4].parse().unwrap())
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(error) => {
            eprintln!("console stderr burst {id}: {error}");
            ExitCode::FAILURE
        }
    }
}
