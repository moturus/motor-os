#![cfg(target_os = "motor")]

#[path = "motor/permissions.rs"]
mod permissions;
#[path = "motor/support.rs"]
mod support;
#[path = "motor/terminal.rs"]
mod terminal;

use support::*;

#[test]
fn pane_reports_one_consistent_size_to_crossterm() {
    let s = Session::new("size");
    let mut client = s.client(RMUX, &[], caps());
    client.text("motor-os");
    let output = s.root.join("size-output");
    client.send(format!("{PROBE} size {}\n", output.display()).as_bytes());
    until("crossterm size report", || {
        std::fs::read_to_string(&output).is_ok_and(|text| text.contains("size-after="))
    });
    let text = std::fs::read_to_string(output).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.first(), Some(&"size=80x23"));
    assert_eq!(lines.last(), Some(&"size-after=80x23"));
    let resizes: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("resize="))
        .collect();
    assert!(!resizes.is_empty());
    assert!(
        resizes.iter().all(|line| **line == "resize=80x23"),
        "{text}"
    );
    client.send(b"exit\n");
    client.finish(0);
}

#[test]
fn pane_terminal_screen_titles_scrollback_and_disconnect() {
    let s = Session::new("terminal");
    let mut client = s.client(RMUX, &[], caps());
    client.text("motor-os");
    client.send(b"echo $((21+21))\n");
    client.wait("arithmetic output", |c| {
        (0..23).any(|row| c.grid.line(row).trim() == "42")
    });
    for sequence in [b"\x1b[?1049h".as_slice(), b"\x1b[?2004h"] {
        assert!(
            client
                .bytes
                .windows(sequence.len())
                .any(|part| part == sequence)
        );
    }

    client.send(b"sleep 314159\n");
    until("foreground sleep", || {
        s.success("/user/bin/ps", &[], caps())
            .contains("sleep 314159")
    });
    client.send(b"\x01r");
    client.wait("foreground title", |c| c.grid.line(23).contains("0:sleep"));
    client.send(b"\x03");
    until("interrupted sleep", || {
        !s.success("/user/bin/ps", &[], caps())
            .contains("sleep 314159")
    });
    client.send(b"echo RMUX_TITLE_RESTORED\n");
    client.text("RMUX_TITLE_RESTORED");
    client.send(b"\x01r");
    client.wait("restored title", |c| c.grid.line(23).contains("0:rush"));

    client.send(b"sleep 271828 &\n");
    until("background sleep", || {
        s.success("/user/bin/ps", &[], caps())
            .contains("sleep 271828")
    });
    client.send(b"\x01r");
    client.wait("background title", |c| c.grid.line(23).contains("0:rush"));
    client.send(b"kill $!\nwait\n");

    let numbers = (1..=30)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    client.send(format!("for I in {numbers}; do echo LINE$I; done\n").as_bytes());
    client.wait("last scrollback line", |c| {
        (0..23).any(|row| c.grid.line(row).trim() == "LINE30")
    });
    client.send(b"\x01[g");
    client.wait("oldest scrollback", |c| {
        let line = c.grid.line(23);
        let Some(counts) = line
            .strip_prefix("-- copy mode -- [")
            .and_then(|s| s.split_once(']'))
        else {
            return false;
        };
        let Some((above, total)) = counts.0.split_once('/') else {
            return false;
        };
        total.parse::<u64>().is_ok_and(|n| n > 0) && above == total
    });
    client.send(b"qexit\n");
    let output = client.finish(0);
    assert!(output.windows(8).any(|part| part == b"\x1b[?1049l"));

    let mut client = s.client(RMUX, &["new", "-s", "hangup"], caps());
    client.text("motor-os");
    // Closing the console leaves the session available for the next attach.
    client.child.stdin.take();
    client.finish(0);
    until("client detached after EOF", || {
        s.success(RMUX, &["ls"], caps()) == "hangup: 1 window"
    });
    s.kill_session("hangup", caps());
}

#[test]
fn delimiter_directories_do_not_alias_encoded_spellings() {
    let a = Session::new(";:=&%3B&amp;&col;&eq;");
    let b = Session::new("%3B%3A%3D%26%253B%26amp%3B%26col%3B%26eq%3B");
    for (session, name) in [(&a, "delimiters"), (&b, "escapes")] {
        let mut client = session.client(RMUX, &["new", "-s", name], caps());
        client.text("motor-os");
        client.send(b"\x01d");
        client.finish(0);
    }
    for (session, name) in [(&a, "delimiters"), (&b, "escapes")] {
        assert_eq!(
            session.success(RMUX, &["ls"], caps()),
            format!("{name}: 1 window")
        );
        session.kill_session(name, caps());
    }
}
