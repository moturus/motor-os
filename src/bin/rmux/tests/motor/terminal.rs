use super::support::*;

fn row(client: &mut Client, text: &str) {
    client.wait(text, |c| {
        (0..c.grid.rows()).any(|r| c.grid.line(r).trim() == text)
    });
}

fn contains(client: &mut Client, text: &str) {
    client.wait(text, |c| {
        (0..c.grid.rows()).any(|r| c.grid.line(r).contains(text))
    });
}

fn lacks(client: &mut Client, text: &str) {
    client.wait(text, |c| {
        (0..c.grid.rows()).all(|r| !c.grid.line(r).contains(text))
    });
}

fn resize(client: &mut Client, rows: usize, cols: usize) {
    client.grid.resize(rows, cols);
    client.send(format!("\x1b[?2048;1$y\x1b[48;{rows};{cols};0;0t").as_bytes());
}

fn red_bar(client: &mut Client, row: usize) {
    client.wait("red status bar", |c| {
        let line = c.grid.line(row);
        line.contains("[No Name]")
            && line.ends_with("NORMAL | 1:1")
            && line.chars().count() == c.grid.cols() - 1
    });
}

#[test]
fn terminal_descriptors_and_interrupt_routes() {
    let s = Session::new("descriptor-routes");
    let mut c = s.client(RMUX, &[], caps());
    c.text("motor-os");
    let report = s.root.join("terminal-report");
    c.send(format!("{PROBE} terminal {}\n", report.display()).as_bytes());
    until("terminal descriptor report", || report.is_file());
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "terminal descriptor invariants PASS\n"
    );

    c.send(format!("{PROBE} ctrl-c-default\n").as_bytes());
    c.text("RMUX_DEFAULT_READY");
    // Type-ahead must survive teardown and see the interrupted leaf's status.
    c.send(b"\x03echo NESTED_STATUS=$?\n");
    contains(&mut c, "NESTED_STATUS=130");
    c.send(b"foo=kept; printf 'BUILTIN_%s\\n' READY; read foo; printf 'READ_%s\\n' UNEXPECTED\n");
    row(&mut c, "BUILTIN_READY");
    c.bytes.clear();
    c.send(b"\x03");
    c.text("^C");
    c.send(b"echo BUILTIN_STATUS=$? FOO=$foo\n");
    contains(&mut c, "BUILTIN_STATUS=130 FOO=kept");
    assert!(
        !c.bytes
            .windows(b"READ_UNEXPECTED".len())
            .any(|p| p == b"READ_UNEXPECTED")
    );
    c.send(b"exit\n");
    c.finish(0);
}

#[test]
fn resize_rewrap_and_pane_line_discipline() {
    let s = Session::new("resize-lines");
    let mut c = s.client(RMUX, &[], caps());
    c.text("motor-os");
    resize(&mut c, 30, 100);
    c.wait("status at row 30", |c| c.grid.line(29).contains("[0] "));
    resize(&mut c, 20, 60);
    c.wait("status at row 20", |c| c.grid.line(19).contains("[0] "));
    resize(&mut c, 30, 100);
    c.wait("status moved back to row 30", |c| {
        c.grid.line(29).contains("[0] ")
    });
    assert!(!c.grid.line(19).contains("[0] "));
    c.send(b"\x0c");
    c.wait("clear prompt", |c| c.grid.line(0).contains('$'));
    let before = (0..29).filter(|&r| c.grid.line(r).contains('$')).count();
    c.send(b"echo o''ne\r");
    row(&mut c, "one");
    c.wait("one Enter, one prompt", |c| c.grid.line(2).contains('$'));
    let after = (0..29).filter(|&r| c.grid.line(r).contains('$')).count();
    assert_eq!(after, before + 1);
    c.send(b"echo a''aa; echo b''bb\r");
    row(&mut c, "aaa");
    row(&mut c, "bbb");
    c.wait("next prompt", |c| c.grid.line(5).contains('$'));
    c.send(b"e");
    c.wait("first keystroke", |c| {
        c.grid.line(5).trim_end().ends_with('e')
    });
    c.bytes.clear();
    c.send(b"x");
    c.text("x");
    assert_eq!(c.bytes, b"x", "a keystroke should be an incremental paint");
    c.send(b"\x15");
    resize(&mut c, 24, 80);
    c.send(b"\x0c");
    c.wait("clear resized prompt", |c| c.grid.line(0).contains('$'));
    c.send(format!("echo {}", "x".repeat(45)).as_bytes());
    contains(&mut c, &"x".repeat(45));
    c.send(b"\x01|");
    c.wait("half-typed line rewrapped by the split", |c| {
        c.grid.line(1).starts_with(&"x".repeat(20))
    });
    c.send(b"\x01c");
    c.wait("second window", |c| c.grid.line(23).contains("1:"));
    c.send(b"exit\r");
    c.wait("second window closed", |c| !c.grid.line(23).contains("1:"));
    c.send(b"\x01o");
    c.wait("original pane selected", |c| c.grid.cursor().1 < 40);
    // Ctrl+C is out of band: finish selecting the pane before interrupting it.
    c.bytes.clear();
    c.send(b"\x03");
    c.text("^C");
    c.send(b"echo COLS=$COLUMNS,$LINES\r");
    contains(&mut c, "COLS=40,23");
    c.send(b"exit\r");
    lacks(&mut c, "│");
    c.send(b"exit\r");
    c.finish(0);
}

#[test]
fn editor_redraws_when_its_pane_changes_size() {
    let s = Session::new("editor-resize");
    let mut c = s.client(RMUX, &[], caps());
    c.text("motor-os");
    c.send(b"/user/bin/red\r");
    // Grid rows are zero-based; Red reserves its last row for messages.
    red_bar(&mut c, 21);
    resize(&mut c, 30, 100);
    red_bar(&mut c, 27);
    resize(&mut c, 20, 60);
    red_bar(&mut c, 17);
    resize(&mut c, 24, 80);
    red_bar(&mut c, 21);
    c.send(b"\x01-");
    red_bar(&mut c, 9);
    c.send(b"\x01c");
    c.wait("second window", |c| c.grid.line(23).contains("1:"));
    c.send(b"exit\r");
    c.wait("second window closed", |c| !c.grid.line(23).contains("1:"));
    c.send(b"\x01o:q\r");
    lacks(&mut c, "[No Name]");
    c.send(b"exit\r");
    lacks(&mut c, "─");
    c.send(b"exit\r");
    c.finish(0);
}
