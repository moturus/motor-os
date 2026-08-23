//! Phase 8 golden tests: the interactive line editor.
//!
//! These are the first tests to drive rush *as a terminal user does* — over a
//! **pty**, with real key bytes going in and the redrawn screen coming back.
//! That is what makes the editor testable at all: it is the one part of the
//! shell whose behavior is invisible to `-c`.
//!
//! Two things make this practical, both deliberate Phase 8 design choices:
//!
//! - The editor asks the terminal two things, and waits for neither for long.
//!   The width comes from [`crossterm::terminal::window_size`], which on a pty
//!   is `TIOCGWINSZ` and never blocks; where it comes from on a console with no
//!   ioctl is crossterm's Motor OS backend, which subscribes to it in band
//!   (`test-terminal-size.sh` drives that end, this file drives the pty one).
//!   The cursor's column comes from `ESC[6n`, which is a round trip — so [`Pty`]
//!   answers it, as the terminal it stands in for would, and a console that does
//!   not answer costs the shell one timeout and is never asked again.
//! - Rendering goes through one function, and [`screen`] below replays what it
//!   writes to recover what the user would see, rather than matching raw bytes —
//!   the same reason a terminal exists. That the editor paints *incrementally*
//!   (a keystroke redraws a character, not the line) is exactly why the bytes
//!   are not worth matching and the screen is: [`Pty::screen`] replays the whole
//!   session, so these tests hold the editor to the picture it adds up to.
//!
//! Expectations are cross-checked against dash and bash where they have an
//! opinion (EOF status, `^C`), and against readline where it is the only
//! authority (the emacs bindings, `^R`).

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

// ---- a pty ------------------------------------------------------------------

/// A pty master, with a shell running on the slave side.
struct Pty {
    master: std::fs::File,
    child: std::process::Child,
    /// The width the pty is currently at, which the cursor replies are
    /// computed against. [`Pty::resize`] keeps it true.
    cols: usize,
    /// Every byte the shell has written, from the first prompt on.
    ///
    /// The screen is what all of them add up to, which is the only way to read
    /// one: the editor writes the *difference* against what it painted last (see
    /// `term`'s `render_diff`), so a chunk of output on its own is a handful of
    /// edits, not a picture. Keeping the lot and replaying it is what a terminal
    /// does — and it means these tests check the incremental painting itself,
    /// not just the last thing it happened to say.
    seen: String,
}

impl Pty {
    /// Start `rush -i` on a pty `cols` wide, with a minimal environment: no
    /// `$ENV`/profile to source, and a one-character prompt so the expected
    /// screen is about the line being edited and not about `$PWD`.
    fn spawn(cols: u16, extra_env: &[(&str, &str)]) -> Pty {
        let (master, slave) = open_pty(cols);
        let mut cmd = Command::new(RUSH);
        cmd.arg("-i")
            .env_clear()
            .env("PS1", "$ ")
            .env("PS2", "> ")
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "xterm");
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        // Redirecting stdio does not change `/dev/tty`: without a new session,
        // it still names the test runner's terminal and crossterm reads that
        // terminal's size. Make the slave rush's controlling terminal too.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // The child talks to the slave on all three fds; it is a terminal, so
        // rush runs its editor. Each `Stdio` owns the fd it is given, hence a
        // dup apiece — and `slave` itself stays ours to close below.
        let child = unsafe {
            cmd.stdin(Stdio::from_raw_fd(dup(slave)))
                .stdout(Stdio::from_raw_fd(dup(slave)))
                .stderr(Stdio::from_raw_fd(dup(slave)))
                .spawn()
                .expect("failed to spawn rush on a pty")
        };
        // The parent must not hold the slave open, or a read on the master
        // never sees EOF when the shell exits.
        unsafe { libc::close(slave) };
        Pty {
            master,
            child,
            cols: cols as usize,
            seen: String::new(),
        }
    }

    /// Resize the terminal under the shell, as a pane split does.
    fn resize(&mut self, cols: u16) {
        set_pty_cols(&self.master, cols);
        self.cols = cols as usize;
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
        self.master.flush().unwrap();
        // Give the shell a moment to consume the keys before the next send, so
        // that a burst is not read as one chunk in a different order than typed.
        std::thread::sleep(Duration::from_millis(30));
    }

    /// What the user would be looking at: everything the shell has written so
    /// far, replayed onto a `cols`-wide grid.
    fn screen(&mut self, cols: usize) -> Vec<String> {
        let _ = self.read_output();
        screen(&self.seen, cols)
    }

    /// Read until the shell goes quiet, and return what arrived this time.
    ///
    /// Callers that ignore the return value are using it as a settling point:
    /// the shell has finished reacting to the last keys. Nothing is lost by
    /// ignoring it — it is all kept in `seen`.
    fn read_output(&mut self) -> String {
        let mut out = Vec::new();
        let mut buf = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut idle_since = Instant::now();
        let mut answered = 0;
        set_nonblocking(&self.master);
        while Instant::now() < deadline {
            match self.master.read(&mut buf) {
                Ok(0) => break, // the shell exited
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    idle_since = Instant::now();
                    // The shell is blocked until its `ESC[6n` is answered, so
                    // the answer goes back from inside this loop: after it, the
                    // loop is what reads the paint that answering unblocked.
                    // Counting on the whole of `out` catches a request split
                    // across two reads.
                    let asked = out
                        .windows(DSR.len())
                        .filter(|w| *w == DSR.as_bytes())
                        .count();
                    while answered < asked {
                        self.answer_cursor_query(&String::from_utf8_lossy(&out));
                        answered += 1;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if idle_since.elapsed() > Duration::from_millis(250) && !out.is_empty() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                // EIO: the slave side closed, i.e. the shell exited.
                Err(_) => break,
            }
        }
        let out = String::from_utf8_lossy(&out).into_owned();
        self.seen.push_str(&out);
        out
    }

    /// Answer `ESC[6n` with where everything written so far left the cursor.
    ///
    /// The shell is blocked on this reply, so it has to go back while the read
    /// loop above is still running rather than after it settles.
    fn answer_cursor_query(&mut self, pending: &str) {
        let mut session = self.seen.clone();
        session.push_str(pending);
        let (_, (row, col)) = replay(&session, self.cols);
        let reply = format!("\x1b[{};{}R", row + 1, col + 1);
        let _ = self.master.write_all(reply.as_bytes());
        let _ = self.master.flush();
    }

    /// Wait for the shell to paint its first prompt, which is when it is
    /// listening: keys sent earlier are read *after* it draws, and come back a
    /// prompt's width out of place. No constant stands in for this under load.
    fn await_prompt(&mut self) {
        for _ in 0..5 {
            if self.seen.contains("$ ") {
                return;
            }
            let _ = self.read_output();
        }
        panic!("rush never prompted; it wrote {:?}", self.seen);
    }

    /// Wait for the shell to exit and report its status.
    fn wait(&mut self) -> i32 {
        // Drain, so the shell is never blocked writing while we wait for it.
        let _ = self.read_output();
        self.child.wait().unwrap().code().unwrap_or(-1)
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn open_pty(cols: u16) -> (std::fs::File, RawFd) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
        let mut name = [0; 128];
        assert_eq!(
            libc::ptsname_r(master, name.as_mut_ptr(), name.len()),
            0,
            "ptsname_r failed"
        );
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(slave >= 0, "opening the pty slave failed");

        // The window size the editor's `TIOCGWINSZ` will report.
        let ws = libc::winsize {
            ws_row: 24,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(libc::ioctl(slave, libc::TIOCSWINSZ, &ws), 0);

        (std::fs::File::from_raw_fd(master), slave)
    }
}

fn dup(fd: RawFd) -> RawFd {
    let new = unsafe { libc::dup(fd) };
    assert!(new >= 0, "dup failed");
    new
}

/// Make the terminal `cols` wide, which is also how the shell is told: setting a
/// pty's size sends `SIGWINCH` to the process group on the other end of it.
fn set_pty_cols(master: &std::fs::File, cols: u16) {
    use std::os::unix::io::AsRawFd;
    let ws = libc::winsize {
        ws_row: 24,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    assert_eq!(
        unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &ws) },
        0
    );
    // The shell is parked waiting for a key; give it the moment it needs to be
    // woken, notice, and repaint.
    std::thread::sleep(Duration::from_millis(100));
}

fn set_nonblocking(f: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        let flags = libc::fcntl(f.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(f.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

// ---- a terminal ------------------------------------------------------------

/// The columns a character occupies, as a terminal would count them. A
/// deliberately separate (and much smaller) judgement than the shell's own
/// `char_width`: the test is checking that the editor agrees with a terminal,
/// so it must not simply ask the editor.
fn cells(c: char) -> usize {
    match c as u32 {
        0x1100..=0x115f | 0x2e80..=0xa4cf | 0xac00..=0xd7a3 | 0xf900..=0xfaff => 2,
        0xff00..=0xff60 | 0x1f300..=0x1f64f | 0x20000..=0x3fffd => 2,
        _ => 1,
    }
}

/// Replay `bytes` onto a `cols`-wide grid and return the rows, trailing blanks
/// trimmed — what a user would see.
///
/// A deliberately small terminal emulator: enough of CSI to follow the editor's
/// own repaint vocabulary (`\r`, cursor motion, erase-to-end-of-line, erase
/// screen), and no more. Anything the editor does not emit is ignored.
fn screen(bytes: &str, cols: usize) -> Vec<String> {
    replay(bytes, cols).0
}

/// The same replay, keeping the cursor: `ESC[6n` asks where these bytes left
/// it, and answering that is part of being the terminal these tests stand in for.
fn replay(bytes: &str, cols: usize) -> (Vec<String>, (usize, usize)) {
    let mut grid: Vec<Vec<char>> = vec![vec![' '; cols]];
    let (mut row, mut col) = (0_usize, 0_usize);
    let mut chars = bytes.chars().peekable();

    let put = |grid: &mut Vec<Vec<char>>, row: usize, col: usize, c: char| {
        while grid.len() <= row {
            grid.push(vec![' '; cols]);
        }
        if col < cols {
            grid[row][col] = c;
        }
    };

    while let Some(c) = chars.next() {
        match c {
            '\r' => col = 0,
            '\n' => {
                row += 1;
                while grid.len() <= row {
                    grid.push(vec![' '; cols]);
                }
            }
            '\x07' => {} // the bell rings; it draws nothing
            '\x1b' => match chars.next() {
                Some('[') => {
                    let mut params = String::new();
                    let mut final_byte = ' ';
                    for f in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&f) {
                            final_byte = f;
                            break;
                        }
                        params.push(f);
                    }
                    let n: usize = params
                        .trim_start_matches('?')
                        .split(';')
                        .next()
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(1);
                    match final_byte {
                        'A' => row = row.saturating_sub(n),
                        'B' => row += n,
                        'C' => col += n,
                        'D' => col = col.saturating_sub(n),
                        // Absolute column, 1-based: what the editor moves to
                        // column 0 with.
                        'G' => col = n.saturating_sub(1),
                        'H' => {
                            row = 0;
                            col = 0;
                        }
                        'K' => {
                            // Erase from the cursor to the end of the line.
                            while grid.len() <= row {
                                grid.push(vec![' '; cols]);
                            }
                            for cell in grid[row].iter_mut().skip(col) {
                                *cell = ' ';
                            }
                        }
                        'J' => {
                            grid = vec![vec![' '; cols]];
                            row = 0;
                            col = 0;
                        }
                        // Colors, cursor show/hide: nothing to draw.
                        _ => {}
                    }
                }
                // OSC: skip to the terminator.
                Some(']') => {
                    for f in chars.by_ref() {
                        if f == '\x07' {
                            break;
                        }
                    }
                }
                _ => {}
            },
            c => {
                let w = cells(c);
                // A character that does not fit goes to the next row whole.
                if col + w > cols {
                    row += 1;
                    col = 0;
                }
                put(&mut grid, row, col, c);
                // A wide character owns the next cell too; mark it as taken so
                // the row reads back as the text and not as "日 本".
                for x in 1..w {
                    put(&mut grid, row, col + x, '\0');
                }
                col += w;
            }
        }
    }
    let mut rows: Vec<String> = grid
        .iter()
        .map(|r| {
            r.iter()
                .filter(|c| **c != '\0') // the second cell of a wide character
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect();
    while rows.last().map(|r| r.is_empty()).unwrap_or(false) {
        rows.pop();
    }
    (rows, (row, col))
}

/// Type `keys` into a fresh shell and return what the screen shows.
fn typed(keys: &[u8], cols: u16) -> Vec<String> {
    let mut pty = Pty::spawn(cols, &[]);
    pty.await_prompt();
    pty.send(keys);
    pty.screen(cols as usize)
}

/// The line the user is editing: the last row that has a prompt on it.
fn prompt_line(rows: &[String]) -> String {
    rows.iter()
        .rev()
        .find(|r| r.starts_with("$ ") || r.starts_with("> ") || r == &"$" || r == &"> ")
        .cloned()
        .unwrap_or_default()
}

const CR: &[u8] = b"\r";

/// The cursor position report the editor asks for before each prompt.
const DSR: &str = "\x1b[6n";

// ---- the tests --------------------------------------------------------------

#[test]
fn typing_a_command_shows_it_and_runs_it() {
    let rows = typed(b"echo hello\r", 80);
    assert!(
        rows.iter().any(|r| r == "$ echo hello"),
        "the typed line: {rows:?}"
    );
    assert!(rows.iter().any(|r| r == "hello"), "its output: {rows:?}");
}

#[test]
fn editing_keys_move_and_change_the_line() {
    // Type `echo XY`, then: Home, Right×5 (after "echo "), delete the X.
    let rows = typed(b"echo XY\x1b[H\x1b[C\x1b[C\x1b[C\x1b[C\x1b[C\x1b[3~", 80);
    assert_eq!(prompt_line(&rows), "$ echo Y");
}

#[test]
fn backspace_deletes_before_the_cursor() {
    let rows = typed(b"echo abc\x7f\x7f", 80);
    assert_eq!(prompt_line(&rows), "$ echo a");
}

#[test]
fn emacs_bindings_edit_the_line() {
    // ^A start, ^F×5, ^K kill to end, then type a replacement.
    let rows = typed(b"echo original\x01\x06\x06\x06\x06\x06\x0bnew", 80);
    assert_eq!(prompt_line(&rows), "$ echo new");
}

#[test]
fn ctrl_u_kills_back_to_the_start_and_ctrl_y_yanks_it_back() {
    // readline's `unix-line-discard` kills *backwards* from the cursor.
    let rows = typed(b"echo foo\x15", 80);
    assert_eq!(prompt_line(&rows), "$");

    // ^Y pastes what ^U cut.
    let rows = typed(b"echo foo\x15\x19", 80);
    assert_eq!(prompt_line(&rows), "$ echo foo");
}

#[test]
fn ctrl_w_kills_a_whitespace_delimited_word() {
    let rows = typed(b"cat /usr/bin/ls\x17", 80);
    assert_eq!(prompt_line(&rows), "$ cat");
}

#[test]
fn alt_b_and_alt_f_move_by_words() {
    // Alt-b twice from the end lands before `foo`; Alt-d then kills it.
    let rows = typed(b"echo foo bar\x1bb\x1bb\x1bd", 80);
    assert_eq!(prompt_line(&rows), "$ echo  bar");
}

#[test]
fn ctrl_t_transposes_characters() {
    let rows = typed(b"echo ba\x14", 80);
    assert_eq!(prompt_line(&rows), "$ echo ab");
}

#[test]
fn ctrl_l_clears_the_screen_and_keeps_the_line() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo one\r");
    let _ = pty.read_output();
    pty.send(b"echo two\x0c");
    let rows = pty.screen(80);
    // The cleared screen holds only the line still being typed.
    assert_eq!(rows, ["$ echo two"], "{rows:?}");
}

#[test]
fn a_long_line_wraps_and_stays_editable() {
    // 30 columns: the prompt plus 34 characters is two rows. Then Home, and a
    // character typed at the start must appear at the start — the cursor math
    // across the wrap is the whole point.
    let rows = typed(b"echo aaaaaaaaaaaaaaaaaaaaaaaaaaaa\x01X", 30);
    assert_eq!(
        rows,
        ["$ Xecho aaaaaaaaaaaaaaaaaaaaaa", "aaaaaa"],
        "{rows:?}"
    );
}

// ---- painting ---------------------------------------------------------------
//
// The tests above check the screen the editor arrives at. These check what it
// *writes* to get there, which is a separate claim: erasing a line and drawing
// it again reaches the identical screen and flickers the whole way, because a
// console slow enough — Motor's is a serial line — paints the blank before it
// paints the text back over it. The fix is to not write what is already there,
// so it is the bytes that have to be tested.

#[test]
fn typing_at_the_end_of_a_line_costs_one_byte() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo");
    let _ = pty.read_output();
    pty.send(b"x");
    // Not "few bytes": the character, and nothing at all besides. There is
    // nothing else a terminal needs to be told in order to show it.
    assert_eq!(pty.read_output(), "x");
}

#[test]
fn an_edit_in_the_middle_redraws_the_tail_and_no_more() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo abc\x01"); // ^A: back to the start of the line
    let _ = pty.read_output();
    pty.send(b"X");
    let out = pty.read_output();
    // Everything after the cursor shifts along, so it is redrawn. The prompt
    // does not move, so it is not.
    assert!(out.contains("Xecho abc"), "the tail: {out:?}");
    assert!(!out.contains('$'), "the prompt was repainted: {out:?}");
    assert_eq!(pty.screen(80), ["$ Xecho abc"]);
}

#[test]
fn moving_the_cursor_draws_no_text() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo abc");
    let _ = pty.read_output();
    pty.send(b"\x1b[D"); // Left
    let out = pty.read_output();
    assert!(!out.contains("echo"), "the line was redrawn: {out:?}");
    assert!(
        out.len() < 8,
        "moving the cursor one cell took {} bytes: {out:?}",
        out.len()
    );
}

#[test]
fn a_backspace_erases_without_repainting_the_line() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo abc");
    let _ = pty.read_output();
    pty.send(b"\x7f");
    let out = pty.read_output();
    assert!(!out.contains("echo"), "the line was repainted: {out:?}");
    assert_eq!(pty.screen(80), ["$ echo ab"]);
}

#[test]
fn enter_runs_one_line_and_leaves_one_prompt() {
    // What a terminal in raw mode sends for Enter is a bare CR, and what it must
    // produce is one line run and one prompt after it.
    //
    // Motor's console sends CRLF for the one keypress, and counting both halves
    // left two prompts behind for every command. That is now the platform's to
    // get right rather than the editor's: crossterm's Motor OS backend drops the
    // LF of a CRLF however much later it arrives, and its own tests hold it to
    // that. A pty never sends one, so there is nothing here to check it with.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo one\r");
    let rows = pty.screen(80);
    assert_eq!(rows, ["$ echo one", "one", "$"], "{rows:?}");
}

#[test]
fn backspacing_back_across_a_wrap_takes_the_row_with_it() {
    // The narrow version of the same thing, one character wide: at 30 columns
    // this line is one character past the end of the first row, so it occupies
    // two. Deleting that one character has to take the second row with it — and
    // the paint has to know the cursor's row went up, which is the part a
    // whole-line repaint never had to work out.
    let mut keys = b"echo ".to_vec();
    keys.extend(std::iter::repeat_n(b'a', 24));
    assert_eq!(typed(&keys, 30), ["$ echo aaaaaaaaaaaaaaaaaaaaaaa", "a"]);
    keys.push(0x7f); // Backspace
    assert_eq!(typed(&keys, 30), ["$ echo aaaaaaaaaaaaaaaaaaaaaaa"]);
}

#[test]
fn a_line_that_shrinks_off_a_row_takes_the_row_with_it() {
    // The other half of drawing only the difference: what the old line put on
    // the screen and the new one does not reach has to be erased, or it stays
    // there as a ghost. 30 columns, so this line is two rows; `^A^K` kills it.
    let mut pty = Pty::spawn(30, &[]);
    pty.await_prompt();
    pty.send(b"echo aaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(pty.screen(30), ["$ echo aaaaaaaaaaaaaaaaaaaaaaa", "aaaaa"]);
    pty.send(b"\x01\x0b"); // ^A ^K
    assert_eq!(pty.screen(30), ["$"]);
}

#[test]
fn utf8_can_be_typed_and_edited() {
    // Bytes ≥ 0x80 were dropped before Phase 8; now they are characters, and a
    // Backspace deletes the whole character, not one byte of it.
    let rows = typed("echo héllo→".as_bytes(), 80);
    assert_eq!(prompt_line(&rows), "$ echo héllo→");

    let rows = typed("echo héllo→\x7f\x7f".as_bytes(), 80);
    assert_eq!(prompt_line(&rows), "$ echo héll");
}

#[test]
fn a_multibyte_command_runs() {
    let rows = typed("echo héllo\r".as_bytes(), 80);
    assert!(rows.iter().any(|r| r == "héllo"), "{rows:?}");
}

#[test]
fn wide_characters_wrap_whole() {
    // 10 columns, prompt 2: "$ " + 4 wide chars fills the row exactly; the
    // fifth cannot be split, so it goes to the next row.
    let rows = typed("echo 日本語です".as_bytes(), 12);
    assert_eq!(rows, ["$ echo 日本", "語です"], "{rows:?}");
}

// ---- history ---------------------------------------------------------------

#[test]
fn up_and_down_walk_the_history() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo one\r");
    pty.send(b"echo two\r");
    let _ = pty.read_output();

    pty.send(b"\x1b[A"); // Up: the newest
    assert_eq!(prompt_line(&pty.screen(80)), "$ echo two");
    pty.send(b"\x1b[A"); // Up again: older
    assert_eq!(prompt_line(&pty.screen(80)), "$ echo one");
    pty.send(b"\x1b[B"); // Down: back
    assert_eq!(prompt_line(&pty.screen(80)), "$ echo two");
    pty.send(b"\x1b[B"); // Down past the end: the line being typed (empty)
    assert_eq!(prompt_line(&pty.screen(80)), "$");
}

#[test]
fn a_half_typed_line_survives_a_trip_through_history() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo one\r");
    let _ = pty.read_output();
    pty.send(b"half typed");
    pty.send(b"\x1b[A\x1b[B");
    assert_eq!(prompt_line(&pty.screen(80)), "$ half typed");
}

#[test]
fn ctrl_r_searches_the_history_backwards() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo apple\r");
    pty.send(b"echo banana\r");
    let _ = pty.read_output();

    pty.send(b"\x12app"); // ^R then a needle
    let rows = pty.screen(80);
    let line = rows.iter().rev().find(|r| r.contains("reverse-i-search"));
    assert_eq!(
        line.cloned().unwrap_or_default(),
        "(reverse-i-search)`app': echo apple",
        "{rows:?}"
    );

    // Enter accepts the found line and runs it.
    pty.send(CR);
    let rows = pty.screen(80);
    assert!(rows.iter().any(|r| r == "apple"), "{rows:?}");
}

#[test]
fn ctrl_r_reports_a_failed_search() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo apple\r");
    let _ = pty.read_output();
    pty.send(b"\x12zzz");
    let rows = pty.screen(80);
    assert!(
        rows.iter().any(|r| r.contains("(failed reverse-i-search)")),
        "{rows:?}"
    );
}

#[test]
fn history_persists_across_sessions_through_histfile() {
    let dir = tmpdir("histfile");
    let path = format!("{dir}/hist");

    let mut pty = Pty::spawn(80, &[("HISTFILE", &path)]);
    pty.await_prompt();
    pty.send(b"echo remembered\r");
    pty.send(b"\x04"); // ^D: exit, saving the history
    assert_eq!(pty.wait(), 0);

    let saved = std::fs::read_to_string(&path).unwrap();
    assert_eq!(saved, "echo remembered\n");

    // A new shell reads it back: Up recalls a command it never saw typed.
    let mut pty = Pty::spawn(80, &[("HISTFILE", &path)]);
    pty.await_prompt();
    pty.send(b"\x1b[A");
    assert_eq!(prompt_line(&pty.screen(80)), "$ echo remembered");
    drop(pty);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_multiline_command_is_one_history_entry() {
    // The classic history-file bug: bash writes this as three lines and reads
    // back three broken entries. rush escapes it, so it round-trips.
    let dir = tmpdir("multiline");
    let path = format!("{dir}/hist");

    let mut pty = Pty::spawn(80, &[("HISTFILE", &path)]);
    pty.await_prompt();
    pty.send(b"for i in 1 2\r");
    pty.send(b"do echo $i\r");
    pty.send(b"done\r");
    pty.send(b"\x04");
    assert_eq!(pty.wait(), 0);

    let saved = std::fs::read_to_string(&path).unwrap();
    assert_eq!(saved, "for i in 1 2\\ndo echo $i\\ndone\n");
    assert_eq!(saved.lines().count(), 1, "one entry, one line");

    let mut pty = Pty::spawn(80, &[("HISTFILE", &path)]);
    pty.await_prompt();
    pty.send(b"\x1b[A");
    // Recalled whole: Enter runs the loop, not a fragment of it.
    pty.send(CR);
    let rows = pty.screen(80);
    assert!(
        rows.iter().any(|r| r == "1") && rows.iter().any(|r| r == "2"),
        "{rows:?}"
    );
    drop(pty);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_history_builtin_lists_and_composes() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo one\r");
    pty.send(b"echo two\r");
    let _ = pty.read_output();
    // A builtin, not a line-editor trick: its output is an ordinary stream, so
    // it can be redirected.
    let dir = tmpdir("historybuiltin");
    let path = format!("{dir}/out");
    pty.send(format!("history > {path}\r").as_bytes());
    let _ = pty.read_output();

    let listed = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        listed,
        "    1  echo one\n    2  echo two\n    3  history > ".to_string() + &path + "\n"
    );
    drop(pty);
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---- completion ------------------------------------------------------------

#[test]
fn tab_completes_a_unique_filename_and_adds_a_space() {
    let dir = tmpdir("complete-unique");
    std::fs::write(format!("{dir}/unique-name.txt"), "content\n").unwrap();

    // The `Z` proves the space: a finished word is finished, and the next thing
    // typed is a new argument rather than more of the filename.
    let rows = typed(format!("cat {dir}/uniq\tZ").as_bytes(), 200);
    assert_eq!(prompt_line(&rows), format!("$ cat {dir}/unique-name.txt Z"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tab_inserts_the_common_prefix_and_lists_the_ambiguity() {
    let dir = tmpdir("complete-ambiguous");
    std::fs::write(format!("{dir}/alpha.txt"), "").unwrap();
    std::fs::write(format!("{dir}/alpine.txt"), "").unwrap();

    // The first Tab can only insert what they share.
    let rows = typed(format!("cat {dir}/al\t").as_bytes(), 200);
    assert_eq!(prompt_line(&rows), format!("$ cat {dir}/alp"));

    // A second Tab, with nothing left to insert, shows the choices — by their
    // basenames, as bash does.
    let rows = typed(format!("cat {dir}/al\t\t").as_bytes(), 200);
    assert!(
        rows.iter()
            .any(|r| r.contains("alpha.txt") && r.contains("alpine.txt")),
        "{rows:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tab_completes_a_directory_with_a_slash_and_no_space() {
    let dir = tmpdir("complete-dir");
    std::fs::create_dir(format!("{dir}/subdir")).unwrap();

    let rows = typed(format!("ls {dir}/sub\t").as_bytes(), 200);
    // No trailing space: the next path component follows the slash.
    assert_eq!(prompt_line(&rows), format!("$ ls {dir}/subdir/"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tab_completes_a_command_in_command_position() {
    // `unalia<TAB>` → `unalias `: a builtin, offered because the word is the
    // command.
    let rows = typed(b"unalia\tZ", 80);
    assert_eq!(prompt_line(&rows), "$ unalias Z");
}

#[test]
fn tab_escapes_a_completed_name_so_it_survives_expansion() {
    let dir = tmpdir("complete-space");
    std::fs::write(format!("{dir}/with space.txt"), "found me\n").unwrap();

    // Unquoted: the space must come back escaped, or `cat` gets two arguments.
    let rows = typed(format!("cat {dir}/with\tZ").as_bytes(), 200);
    assert_eq!(
        prompt_line(&rows),
        format!("$ cat {dir}/with\\ space.txt Z")
    );

    // And the completed command must actually run.
    let rows = typed(format!("cat {dir}/with\t\r").as_bytes(), 200);
    assert!(rows.iter().any(|r| r == "found me"), "{rows:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tab_completes_inside_quotes_without_escaping() {
    let dir = tmpdir("complete-quoted");
    std::fs::write(format!("{dir}/with space.txt"), "quoted hit\n").unwrap();

    // Inside single quotes a space needs no backslash; the quote is closed for
    // us, and the whole thing runs.
    let rows = typed(format!("cat '{dir}/with\t\r").as_bytes(), 200);
    assert!(rows.iter().any(|r| r == "quoted hit"), "{rows:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tab_completes_a_variable_name() {
    let mut pty = Pty::spawn(80, &[("RUSH_TEST_UNIQUE", "the-value")]);
    pty.await_prompt();
    pty.send(b"echo $RUSH_TEST_UNIQ\t\r");
    let rows = pty.screen(80);
    assert!(rows.iter().any(|r| r == "the-value"), "{rows:?}");
}

// ---- EOF, interrupts, continuation -----------------------------------------

#[test]
fn ctrl_d_at_an_empty_prompt_exits_with_the_last_status() {
    // POSIX §2.5.2, and what dash does: EOF exits with `$?`, not 0.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"false\r");
    let _ = pty.read_output();
    pty.send(b"\x04");
    assert_eq!(pty.wait(), 1);

    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"true\r");
    let _ = pty.read_output();
    pty.send(b"\x04");
    assert_eq!(pty.wait(), 0);
}

#[test]
fn ctrl_d_on_a_non_empty_line_deletes_forward_instead_of_exiting() {
    // readline's `delete-char`: only an *empty* line means end of input.
    let rows = typed(b"echo abc\x01\x04", 80);
    assert_eq!(prompt_line(&rows), "$ cho abc");
}

#[test]
fn ctrl_d_mid_command_reports_the_syntax_error_and_carries_on() {
    // dash: `^D` in a continuation abandons the command with a syntax error and
    // returns to PS1 — an interactive shell does not exit on a syntax error.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo \"unterminated\r");
    pty.send(b"\x04");
    let rows = pty.screen(80);
    assert!(
        rows.iter()
            .any(|r| r.contains("unterminated quoted string")),
        "{rows:?}"
    );
    // Still alive, and back at PS1.
    pty.send(b"echo alive\r");
    let rows = pty.screen(80);
    assert!(rows.iter().any(|r| r == "alive"), "{rows:?}");
}

#[test]
fn ctrl_d_finishes_an_unterminated_here_document() {
    // The other half of dash's rule: at EOF, input that ends mid-here-doc is
    // not broken — the body simply ends there, and it runs.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"cat <<EOT\r");
    pty.send(b"the body\r");
    pty.send(b"\x04");
    let rows = pty.screen(80);
    assert!(rows.iter().any(|r| r == "the body"), "{rows:?}");
}

#[test]
fn ctrl_c_abandons_the_line_and_sets_the_status() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo never-run\x03");
    let rows = pty.screen(80);
    assert!(
        rows.iter().any(|r| r.ends_with("^C")),
        "the interrupt is shown: {rows:?}"
    );
    // The command did not run, and `$?` is 130 (128 + SIGINT).
    pty.send(b"echo $?\r");
    let rows = pty.screen(80);
    assert!(!rows.iter().any(|r| r == "never-run"), "{rows:?}");
    assert!(rows.iter().any(|r| r == "130"), "{rows:?}");
}

#[test]
fn ctrl_c_abandons_a_whole_multi_line_command() {
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"for i in 1 2\r");
    pty.send(b"do echo $i\r");
    pty.send(b"\x03"); // the half-typed loop is dropped, not just its last line
    pty.send(b"echo after\r");
    let rows = pty.screen(80);
    assert!(rows.iter().any(|r| r == "after"), "{rows:?}");
    assert!(
        !rows.iter().any(|r| r == "1"),
        "the loop never ran: {rows:?}"
    );
}

#[test]
fn a_continuation_prompts_with_ps2() {
    let rows = typed(b"echo \"one\rtwo\"\r", 80);
    assert!(rows.iter().any(|r| r == "> two\""), "PS2 shown: {rows:?}");
    assert!(rows.iter().any(|r| r == "one"), "{rows:?}");
    assert!(rows.iter().any(|r| r == "two"), "{rows:?}");
}

#[test]
fn a_blank_line_inside_a_quoted_string_is_kept() {
    // Before Phase 8 the editor swallowed *every* empty line, including the
    // ones that are content: this printed "a\nb" instead of "a\n\nb".
    let rows = typed(b"echo \"a\r\rb\"\r", 80);
    let out: Vec<&String> = rows.iter().skip_while(|r| !r.ends_with("b\"")).collect();
    assert_eq!(out[1..4], ["a", "", "b"], "{rows:?}");
}

#[test]
fn output_with_no_trailing_newline_survives_the_next_prompt() {
    // The editor paints from column 0 and erases as it goes, so a prompt drawn
    // where partial output left the cursor would wipe it off the screen. It
    // paints from `term::line_origin` instead, which is where that output
    // stopped — so the output stays and the prompt continues its row, as bash's
    // does.
    let rows = typed(b"printf partial\recho next\r", 80);
    assert!(
        rows.iter().any(|r| r.starts_with("partial$ ")),
        "the output is still there, with the prompt after it: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains('%')),
        "and nothing is added to say so: {rows:?}"
    );
    assert!(rows.iter().any(|r| r == "next"), "{rows:?}");
}

#[test]
fn a_complete_line_of_output_gets_no_marker() {
    // The other half: when output *does* end in a newline — the normal case —
    // the marker must leave no trace at all.
    let rows = typed(b"echo whole\recho next\r", 80);
    assert!(rows.iter().any(|r| r == "whole"), "{rows:?}");
    assert!(
        !rows.iter().any(|r| r.contains('%')),
        "no marker anywhere: {rows:?}"
    );
}

#[test]
fn a_prompt_is_laid_out_for_the_width_the_terminal_is_now() {
    // This is the shape of an rmux pane a split has just halved: the terminal
    // is a different size than it was, and a prompt laid out for the size it
    // used to be is the stray `%` of rmux's details.md §3.2 — a marker plus a
    // row of spaces for a screen that is no longer there, so the spaces
    // overflow and the marker stays on show.
    //
    // How the editor is *told* is the platform's business now (crossterm): here
    // a `SIGWINCH` from the pty, and on Motor OS — which has no signals and no
    // ioctl — a report the terminal writes into the program's own stdin. Either
    // way it arrives as a resize among the keys.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();

    pty.resize(40);
    // Enter: the prompt that follows is the first one laid out at the new size,
    // and a line that overruns 40 columns is where that shows.
    pty.master.write_all(CR).unwrap();
    let _ = pty.read_output();
    pty.send(&b"x".repeat(45));

    let rows = pty.screen(40);
    assert!(
        rows.iter().any(|r| *r == format!("$ {}", "x".repeat(38))),
        "the prompt's row ends at 40: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| *r == "x".repeat(7)),
        "and the rest wrapped onto the next: {rows:?}"
    );
}

#[test]
fn the_line_being_edited_is_repainted_at_the_new_width_with_no_key_typed() {
    // The test above ends its line first, so the next prompt is simply laid out
    // afresh. This is the half that has to happen on the news alone: the
    // terminal changes shape mid-edit and nothing follows it — no key, and on
    // Motor OS no signal either. What the editor is holding is a line laid out
    // for a screen that is not there any more, and it has one chance to redraw
    // it, which is when the resize arrives among the keys it is waiting for.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    // 50 characters: one row of 80, two of 40.
    let line = format!("echo {}", "x".repeat(45));
    pty.send(line.as_bytes());
    let _ = pty.read_output();

    pty.resize(40);
    let repaint = pty.read_output();

    // A width that changed forces a full repaint, which starts at column 0 —
    // so these bytes are a picture on their own, and replaying them is what the
    // user is left looking at.
    assert_eq!(
        screen(&repaint, 40),
        vec![format!("$ echo {}", "x".repeat(33)), "x".repeat(12)],
        "in: {repaint:?}"
    );
}

#[test]
fn a_resize_during_a_history_search_redraws_the_search_and_does_not_end_it() {
    // `^R` runs a read loop of its own, and a resize is not a key that leaves
    // it: the search stays up, redrawn for the terminal it is now on.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(format!("echo {}\r", "y".repeat(45)).as_bytes());
    let _ = pty.read_output();
    pty.send(b"\x12yyy");
    let _ = pty.read_output();

    pty.resize(40);
    let repaint = pty.read_output();

    // "(reverse-i-search)`yyy': " is 24 columns, and the line it found is 50,
    // so at 40 the two together take three rows.
    assert_eq!(
        screen(&repaint, 40),
        vec![
            format!("(reverse-i-search)`yyy': echo {}", "y".repeat(10)),
            "y".repeat(35),
        ],
        "in: {repaint:?}"
    );
}

#[test]
fn columns_and_lines_are_the_size_the_command_is_run_at() {
    // What the editor knows is of no use to the program it launches unless it
    // is written down where a program looks, which on Motor OS is `$COLUMNS`
    // and `$LINES` — the environment being how a terminal's owner tells a child
    // its size before the child has said anything.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo size=$COLUMNS,$LINES\r");
    let rows = pty.screen(80);
    assert!(rows.iter().any(|r| r == "size=80,24"), "{rows:?}");

    pty.resize(40);
    pty.send(b"echo size=$COLUMNS,$LINES\r");
    let rows = pty.screen(40);
    assert!(rows.iter().any(|r| r == "size=40,24"), "{rows:?}");
}

#[test]
fn a_size_the_environment_carried_in_stays_in_the_environment() {
    // The export rule is the variable's own, as in bash: an rmux pane and an
    // ssh session both put `$COLUMNS` in the environment when they spawn the
    // shell, so keeping it current there is what reaches the shell's children.
    let mut pty = Pty::spawn(80, &[("COLUMNS", "80"), ("LINES", "24")]);
    pty.await_prompt();
    pty.resize(40);
    pty.send(b"export -p | grep COLUMNS\r");
    let rows = pty.screen(40);
    assert!(
        rows.iter().any(|r| r == "export COLUMNS='40'"),
        "COLUMNS left the environment, or went stale in it: {rows:?}"
    );
}

#[test]
fn a_size_nobody_exported_is_not_exported_by_the_shell() {
    // The serial console is the other half of that rule: nothing there sets
    // `$COLUMNS`, so the shell tracking it must not start exporting a variable
    // the user never asked to pass on. Its children read the terminal itself.
    let mut pty = Pty::spawn(80, &[]);
    pty.await_prompt();
    pty.send(b"echo size=$COLUMNS; export -p | grep -c COLUMNS\r");
    let rows = pty.screen(80);
    assert!(rows.iter().any(|r| r == "size=80"), "{rows:?}");
    assert!(
        rows.iter().any(|r| r == "0"),
        "COLUMNS was exported: {rows:?}"
    );
}

#[test]
fn an_empty_line_at_the_prompt_just_reprompts() {
    let rows = typed(b"\r\r\recho hi\r", 80);
    assert!(rows.iter().any(|r| r == "hi"), "{rows:?}");
}

fn tmpdir(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("rush-p8-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_str().unwrap().to_string()
}
