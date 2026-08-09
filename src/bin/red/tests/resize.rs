//! Resize, as a terminal user causes it.
//!
//! red's only source of size news is the event stream: `main`'s loop takes a
//! [`Key::Resize`] out from among the keys and applies it, and nothing anywhere
//! asks the terminal for its size on a clock. These tests drive that from the
//! outside, over a **pty**, because the property worth checking is not that
//! `apply_terminal_size` sets two fields — `editor.rs` unit-tests that — but
//! that a resize nobody typed reaches the editor at all, and arrives the right
//! way round.
//!
//! A pty is this host's version of the same event: resizing one raises
//! `SIGWINCH`, which crossterm turns into `Event::Resize`. Motor OS has no
//! signals, and there the carrier is an in-band report the terminal pushes
//! (DEC mode 2048, `docs/plans/terminal-size-events.md`) — but everything above
//! crossterm, which is the whole of red's side, is the same code on both. What
//! only Motor OS can answer is the owner-known first paint, where the size
//! arrives as `$COLUMNS`/`$LINES` set by rmux or russhd before red exists;
//! `src/tests/test-terminal-size.sh` drives that end.
//!
//! The gauge is red's own status bar. `render_status_bar` pads it to exactly
//! `screen_cols`, and `draw` puts it on the row below the text area, so a single
//! bar says both how wide red thinks the terminal is and how tall. Nothing here
//! ever types a key, which is the point: a keystroke repaints too, so a repaint
//! that follows one proves nothing about what caused it.

#![cfg(unix)]

use std::io::Read;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const RED: &str = env!("CARGO_BIN_EXE_red");

// ---- a pty ------------------------------------------------------------------

/// A pty master, with red running on the slave side.
struct Pty {
    master: std::fs::File,
    child: std::process::Child,
    /// Everything red has written so far.
    seen: String,
}

impl Pty {
    /// Start red on a pty of the given shape, editing nothing.
    fn spawn(cols: u16, rows: u16) -> Pty {
        let (master, slave) = open_pty(cols, rows);
        let mut cmd = Command::new(RED);
        cmd.env_clear()
            .env("TERM", "xterm")
            // `home_dir()` falls back to the password database when `$HOME` is
            // unset, so it is pointed somewhere empty rather than cleared: the
            // editor under test is the default one, not the developer's.
            .env("HOME", env!("CARGO_TARGET_TMPDIR"));
        // Redirecting stdio does not change `/dev/tty`: without a new session it
        // still names the test runner's terminal, whose size crossterm would
        // read instead. Make the slave red's controlling terminal too, which is
        // also what makes `SIGWINCH` arrive.
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
        // Each `Stdio` owns the fd it is given, hence a dup apiece; `slave`
        // itself stays ours to close below.
        let child = unsafe {
            cmd.stdin(Stdio::from_raw_fd(dup(slave)))
                .stdout(Stdio::from_raw_fd(dup(slave)))
                .stderr(Stdio::from_raw_fd(dup(slave)))
                .spawn()
                .expect("failed to spawn red on a pty")
        };
        // The parent must not hold the slave open, or a read on the master never
        // sees EOF when the editor exits.
        unsafe { libc::close(slave) };
        Pty {
            master,
            child,
            seen: String::new(),
        }
    }

    /// Reshape the terminal, and return everything red wrote afterwards.
    ///
    /// No key is ever sent, here or anywhere in this file, so those bytes have
    /// exactly one possible cause.
    fn resize(&mut self, cols: u16, rows: u16) -> String {
        set_pty_size(self.master.as_raw_fd(), cols, rows);
        self.read_output()
    }

    /// Read until red goes quiet, and return what arrived this time.
    fn read_output(&mut self) -> String {
        let mut out = Vec::new();
        let mut buf = [0_u8; 4096];
        let deadline = Instant::now() + Duration::from_millis(2000);
        let mut idle_since = Instant::now();
        set_nonblocking(&self.master);
        while Instant::now() < deadline {
            match self.master.read(&mut buf) {
                Ok(0) => break, // red exited
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    idle_since = Instant::now();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if idle_since.elapsed() > Duration::from_millis(250) && !out.is_empty() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                // EIO: the slave side closed, i.e. red exited.
                Err(_) => break,
            }
        }
        let out = String::from_utf8_lossy(&out).into_owned();
        self.seen.push_str(&out);
        out
    }

    /// Wait for red's first paint. Until it has painted there is no size to read
    /// off the wire, and a resize would be racing the first draw.
    fn await_first_paint(&mut self) {
        for _ in 0..5 {
            if !status_bars(&self.seen).is_empty() {
                return;
            }
            let _ = self.read_output();
        }
        panic!("red never painted a status bar; it wrote {:?}", self.seen);
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn open_pty(cols: u16, rows: u16) -> (std::fs::File, RawFd) {
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
        set_pty_size(slave, cols, rows);
        (std::fs::File::from_raw_fd(master), slave)
    }
}

fn dup(fd: RawFd) -> RawFd {
    let new = unsafe { libc::dup(fd) };
    assert!(new >= 0, "dup failed");
    new
}

/// Give the pty a shape, which is also how the program on it is told: setting a
/// pty's size sends `SIGWINCH` to the process group on the other end.
fn set_pty_size(fd: RawFd, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    assert_eq!(unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) }, 0);
}

fn set_nonblocking(f: &std::fs::File) {
    unsafe {
        let flags = libc::fcntl(f.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(f.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

// ---- reading the size back off the wire -------------------------------------

/// Every status bar in `out`, as (row, width): the row a terminal counts from 1,
/// and the number of characters the bar was padded to.
///
/// Both are read off the wire rather than asked of red — the bar is placed by
/// the cursor move in front of it and runs to the next escape sequence.
fn status_bars(out: &str) -> Vec<(usize, usize)> {
    // `Style::Status` is near-black ink on amber ground, and nothing else in red
    // paints on that ground, so it alone identifies the bar.
    const GROUND: &str = "\x1b[48;5;222m";
    let mut bars = Vec::new();
    let mut at = 0;
    while let Some(found) = out[at..].find(GROUND) {
        let text = at + found + GROUND.len();
        let width = out[text..].chars().take_while(|&c| c != '\x1b').count();
        bars.push((row_of_last_move(&out[..at + found]), width));
        at = text;
    }
    bars
}

/// The row the last cursor move in `before` moved to, counting from 1.
fn row_of_last_move(before: &str) -> usize {
    let mut rest = before;
    while let Some(csi) = rest.rfind("\x1b[") {
        let seq = &rest[csi + 2..];
        if let Some(end) = seq.find(|c: char| c.is_ascii_alphabetic())
            && seq.as_bytes()[end] == b'H'
        {
            return seq[..end]
                .split(';')
                .next()
                .and_then(|row| row.parse().ok())
                .unwrap_or(1);
        }
        rest = &rest[..csi];
    }
    0
}

/// The last status bar in `out`: the shape red has left the user looking at.
fn last_bar(out: &str) -> (usize, usize) {
    match status_bars(out).last() {
        Some(&bar) => bar,
        None => panic!("red painted no status bar; it wrote {out:?}"),
    }
}

// ---- the tests --------------------------------------------------------------

#[test]
fn the_first_paint_is_the_shape_the_terminal_already_is() {
    let mut pty = Pty::spawn(100, 30);
    pty.await_first_paint();

    // 30 rows: 28 of text, then the status bar, then the message bar. red has
    // asked nothing and waited for nothing to know that.
    assert_eq!(
        last_bar(&pty.seen),
        (29, 100),
        "first paint: {:?}",
        pty.seen
    );
}

#[test]
fn a_resize_repaints_at_the_new_shape_with_no_key_typed() {
    let mut pty = Pty::spawn(80, 24);
    pty.await_first_paint();
    assert_eq!(last_bar(&pty.seen), (23, 80), "first paint: {:?}", pty.seen);

    let after = pty.resize(40, 20);

    // A changed row count invalidates the frame cache, so the screen is cleared
    // once and repainted whole.
    assert!(
        after.contains("\x1b[2J"),
        "the resize did not repaint the screen: {after:?}"
    );
    // 40x20 is not 20x40: a bar 40 wide on row 19 also says rows and columns
    // did not change places on the way in.
    assert_eq!(last_bar(&after), (19, 40), "after the resize: {after:?}");
}

#[test]
fn the_second_resize_is_noticed_as_readily_as_the_first() {
    let mut pty = Pty::spawn(80, 24);
    pty.await_first_paint();

    let after = pty.resize(40, 20);
    assert_eq!(last_bar(&after), (19, 40), "after the resize: {after:?}");

    // Not a one-shot: the subscription outlives the first report it delivers,
    // which is the whole difference between a push and a question answered once.
    let after = pty.resize(100, 30);
    assert_eq!(
        last_bar(&after),
        (29, 100),
        "after the second resize: {after:?}"
    );
}
