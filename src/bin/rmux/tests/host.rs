//! rmux on the Linux host, driven over a pty the way a user drives it.
//!
//! `tests/m1.rs` drives rmux through pipes, which is enough for the byte pump
//! and says nothing about the half that exists only here: a pane on a real pty
//! (details.md §3.1), rmux's own console in raw mode, and the size `TIOCGWINSZ`
//! answers (§3.2). All three need a terminal on both sides, so this test is
//! one.
//!
//! The `Pty` below is rush's (`rush/tests/phase8.rs:37-174`), earmarked by §9.1
//! for the conformance harness; this is its first use. It waits
//! for a marker rather than for a duration — a fixed sleep is the usual way
//! these tests turn flaky.
//!
//! # The wire is not the picture
//!
//! Everything rmux writes is also replayed into a [`Grid`], and a claim about
//! what the user sees is asserted *there*. The reason is the frame diff: it
//! sends only the cells that changed (§6.3), so text that is already on screen
//! in the right place is never sent at all, and whether it was sent a moment ago
//! depends on a race with whatever program was drawing. Two checks here failed
//! that way before they were moved onto the grid. §9.1 says the same thing about
//! the conformance harness — compare the replayed screen, not bytes — and this
//! is that, with rmux's own emulator doing the replay.

#![cfg(unix)]

use std::io::Read;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use rmux::ansi::Parser;
use rmux::grid::Grid;

const RMUX: &str = env!("CARGO_BIN_EXE_rmux");
const ROWS: u16 = 30;
const COLS: u16 = 90;
/// A scratch directory this test alone uses, so that parallel tests do not
/// share one server -- and one session -- through the port file (§4.2).
fn private_tmpdir() -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rmux-host-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Distinctive enough that it cannot be mistaken for a shell's own output.
const PS1: &str = "rmux-test$ ";
/// What that prompt looks like *on the wire*, which is not the same string.
/// rmux renders rather than relays now, and the compositor does not paint a
/// blank over a blank -- so `PS1`'s trailing space is never sent, and the
/// cursor lands past it instead.
const PROMPT: &str = "rmux-test$";

/// rmux running on a pty, with this test as the terminal on the other end.
struct Pty {
    master: std::fs::File,
    child: std::process::Child,
    seen: String,
    /// What rmux has painted, rather than what it wrote: see the module docs.
    grid: Grid,
    parser: Parser,
    /// Kept so [`Drop`] can find the server this client started (§4.2).
    tmpdir: std::path::PathBuf,
}

impl Pty {
    /// Run `rmux <args>` on a pty of its own, in `tmpdir`.
    fn spawn(tmpdir: &std::path::Path, args: &[&str]) -> Pty {
        Pty::spawn_sized(tmpdir, args, ROWS, COLS)
    }

    /// The same, on a console of a size this test chose.
    ///
    /// Every other test takes [`ROWS`] x [`COLS`]; `aggressive-resize` is about
    /// what happens when two clients disagree (§7.4), so it needs a second
    /// size and a screen replayed at it.
    fn spawn_sized(tmpdir: &std::path::Path, args: &[&str], rows: u16, cols: u16) -> Pty {
        let (master, slave) = open_pty_sized(rows, cols);
        // rmux talks to the slave on all three descriptors, so it believes it
        // is on a terminal for the same reason its own panes will. `PS1` is
        // inherited straight through rmux into the pane's shell, which is what
        // makes the prompt below a check on the *pane*.
        let child = unsafe {
            Command::new(RMUX)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("TERM", "xterm")
                .env("PS1", PS1)
                .env("TMPDIR", tmpdir)
                // The server reads `$HOME/.config/rmux.toml` (§2.2), so a test
                // that wants a config of its own needs a home of its own --
                // and every other test needs one it knows is empty.
                .env("HOME", tmpdir)
                .args(args)
                .stdin(Stdio::from_raw_fd(dup(slave)))
                .stdout(Stdio::from_raw_fd(dup(slave)))
                .stderr(Stdio::from_raw_fd(dup(slave)))
                // A session of its own, with this pty as its controlling
                // terminal: that is what a user's terminal gives rmux, and it
                // is what makes a resize reach it -- the kernel sends
                // `SIGWINCH` to the pty's foreground process group, and a
                // process that is not in one is never told. On Motor OS, where
                // there is neither a signal nor a pty, the same news arrives as
                // the answer to an `ESC[6n` (§3.2).
                //
                // SAFETY: `pre_exec` runs between fork and exec, so it may call
                // only async-signal-safe functions; `setsid` and `ioctl` are
                // both on that list.
                .pre_exec(|| {
                    // Descriptor 0, not `slave`: this runs after the fork, and
                    // the parent closes `slave` and opens the next test's pty
                    // on the same number. Stdin is this child's own dup of it.
                    if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                })
                .spawn()
                .expect("failed to spawn rmux on a pty")
        };
        // The parent must not hold the slave open, or a read on the master
        // never sees the end when rmux exits.
        unsafe { libc::close(slave) };
        Pty {
            master,
            child,
            seen: String::new(),
            grid: Grid::new(rows as usize, cols as usize),
            parser: Parser::new(),
            tmpdir: tmpdir.to_owned(),
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
        self.master.flush().unwrap();
    }

    /// Whether `needle` has appeared at *any* point.
    ///
    /// [`Pty::wait_for`] deliberately only matches what arrives after the call,
    /// so that a stale prompt cannot satisfy a later check. This is for the
    /// other case: text that may already be on screen by the time the test
    /// looks, which is most of what the status line says.
    fn saw(&mut self, needle: &str) -> bool {
        self.pump();
        self.seen.contains(needle) || self.wait_for(needle)
    }

    /// Read until `needle` turns up, or give up and say what did.
    fn wait_for(&mut self, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        let from = self.seen.len().saturating_sub(needle.len());
        while Instant::now() < deadline {
            if self.seen[from..].contains(needle) {
                return true;
            }
            self.pump();
        }
        self.seen[from..].contains(needle)
    }

    fn pump(&mut self) {
        let mut buf = [0_u8; 4096];
        set_nonblocking(&self.master);
        match self.master.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(n) => {
                self.seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                let grid = &mut self.grid;
                self.parser.feed(&buf[..n], &mut |action| {
                    let _ = grid.apply(action);
                });
            }
            // WouldBlock: nothing yet. Anything else (EIO) means rmux is gone,
            // and the deadline in `wait_for` is what ends the wait.
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }

    /// One row of the painted screen, trailing blanks trimmed.
    fn painted_row(&self, row: usize) -> String {
        self.grid.line(row)
    }

    /// Whether some row of the painted screen holds `needle` right now.
    fn painted(&self, needle: &str) -> bool {
        (0..self.grid.rows()).any(|row| self.painted_row(row).contains(needle))
    }

    /// Wait until some row of the painted screen contains `needle`.
    ///
    /// Like [`Pty::saw`], this matches what is *on screen*, including text that
    /// was already there -- so the needles want to be things that appear once.
    fn wait_painted(&mut self, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.painted(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump();
        }
    }

    /// Wait until `row` of the painted screen contains `needle`.
    fn wait_painted_row(&mut self, row: usize, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.painted_row(row).contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump();
        }
    }

    /// Change the size of this console, as dragging a terminal window does.
    ///
    /// The replayed screen goes with it, and has to: rmux paints absolute
    /// positions (§6.2) and a terminal clamps them to itself, so a grid left at
    /// the old size would put the status line on a row the user cannot see --
    /// which is the very thing being tested, and would be hidden by a harness
    /// that got it wrong. Nothing tells rmux this happened (§3.2): on the host
    /// `TIOCSWINSZ` sends the pane's shell a `SIGWINCH`, but rmux's own client
    /// has to notice for itself.
    fn resize(&mut self, rows: u16, cols: u16) {
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let set = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
        assert_eq!(set, 0, "TIOCSWINSZ failed");
        self.grid = Grid::new(rows as usize, cols as usize);
        self.parser = Parser::new();
    }

    /// Wait until the painted cell at `(row, col)` holds `wanted`.
    fn wait_painted_at(&mut self, row: usize, col: usize, wanted: char) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.grid.cell(row, col).ch == wanted {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump();
        }
    }

    /// The whole painted screen, for a failure message that shows the picture.
    fn picture(&self) -> String {
        (0..self.grid.rows())
            .map(|row| format!("{row:>3}|{}\n", self.painted_row(row)))
            .collect()
    }

    /// Everything rmux has written since `mark`.
    fn mark(&self) -> usize {
        self.seen.len()
    }

    /// Pump until rmux has stopped writing, and mark that point.
    ///
    /// What a paint *costs* (§9.2) is only exact if it is measured between two
    /// standstills: a mark taken while a shell is still printing its prompt
    /// charges the next keystroke for the rest of the prompt.
    fn quiesced(&mut self) -> usize {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut last = self.seen.len();
        let mut since = Instant::now();
        while Instant::now() < deadline {
            self.pump();
            if self.seen.len() != last {
                last = self.seen.len();
                since = Instant::now();
            } else if since.elapsed() >= Duration::from_millis(250) {
                break;
            }
        }
        self.seen.len()
    }

    fn since(&self, mark: usize) -> &str {
        &self.seen[mark..]
    }

    /// Wait for rmux itself to exit, and report whether it did.
    fn exited(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return true;
            }
            self.pump();
        }
        false
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Killing the client is not enough, and that is not a bug: a session
        // outliving its client is what a detach *is* (§7.3), so a server and a
        // pane shell stay behind on purpose. A test that leaves them leaks one
        // of each per run -- which, after a few hundred runs of this suite, is
        // a few hundred of each. Ask the server to end its sessions, which is
        // also the only thing that reaps their shells (§3.6), and it exits when
        // the last one goes.
        end_sessions(&self.tmpdir);
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

/// End every session on the server in `tmpdir`, through the real commands.
fn end_sessions(tmpdir: &std::path::Path) {
    let rmux = |args: &[&str]| -> Option<String> {
        let mut child = Command::new(RMUX)
            .env("TMPDIR", tmpdir)
            .env("HOME", tmpdir)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        wait_bounded(&mut child)?;
        // A listing is tens of bytes, so the pipe cannot have filled and this
        // cannot block on a child that has already been waited for.
        let out = child.wait_with_output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    // No server, or one that has already gone, prints nothing and needs nothing.
    let Some(listing) = rmux(&["ls"]) else {
        return;
    };
    for line in listing.lines() {
        if let Some((name, _)) = line.split_once(':') {
            let _ = rmux(&["kill-session", "-t", name]);
        }
    }
}

/// Wait for a command, but not forever.
///
/// Every rmux command here answers in milliseconds when it answers at all, so a
/// deadline costs nothing and buys the difference between one test failing and
/// the whole suite hanging -- these also run from a destructor, where a hang
/// would take every test with it. `None` means it had to be killed.
fn wait_bounded(child: &mut std::process::Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Err(_) => return None,
        }
    }
}

fn open_pty_sized(rows: u16, cols: u16) -> (std::fs::File, RawFd) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
        let name = libc::ptsname(master);
        assert!(!name.is_null(), "ptsname failed");
        let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
        assert!(slave >= 0, "opening the pty slave failed");

        // This terminal does not echo, so anything that comes back came from
        // rmux. Without that, the host's own line discipline echoes every
        // keystroke and `a_keystroke_reaches_the_pane_before_enter_does` passes
        // whether or not rmux ever put this console in raw mode -- which it
        // did, until the check was falsified and found vacuous.
        let mut termios: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(slave, &mut termios), 0);
        termios.c_lflag &= !libc::ECHO;
        assert_eq!(libc::tcsetattr(slave, libc::TCSANOW, &termios), 0);

        // The size rmux's own `TIOCGWINSZ` will report, and therefore the size
        // it must hand its pane.
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(libc::ioctl(slave, libc::TIOCSWINSZ, &winsize), 0);
        (std::fs::File::from_raw_fd(master), slave)
    }
}

fn dup(fd: RawFd) -> RawFd {
    let new = unsafe { libc::dup(fd) };
    assert!(new >= 0, "dup failed");
    new
}

fn set_nonblocking(file: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        let fd = file.as_raw_fd();
        libc::fcntl(
            fd,
            libc::F_SETFL,
            libc::fcntl(fd, libc::F_GETFL, 0) | libc::O_NONBLOCK,
        );
    }
}

/// A pane with a shell at a prompt, ready to be typed at.
fn shell() -> Pty {
    shell_in(&private_tmpdir())
}

/// The same, on a named server, so two clients can meet on one session.
fn shell_in(tmpdir: &std::path::Path) -> Pty {
    shell_args(tmpdir, &[])
}

/// The same, for a client given arguments of its own.
fn shell_args(tmpdir: &std::path::Path, args: &[&str]) -> Pty {
    let mut pty = Pty::spawn(tmpdir, args);
    assert!(
        pty.wait_for(PROMPT),
        "the pane's shell never reached a prompt: {:?}",
        pty.seen
    );
    pty
}

#[test]
fn a_pane_is_a_real_terminal_to_the_program_in_it() {
    // dash prints `$PS1` only when it believes it is interactive, which it
    // decides with `isatty()` -- a property of the descriptor here, which no
    // environment variable can forge (§3.1). Reaching a prompt at all is the
    // check; running a command proves the bytes go both ways.
    let mut pty = shell();
    let mark = pty.mark();
    pty.send(b"echo $((21+21))\r");
    assert!(pty.wait_for("42"), "{:?}", pty.since(mark));
}

#[test]
fn a_pane_is_told_the_size_of_the_console_it_is_on() {
    // rmux asks the platform (`TIOCGWINSZ`) and hands the answer to the pane's
    // pty (`TIOCSWINSZ`), so `stty` inside the pane reports what this test set
    // -- minus the row the status line keeps for itself (§7.3).
    let mut pty = shell();
    let mark = pty.mark();
    pty.send(b"stty size\r");
    assert!(
        pty.wait_for(&format!("{} {COLS}", ROWS - 1)),
        "{:?}",
        pty.since(mark)
    );
}

#[test]
fn the_status_line_says_which_session_and_window_you_are_in() {
    // tmux's default `status-left` is `[#S]`, and with real sessions (§7.3)
    // that is a question a user can have. The window list follows it, marked,
    // because `prefix 0`-`9` selects by the numbers shown there.
    let mut pty = shell();
    // Two checks rather than one needle: the current window is bold, so an SGR
    // sequence sits between the session name and the window list.
    assert!(pty.saw("[0] "), "no session name: {:?}", pty.seen);
    assert!(pty.saw("0:sh*"), "no window list: {:?}", pty.seen);

    let mark = pty.mark();
    pty.send(b"\x01c");
    assert!(
        pty.wait_for("1:"),
        "the new window did not reach the status line: {:?}",
        pty.since(mark)
    );
}

#[test]
fn a_keystroke_reaches_the_pane_before_enter_does() {
    // Only true with rmux's own console in raw mode. Cooked, the host's line
    // discipline holds `xy` until Enter and rmux never sees it; this terminal
    // does not echo (see `open_pty`), so the `xy` that comes back can only be
    // the pane's own pty echoing what rmux forwarded to it.
    let mut pty = shell();
    let mark = pty.mark();
    pty.send(b"xy");
    assert!(pty.wait_for("xy"), "{:?}", pty.since(mark));
}

#[test]
fn an_interrupt_reaches_the_pane_and_leaves_rmux_alone() {
    // The pane's child is in a session of its own with the pty as controlling
    // terminal, so a `^C` becomes its SIGINT rather than rmux's. Without that
    // the sleep runs on, the shell never reads the next line, and nothing
    // below arrives.
    //
    // Two traps, both of which made this check vacuous until it was falsified:
    // a pty echoes what is typed whether or not the shell ever reads it, so a
    // needle that appears in the echoed line tests nothing (hence the quoting,
    // which the shell strips and the echo does not); and `^C` *flushes* the
    // input queue, so it must not be sent until the pane has demonstrably
    // started the command it is meant to interrupt.
    let mut pty = shell();
    pty.send(b"echo start\"\"ed; sleep 30\r");
    assert!(
        pty.wait_for("started"),
        "the pane never started the command: {:?}",
        pty.seen
    );

    let mark = pty.mark();
    pty.send(b"\x03");
    pty.send(b"echo al\"\"ive\r");
    assert!(pty.wait_for("alive"), "{:?}", pty.since(mark));
}

/// red's binary, if it has been built.
///
/// Skipping rather than failing when a tool is absent is §9.1's discipline
/// for exactly this (§9.1's `have_tmux`): a checkout that has not built red
/// still tests clean.
fn red_binary() -> Option<String> {
    let path = format!("{}/../red/target/debug/red", env!("CARGO_MANIFEST_DIR"));
    std::path::Path::new(&path).exists().then_some(path)
}

/// Every row a `ESC[{row};{col}H` in `seen` addressed.
fn rows_addressed(seen: &str) -> Vec<usize> {
    let mut rows = Vec::new();
    let mut rest = seen;
    while let Some(at) = rest.find("\x1b[") {
        rest = &rest[at + 2..];
        let row: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !row.is_empty() && rest[row.len()..].starts_with(';') {
            let tail = &rest[row.len() + 1..];
            let col: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !col.is_empty() && tail[col.len()..].starts_with('H') {
                rows.push(row.parse().unwrap_or(0));
            }
        }
    }
    rows
}

#[test]
fn red_runs_inside_a_pane_and_sizes_itself_to_it() {
    // M3's milestone (§10), and the check that §3.2 works end to end: a pane is
    // a terminal to the program in it, and one that can say how big it is. Here
    // that answer is the pane's pty (§3.1) and red reads it with an ioctl; on
    // Motor OS, where there is no pty and no ioctl, it is the `ESC[6n` that
    // crossterm asks on a clock and rmux's grid clamps to the pane. red painting
    // below row 24 is the proof it was told 30 rather than falling back to a
    // default.
    let Some(red) = red_binary() else {
        eprintln!("note: red is not built; skipping M3's milestone check");
        return;
    };
    // In the pane's own directory, so it goes when the pane does and two runs
    // at once cannot be reading each other's file.
    let mut pty = shell();
    let file = pty.tmpdir.join("red-check.txt");
    std::fs::write(&file, "alpha\nbravo\ncharlie\n").unwrap();

    pty.send(format!("{red} {}\r", file.display()).as_bytes());
    assert!(
        pty.wait_for("charlie"),
        "red never painted the file: {:?}",
        pty.seen
    );
    // red puts its status line on the last row it believes it has. Landing on
    // row 30 is the assertion: with a 24-row default it would be on row 23.
    assert!(
        rows_addressed(&pty.seen).contains(&(ROWS as usize)),
        "red sized itself to a default rather than to its pane: {:?}",
        pty.seen
    );

    // And rmux gives the pane back. red lives on the alternate screen
    // (`red/src/terminal.rs:14`), so leaving it also exercises the pane's own
    // `?1049` (§5.3): the shell's screen has to come back underneath.
    pty.send(b"\x1b:q!\r");
    assert!(
        pty.wait_for(PROMPT),
        "the shell's screen did not come back after red: {:?}",
        pty.seen
    );
}

#[test]
fn a_new_window_is_a_new_shell_and_the_old_one_keeps_running() {
    // `prefix c` (§2.1). Each window is its own shell, so a variable set in one
    // is absent in the other -- and still set when you come back to it, which
    // is the half that proves the first window was never restarted.
    let mut pty = shell();
    pty.send(b"WHICH=fir\"\"st\r");
    assert!(pty.wait_for(PROMPT), "{:?}", pty.seen);

    // The status line, *not* the new shell's prompt. A new window's prompt lands
    // on the same cells the old window's prompt was on, and the frame diff is
    // entitled to send nothing for a cell that already says the right thing
    // (§6.3) -- so whether those bytes appear depends on whether the shell got
    // its prompt out before the switch was painted. That race made this check
    // fail about one run in ten under load. The window list has to change.
    pty.send(b"\x01c");
    assert!(
        pty.wait_for("1:sh*"),
        "prefix c did not open a window: {:?}",
        pty.seen
    );
    let mark = pty.mark();
    pty.send(b"echo [$WHICH]\r");
    assert!(
        pty.wait_for("[]"),
        "the new window shares the old one's shell: {:?}",
        pty.since(mark)
    );

    pty.send(b"\x01p");
    let mark = pty.mark();
    pty.send(b"echo [$WHICH]\r");
    assert!(
        pty.wait_for("[first]"),
        "the first window's shell was restarted: {:?}",
        pty.since(mark)
    );
}

/// What a `prefix |` leaves on this test's console: the two `stty size` answers
/// and the column the border lands in.
///
/// Derived rather than written down, because the arithmetic is the claim: one
/// column goes to the border and the odd column goes to the left pane (§7.1),
/// and the status line has already taken a row (§7.3).
fn side_by_side() -> (String, String, usize) {
    let rows = ROWS as usize - 1;
    let room = COLS as usize - 1;
    let left = room.div_ceil(2);
    (
        format!("{rows} {left}"),
        format!("{rows} {}", room - left),
        left,
    )
}

/// A pane with a shell, split side by side, the new pane in front.
fn split_shell() -> Pty {
    let mut pty = shell();
    // A variable only this shell has, so the pane the keys reach can be named
    // later rather than guessed at.
    pty.send(b"WHO=le\"\"ft\r");
    assert!(pty.wait_for(PROMPT), "{:?}", pty.seen);

    let (_, _, border) = side_by_side();
    pty.send(b"\x01|");
    assert!(
        pty.wait_painted_at(1, border, '│'),
        "prefix | drew no border:\n{}",
        pty.picture()
    );
    pty
}

#[test]
fn a_split_is_a_second_shell_beside_the_first() {
    // `bind | split-window -h` (§2.1), and the whole of M7's point: two programs
    // on one screen. Each pane is its own shell, so a variable set in one is
    // absent in the other -- and still there when the keys come back, which is
    // what proves the first shell was neither restarted nor written over.
    let mut pty = split_shell();
    pty.send(b"echo [$WHO]\r");
    assert!(
        pty.wait_painted("[]"),
        "the new pane shares the old one's shell:\n{}",
        pty.picture()
    );

    // `M-Left` is the config's own binding (§2.1) and is geometric (§7.2): the
    // pane to the left is the one that was split.
    pty.send(b"\x1b[1;3D");
    pty.send(b"echo [$WHO]\r");
    assert!(
        pty.wait_painted("[left]"),
        "M-Left did not reach the pane on the left:\n{}",
        pty.picture()
    );
}

#[test]
fn a_split_tells_both_shells_they_are_narrower_now() {
    // The half of §3.2 the host has: a pane's child is told its terminal changed
    // shape (`TIOCSWINSZ`, which `stty` reads back), so the shell that was there
    // before the split learns it has half the columns. Without that it keeps
    // editing its line as though it still had the whole window.
    let (left, right, _) = side_by_side();
    let mut pty = split_shell();

    pty.send(b"stty size\r");
    assert!(
        pty.wait_painted(&right),
        "the new pane was not sized to its box (wanted {right:?}):\n{}",
        pty.picture()
    );

    pty.send(b"\x1b[1;3D");
    pty.send(b"stty size\r");
    assert!(
        pty.wait_painted(&left),
        "the pane that was split was never told (wanted {left:?}):\n{}",
        pty.picture()
    );
}

#[test]
fn killing_a_pane_gives_its_space_back_and_leaves_the_window() {
    // `prefix x`. A window with two panes survives one of them going, which is
    // the difference a split makes to what killing means -- and the pane that is
    // left gets the whole window back, told about it like any other resize.
    let (_, _, border) = side_by_side();
    let mut pty = split_shell();
    pty.send(b"\x01x");
    assert!(
        pty.wait_painted_at(1, border, ' '),
        "prefix x left the border where it was:\n{}",
        pty.picture()
    );

    pty.send(b"echo [$WHO]\r");
    assert!(
        pty.wait_painted("[left]"),
        "the surviving pane is not the one that was there:\n{}",
        pty.picture()
    );
    pty.send(b"stty size\r");
    assert!(
        pty.wait_painted(&format!("{} {COLS}", ROWS - 1)),
        "the pane did not get the whole window back:\n{}",
        pty.picture()
    );
}

#[test]
fn a_zoomed_pane_takes_the_whole_window_and_gives_it_back() {
    // `prefix z` (§2.1's `resize-pane -Z`). The status line's `Z` is the only
    // thing on screen that says why the other pane is not there, and `stty` is
    // what says the zoom is real rather than drawn.
    let (_, right, _) = side_by_side();
    let mut pty = split_shell();

    pty.send(b"\x01z");
    assert!(
        pty.wait_painted("0:sh*Z"),
        "no zoom flag:\n{}",
        pty.picture()
    );
    pty.send(b"stty size\r");
    assert!(
        pty.wait_painted(&format!("{} {COLS}", ROWS - 1)),
        "the zoomed pane did not get the window:\n{}",
        pty.picture()
    );

    pty.send(b"\x01z");
    pty.send(b"stty size\r");
    assert!(
        pty.wait_painted(&right),
        "the pane did not go back into its box (wanted {right:?}):\n{}",
        pty.picture()
    );
}

#[test]
fn killing_the_last_window_ends_the_session() {
    // `prefix &`. rmux kills outright where tmux asks first -- see the M6
    // entry in details.md, which records that as a divergence.
    let mut pty = shell();
    pty.send(b"\x01&");
    assert!(
        pty.exited(),
        "prefix & left the session running: {:?}",
        pty.seen
    );
}

#[test]
fn a_session_outlives_the_client_that_started_it() {
    // M4's whole point (§7.3): a detach leaves the shells running, and that is
    // the only reason a server is worth having. `C-a d` is the binding the
    // config specifies (§2.1), and the server is what recognizes it (§4.1) --
    // the client relays those two bytes like any others.
    let server = private_tmpdir();
    let mut pty = shell_in(&server);

    // A variable is state only *this* shell process has, so finding it again
    // proves the same shell survived rather than a new one being started.
    pty.send(b"MARK=sur\"\"vived\r");
    assert!(
        pty.wait_for(PROMPT),
        "the shell never took it: {:?}",
        pty.seen
    );

    pty.send(b"\x01d");
    assert!(
        pty.exited(),
        "the client did not detach on C-a d: {:?}",
        pty.seen
    );

    let mut again = shell_in(&server);
    again.send(b"echo $MARK\r");
    assert!(
        again.wait_for("survived"),
        "the session did not survive the detach: {:?}",
        again.seen
    );
}

/// A second console, small enough that which of the two is smaller is never in
/// doubt on either axis.
const SMALL_ROWS: u16 = 20;
const SMALL_COLS: u16 = 60;

#[test]
fn a_window_is_sized_to_the_smallest_client_watching_it() {
    // `setw -g aggressive-resize on` (§2.1). With one client it is a no-op,
    // which is why the size lives on the client (§7.4) -- and it is only
    // reachable at all because the client-server split is real (§4.1). The
    // pane's own `stty size` is what answers, since a window's size is what its
    // panes are told their terminals are (§3.2).
    let server = private_tmpdir();
    let mut big = shell_in(&server);
    big.send(b"stty size\r");
    assert!(
        big.wait_painted(&format!("{} {COLS}", ROWS - 1)),
        "one client did not get its own size:\n{}",
        big.picture()
    );

    // A second client on the same session, on a smaller console. Attaching is
    // not stealing: both are attached now, and the window has to suit both.
    let mut small = Pty::spawn_sized(&server, &[], SMALL_ROWS, SMALL_COLS);
    assert!(
        small.wait_for(PROMPT),
        "the second client never attached: {:?}",
        small.seen
    );

    big.send(b"stty size\r");
    assert!(
        big.wait_painted(&format!("{} {SMALL_COLS}", SMALL_ROWS - 1)),
        "the window was not resized for the second client:\n{}",
        big.picture()
    );

    // And it grows back when that client is gone, which is what says the size
    // is recomputed from who is watching rather than remembered as a low-water
    // mark.
    small.send(b"\x01d");
    assert!(
        small.exited(),
        "the second client did not detach: {:?}",
        small.seen
    );
    big.send(b"stty size\r");
    assert!(
        big.wait_painted(&format!("{} {COLS}", ROWS - 1)),
        "the window kept the size of a client that has gone:\n{}",
        big.picture()
    );
}

#[test]
fn a_window_nobody_is_looking_at_keeps_its_size() {
    // The other half of `aggressive-resize`, and the half that makes it worth
    // having: only the window in front is resized for a client that arrives, so
    // a background window is not narrowed by a console nobody read it on. It
    // matters because a resize *clips* rather than reflows (M3), so the columns
    // a narrowing takes off a background window are gone for good.
    let server = private_tmpdir();
    let mut big = shell_in(&server);
    big.send(b"\x01c");
    // The status line is what says the new window is in front, and the prompt
    // is not: the new shell's prompt is the same text in the same cells as the
    // one already on screen, so whether the diff sends anything at all comes
    // down to which of the two got there first (see the module docs). Waiting
    // for it passed until a test was added elsewhere in this file and the
    // machine got busy enough to lose the race.
    assert!(
        big.wait_painted("1:sh*"),
        "the second window never came up:\n{}",
        big.picture()
    );

    // A line that fits the big console and not the small one, so clipping is
    // visible as its tail going missing.
    let wide = format!("printf '{}ZZZ\\n'\r", "a".repeat(SMALL_COLS as usize));
    big.send(wide.as_bytes());
    assert!(
        big.wait_painted("ZZZ"),
        "the wide line never printed:\n{}",
        big.picture()
    );
    // The status line is what says the switch happened. The prompt is not: it
    // is already on screen in the right place, so the frame diff never sends it
    // again (see the module docs).
    big.send(b"\x010");
    assert!(
        big.wait_for("0:sh*"),
        "the first window did not come back: {:?}",
        big.seen
    );

    // A small client comes and goes while window 1 is in the background. It
    // stays in scope after that on purpose: dropping a `Pty` ends every session
    // on its server (see [`Pty::drop`]), which is the right cleanup for a test
    // and would take this one's other client with it.
    let mut small = Pty::spawn_sized(&server, &[], SMALL_ROWS, SMALL_COLS);
    assert!(
        small.wait_for(PROMPT),
        "the second client never attached: {:?}",
        small.seen
    );
    small.send(b"\x01d");
    assert!(small.exited(), "the second client did not detach");

    big.send(b"\x011");
    assert!(
        big.wait_painted("ZZZ"),
        "a window in the background was narrowed to a client that never showed it:\n{}",
        big.picture()
    );
}

#[test]
fn an_unbound_key_reaches_the_pane_as_the_bytes_it_was_made_of() {
    // §8.1: the decoder exists to recognize what is *bound*, and everything
    // else is forwarded byte for byte. A plain arrow is in neither table, so
    // the program in the pane gets it -- and the pane's own pty echoing
    // `^[[D` is that arrival, since a swallowed key would never be written.
    let mut pty = shell();
    let mark = pty.mark();
    pty.send(b"\x1b[D");
    assert!(
        pty.wait_for("^[[D"),
        "a plain Left did not reach the pane: {:?}",
        pty.since(mark)
    );
}

#[test]
fn a_bound_key_is_taken_by_rmux_and_never_reaches_the_pane() {
    // The other half, and the visible cost of the tables being real: the
    // config binds `M-Left` (§2.1), so it is rmux's key -- and in a window with
    // one pane there is nothing to its left, so it does nothing at all. A bound
    // key that leaked through would type escape sequences into a shell.
    let mut pty = shell();
    let mark = pty.mark();
    pty.send(b"\x1b[1;3D");
    pty.send(b"echo do\"\"ne\r");
    assert!(pty.wait_for("done"), "{:?}", pty.since(mark));
    assert!(
        !pty.since(mark).contains("^[[1;3D"),
        "M-Left reached the pane: {:?}",
        pty.since(mark)
    );
}

#[test]
fn a_config_file_moves_the_prefix() {
    // §2.2's whole point: the defaults are compiled in (§2.1) and `rmux.toml`
    // overrides them. Moving the prefix is the override that proves the table
    // is data rather than code -- both halves of it, since the old prefix has
    // to stop being one.
    let dir = private_tmpdir();
    std::fs::create_dir_all(dir.join(".config")).unwrap();
    std::fs::write(dir.join(".config/rmux.toml"), "prefix = \"C-b\"\n").unwrap();

    let mut pty = shell_in(&dir);
    let mark = pty.mark();
    pty.send(b"\x01");
    assert!(
        pty.wait_for("^A"),
        "C-a is still being taken as the prefix: {:?}",
        pty.since(mark)
    );

    pty.send(b"\x02d");
    assert!(
        pty.exited(),
        "C-b d did not detach, so the config did not apply: {:?}",
        pty.seen
    );
}

#[test]
fn a_config_file_can_ask_for_emacs_copy_keys() {
    // `mode-keys = "emacs"` (§2.2), end to end: the table copy mode gets is
    // the one the config named, and the keys that prove it are ones vi mode
    // does not have. `C-p` walks up the scrollback and `C-Space`/`C-w` take a
    // line -- which then pastes, so the buffer is visible in the pane rather
    // than only in the server.
    let dir = private_tmpdir();
    std::fs::create_dir_all(dir.join(".config")).unwrap();
    std::fs::write(dir.join(".config/rmux.toml"), "mode-keys = \"emacs\"\n").unwrap();

    let mut pty = shell_in(&dir);
    pty.send(b"echo COPYME\r");
    assert!(
        pty.wait_painted("COPYME"),
        "the pane never printed:\n{}",
        pty.picture()
    );

    // Copy mode, then emacs' own motions: up two lines to the echoed output,
    // and select to the end of it.
    pty.send(b"\x01[");
    assert!(
        pty.wait_painted("-- copy mode --"),
        "copy mode never opened:\n{}",
        pty.picture()
    );
    pty.send(b"\x10\x10\x01\x00\x05\x17");
    assert!(
        pty.wait_painted("0:sh*"),
        "the copy did not leave copy mode:\n{}",
        pty.picture()
    );

    pty.send(b"\x01]");
    assert!(
        pty.wait_for("COPYME"),
        "the emacs keys copied nothing: {:?}",
        pty.seen
    );
}

#[test]
fn the_prefix_can_still_be_typed_at_the_pane() {
    // `bind C-a send-prefix` (§2.1, §8.2): `C-a C-a` is one literal C-a, which
    // is what makes a prefix usable at all when something inside a pane wants
    // that key. rush prints `^C`-style markers for control characters, so what
    // comes back names the byte that arrived.
    let mut pty = shell();
    let mark = pty.mark();
    pty.send(b"echo A\x01\x01B\r");
    assert!(pty.wait_for("AB"), "the command never ran: {:?}", pty.seen);
    // The pane's own pty echoes a control byte as `^A`, so that marker in what
    // came back is the byte itself arriving. Without `send-prefix` both bytes
    // would have been eaten by the server and the echo would read `echo AB`.
    assert!(
        pty.since(mark).contains("^A"),
        "the literal prefix did not reach the pane: {:?}",
        pty.since(mark)
    );
}

#[test]
fn rmux_exits_when_the_shell_in_its_pane_does() {
    let mut pty = shell();
    pty.send(b"exit\r");
    assert!(pty.exited(), "rmux outlived its only pane: {:?}", pty.seen);
}

#[test]
fn a_window_can_be_renamed_and_the_status_line_says_so() {
    // `prefix ,` (§2.1). The prompt borrows the status row, and the keys typed
    // into it reach no pane -- which is the point of a mode.
    let mut pty = shell();
    pty.send(b"\x01,");
    assert!(pty.saw("(rename-window)"), "no prompt: {:?}", pty.seen);
    pty.send(b"build\r");
    assert!(
        pty.wait_for("0:build*"),
        "the rename did not reach the status line: {:?}",
        pty.seen
    );
}

#[test]
fn a_session_can_be_renamed_and_the_status_line_says_so() {
    // `prefix $` (§7.3). A session's name is what `rmux attach -t` takes, so
    // this is a rename of the thing itself and not of a label.
    let mut pty = shell();
    pty.send(b"\x01$");
    assert!(pty.saw("(rename-session)"), "no prompt: {:?}", pty.seen);
    pty.send(b"work\r");
    assert!(
        pty.wait_for("[work]"),
        "the rename did not reach the status line: {:?}",
        pty.seen
    );
}

#[test]
fn a_command_typed_at_the_prompt_runs() {
    // `prefix :` (§2.1), which was a bound key that did nothing until M9. The
    // vocabulary is the one a config file's values are written in (§2.2) -- and
    // the prompt does not make it a command *language*: `Command::parse` takes
    // a name and its flags and nothing else.
    let (_, _, border) = side_by_side();
    let mut pty = shell();
    pty.send(b"\x01:");
    assert!(
        pty.wait_painted(":"),
        "prefix : opened no prompt:\n{}",
        pty.picture()
    );

    pty.send(b"split-window -h\r");
    assert!(
        pty.wait_painted_at(1, border, '│'),
        "the typed command did not run:\n{}",
        pty.picture()
    );
}

#[test]
fn a_command_rmux_does_not_have_is_said_on_the_message_line() {
    // §2.2's message line, from the outside: the row a message lands on is the
    // status row, and the next key is what takes it back. Without it, a
    // mistyped command and a command that did nothing look identical.
    let mut pty = shell();
    pty.send(b"\x01:frobnicate\r");
    assert!(
        pty.wait_painted("unknown command: frobnicate"),
        "rmux said nothing about a command it does not have:\n{}",
        pty.picture()
    );
    // On the status row, not over the pane -- a message costs no rows.
    assert!(
        pty.painted_row(ROWS as usize - 1)
            .contains("unknown command"),
        "the message is not on the status row:\n{}",
        pty.picture()
    );

    pty.send(b"x");
    assert!(
        pty.wait_painted("0:sh*"),
        "the next key did not take the status row back:\n{}",
        pty.picture()
    );
}

#[test]
fn a_prompt_can_be_abandoned_without_renaming_anything() {
    let mut pty = shell();
    pty.send(b"\x01,");
    assert!(pty.saw("(rename-window)"), "{:?}", pty.seen);
    pty.send(b"nonsense\x1b");
    // Esc puts the status line back, name untouched.
    assert!(
        pty.wait_for("0:sh*"),
        "Esc did not abandon the prompt: {:?}",
        pty.seen
    );
}

/// Where the client looks for the port a server is on (`sys::unix::port_file`).
fn port_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(format!("rmux-{}.port", unsafe { libc::getuid() }))
}

#[test]
fn a_client_that_reaches_something_other_than_a_server_starts_one() {
    // The port file names a port and nothing more, so what answers there may not
    // be a server: a file left behind by one that was killed, or a port since
    // handed to another program. All of those look the same from the client --
    // a connection accepted, and then silence -- and a listener that never
    // speaks stands in for every one of them.
    //
    // This is the shape of a hang found on the VM: a client with both reader
    // threads up, blocked waiting, and no server process on the machine at all.
    // On a console it is invisible -- a blank alternate screen with the cursor
    // wherever the size probe left it -- which is the worst way for a program to
    // fail. Being *told* was the first fix; opening the session anyway is this
    // one, because on Motor OS a reboot with a session running leaves exactly
    // this behind and "try again" was the whole of the user's morning.
    let dir = private_tmpdir();
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    std::fs::write(port_file(&dir), port.to_string()).unwrap();

    // A pty of its own, like every other client here. Not a spare detail: a
    // client takes its console into raw mode, and one started on the terminal
    // `cargo test` was run from would take *that* -- either leaving it raw for
    // the developer, or stopping the whole run with a `SIGTTOU` from a
    // background process group, somewhere no timeout can reach it.
    let mut pty = Pty::spawn(&dir, &[]);
    assert!(
        pty.wait_for(PROMPT),
        "rmux never got past the port file: {:?}",
        pty.seen
    );

    // And the misleading port was forgotten: the file names the server this
    // client started instead.
    let named = std::fs::read_to_string(port_file(&dir)).unwrap();
    assert_ne!(named.trim().parse::<u16>().unwrap(), port, "{named:?}");
}

#[test]
fn a_question_asked_of_something_that_is_not_a_server_answers_too() {
    // `rmux ls` has nowhere to show a hang: it would simply never return, and a
    // script that runs it would stop there.
    let dir = private_tmpdir();
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std::fs::write(
        port_file(&dir),
        silent.local_addr().unwrap().port().to_string(),
    )
    .unwrap();

    let mut ls = Command::new(RMUX)
        .env("TMPDIR", &dir)
        .env("HOME", &dir)
        .arg("ls")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = wait_bounded(&mut ls).expect("rmux ls never returned");
    assert_eq!(status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ls_names_every_session_and_says_which_is_attached() {
    // `rmux ls` (§7.3), which is a question about the server and never touches
    // the console -- so it is an ordinary command, not a client.
    let dir = private_tmpdir();
    let _held = shell_in(&dir);
    let out = Command::new(RMUX)
        .env("TMPDIR", &dir)
        .env("HOME", &dir)
        .arg("ls")
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0));
    assert!(listing.contains("0: 1 window (attached)"), "{listing:?}");
}

#[test]
fn kill_session_answers_the_client_that_asked_for_it() {
    // `rmux kill-session -t 0` (§7.3). The server used to handle this one
    // silently, and a client blocked on a reply waits silence out forever -- so
    // what this checks is that the command *returns*, not just that the session
    // goes. Spawned rather than `output()`ed because the regression is a hang,
    // and a hang has no timeout inside the test harness.
    //
    // Two sessions, and the *other* one is the point: killing the last session
    // ends the server, and a server that goes closes the socket, which answers
    // the question by accident. With `notes` still there the server stays up and
    // owes the reply.
    let dir = private_tmpdir();
    let _held = shell_in(&dir);
    let _notes = shell_args(&dir, &["new", "-s", "notes"]);
    let mut kill = Command::new(RMUX)
        .env("TMPDIR", &dir)
        .env("HOME", &dir)
        .args(["kill-session", "-t", "0"])
        .spawn()
        .unwrap();

    let status = wait_bounded(&mut kill).expect("kill-session never returned");
    assert_eq!(status.code(), Some(0));

    // And the session went with it, which is what was asked for -- while the
    // one that was not named stayed.
    let listing = Command::new(RMUX)
        .env("TMPDIR", &dir)
        .env("HOME", &dir)
        .arg("ls")
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout);
    assert!(listing.contains("notes:"), "{listing:?}");
    assert!(
        !listing.contains("0:"),
        "the session outlived its kill: {listing:?}"
    );
}

#[test]
fn new_starts_a_session_of_its_own_and_the_list_switches_between_them() {
    // `rmux new -s notes` (§7.3), then `prefix s` -- the plain numbered menu,
    // which is the smallest thing that lets a user see and switch sessions
    // (§1.2 keeps choose-tree out).
    let dir = private_tmpdir();
    let _first = shell_in(&dir);
    let mut second = shell_args(&dir, &["new", "-s", "notes"]);
    assert!(
        second.saw("[notes]"),
        "new did not name the session: {:?}",
        second.seen
    );

    second.send(b"\x01s");
    assert!(
        second.saw("-- sessions:"),
        "no session list: {:?}",
        second.seen
    );
    // Pick the first one by digit; the status line follows.
    second.send(b"0");
    assert!(
        second.wait_for("[0]"),
        "the list did not switch sessions: {:?}",
        second.seen
    );
}

// ---- byte costs (§9.2) ----
//
// rmux's output reaches a Motor user through sys-tty, which writes it to a
// polled UART a byte at a time (§6.3): a full 80x24 repaint is several
// kilobytes and about a second on a real serial line. So the diff is the
// feature rather than an optimization, and "switching panes costs N bytes" is
// a claim that can regress silently and that only a test can hold.
//
// `screen.rs`'s own tests make the same claims against a `Frame`, which is
// where they are cheapest to write. These are the end-to-end version: what
// actually goes down the wire, through the server, the socket, and the client.

#[test]
fn a_keystroke_echoed_in_a_pane_costs_one_byte() {
    // §9.2's central claim, measured on the wire, and it is the strongest form
    // of it: a character typed at a prompt costs the character. Not seven bytes
    // and a position -- the console's cursor is already where that character
    // goes, because rmux knows what it last sent (§6.1) rather than guessing.
    // Pinned as an equality, so a regression shows up as the bytes it added.
    //
    // The keystroke before it is not ceremony. The status line is reverse video
    // (§7.3), so a frame that ends on it leaves the console in that style, and
    // the next cell painted in a pane has to say `ESC[0m` first -- five bytes
    // rather than one. Whether the *first* keystroke pays that depends on
    // whether the shell's prompt landed in the same frame as the status line,
    // which is a race with the shell's startup: under a loaded host it did, and
    // this test failed once in five runs before it measured from a style it had
    // put the console in itself.
    let mut pty = shell();
    pty.send(b"a");
    assert!(pty.wait_for("a"), "{:?}", pty.seen);
    let mark = pty.quiesced();
    pty.send(b"x");
    assert!(pty.wait_for("x"), "{:?}", pty.since(mark));
    pty.quiesced();

    let cost = pty.since(mark).to_owned();
    assert_eq!(cost, "x", "a keystroke cost {} bytes", cost.len());
}

#[test]
fn moving_between_panes_repaints_no_pane_content() {
    // Both panes are already on screen and neither changed, so what a switch
    // costs is the cursor moving to the other one -- the composited cursor
    // being the only thing that says which pane is in front (§7.1). Anything
    // more means the compositor is repainting cells it has already sent.
    let mut pty = split_shell();
    let mark = pty.quiesced();
    pty.send(b"\x1b[1;3D");
    pty.quiesced();

    let cost = pty.since(mark).to_owned();
    assert!(
        !cost.contains(PROMPT),
        "a pane switch repainted a prompt: {cost:?}"
    );
    assert!(
        cost.len() <= 8,
        "a pane switch cost {} bytes: {cost:?}",
        cost.len()
    );
}

#[test]
fn an_idle_multiplexer_writes_nothing_at_all() {
    // There is no clock on the status line, and this is what that buys (§7.3):
    // a server that blocks until something happens rather than waking every
    // second, and a console that receives nothing while nobody types. A clock
    // would cost this test a rewrite and every idle serial line six bytes a
    // minute.
    let mut pty = shell();
    let mark = pty.quiesced();
    std::thread::sleep(Duration::from_millis(500));
    pty.pump();
    assert_eq!(pty.since(mark), "", "an idle rmux wrote to the console");
}

#[test]
fn a_resize_moves_the_border_on_screen() {
    // `prefix C-Left` and `prefix C-Right`, which are tmux's own bindings for
    // `resize-pane` (§2.1's table plus the tmux defaults it is written
    // against). The border moves the way the arrow points, whichever pane is
    // active -- see `layout::resize`, and the corpus case that settled it.
    let mut pty = split_shell();
    let (_, _, border) = side_by_side();
    pty.send(b"\x01\x1b[1;5D");
    assert!(
        pty.wait_painted_at(1, border - 1, '│'),
        "the border did not move left:\n{}",
        pty.picture()
    );

    // And back, which is what says the border is being moved rather than
    // redrawn somewhere new each time.
    pty.send(b"\x01\x1b[1;5C");
    assert!(
        pty.wait_painted_at(1, border, '│'),
        "the border did not come back:\n{}",
        pty.picture()
    );
}

#[test]
fn a_pane_is_told_the_size_a_resize_gave_it() {
    // The tree and the grids cannot disagree (`Window::fit`), and `stty size`
    // is the pane's own answer rather than rmux's -- it comes from the pty the
    // pane was spawned on, which `Pane::resize` is what changes.
    let mut pty = split_shell();
    let (_, right, _) = side_by_side();
    pty.send(b"stty size\r");
    assert!(
        pty.wait_painted(&right),
        "the new pane started at the wrong size:\n{}",
        pty.picture()
    );

    pty.send(b"\x01\x1b[1;5D");
    pty.send(b"stty size\r");
    let (rows, cols) = right.split_once(' ').expect("two numbers");
    let wider = format!("{rows} {}", cols.parse::<usize>().unwrap() + 1);
    assert!(
        pty.wait_painted(&wider),
        "the pane was not told it had been resized:\n{}",
        pty.picture()
    );
}

/// A console two thirds the size, and still big enough for a split.
const SMALLER: (u16, u16) = (ROWS - 10, COLS - 30);

#[test]
fn a_console_that_changes_size_is_noticed_and_repainted() {
    // Nothing tells rmux that a terminal window was dragged: Motor has no size
    // call and no `SIGWINCH`, and the host's signal is not in the `sys::` seam
    // (§3.2). So the client asks on a clock, and this is what that buys -- the
    // status line follows the bottom of the console instead of staying on a row
    // that is no longer there. Without it the row is simply lost, and *stays*
    // lost when the console comes back, because the frame diff sends only what
    // changed (§6.2) and nothing in rmux did.
    let mut pty = split_shell();
    assert!(
        pty.wait_painted_row(ROWS as usize - 1, "0:sh*"),
        "no status line to begin with:\n{}",
        pty.picture()
    );

    pty.resize(SMALLER.0, SMALLER.1);
    assert!(
        pty.wait_painted_row(SMALLER.0 as usize - 1, "0:sh*"),
        "a smaller console did not get its status line back:\n{}",
        pty.picture()
    );

    pty.resize(ROWS, COLS);
    assert!(
        pty.wait_painted_row(ROWS as usize - 1, "0:sh*"),
        "the console came back and the status line did not:\n{}",
        pty.picture()
    );
}

#[test]
fn a_console_squeezed_to_nothing_does_not_take_the_session_with_it() {
    // A resize is a user dragging a window, so every size on the way is a size
    // rmux is handed -- including two rows and a split that has no room to be
    // one. The session is not the client's to lose: it must arrive back intact
    // when the window does.
    let mut pty = split_shell();
    pty.resize(2, 12);
    assert!(
        pty.wait_painted_row(1, "0:sh*"),
        "a two-row console lost its status line:\n{}",
        pty.picture()
    );

    pty.resize(ROWS, COLS);
    assert!(
        pty.wait_painted_row(ROWS as usize - 1, "0:sh*"),
        "the session did not come back with the window:\n{}",
        pty.picture()
    );
}

#[test]
fn a_pane_is_told_the_console_changed_size() {
    // A repaint at the right size is half of it; the pane's own idea of its
    // terminal is the other half, and it is what `red` and `rush` size
    // themselves by (§3.2). One pane, so it gets everything but the status row.
    let mut pty = shell();
    assert!(pty.wait_painted(PROMPT), "no prompt:\n{}", pty.picture());

    // The status line on the new bottom row is what says the resize has landed.
    // Asking before it has is a race the shell wins: it answers at the size it
    // still has, and the answer scrolls into history when the pane shrinks.
    pty.resize(SMALLER.0, SMALLER.1);
    assert!(
        pty.wait_painted_row(SMALLER.0 as usize - 1, "0:sh*"),
        "the console shrank and rmux did not notice:\n{}",
        pty.picture()
    );

    pty.send(b"stty size\r");
    let wanted = format!("{} {}", SMALLER.0 - 1, SMALLER.1);
    assert!(
        pty.wait_painted(&wanted),
        "the pane was not told the console shrank (wanted {wanted:?}):\n{}",
        pty.picture()
    );
}

#[test]
fn a_refresh_is_the_one_key_that_repaints_everything() {
    // The other half of §9.2's "a full repaint happens only on resize and a
    // refresh", and the half a keystroke test cannot make: the prompt is
    // already on screen, so the diff would never send it again (see the module
    // docs) -- and here it does, because `prefix r` threw away what rmux
    // believed the console held. That belief is exactly what a stray write to
    // the console breaks, and nothing but this key can fix it.
    let mut pty = shell();
    assert!(pty.wait_painted(PROMPT), "no prompt:\n{}", pty.picture());
    let mark = pty.quiesced();
    pty.send(b"\x01r");
    assert!(
        pty.wait_for(PROMPT),
        "a refresh did not repaint the pane: {:?}",
        pty.since(mark)
    );
    // The status line comes with it: a full repaint is the whole console.
    assert!(
        pty.since(mark).contains("0:sh*"),
        "a refresh did not repaint the status line: {:?}",
        pty.since(mark)
    );
}

#[test]
fn a_clear_screen_still_belongs_to_the_program_in_the_pane() {
    // `C-l` is bound to nothing, deliberately: tmux leaves it to the pane and
    // so does rmux, because a multiplexer that took it would take it from every
    // program in every pane -- readline clears a screen with it, and `less` and
    // `vi` redraw with it. The pane's own pty echoing `^L` is that arrival, as
    // it is for the arrow key above.
    let mut pty = shell();
    assert!(pty.wait_painted(PROMPT), "no prompt:\n{}", pty.picture());
    let mark = pty.mark();
    pty.send(b"\x0c");
    assert!(
        pty.wait_for("^L"),
        "`C-l` did not reach the pane: {:?}",
        pty.since(mark)
    );
}

/// A shell that has printed more than the screen can hold, so that the marker
/// at the start of it is in the scrollback and nowhere else (§7.5).
fn shell_with_scrollback() -> Pty {
    let mut pty = shell();
    pty.send(b"echo STARTMARK; for i in $(seq 1 60); do echo LINE$i; done\r");
    assert!(
        pty.wait_painted("LINE60"),
        "the pane never printed enough to scroll:\n{}",
        pty.picture()
    );
    assert!(
        !pty.painted("STARTMARK"),
        "the marker never left the screen, so nothing was scrolled back:\n{}",
        pty.picture()
    );
    pty
}

#[test]
fn copy_mode_reads_what_has_scrolled_off_the_top() {
    // M8's milestone (§10): `prefix [` then `g`, and a line the pane lost off
    // the top is on screen again. It exists only in the compacted history
    // (§7.5) by then -- the check above says so -- so this is that
    // representation being rendered back.
    let mut pty = shell_with_scrollback();
    pty.send(b"\x01[");
    assert!(
        pty.wait_painted("-- copy mode --"),
        "prefix [ did not open copy mode:\n{}",
        pty.picture()
    );
    pty.send(b"g");
    assert!(
        pty.wait_painted("STARTMARK"),
        "copy mode did not reach the scrollback:\n{}",
        pty.picture()
    );

    // And `q` puts the pane back where the shell left it.
    pty.send(b"q");
    assert!(
        pty.wait_painted("LINE60"),
        "q did not leave copy mode:\n{}",
        pty.picture()
    );
}

#[test]
fn a_search_in_copy_mode_finds_a_line_that_is_no_longer_on_screen() {
    // `?needle Enter` (§7.6). The needle is in history, so what this exercises
    // is the search reading the same rows copy mode walks.
    let mut pty = shell_with_scrollback();
    pty.send(b"\x01[");
    pty.send(b"?STARTMARK\r");
    assert!(
        pty.wait_painted("STARTMARK"),
        "the search did not find the line:\n{}",
        pty.picture()
    );
    pty.send(b"q");
}

#[test]
fn text_copied_out_of_the_scrollback_pastes_into_the_pane() {
    // The other half of §7.6, end to end: select a line in copy mode, `Enter`
    // to take it, `prefix ]` to type it back into the shell. What comes back is
    // the pane's own pty echoing what rmux wrote to it -- with no trailing
    // newline, because the copied line has none and a paste is exactly the
    // bytes that were copied.
    let mut pty = shell();
    pty.send(b"echo COPY\"\"ME\r");
    assert!(
        pty.wait_painted("COPYME"),
        "the marker never printed:\n{}",
        pty.picture()
    );

    // Backwards from the prompt, so the match is the *output* line rather than
    // the command that printed it; then start of line, select, end of line.
    pty.send(b"\x01[");
    pty.send(b"?COPYME\r");
    pty.send(b"0 $\r");
    pty.send(b"\x01]");
    assert!(
        pty.wait_painted(&format!("{PROMPT} COPYME")),
        "the paste did not reach the shell:\n{}",
        pty.picture()
    );
}
