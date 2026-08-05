//! M1 end-to-end: rmux as a byte pump between the console and one shell.
//!
//! `pane`'s unit tests drive a pane directly; these drive the *binary*, over its
//! own stdin and stdout, which is the only way to reach the half M1 adds — the
//! event loop, the console reader, and the exit code the pane's child chose.
//!
//! A pty, and not a pipe, because rmux's console layer is crossterm's now and
//! crossterm reads a terminal: on the host, given a stdin that is not one, it
//! goes looking for `/dev/tty` — which in a test run is whichever terminal
//! `cargo test` was started from. Motor OS has no such trapdoor and no ptys
//! either; there a console is a pipe that says it is a terminal, which is the
//! shape `tests/host.rs`'s panes have and this file cannot reproduce on Linux.

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

const RMUX: &str = env!("CARGO_BIN_EXE_rmux");

/// A scratch directory this test alone uses.
///
/// rmux is a server plus clients now, and a client attaches to whichever
/// server the port file names (details.md §4.2). Tests run in parallel, so
/// without a directory apiece they would all attach to the *same* session and
/// read each other's output. `$TMPDIR` is what decides where the port file
/// goes on the host, which is exactly the knob needed.
fn private_tmpdir() -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "rmux-m1-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// rmux on a console this test is the terminal on the other end of.
struct Console {
    master: std::fs::File,
    child: std::process::Child,
    tmpdir: std::path::PathBuf,
    seen: String,
}

impl Console {
    fn start(rows: u16, cols: u16) -> Console {
        let tmpdir = private_tmpdir();
        let (master, slave) = open_pty(rows, cols);
        // A session of its own, with the pty as its controlling terminal: that
        // is what a user's terminal gives rmux, and it is what makes a resize
        // reach it — the kernel sends `SIGWINCH` to the pty's foreground
        // process group, and a process that is not in one is never told.
        //
        // SAFETY: `pre_exec` runs between fork and exec, so it may call only
        // async-signal-safe functions; `setsid` and `ioctl` are both on that
        // list.
        let child = unsafe {
            Command::new(RMUX)
                .env("TMPDIR", &tmpdir)
                .env("HOME", &tmpdir)
                .stdin(Stdio::from_raw_fd(dup(slave)))
                .stdout(Stdio::from_raw_fd(dup(slave)))
                .stderr(Stdio::from_raw_fd(dup(slave)))
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
        // The parent must not hold the slave open, or a read on the master never
        // sees the end when rmux exits.
        unsafe { libc::close(slave) };
        Console {
            master,
            child,
            tmpdir,
            seen: String::new(),
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
        self.master.flush().unwrap();
    }

    fn pump(&mut self) {
        let mut buf = [0_u8; 4096];
        set_nonblocking(&self.master);
        match self.master.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(n) => self.seen.push_str(&String::from_utf8_lossy(&buf[..n])),
            // WouldBlock: nothing yet. Anything else (EIO) means rmux is gone.
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }

    /// Read until `needle` has been painted, or give up.
    fn wait_for(&mut self, needle: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.seen.contains(needle) {
                return true;
            }
            self.pump();
        }
        self.seen.contains(needle)
    }

    /// Make the console `rows` x `cols`, which is also how rmux is told: setting
    /// a pty's size sends `SIGWINCH` to the process group on the other end.
    fn resize(&mut self, rows: u16, cols: u16) {
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let set = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
        assert_eq!(set, 0, "TIOCSWINSZ failed");
    }

    /// Wait for rmux to exit, and report the status it chose.
    ///
    /// Everything it painted on the way out is read first: a pty holds what was
    /// written to it after the writer is gone, and a harness that stopped at the
    /// exit would miss the last frame -- which is the very thing
    /// `what_a_pane_printed_last_is_painted_before_rmux_leaves` is about.
    fn wait(&mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                self.drain();
                return status.code().unwrap_or(-1);
            }
            self.pump();
        }
        panic!("rmux did not exit; it painted {:?}", self.seen);
    }

    /// Read what is left in the pty, until nothing is: a closed slave reads as
    /// an error once its buffer is empty.
    fn drain(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = [0_u8; 4096];
        set_nonblocking(&self.master);
        while Instant::now() < deadline {
            match self.master.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

fn open_pty(rows: u16, cols: u16) -> (std::fs::File, RawFd) {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
        let slave = {
            // `ptsname` uses one process-wide buffer, so consume its answer
            // before another test can replace it with another pty's name.
            static PTSNAME: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _held = PTSNAME.lock().unwrap_or_else(|held| held.into_inner());
            let name = libc::ptsname(master);
            assert!(!name.is_null(), "ptsname failed");
            let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0, "opening the pty slave failed");
            slave
        };

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

fn set_nonblocking(f: &std::fs::File) {
    unsafe {
        let flags = libc::fcntl(f.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(f.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Type `script` at a fresh rmux and return what it painted plus its status.
fn rmux(script: &str) -> (String, i32) {
    let mut console = Console::start(24, 80);
    console.send(script.as_bytes());
    let code = console.wait();
    (console.seen.clone(), code)
}

#[test]
fn rmux_runs_a_shell_and_relays_what_it_prints() {
    let (out, code) = rmux("echo $((21+21))\nexit\n");
    assert!(out.contains("42"), "{out:?}");
    assert_eq!(code, 0);
}

#[test]
fn rmux_exits_with_the_status_its_shell_chose() {
    let (_, code) = rmux("exit 5\n");
    assert_eq!(code, 5);
}

#[test]
fn a_panes_stderr_is_painted_on_the_console_like_the_rest_of_it() {
    // Both of a pane's pipes are the same terminal to the program in it, so
    // both end up on the console — never on rmux's own stderr, which belongs to
    // rmux's own complaints.
    let (out, _) = rmux("echo oops >&2\nexit\n");
    assert!(out.contains("oops"), "{out:?}");
}

#[test]
fn what_a_pane_printed_last_is_painted_before_rmux_leaves() {
    // A pane's waiter reports the exit only once its output has been drained
    // (details.md §4.5), so the last thing a program printed is in the grid by
    // the time rmux stops -- and stopping without painting it throws that
    // away, which is the same loss the drain exists to prevent, one layer up.
    // This failed about three runs in five before the final render was added,
    // so the loop is the test.
    for _ in 0..5 {
        let (out, code) = rmux("echo la\"\"st\nexit\n");
        assert!(out.contains("last"), "{out:?}");
        assert_eq!(code, 0);
    }
}

#[test]
fn a_console_that_changed_shape_is_believed() {
    // §3.2, from rmux's end: something tells the client its console is a
    // different size, and every row of the picture moves. How it is told is the
    // platform's business (crossterm) -- a `SIGWINCH` here, and on Motor OS the
    // answer to an `ESC[6n` asked on a clock -- but what rmux does with it is
    // this: the status line is the last row, so a status line on row 30 can only
    // be a console rmux believes has 30 rows.
    let mut console = Console::start(10, 40);
    assert!(
        console.wait_for("\x1b[10;1H"),
        "rmux never painted a 10-row console: {:?}",
        console.seen
    );

    console.resize(30, 90);
    assert!(
        console.wait_for("\x1b[30;1H"),
        "the console grew and rmux went on painting it small: {:?}",
        console.seen
    );

    // A session outlives its client by design (§7.3), so it is ended rather
    // than abandoned -- and the exit is the proof that it was.
    console.send(b"exit\n");
    assert_eq!(console.wait(), 0);
}

#[test]
fn rmux_refuses_a_command_it_does_not_have() {
    // The surface is fixed (§4.1, §7.3) and nothing outside it is planned, so
    // an unknown verb is a usage message rather than a guess.
    for args in [
        vec!["frobnicate"],
        vec!["new", "-x", "boom"],
        vec!["ls", "extra"],
    ] {
        let tmpdir = private_tmpdir();
        let out = Command::new(RMUX)
            .env("TMPDIR", &tmpdir)
            .args(&args)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&tmpdir);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn ls_with_no_server_running_says_nothing_and_succeeds() {
    // There are no sessions, and saying so is the answer -- starting a server
    // to be told it has none would be worse.
    let tmpdir = private_tmpdir();
    let out = Command::new(RMUX)
        .env("TMPDIR", &tmpdir)
        .arg("ls")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&tmpdir);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
}
