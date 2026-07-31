//! The Unix host backend, used for development and for testing against real
//! tmux.
//!
//! Everything here exists because the host has what Motor OS does not: a pty,
//! an ioctl to ask a terminal its size, and a termios to switch between cooked
//! and raw. rmux uses all three, and none of them reaches the Motor build.

use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Mutex;

use super::PaneIo;

/// How this platform says "there is no more input".
///
/// A pipe says it by closing, and Motor's panes do exactly that. A pty cannot:
/// the master is one open file for both directions, so dropping the writing
/// half would take the reading half with it and rmux would lose the child's
/// last output. A pty says it the way a user does instead — with the line
/// discipline's EOF character, which is what `^D` has always been.
pub const END_OF_INPUT: Option<u8> = Some(0x04);

/// Whether a pane has to turn a program's `\n` into a new line itself.
///
/// No: a pty has a line discipline, and `ONLCR` — on by default — already
/// delivers `\r\n` to the master. Doing it here as well would be harmless but
/// dishonest, since a real terminal does not.
pub const PANE_NEWLINE_MODE: bool = false;

/// What Enter looks like on its way *into* a pane (details.md §3.4).
///
/// A carriage return, which is what a pty's line discipline expects and turns
/// into a newline itself (`ICRNL`). rmux forwards a user's keystrokes byte for
/// byte (§8.1) and never has to ask; this is for the bytes rmux makes up, which
/// today means a paste (§7.6).
pub const ENTER: &[u8] = b"\r";

/// Spawn a pane's child on a real pty.
///
/// The child gets the slave on all three descriptors, in a session of its own,
/// with the pty as its controlling terminal — which is what makes `isatty()`
/// true, gives the shell its job control, and sends a `^C` to the child rather
/// than to rmux. The parent keeps the master, and that one stream carries the
/// child's stdout and stderr together.
pub fn spawn_pane(mut cmd: Command, size: (u16, u16)) -> std::io::Result<PaneIo> {
    let (master, slave) = open_pty(size)?;

    // SAFETY: `pre_exec` runs between fork and exec, so it may call only
    // async-signal-safe functions; `setsid` and `ioctl` are both on that list.
    // Each `Stdio` owns the descriptor it is given, hence a dup apiece.
    let spawned = unsafe {
        cmd.stdin(Stdio::from_raw_fd(dup(slave)?))
            .stdout(Stdio::from_raw_fd(dup(slave)?))
            .stderr(Stdio::from_raw_fd(dup(slave)?))
            .pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(slave, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .spawn()
    };

    // The parent must not hold the slave open, or a read on the master never
    // ends when the child does. Closed on the failure path too.
    unsafe { libc::close(slave) };
    let child = spawned?;

    let input = Box::new(master.try_clone()?);
    // A descriptor of its own, so that telling the pane its size does not depend
    // on which of the other two halves is still alive.
    let sizer = master.try_clone()?;
    let output: Vec<Box<dyn Read + Send>> = vec![Box::new(master)];
    Ok(PaneIo {
        child,
        input,
        output,
        tell_size: Box::new(move |size| set_pty_size(sizer.as_raw_fd(), size)),
    })
}

/// Tell a pty how big it is, which also sends the child a `SIGWINCH`.
///
/// The half of §3.2 that only the host has. Motor's panes have no equivalent and
/// find out at their next `ESC[6n` instead (`sys::TellSize`).
fn set_pty_size(fd: RawFd, size: (u16, u16)) {
    let (rows, cols) = size;
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) };
}

/// A pty pair, `(master, slave)`, sized so the child is not born blind.
///
/// The size is set on the *slave* here, before there is a child to notify;
/// afterwards it is set on the master, which is the same pty and which does
/// notify ([`set_pty_size`]).
fn open_pty(size: (u16, u16)) -> std::io::Result<(File, RawFd)> {
    unsafe {
        let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Owned from here on, so every early return below closes it.
        let master = File::from_raw_fd(fd);
        if libc::grantpt(fd) < 0 || libc::unlockpt(fd) < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // `ptsname` answers from a *static buffer*, so two panes opening a pty
        // at once race on it: one of them reads a name the other has already
        // replaced, and opening a truncated `/dev/pts` fails with EISDIR. Found
        // by the test suite, which spawns panes from a thread apiece -- but the
        // hazard is not the tests', and "only the event loop spawns panes" is
        // not an invariant worth resting a data race on. The lock covers
        // `ptsname` and the `open` that consumes its answer, and nothing else.
        let slave = {
            static PTSNAME: Mutex<()> = Mutex::new(());
            // Poisoning is not a reason to stop excluding: a panic elsewhere --
            // in a test, say -- would otherwise turn this lock into nothing at
            // all, and the race it exists for comes straight back, as a handful
            // of unrelated panes failing to open at once.
            let _held = PTSNAME.lock().unwrap_or_else(|held| held.into_inner());
            let name = libc::ptsname(fd);
            if name.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            libc::open(name, libc::O_RDWR | libc::O_NOCTTY)
        };
        if slave < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // `pre_exec` still needs it; the exec that follows must not inherit it.
        libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC);

        let (rows, cols) = size;
        let winsize = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        libc::ioctl(slave, libc::TIOCSWINSZ, &winsize);
        Ok((master, slave))
    }
}

fn dup(fd: RawFd) -> std::io::Result<RawFd> {
    let new = unsafe { libc::dup(fd) };
    if new < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(new)
}

/// Where the server publishes the port it bound (details.md §4.2).
///
/// `$TMPDIR` is shared between users on a host, so the name is not: a server
/// belongs to whoever started it. Honouring `$TMPDIR` is also what lets a test
/// give itself a server of its own.
pub fn port_file() -> PathBuf {
    std::env::temp_dir().join(format!("rmux-{}.port", unsafe { libc::getuid() }))
}

/// Where a user's overrides live (details.md §2.2), the same convention red uses.
///
/// `$HOME` rather than `$XDG_CONFIG_HOME`, because that is what red does and
/// two programs in one repo disagreeing about it would be worse than either
/// choice.
pub fn config_file() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".config/rmux.toml")
}

/// Spawn `cmd`'s child in a session of its own, so it outlives this process.
///
/// An orphan survives here without being asked -- init adopts it -- but it
/// would keep this process's controlling terminal and take a `^C` meant for
/// somebody else. `setsid` is what makes it genuinely a daemon.
pub fn detach(cmd: &mut Command) {
    // SAFETY: `pre_exec` runs between fork and exec, so it may call only
    // async-signal-safe functions; `setsid` is one.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}
