//! Unix host backend: terminal, signals, and process control.
//!
//! This is the ONLY place in the crate that may touch termios. It exists so the
//! shell is comfortable to develop and test on Linux; the portable contract
//! (see `sys` module docs) is that the console is always raw and driven purely
//! with ANSI escape sequences, which is what the Motor OS backend assumes.
//!
//! This is also where rush's signal vocabulary meets a kernel that can actually
//! deliver signals — the Motor OS backend implements the same surface with the
//! degradations its platform forces.

use std::process::Child;

use libc::termios as Termios;

use super::{Disposition, KillError, WaitOutcome};

pub struct HostTerm {
    cooked_termios: Termios,
    raw_termios: Termios,
}

impl HostTerm {
    pub fn new() -> Self {
        let mut cooked_termios: Termios = unsafe { core::mem::zeroed() };
        unsafe {
            libc::tcgetattr(libc::STDOUT_FILENO, &mut cooked_termios);
        }

        let mut raw_termios: Termios = cooked_termios;
        // We do not call 'libc::cfmakeraw(&mut raw_termios)'
        // at the resulting terminal becomes too raw. We need it
        // slightly cooked.

        raw_termios.c_iflag &=
            !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);

        // raw_termios.c_oflag &= !libc::OPOST;

        raw_termios.c_cflag |= libc::CS8;
        raw_termios.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);

        Self {
            cooked_termios,
            raw_termios,
        }
    }
}

impl super::TermImpl for HostTerm {
    fn make_raw(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDOUT_FILENO, libc::TCSANOW, &self.raw_termios);
        }
    }

    fn make_cooked(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDOUT_FILENO, libc::TCSANOW, &self.cooked_termios);
        }
    }

    fn on_exit(&mut self) {
        self.make_cooked(); // Restore termios.
    }

    /// `TIOCGWINSZ` — the host can answer without asking the terminal, which is
    /// both exact and free of a round-trip the terminal might never answer.
    fn width(&mut self) -> Option<usize> {
        let mut ws: libc::winsize = unsafe { core::mem::zeroed() };
        let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if rc != 0 || ws.ws_col == 0 {
            // Not a terminal, or one that does not know its own size.
            return None;
        }
        Some(ws.ws_col as usize)
    }
}

// ---- signals ---------------------------------------------------------------

/// The handler installed for every *caught* signal. It may call nothing that is
/// not async-signal-safe, so it only records the delivery; [`crate::signal`]
/// runs the trap itself at the next safe point.
extern "C" fn note_handler(signo: libc::c_int) {
    super::note_signal(signo);
}

/// Point `signo` at `disp`, returning whether the platform accepted it.
///
/// `sa_flags` deliberately omits `SA_RESTART`: a trapped signal must interrupt a
/// blocking wait so its trap runs promptly rather than whenever the foreground
/// child happens to finish. (This is why `sigaction` is used rather than
/// `signal`, whose glibc BSD semantics imply `SA_RESTART`.) [`wait_child`] is
/// written to expect the resulting `EINTR`.
pub fn set_disposition(signo: i32, disp: Disposition) -> bool {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = match disp {
            Disposition::Default => libc::SIG_DFL,
            Disposition::Ignore => libc::SIG_IGN,
            Disposition::Catch => note_handler as *const () as usize,
        };
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(signo, &sa, std::ptr::null_mut()) == 0
    }
}

/// Send `signo` to `pid`. Signal 0 performs the usual existence/permission check
/// without sending anything.
pub fn kill(pid: u64, signo: i32) -> Result<(), KillError> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, signo) };
    if rc == 0 {
        return Ok(());
    }
    Err(match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => KillError::NoSuchProcess,
        Some(libc::EPERM) => KillError::PermissionDenied,
        _ => KillError::Unsupported,
    })
}

// ---- process control -------------------------------------------------------

/// Wait for `child`, returning early if a signal arrives first.
///
/// `Child::wait` retries across `EINTR`, which would hold a trap until the child
/// happened to exit — so the blocking wait is done here with `waitid(WNOWAIT)`,
/// which reports the child's exit *without* reaping it. That leaves the child a
/// zombie, so the subsequent `Child::wait` returns the status immediately and
/// `std` keeps ownership of the reaping (calling `waitpid` behind its back would
/// make it lose the status, or reap an unrelated, recycled pid later).
pub fn wait_child(child: &mut Child) -> std::io::Result<WaitOutcome> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => return Ok(WaitOutcome::Interrupted),
            // ECHILD: already reaped. `Child::wait` has the status cached, so
            // fall through to it rather than reporting an error.
            Some(libc::ECHILD) => {}
            _ => return Err(err),
        }
    }
    child
        .wait()
        .map(|s| WaitOutcome::Exited(exit_status_code(s)))
}

/// The shell status for a child's exit: its exit code, or `128 + signo` when a
/// signal killed it (POSIX §2.8.2 — `sh -c 'kill -9 $$'` reports 137).
pub fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}
