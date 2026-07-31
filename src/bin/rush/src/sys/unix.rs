//! Unix host backend: signals and process control.
//!
//! It exists so the shell is comfortable to develop and test on Linux. This is
//! where rush's signal vocabulary meets a kernel that can actually deliver
//! signals — the Motor OS backend implements the same surface with the
//! degradations its platform forces. The terminal is not here: raw mode, the
//! size and the keys are crossterm's, on both platforms (see `crate::term`).

use std::process::Child;

use super::{Disposition, KillError, WaitOutcome};

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
/// The Unix host has no capability model, so there is nothing to grant; the
/// `spawn-detached` list is inert here (the env var it would set means nothing
/// off Motor). Present so the shell core stays free of `cfg`.
pub fn detach_cap_grant() -> Option<(&'static str, String)> {
    None
}

pub fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}
