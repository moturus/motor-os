//! Motor OS backend: signals and process control.
//!
//! Motor OS has no termios: the console is always raw and is driven entirely
//! with ANSI escape sequences (see the `sys` module docs). The terminal itself
//! is crossterm's — its Motor OS backend reads the keys and asks the terminal
//! how big it is — so what is left here is the two things that have no terminal
//! in them at all.
//!
//! # Motor OS has no signals
//!
//! This is the defining constraint of Phase 7 (§0.1). Motor OS has no signal
//! delivery of any kind: a process cannot ask to be notified of anything, and
//! the only thing one process may do to another is *terminate* it
//! (`SysCpu::kill_pid`, an unconditional kill — there is no catchable `TERM`).
//! So:
//!
//! - [`set_disposition`] always reports failure. A `trap … INT` is still
//!   *stored* by the shell, and still runs when the terminal reader sees a `^C`
//!   byte and synthesizes the signal itself (`sys::note_signal`) — that path is
//!   platform-independent, which is the whole point of routing delivery through
//!   the shared pending bitmap. What cannot happen here is delivery from
//!   *outside* the process.
//! - [`kill`] can only honor the signals whose meaning is "die": `KILL` and
//!   `TERM`. Anything else (`USR1`, `HUP`, `STOP`, …) is refused rather than
//!   silently turned into a kill, because a script sending `USR1` wants a
//!   notification, not a corpse.
//! - [`wait_child`] can never be interrupted, since nothing can arrive while it
//!   blocks.

use std::process::Child;

use super::{Disposition, KillError, WaitOutcome};

// ---- signals ---------------------------------------------------------------

/// Motor OS cannot deliver signals, so no disposition can be established: the
/// caller (`crate::signal`) treats `false` as "stored, but it will never fire
/// from outside this process" and degrades gracefully.
pub fn set_disposition(_signo: i32, _disp: Disposition) -> bool {
    false
}

/// Terminate `pid`, if the signal means "die"; check existence for signal 0.
///
/// Motor OS has one primitive here — an unconditional kill — so `TERM` is as
/// hard as `KILL` (the target cannot catch or ignore it), and every other signal
/// is refused rather than silently turned into a kill. See the module docs.
pub fn kill(pid: u64, signo: i32) -> Result<(), KillError> {
    const SIGKILL: i32 = 9;
    const SIGTERM: i32 = 15;

    if signo == 0 {
        // An existence check. There is no per-pid query, but the process list is
        // ordered by pid and includes `start` when present, so one entry decides
        // it. A zombie (`active == 0`) is reported as gone.
        let mut buf = [moto_sys::stats::ProcessInfoV1::default(); 1];
        return match moto_sys::stats::ProcessInfoV1::list(pid, &mut buf) {
            Ok(n) if n >= 1 && buf[0].pid == pid && buf[0].active != 0 => Ok(()),
            Ok(_) => Err(KillError::NoSuchProcess),
            Err(_) => Err(KillError::PermissionDenied),
        };
    }
    if signo != SIGKILL && signo != SIGTERM {
        return Err(KillError::Unsupported);
    }
    // `ErrorCode` is a bare `u16`, so these are constants rather than variants.
    moto_sys::SysCpu::kill_pid(pid).map_err(|err| match err {
        moto_rt::E_NOT_FOUND => KillError::NoSuchProcess,
        moto_rt::E_NOT_ALLOWED => KillError::PermissionDenied,
        _ => KillError::Unsupported,
    })
}

// ---- detached spawn --------------------------------------------------------

/// The explicit grant used for an ordinary child of a System shell.
///
/// The runtime deliberately does not propagate System by default. Rush is the
/// session boundary that does so; the caller skips this grant when the command
/// supplied its own replacement mask.
pub fn ordinary_child_cap_grant() -> Option<(&'static str, String)> {
    let own = moto_sys::ProcessStaticPage::get().capabilities;
    if !matches!(
        moto_sys::caps::ProcessRole::from_caps(own),
        moto_sys::caps::ProcessRole::System
    ) {
        return None;
    }
    let child =
        own & (moto_sys::caps::CAP_SYS | moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_LOG);
    Some((
        moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
        format!("0x{child:x}"),
    ))
}

/// The env assignment that grants a child `CAP_SPAWN_DETACHED` while preserving
/// the shell's derived role, or `None` if this shell cannot grant detach.
///
/// Used for the programs the shell is configured to trust with detaching (the
/// `spawn-detached` list in `/user/cfg/rush.toml`). The capability is granted
/// only where the shell has it — the kernel would refuse a grant of a capability
/// the parent lacks anyway, so this just avoids setting a doomed env var.
pub fn detach_cap_grant() -> Option<(&'static str, String)> {
    let own = moto_sys::ProcessStaticPage::get().capabilities;
    if own & moto_sys::caps::CAP_SPAWN_DETACHED == 0 {
        return None;
    }
    let role_cap = match moto_sys::caps::ProcessRole::from_caps(own) {
        moto_sys::caps::ProcessRole::System => moto_sys::caps::CAP_SYS,
        moto_sys::caps::ProcessRole::Interactive => moto_sys::caps::CAP_INTERACTIVE,
        moto_sys::caps::ProcessRole::None => 0,
    };
    let child = own
        & (moto_sys::caps::CAP_SPAWN
            | moto_sys::caps::CAP_LOG
            | moto_sys::caps::CAP_SPAWN_DETACHED
            | role_cap);
    Some((
        moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
        format!("0x{child:x}"),
    ))
}

// ---- process control -------------------------------------------------------

/// Wait for `child`. Nothing can interrupt this on Motor OS (no signals), so the
/// outcome is always `Exited`.
pub fn wait_child(child: &mut Child) -> std::io::Result<WaitOutcome> {
    child
        .wait()
        .map(|s| WaitOutcome::Exited(exit_status_code(s)))
}

/// The shell status for a child's exit. No signal can kill a process here, so
/// unlike the Unix backend there is no `128 + signo` case; a status Motor OS
/// could not represent as a code is reported as 128.
pub fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(128)
}
