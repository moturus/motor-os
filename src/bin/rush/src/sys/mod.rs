//! Platform abstraction layer.
//!
//! The shell core is written against this module so that everything
//! platform-specific lives behind a single seam. Two backends exist: the Unix
//! host backend (`unix`, used for development and testing on Linux) and the
//! Motor OS backend (`motor`).
//!
//! # Terminal contract: the console is always raw
//!
//! Motor OS does **not** implement termios. There is no `tcgetattr`/`tcsetattr`,
//! no cooked/raw mode toggle, no `ISIG`/`ICANON`, and no `tcsetpgrp`. The console
//! is *always* raw: the shell receives input bytes directly and drives the
//! display entirely with ANSI escape sequences. The terminal itself is no longer
//! this module's business — `crossterm` owns it (see [`crate::term`]), and its
//! Motor OS backend is where that contract is kept; the Unix host's termios is
//! the same crate's other backend, and neither is spelled out here.
//!
//! A consequence carried through the rest of the plan: because no terminal driver
//! turns `^C`/`^Z` into signals, interrupt handling must detect the control
//! *bytes* itself and (to interrupt a child) deliver a signal via an OS `kill`
//! primitive. Terminal job control (`^Z` suspend, `fg`/`bg`, `tcsetpgrp`) is not
//! achievable on Motor OS and is deferred.
//!
//! # Planned surface (added incrementally by later phases)
//!
//! As the executor is rewritten, this module will also own:
//! - process primitives: spawn with explicit fd wiring, `wait`, `kill`;
//! - pipe/fd primitives: `pipe`, `dup2`, `close` (real N-stage pipelines and fd
//!   redirections need these; `std::process::Stdio` alone cannot wire a builtin
//!   into a pipeline);
//! - a subshell strategy: real `fork` on Unix vs. state-clone emulation on Motor
//!   OS where `fork` is unavailable.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    detach_cap_grant, exit_status_code, kill, ordinary_child_cap_grant, set_disposition, wait_child,
};

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::{
    detach_cap_grant, exit_status_code, kill, ordinary_child_cap_grant, set_disposition, wait_child,
};

// ---- signals ---------------------------------------------------------------

use std::sync::atomic::{AtomicBool, Ordering};

/// One past the highest signal number rush tracks.
///
/// POSIX signal numbers are the canonical namespace here even on Motor OS,
/// which has no signals at all: they are what `trap INT` and `kill -9` name, and
/// what a script expects to see in `$?` as `128 + signo`. On Motor they are
/// simply a vocabulary the shell understands but the kernel cannot deliver.
pub const NSIG: usize = 32;

/// Signals delivered but not yet handled, indexed by signal number.
///
/// A signal handler may touch nothing but async-signal-safe state, so delivery
/// does no more than set a flag here; the executor drains it at a safe point
/// between commands (see [`crate::signal`]). Both backends share this bitmap: on
/// the Unix host a real handler sets it, while on Motor OS — which cannot
/// deliver a signal at all — the terminal reader sets it directly on seeing a
/// `^C` byte, which is what makes `trap … INT` work there (§0.1).
static PENDING: [AtomicBool; NSIG] = [const { AtomicBool::new(false) }; NSIG];
/// A fast path for [`signal_pending`], which is checked after every command.
static ANY_PENDING: AtomicBool = AtomicBool::new(false);

/// Record `signo` as delivered. Async-signal-safe: atomic stores only, so this
/// is callable directly from a signal handler.
pub fn note_signal(signo: i32) {
    if let Some(slot) = PENDING.get(signo as usize) {
        slot.store(true, Ordering::SeqCst);
        ANY_PENDING.store(true, Ordering::SeqCst);
    }
}

/// Whether any signal is waiting to be handled.
pub fn signal_pending() -> bool {
    ANY_PENDING.load(Ordering::Relaxed)
}

/// Take the set of delivered signals, in signal-number order, clearing it.
pub fn take_pending_signals() -> Vec<i32> {
    if !ANY_PENDING.swap(false, Ordering::SeqCst) {
        return Vec::new();
    }
    (0..NSIG as i32)
        .filter(|&signo| PENDING[signo as usize].swap(false, Ordering::SeqCst))
        .collect()
}

/// What should happen when a signal arrives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    /// The platform's default action (for most signals: kill the shell).
    Default,
    /// Ignore it (`trap '' SIG`).
    Ignore,
    /// Catch it: delivery only sets the pending flag, and the executor runs the
    /// trap at the next safe point (`trap 'action' SIG`).
    Catch,
}

/// Why a [`kill`] failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KillError {
    NoSuchProcess,
    PermissionDenied,
    /// The platform cannot deliver this signal — always the case on Motor OS for
    /// anything but a terminate.
    Unsupported,
}

/// The outcome of waiting for a foreground child.
pub enum WaitOutcome {
    Exited(i32),
    /// A signal arrived before the child exited; the child is still running. The
    /// caller runs any pending traps and waits again.
    ///
    /// Never constructed on Motor OS, where nothing can arrive while a wait
    /// blocks — hence the `allow`: the variant is part of the portable vocabulary
    /// even on the platform that cannot produce it, and every caller must handle
    /// it to compile for the host.
    #[cfg_attr(not(unix), allow(dead_code))]
    Interrupted,
}

/// The shell's process id, backing the `$$` special parameter.
///
/// `u64` to match the job table's pids ([`crate::jobs`]); every platform rush
/// runs on reports a pid that fits `u32`, Motor OS included since its kernel
/// bounds pids to the i32-positive range.
pub fn pid() -> u64 {
    u64::from(std::process::id())
}
