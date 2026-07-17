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
//! is *always* raw: the shell receives input bytes directly and must drive the
//! display entirely with ANSI escape sequences (e.g. `ESC[6n` to query the
//! cursor). The Unix backend implements `make_raw`/`make_cooked` via termios only
//! as a convenience for running on Linux; the shell core must never *depend* on
//! mode switching, and no termios call may appear outside `sys::unix`.
//!
//! A consequence carried through the rest of the plan: because no terminal driver
//! turns `^C`/`^Z` into signals, interrupt handling must detect the control
//! *bytes* itself and (to interrupt a child) deliver a signal via an OS `kill`
//! primitive. Terminal job control (`^Z` suspend, `fg`/`bg`, `tcsetpgrp`) is not
//! achievable on Motor OS and is deferred.
//!
//! # Planned surface (added incrementally by later phases)
//!
//! Only the terminal backend is needed today. As the executor is rewritten,
//! this module will also own:
//! - process primitives: spawn with explicit fd wiring, `wait`, `kill`;
//! - pipe/fd primitives: `pipe`, `dup2`, `close` (real N-stage pipelines and fd
//!   redirections need these; `std::process::Stdio` alone cannot wire a builtin
//!   into a pipeline);
//! - a subshell strategy: real `fork` on Unix vs. state-clone emulation on Motor
//!   OS where `fork` is unavailable.

/// Terminal mode control. On Motor OS the methods are no-ops (the console is
/// already raw); on the Unix host they toggle termios.
pub trait TermImpl: Send + Sync {
    fn make_raw(&mut self) {}
    fn make_cooked(&mut self) {}
    fn on_exit(&mut self) {}

    /// The terminal's width in columns, if the *platform* can say.
    ///
    /// The Unix host can (`TIOCGWINSZ`), which makes the answer free and exact,
    /// and — because it needs no reply from the terminal — makes the line editor
    /// testable over a pty. Motor OS has no ioctl and no terminal-size call at
    /// all, so it returns `None` and the editor asks the terminal itself with an
    /// ANSI query (see `term::probe_width`).
    fn width(&mut self) -> Option<usize> {
        None
    }
}

/// No-op terminal backend used whenever there is no real terminal to configure:
/// piped/non-interactive mode on any platform.
pub struct NoopTerm;

impl NoopTerm {
    pub fn new() -> Self {
        Self
    }
}

impl TermImpl for NoopTerm {}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::HostTerm as TerminalBackend;
#[cfg(unix)]
pub use unix::{detach_cap_grant, exit_status_code, kill, set_disposition, wait_child};

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::MotorTerm as TerminalBackend;
#[cfg(not(unix))]
pub use motor::{detach_cap_grant, exit_status_code, kill, set_disposition, wait_child};

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
/// Motor OS pids are `u64` and its `std` pal deliberately `panic!`s in
/// `std::process::id()` (which returns `u32`), so pids must come from `moto-sys`
/// there; the Unix host uses `std`.
#[cfg(unix)]
pub fn pid() -> u64 {
    std::process::id() as u64
}

#[cfg(not(unix))]
pub fn pid() -> u64 {
    moto_sys::current_pid()
}
