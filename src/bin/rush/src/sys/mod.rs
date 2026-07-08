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

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::MotorTerm as TerminalBackend;
