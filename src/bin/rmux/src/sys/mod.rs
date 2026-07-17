//! Platform abstraction layer.
//!
//! rmux is written against this module so that everything platform-specific
//! lives behind a single seam. Two backends exist: the Unix host backend
//! (`unix`, used for development and for testing against real tmux) and the
//! Motor OS backend (`motor`).
//!
//! The discriminator is `cfg(unix)` / `cfg(not(unix))`, not
//! `target_os = "motor"`: Motor OS sets no target family, so `unix` is simply
//! never true there (see `red/src/config.rs:38` for the same observation).
//!
//! # Terminal contract: the console is always raw
//!
//! Motor OS does not implement termios. There is no `tcgetattr`/`tcsetattr`, no
//! cooked/raw mode toggle, no `ISIG`, no `tcsetpgrp`, no ioctl, and no signals.
//! The console is *always* raw, and rmux must drive the display entirely with
//! ANSI escape sequences. This is rush's contract verbatim
//! (`rush/src/sys/mod.rs:7`), and it is why there is no `make_raw` here: on
//! Motor there is nothing to configure, and on the host the pty the tests drive
//! is configured by the test.
//!
//! # A pane's terminal is not the same object on the two platforms
//!
//! This is the seam's reason for existing (plan.md §3.1). A pane must convince
//! its child that it owns a terminal, and the two platforms grant that in
//! completely different ways:
//!
//! - **Motor OS** has no pty at all, and does not need one: `is_terminal()` is
//!   an *environment variable* (`rt.vdso/src/rt_fs.rs:1203` reads
//!   `MOTURUS_STDIO_IS_TERMINAL`), so a child on plain pipes plus
//!   [`mark_terminal`] believes it is on a terminal. `sys-tty` and `russhd`
//!   already do exactly this.
//! - **The Unix host** decides `isatty()` from the fd, so the variable means
//!   nothing and a pane needs a *real* pty. That is deferred to M1, where the
//!   pane layer lands; it is called out here so the next reader does not assume
//!   the Motor mechanism is the portable one. It is not — it is the reason this
//!   module exists.
//!
//! # Planned surface (added incrementally by later phases)
//!
//! Only what M0 needs is here. As the phases land, this module will also own:
//! - `size() -> Option<(usize, usize)>`: the console's dimensions from the
//!   *platform* (the host's `TIOCGWINSZ`), `None` on Motor — which has no
//!   terminal-size call, so rmux asks the terminal itself with an ANSI query
//!   and never waits for the reply (plan.md §3.2);
//! - the pane-terminal spawn described above (pipes + env on Motor, a pty on the
//!   host);
//! - the Enter encoding: sys-tty turns a CR keypress into CRLF
//!   (`sys-tty/src/main.rs:127`), and a pane must be sent what sys-tty would
//!   have sent it, or rush behaves differently inside rmux than outside it
//!   (plan.md §3.4).

use std::path::PathBuf;

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::{mark_terminal, tmp_dir};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{mark_terminal, tmp_dir};

/// A writable path for rmux's own bookkeeping — today the server's port file
/// (plan.md §4.2).
///
/// Kept as a function rather than a constant because the host answers from the
/// environment.
pub fn scratch_file(name: &str) -> PathBuf {
    tmp_dir().join(name)
}
