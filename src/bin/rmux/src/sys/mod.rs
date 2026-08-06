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
//! # rmux's own console is not here
//!
//! Raw mode, the alternate screen, the keys and the size are crossterm's, on
//! both platforms (`client`). What is left in this module is the other terminal
//! — the one rmux *gives* a pane, which is the seam below.
//!
//! # A pane's terminal is not the same object on the two platforms
//!
//! This is the seam's reason for existing (details.md §3.1). A pane must convince
//! its child that it owns a terminal, and the two platforms grant that in
//! completely different ways:
//!
//! - **Motor OS** has no pty at all, and does not need one: a terminal
//!   provider passes `MOTURUS_STDIO_IS_TERMINAL=true` at spawn, and the
//!   runtime consumes it and marks the child's stdio descriptors as terminal
//!   endpoints (docs/plans/is_terminal_redesign.md), so a child on plain
//!   pipes reports `is_terminal() == true`. `sys-tty` and `russhd` already
//!   do exactly this.
//! - **The Unix host** decides `isatty()` from the file descriptor, so no
//!   environment variable can forge it and a pane gets a *real* pty.
//!
//! [`spawn_pane`] hides the difference, and [`PaneIo`] is what both produce.
//! The asymmetries that survive it are named where they live: a pty merges
//! stdout and stderr into one stream where pipes keep two (§4.5), it cannot be
//! closed from this end, which is what [`END_OF_INPUT`] is about, only one of
//! the two can be *told* its size ([`TellSize`]), and only one of them has a
//! line discipline to turn a program's `\n` into a new line
//! ([`PANE_NEWLINE_MODE`]) or a user's Enter into one ([`ENTER`]).

use std::io::Read;
use std::io::Write;
use std::process::Child;

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::{
    END_OF_INPUT, ENTER, PANE_NEWLINE_MODE, config_file, detach, port_file, spawn_pane,
};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    END_OF_INPUT, ENTER, PANE_NEWLINE_MODE, config_file, detach, port_file, spawn_pane,
};

/// Tell a pane's terminal how big it has become.
///
/// A split halves a pane, so a pane's child has to be able to find out that its
/// terminal changed shape — and the two platforms are as far apart here as
/// anywhere in this module (§3.2):
///
/// - **The Unix host** has `TIOCSWINSZ`, which both sets the pty's size and
///   sends the child a `SIGWINCH`. So this really does tell it.
/// - **Motor OS** has neither, and nothing else that could: no ioctl, no
///   terminal-size call, no signals (§3.6). This is a no-op there, and the
///   child finds out at its next `ESC[6n`, which rmux answers with the pane's
///   new size — the substitute §3.2 is built on, and the reason `rush` probing
///   at every prompt matters.
pub type TellSize = Box<dyn Fn((u16, u16)) + Send>;

/// A pane's end of the terminal it gives its child.
///
/// One stream out on a pty, two on pipes: the platform decides, and the pane
/// pumps however many it is handed.
pub struct PaneIo {
    pub child: Child,
    /// Where a keystroke goes.
    pub input: Box<dyn Write + Send>,
    /// Everything the child writes.
    pub output: Vec<Box<dyn Read + Send>>,
    /// How to say the pane is a different size now, where saying so is possible.
    pub tell_size: TellSize,
}
