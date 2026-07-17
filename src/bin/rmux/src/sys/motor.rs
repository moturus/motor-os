//! The Motor OS backend.

use std::path::PathBuf;
use std::process::Command;

/// The environment variable Motor's runtime reads to answer `is_terminal()`.
///
/// Spelled out rather than taken from `moto-rt` on purpose: it is a string, and
/// depending on a crate to obtain a string would cost rmux its zero-dependency
/// goal (plan.md §4.6) for nothing. The definition lives at
/// `moto-rt/src/process.rs:30`; the code that reads it is
/// `rt.vdso/src/rt_fs.rs:1203`, which checks this variable and *nothing about
/// the file descriptor*.
const STDIO_IS_TERMINAL_ENV_KEY: &str = "MOTURUS_STDIO_IS_TERMINAL";

/// Tell `cmd`'s child that its stdio is a terminal.
///
/// This is the whole of Motor's pty equivalent (plan.md §3.1): with this set, a
/// child spawned on plain pipes reports `is_terminal() == true` and behaves
/// interactively. `sys-tty/src/main.rs:89` and `russhd`'s
/// `local_session.rs:67` do the same thing for the same reason.
///
/// Note the runtime *also* sets this itself when a child inherits both stdin
/// and stdout (`moto-rt/src/process.rs:245`). rmux's panes are on pipes, not
/// inherited, so that path never fires and this call is required.
pub fn mark_terminal(cmd: &mut Command) {
    cmd.env(STDIO_IS_TERMINAL_ENV_KEY, "true");
}

/// Motor's writable scratch directory.
pub fn tmp_dir() -> PathBuf {
    PathBuf::from("/sys/tmp")
}
