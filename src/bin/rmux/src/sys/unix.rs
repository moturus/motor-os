//! The Unix host backend, used for development and for testing against real
//! tmux.

use std::path::PathBuf;
use std::process::Command;

/// Tell `cmd`'s child that its stdio is a terminal — which, on the host, this
/// cannot do.
///
/// A no-op, and deliberately so. `isatty()` here is a property of the file
/// descriptor, so no environment variable can forge it: the host makes a pane a
/// terminal by giving it a *real* pty, which arrives with the pane layer in M1.
///
/// The function exists anyway so the caller stays free of `cfg`, and so that the
/// asymmetry is stated in the one place someone would look for it rather than
/// being an unexplained gap on one side of a `cfg`.
pub fn mark_terminal(_cmd: &mut Command) {}

/// The host's writable scratch directory.
pub fn tmp_dir() -> PathBuf {
    std::env::temp_dir()
}
