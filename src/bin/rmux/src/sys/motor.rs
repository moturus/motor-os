//! The Motor OS backend.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use super::PaneIo;

/// The launch-only instruction that marks a child's stdio as terminals.
///
/// Spelled out rather than taken from `moto-rt` on purpose: it is a string, and
/// depending on a crate to obtain a string would cost rmux its zero-dependency
/// goal (details.md §4.6) for nothing. The definition lives in
/// `moto-rt/src/process.rs`; the spawning runtime consumes the entry before
/// the child starts and marks the child's explicitly created stdio pipes as
/// terminal endpoints, which the child's descriptors then report
/// (docs/tui.md).
const STDIO_IS_TERMINAL_ENV_KEY: &str = "MOTURUS_STDIO_IS_TERMINAL";

/// How this platform says "there is no more input": by closing the pipe.
///
/// See the Unix backend for why this is a choice rather than an obvious fact.
pub const END_OF_INPUT: Option<u8> = None;

/// Whether a pane has to turn a program's `\n` into a new line itself.
///
/// Yes. Motor OS has no line discipline at all (details.md §3.1) and a pane here is
/// a pipe, so nothing stands between a program's `\n` and the pane's grid. What
/// the platform's *own* terminal does is exactly this rewrite -- `sys-tty`'s
/// `send()` turns `\n` into `\n\r` on the way to the wire (§3.3) -- so a pane
/// that skipped it would start every second line of output where the last one
/// ended. Bug-for-bug compatibility with sys-tty, deliberately, and the same
/// argument §3.4 makes for Enter in the other direction.
pub const PANE_NEWLINE_MODE: bool = true;

/// What Enter looks like on its way *into* a pane (details.md §3.4).
///
/// `CR LF`, because that is what `sys-tty` synthesizes for the real console
/// (`main.rs:127-132`) and therefore what rush receives outside rmux -- and a
/// program must behave identically inside a pane and outside one. Bug-for-bug
/// compatibility, deliberately, as §3.4 says.
pub const ENTER: &[u8] = b"\r\n";

/// Spawn a pane's child on the terminal Motor OS actually has.
///
/// This is the whole of Motor's pty equivalent (details.md §3.1): plain pipes plus
/// one launch hint, after which the child reports `is_terminal() == true` and
/// behaves interactively. `sys-tty/src/main.rs:89` and `russhd`'s
/// `local_session.rs` do the same thing for the same reason.
///
/// A child spawned with *inherited* stdio copies each stream's terminal
/// status from the parent instead. rmux's panes are on pipes, not inherited,
/// so setting the hint here is required.
pub fn spawn_pane(mut cmd: Command, size: (u16, u16)) -> std::io::Result<PaneIo> {
    let (rows, cols) = size;
    cmd.env(STDIO_IS_TERMINAL_ENV_KEY, "true");
    // Mechanism 2 of §3.2: `$LINES`/`$COLUMNS` are what crossterm's Motor OS
    // backend answers `terminal::size()` with until the terminal has reported,
    // so a pane's program is the right size from its *first* frame -- which is
    // the one thing no in-band report can be early enough for. A resize after
    // that is pushed rather than waited for (mode 2048), so this is the size at
    // spawn and not the only size the program will ever be told.
    cmd.env("LINES", rows.to_string());
    cmd.env("COLUMNS", cols.to_string());

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let input = Box::new(child.stdin.take().unwrap());
    // Two streams, where a pty merges them into one: a documented divergence
    // (§4.5), and the reason interleaving under heavy concurrent output can
    // differ from Linux.
    let output: Vec<Box<dyn Read + Send>> = vec![
        Box::new(child.stdout.take().unwrap()),
        Box::new(child.stderr.take().unwrap()),
    ];
    Ok(PaneIo {
        child,
        input,
        output,
        // Nothing here can be told anything: no ioctl, no terminal-size call, no
        // signals (§3.2, §3.6). `$COLUMNS` was set above and is read at spawn,
        // so what a resized pane's child learns, it learns from the `ESC[6n` the
        // pane answers with its new size.
        tell_size: Box::new(|_| {}),
    })
}

/// Where the server publishes the port it bound (details.md §4.2).
///
/// `/sys/tmp` is Motor's scratch convention, and rmux creates it: the image
/// ships no such directory, because git cannot track an empty one and nothing
/// else has needed it yet. Tests may select a private server with `$TMPDIR`, as
/// they do on Unix; ordinary sessions share the default. `/sys` is writable,
/// so this costs one `mkdir` on first use rather than a change to the image.
pub fn port_file() -> PathBuf {
    std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/sys/tmp"))
        .join("rmux.port")
}

/// Where a user's overrides live (details.md §2.2), the same convention red uses.
pub fn config_file() -> PathBuf {
    PathBuf::from("/user/cfg/rmux.toml")
}

/// Spawn `cmd`'s child reparented to the kernel, so it outlives this process.
///
/// Motor's equivalent of Unix's reparent-to-init, and not a default: an
/// ordinary orphan here is *killed* when its parent is reaped (§4.4, measured
/// in M0). Requested by an environment variable and consumed by the spawner's
/// runtime, which is why a program linking nothing can ask for it; the kernel
/// checks that this process holds `CAP_SPAWN_DETACHED`, which rush grants to
/// the programs listed in `/user/cfg/rush.toml`'s `spawn-detached`.
pub fn detach(cmd: &mut Command) {
    cmd.env("MOTOR_OS_DETACHED", "true");
}
