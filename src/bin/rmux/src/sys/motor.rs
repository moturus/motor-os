//! The Motor OS backend.

use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use super::PaneIo;

/// The environment variable Motor's runtime reads to answer `is_terminal()`.
///
/// Spelled out rather than taken from `moto-rt` on purpose: it is a string, and
/// depending on a crate to obtain a string would cost rmux its zero-dependency
/// goal (details.md §4.6) for nothing. The definition lives at
/// `moto-rt/src/process.rs:30`; the code that reads it is
/// `rt.vdso/src/rt_fs.rs:1203`, which checks this variable and *nothing about
/// the file descriptor*.
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
/// one environment variable, after which the child reports
/// `is_terminal() == true` and behaves interactively. `sys-tty/src/main.rs:89`
/// and `russhd`'s `local_session.rs:67` do the same thing for the same reason.
///
/// The runtime *also* sets that variable itself when a child inherits both
/// stdin and stdout (`moto-rt/src/process.rs:245`). rmux's panes are on pipes,
/// not inherited, so that path never fires and setting it here is required.
pub fn spawn_pane(mut cmd: Command, size: (u16, u16)) -> std::io::Result<PaneIo> {
    let (rows, cols) = size;
    cmd.env(STDIO_IS_TERMINAL_ENV_KEY, "true");
    // Mechanism 2 of §3.2, and the closest thing to `SIGWINCH` that exists
    // here: rush re-reads `$COLUMNS` at every prompt (`rush/src/term.rs:858`),
    // so a pane's shell learns its width for free. Nothing notifies a pane of a
    // resize; it finds out at its next probe.
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

/// The console's size, if the *platform* can say — and here it cannot.
///
/// Motor has no ioctl and no terminal-size call at all
/// (`rush/src/sys/mod.rs:46`), so rmux asks the terminal itself with an ANSI
/// query and never waits for the reply (§3.2).
pub fn console_size() -> Option<(u16, u16)> {
    None
}

/// Raw mode, which Motor has no concept of: the console is always raw.
pub struct RawConsole;

impl RawConsole {
    pub fn enter() -> RawConsole {
        RawConsole
    }

    pub fn restore() {}
}

/// Where the server publishes the port it bound (details.md §4.2).
///
/// `/sys/tmp` is Motor's scratch convention, and rmux creates it: the image
/// ships no such directory, because git cannot track an empty one and nothing
/// else has needed it yet. `/sys` is writable, so this costs one `mkdir` on
/// first use rather than a change to the image. One machine, one server.
pub fn port_file() -> PathBuf {
    PathBuf::from("/sys/tmp/rmux.port")
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
