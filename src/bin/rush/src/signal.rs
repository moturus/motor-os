//! Traps and signal dispatch (Phase 7).
//!
//! The `trap` builtin records an action per *condition* — `EXIT` or a signal —
//! and this module is what makes those actions run. It owns three things:
//!
//! 1. **The signal vocabulary** ([`parse_condition`], [`signo_to_name`]): the
//!    POSIX names and numbers, used identically on both platforms so that a
//!    script reads the same everywhere, whether or not the kernel underneath can
//!    deliver what it names.
//! 2. **Dispositions** ([`apply_disposition`]): setting a trap asks the platform
//!    to catch the signal, `trap '' SIG` to ignore it, and `trap - SIG` to
//!    restore the default. Signals with no trap are never touched, so they keep
//!    their default behavior — which is why rush needs no default-action
//!    emulation of its own: an untrapped `TERM` still kills the shell because
//!    the kernel does it.
//! 3. **Dispatch** ([`run_pending_traps`], [`fire_exit_trap`]): a delivered
//!    signal only sets a flag (a handler may do nothing else safely), so the
//!    trap action itself runs here, at a *safe point* between commands, where it
//!    is just another script to execute.
//!
//! # Delivery is platform-independent; only its *source* differs
//!
//! Both platforms funnel into the same pending bitmap in [`crate::sys`]. On the
//! Unix host a real signal handler sets it. On Motor OS, which has no signals at
//! all, the terminal reader sets it directly when it sees a `^C` byte (§0.1) —
//! so `trap … INT` works there, and the machinery above does not know or care
//! which happened. What Motor OS cannot do is deliver a signal from *outside*
//! the process: [`crate::sys::set_disposition`] reports failure there, the trap
//! is stored, and it simply never fires. That is the documented degradation.

use crate::exec;
use crate::shell::Shell;
use crate::sys::{self, Disposition};

pub const SIGINT: i32 = 2;

/// The signals rush names, with their POSIX/Linux numbers. This is the canonical
/// namespace on every platform (see the module docs), and the order here is the
/// numeric one, which is also the order traps run in when several are pending.
const SIGNALS: &[(&str, i32)] = &[
    ("HUP", 1),
    ("INT", SIGINT),
    ("QUIT", 3),
    ("ILL", 4),
    ("TRAP", 5),
    ("ABRT", 6),
    ("BUS", 7),
    ("FPE", 8),
    ("KILL", 9),
    ("USR1", 10),
    ("SEGV", 11),
    ("USR2", 12),
    ("PIPE", 13),
    ("ALRM", 14),
    ("TERM", 15),
    ("CHLD", 17),
    ("CONT", 18),
    ("STOP", 19),
    ("TSTP", 20),
    ("TTIN", 21),
    ("TTOU", 22),
    ("URG", 23),
    ("XCPU", 24),
    ("XFSZ", 25),
    ("VTALRM", 26),
    ("PROF", 27),
    ("WINCH", 28),
    ("IO", 29),
    ("SYS", 31),
];

/// A condition a trap can be set on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Condition {
    /// `EXIT` (equivalently, signal number 0): the shell is terminating.
    Exit,
    Signal(i32),
}

/// Parse a `trap` operand — a name (`INT`), a `SIG`-prefixed name (`SIGINT`), a
/// number (`2`), `EXIT`, or `0` — into its condition, case-insensitively.
///
/// `None` means "bad trap": the operand names nothing rush knows.
pub fn parse_condition(word: &str) -> Option<Condition> {
    let upper = word.to_ascii_uppercase();
    let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
    if bare == "EXIT" {
        return Some(Condition::Exit);
    }
    if let Ok(num) = bare.parse::<i32>() {
        if num == 0 {
            return Some(Condition::Exit);
        }
        // Only numbers rush can actually name are accepted, so that a trap on a
        // signal it could never report is rejected up front rather than stored
        // and silently ignored.
        return signo_to_name(num).map(|_| Condition::Signal(num));
    }
    SIGNALS
        .iter()
        .find(|(name, _)| *name == bare)
        .map(|(_, signo)| Condition::Signal(*signo))
}

/// The bare name for a signal number (`2` → `INT`), or `None` if rush has no
/// name for it.
pub fn signo_to_name(signo: i32) -> Option<&'static str> {
    SIGNALS
        .iter()
        .find(|(_, num)| *num == signo)
        .map(|(name, _)| *name)
}

/// The canonical key a condition is stored and listed under (`2` → `INT`), which
/// is what `trap` with no arguments prints — matching dash, which reports
/// `trap 'x' 2` as `INT`.
pub fn condition_name(cond: Condition) -> String {
    match cond {
        Condition::Exit => "EXIT".to_string(),
        Condition::Signal(signo) => signo_to_name(signo)
            .map(str::to_string)
            .unwrap_or_else(|| signo.to_string()),
    }
}

/// Ask the platform to establish `disp` for `cond`, returning whether it could.
///
/// A `false` here is not an error: it is how a platform says "this signal can
/// never reach you". Motor OS answers that for everything, and the Unix host for
/// `KILL`/`STOP`, which no one may catch. The trap is stored regardless (dash
/// accepts `trap 'x' KILL` silently too) — it just never fires.
pub fn apply_disposition(cond: Condition, action: Option<&str>) -> bool {
    let Condition::Signal(signo) = cond else {
        // `EXIT` is not a signal: nothing to install, and it always "works".
        return true;
    };
    let disp = match action {
        None => Disposition::Default,
        Some("") => Disposition::Ignore,
        Some(_) => Disposition::Catch,
    };
    sys::set_disposition(signo, disp)
}

/// Run the trap actions for any signals delivered since the last check, and
/// report the last signal whose trap ran (`None` if none did).
///
/// Called at *safe points* — between the commands of a list, around a foreground
/// wait, and before each interactive prompt — never from a handler.
///
/// `$?` is saved across the action and restored afterwards, so a trap firing
/// between two commands cannot change what the next one sees (POSIX §2.14
/// `trap`; verified against dash).
///
/// The return value exists for `wait`, which POSIX says must return `128 + signo`
/// when a trapped signal interrupts it; nothing else needs to care.
pub fn run_pending_traps(shell: &mut Shell) -> Option<i32> {
    if !sys::signal_pending() {
        return None;
    }
    let mut fired = None;
    for signo in sys::take_pending_signals() {
        let Some(name) = signo_to_name(signo) else {
            continue;
        };
        let Some(action) = shell.get_trap(name).map(String::from) else {
            continue;
        };
        if action.is_empty() {
            continue; // `trap '' SIG`: ignored.
        }
        let saved = shell.status();
        exec::run_source(&action, shell);
        shell.set_status(saved);
        fired = Some(signo);
    }
    fired
}

/// Run the `EXIT` trap action, if any, and clear it so it fires exactly once.
///
/// Called when the shell itself is about to terminate: the `exit` builtin, the
/// end of a `-c` string or script, and a `set -e` exit. The action sees the `$?`
/// the shell is exiting with, and cannot change the exit status (dash: `trap
/// "echo bye:$?" EXIT; false` prints `bye:1` and exits 1).
pub fn fire_exit_trap(shell: &mut Shell) {
    if let Some(action) = shell.get_trap("EXIT").map(String::from) {
        shell.clear_trap("EXIT");
        if !action.is_empty() {
            let saved = shell.status();
            exec::run_source(&action, shell);
            shell.set_status(saved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_numbers_and_exit() {
        assert_eq!(parse_condition("INT"), Some(Condition::Signal(2)));
        assert_eq!(parse_condition("SIGINT"), Some(Condition::Signal(2)));
        assert_eq!(parse_condition("sigint"), Some(Condition::Signal(2)));
        assert_eq!(parse_condition("2"), Some(Condition::Signal(2)));
        assert_eq!(parse_condition("EXIT"), Some(Condition::Exit));
        assert_eq!(parse_condition("0"), Some(Condition::Exit));
        assert_eq!(parse_condition("NOPE"), None);
        assert_eq!(parse_condition("99"), None);
    }

    #[test]
    fn numbers_canonicalize_to_names_for_listing() {
        // dash prints `trap 'x' 2` back as INT.
        assert_eq!(condition_name(parse_condition("2").unwrap()), "INT");
        assert_eq!(condition_name(parse_condition("SIGTERM").unwrap()), "TERM");
        assert_eq!(condition_name(Condition::Exit), "EXIT");
    }

    #[test]
    fn signal_names_are_unique_and_round_trip() {
        for (name, signo) in SIGNALS {
            assert_eq!(signo_to_name(*signo), Some(*name));
            assert_eq!(parse_condition(name), Some(Condition::Signal(*signo)));
        }
    }
}
