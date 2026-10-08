//! Platform abstraction layer, the rush/rmux seam idiom: `mod.rs` declares
//! the portable vocabulary and each backend exports the same names. The
//! discriminator is `cfg(unix)` / `cfg(not(unix))`, **not** `target_os =
//! "motor"` — Motor OS sets no target family, so `unix` is simply never true
//! there.
//!
//! Step 0 owned only the interrupt flag; step 5 added process control — how a
//! command is started so it can be stopped again, and how its end is
//! described. The Motor backend uses native process control and turns an
//! explicit Ctrl+C handler into the same flag (see `motor.rs`).

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    TerminalInput, cancellation_text, cleanup_after_exit, install_interrupt_handler, kill_tree,
    process_alive, process_is_descendant_of, process_is_gears, raw_console, spawn, status_text,
};

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::{
    TerminalInput, cancellation_text, cleanup_after_exit, install_interrupt_handler, kill_tree,
    process_alive, process_is_descendant_of, process_is_gears, raw_console, spawn, status_text,
};

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(not(unix), test))]
fn debug_name_may_be_gears(name: &str, limit: usize) -> bool {
    // Native names contain the path plus unquoted arguments. A truncated or
    // unreadable name cannot prove that a live lock belongs to another program.
    if name.is_empty() || name.ends_with('…') || name.len() >= limit {
        return true;
    }
    // Any space can end the executable path, including one containing spaces.
    name.match_indices(' ')
        .map(|(end, _)| end)
        .chain(std::iter::once(name.len()))
        .any(|end| {
            std::path::Path::new(&name[..end])
                .file_name()
                .is_some_and(|file| file == "gears")
        })
}

#[cfg(test)]
#[test]
fn native_command_names_preserve_gears_and_unknown_live_owners() {
    for name in [
        "gears",
        "/devtools/bin/gears",
        "/devtools/bin/gears --ui line",
        "/user/my tools/gears -p hi",
        "/user/long-executable-path/gea…",
        "",
        "/12345678901234567890123456789012",
    ] {
        assert!(debug_name_may_be_gears(name, 32), "{name}");
    }
    for name in [
        "/system/bin/sysbox sleep 30",
        "/system/bin/rush -c hi",
        "/devtools/bin/gears-other",
        "not-gears",
    ] {
        assert!(!debug_name_may_be_gears(name, 32), "{name}");
    }
}

/// The one pending-interrupt flag (^C). Delivery only sets it — on the Unix
/// host from a SIGINT handler and on Motor OS from an explicit Ctrl+C handler
/// — and the REPL consumes it at safe points.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Record an interrupt. Async-signal-safe: an atomic store only.
pub fn note_interrupt() {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

pub fn interrupt_pending() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Take the pending interrupt, clearing it; true if one was pending.
pub fn take_interrupt() -> bool {
    INTERRUPTED.swap(false, Ordering::SeqCst)
}

// Interrupt lifecycle tests are in `tests/hook_interrupt.rs`, which is a
// process of its own. Nothing that sets or takes this flag can be tested
// beside the agent tests: they take it too, at every safe point in a turn, and
// whichever got there first made the other fail.
