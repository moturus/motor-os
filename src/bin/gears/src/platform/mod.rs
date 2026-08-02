//! Platform abstraction layer, the rush/rmux seam idiom: `mod.rs` declares
//! the portable vocabulary and each backend exports the same names. The
//! discriminator is `cfg(unix)` / `cfg(not(unix))`, **not** `target_os =
//! "motor"` — Motor OS sets no target family, so `unix` is simply never true
//! there.
//!
//! Step 0 owned only the interrupt flag; step 5 adds process control — how a
//! command is started so it can be stopped again, and how its end is
//! described. Step 10 made the Motor backend real (moto-sys process control;
//! no signals, so no in-band ^C delivery yet — see `motor.rs`).

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{install_interrupt_handler, kill_tree, process_alive, spawn, status_text};

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::{install_interrupt_handler, kill_tree, process_alive, spawn, status_text};

use std::sync::atomic::{AtomicBool, Ordering};

/// The one pending-interrupt flag (^C). Delivery only sets it — on the Unix
/// host from a real SIGINT handler, on Motor OS from the stdin reader seeing
/// an in-band 0x03 byte — and the REPL consumes it at safe points.
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

// The tests for the three above are in `tests/interrupt.rs`, which is a
// process of its own. Nothing that sets or takes this flag can be tested
// beside the agent tests: they take it too, at every safe point in a turn, and
// whichever got there first made the other fail.
