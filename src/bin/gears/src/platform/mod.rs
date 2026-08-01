//! Platform abstraction layer, the rush/rmux seam idiom: `mod.rs` declares
//! the portable vocabulary and each backend exports the same names. The
//! discriminator is `cfg(unix)` / `cfg(not(unix))`, **not** `target_os =
//! "motor"` — Motor OS sets no target family, so `unix` is simply never true
//! there.
//!
//! Step 0 owns only the interrupt flag; process spawn/kill/wait arrives in
//! step 5 of the plan, and the Motor backend becomes real in step 10.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::install_interrupt_handler;

#[cfg(not(unix))]
mod motor;
#[cfg(not(unix))]
pub use motor::install_interrupt_handler;

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

#[cfg(test)]
mod tests {
    use super::*;

    // One test, not two: the flag is process-global, and cargo's parallel
    // test threads would race a split version of this.
    #[test]
    fn interrupt_flag_notes_takes_and_fires_on_sigint() {
        assert!(!interrupt_pending());
        note_interrupt();
        assert!(interrupt_pending());
        assert!(take_interrupt());
        assert!(!interrupt_pending());
        assert!(!take_interrupt());

        // Install first and insist on success: with the handler missing, the
        // raise below would kill the test runner.
        #[cfg(unix)]
        {
            assert!(install_interrupt_handler());
            unsafe { libc::raise(libc::SIGINT) };
            assert!(take_interrupt());
        }
    }
}
