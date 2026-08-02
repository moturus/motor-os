//! The interrupt flag, alone in a process.
//!
//! This is one test in a file of its own, and that is the whole point of the
//! file. The flag is process-global and *taken* rather than read — the agent
//! loop consumes it at every safe point — so a test that sets one, and a test
//! that runs an agent, cannot share a process. Under `cargo test` they did:
//! this test lived beside the code, libtest ran it on one thread while an
//! agent test ran on another, and about one release run in twenty either the
//! agent cancelled a turn it was asked to finish or this test found its own
//! interrupt already taken. An integration test gets a process to itself, and
//! that is the only isolation strong enough for a static.
//!
//! Everything here must therefore stay in one `#[test]`. A second one in this
//! file would race the first for exactly the same reason.

use gears::platform::{interrupt_pending, note_interrupt, take_interrupt};

#[test]
fn the_flag_notes_takes_and_fires_on_sigint() {
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
        assert!(gears::platform::install_interrupt_handler());
        unsafe { libc::raise(libc::SIGINT) };
        assert!(take_interrupt());
    }
}
