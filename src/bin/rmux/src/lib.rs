//! rmux — a terminal multiplexer for Motor OS.
//!
//! The plan is in `plan.md`, and doc comments cite it by section ("plan.md
//! §3.1"). Nothing in it is built yet beyond M0's scaffolding: the library seam,
//! the `tests/` hook, and the `sys::` platform layer. The M0 spikes that this
//! scaffolding once carried have served their purpose — their answers are
//! recorded in plan.md (§4.4 orphan survival, §8.3 key bytes) — and are gone.
//!
//! The crate root is a library with a thin `main.rs` over it, following rush:
//! that is what lets `tests/` drive the binary as an integration test while the
//! pure parts (the terminal emulator, the layout tree) stay unit-testable
//! without a terminal at all (plan.md §9.3).

pub mod sys;

/// Run rmux. Returns the process exit code.
pub fn run(_args: &[String]) -> i32 {
    // M1 turns this into the real entry point (spawn a pane on piped stdio with
    // the is-terminal env var, pump bytes both ways, drain on exit — plan.md
    // §10). Until then the crate is scaffolding, and this is the placeholder
    // over the library seam and the sys:: platform layer.
    println!("Hello from future rmux");
    0
}
