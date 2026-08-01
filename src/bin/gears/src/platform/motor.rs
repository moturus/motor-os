//! Motor OS backend: compiling stubs until step 10 of the plan.
//!
//! Motor OS has no signals; ^C arrives as an in-band 0x03 byte, which the
//! stdin reader will report via `super::note_interrupt` when this backend
//! becomes real.

pub fn install_interrupt_handler() -> bool {
    unimplemented!("the Motor OS backend arrives in step 10 of the plan")
}

pub fn process_alive(_pid: u32) -> bool {
    unimplemented!("the Motor OS backend arrives in step 10 of the plan")
}
