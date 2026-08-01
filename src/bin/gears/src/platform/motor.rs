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

/// Motor OS has no process groups, so this becomes a plain spawn; what a
/// timeout can reach is then the child alone (see the unix backend).
pub fn spawn(_command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    unimplemented!("the Motor OS backend arrives in step 10 of the plan")
}

pub fn kill_tree(_child: &std::process::Child) {
    unimplemented!("the Motor OS backend arrives in step 10 of the plan")
}

/// No signal can kill a process here, so unlike the unix backend there is no
/// "killed by" case to report (the rush precedent, `sys/motor.rs`).
pub fn status_text(_status: std::process::ExitStatus) -> String {
    unimplemented!("the Motor OS backend arrives in step 10 of the plan")
}
