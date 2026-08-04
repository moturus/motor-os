//! Motor OS backend: process control via moto-sys, and no signals anywhere.
//!
//! Motor OS cannot deliver a signal to a process; a ^C is an in-band 0x03
//! byte on stdin. At the prompt the REPL's own line editor sees that byte
//! (`ui/line.rs`, switched on by [`raw_console`]); mid-turn nothing reads
//! stdin, so interrupting a running turn is still **unsupported on Motor
//! OS** (recorded in the step 10 notes of the plan). The process side is
//! real: spawn, kill and liveness all work, they just reach one process at a
//! time — Motor OS has no process groups either.

/// There is no handler to install, and nothing failed: no signal can arrive
/// from outside the process. Delivery is the stdin reader seeing 0x03 and
/// calling `super::note_interrupt` — which the line editor does at the
/// prompt; mid-turn there is no reader yet.
pub fn install_interrupt_handler() -> bool {
    true
}

/// Whether the console needs gears to do its own echo and line editing.
/// Whenever stdin is a terminal at all: Motor OS has no termios and no
/// cooked mode, so a console here is raw by construction (the rush contract,
/// `rush/src/sys/mod.rs`) and nothing echoes a keystroke unless the program
/// does. A pipe is not a terminal and gets neither echo nor editing.
pub fn raw_console() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// Whether a process still exists. There is no per-pid query, but the process
/// list is ordered by pid, so one entry starting at `pid` decides it (the
/// rush idiom, `sys/motor.rs`). A zombie (`active == 0`) is gone; a list this
/// process may not read is "alive", the way `EPERM` is on the host — a lock
/// that cannot be checked must not be broken.
pub fn process_alive(pid: u32) -> bool {
    // Pid 0 in a lockfile is junk rather than an owner (see the unix backend).
    if pid == 0 {
        return false;
    }
    let pid = u64::from(pid);
    let mut buf = [moto_sys::stats::ProcessInfoV1::default(); 1];
    match moto_sys::stats::ProcessInfoV1::list(pid, &mut buf) {
        Ok(n) => n >= 1 && buf[0].pid == pid && buf[0].active != 0,
        Err(_) => true,
    }
}

/// A plain spawn: Motor OS has no process groups, so what a timeout can stop
/// is the child alone. `kill_tree` below is a kill of one, and a compiler's
/// own children are what it may leave behind — accepted for now, and noted
/// where the plan records what the port does not cover.
pub fn spawn(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    command.spawn()
}

/// Kill `child` — itself, not a tree; see [`spawn`]. The one primitive is an
/// unconditional kill (`SysCpu::kill_pid`), as hard as SIGKILL.
pub fn kill_tree(child: &std::process::Child) {
    let _ = moto_sys::SysCpu::kill_pid(u64::from(child.id()));
}

/// No signal can kill a process here, so unlike the unix backend there is no
/// "killed by" case to report (the rush precedent, `sys/motor.rs`).
pub fn status_text(status: std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit status {code}"),
        None => "stopped".to_string(),
    }
}
