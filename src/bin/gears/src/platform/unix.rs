//! Unix host backend: real signals, used for development and testing.

/// The SIGINT handler: records delivery and nothing else (a handler may only
/// touch async-signal-safe state).
extern "C" fn note_handler(_signo: libc::c_int) {
    super::note_interrupt();
}

/// Point SIGINT at the interrupt flag; false if the platform refused.
///
/// `sa_flags` omits `SA_RESTART` so a ^C interrupts a blocking read promptly
/// instead of whenever the read happens to return (the rush idiom).
pub fn install_interrupt_handler() -> bool {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = note_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut()) == 0
    }
}

/// Start `command` in a process group of its own, so that a timeout can stop
/// everything it started. `cargo` is a tree, and killing only the process
/// gears spawned would leave `rustc` running behind it.
///
/// The cost of the group is that a terminal `^C` no longer reaches the child;
/// stopping a running tool on demand arrives with step 7's per-agent abort
/// flags, which have to work on Motor OS too — where there are no signals to
/// deliver and a tty could not do it anyway.
pub fn spawn(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    command.process_group(0).spawn()
}

/// Kill `child` and everything in its process group. The group is the child's
/// own (see [`spawn`]), so this can never reach gears itself.
pub fn kill_tree(child: &std::process::Child) {
    let Ok(pid @ 1..) = libc::pid_t::try_from(child.id()) else {
        return;
    };
    unsafe { libc::killpg(pid, libc::SIGKILL) };
}

/// How a finished child is described. A signalled death has no exit code, and
/// saying which signal is the difference between "the test failed" and "the
/// test was killed".
pub fn status_text(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit status {code}"),
        (None, Some(signal)) => format!("killed by signal {signal}"),
        (None, None) => "stopped".to_string(),
    }
}

/// Whether a process still exists — signal 0 checks without delivering.
/// `EPERM` means it exists and belongs to somebody else, which is still
/// "alive"; only `ESRCH` says the pid is free.
pub fn process_alive(pid: u32) -> bool {
    // `kill` reads 0 as "my whole process group", never as a process, so a
    // lockfile naming it is junk rather than an owner — and answering "alive"
    // to it would make every such lock permanent.
    let Ok(pid @ 1..) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}
