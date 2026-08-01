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
