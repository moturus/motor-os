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
