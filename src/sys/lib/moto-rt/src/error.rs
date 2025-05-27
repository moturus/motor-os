//! Common Motor OS error codes.
pub type ErrorCode = u16;

pub const E_OK: u16 = 0;
pub const E_UNSPECIFIED: u16 = 1;
pub const E_UNKNOWN: u16 = 2;
pub const E_NOT_READY: u16 = 3;
pub const E_NOT_IMPLEMENTED: u16 = 5;
pub const E_VERSION_TOO_HIGH: u16 = 6;
pub const E_VERSION_TOO_LOW: u16 = 7;
pub const E_INVALID_ARGUMENT: u16 = 8;
pub const E_OUT_OF_MEMORY: u16 = 9;
pub const E_NOT_ALLOWED: u16 = 10; // PERMISSION ERROR.
pub const E_NOT_FOUND: u16 = 11;
pub const E_INTERNAL_ERROR: u16 = 12;
pub const E_TIMED_OUT: u16 = 13;
pub const E_ALREADY_IN_USE: u16 = 14;
pub const E_UNEXPECTED_EOF: u16 = 15;
pub const E_INVALID_FILENAME: u16 = 16;
pub const E_NOT_A_DIRECTORY: u16 = 17;
pub const E_BAD_HANDLE: u16 = 18;
pub const E_FILE_TOO_LARGE: u16 = 19;
pub const E_BUFFER_FULL: u16 = 20;
pub const E_NOT_CONNECTED: u16 = 21;

pub const E_MAX: u16 = u16::MAX;

#[cfg(not(feature = "base"))]
pub fn log_to_kernel(msg: &str) {
    let vdso_log_to_kernel: extern "C" fn(*const u8, usize) = unsafe {
        core::mem::transmute(
            super::RtVdsoVtable::get()
                .log_to_kernel
                .load(core::sync::atomic::Ordering::Relaxed) as usize as *const (),
        )
    };

    let bytes = msg.as_bytes();
    vdso_log_to_kernel(bytes.as_ptr(), bytes.len());
}

#[cfg(not(feature = "base"))]
#[macro_export]
macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            $crate::error::log_to_kernel(alloc::format!($($arg)*).as_str());
        }
    };
}

/// Log backtrace to rt_fd. If rt_fd is < 0, logs to the kernel log.
#[cfg(not(feature = "base"))]
pub fn log_backtrace(rt_fd: crate::RtFd) {
    let vdso_log_backtrace: extern "C" fn(crate::RtFd) = unsafe {
        core::mem::transmute(
            super::RtVdsoVtable::get()
                .log_backtrace
                .load(core::sync::atomic::Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_log_backtrace(rt_fd);
}

#[cfg(not(feature = "base"))]
pub fn log_panic(info: &core::panic::PanicInfo<'_>) {
    if crate::fs::is_terminal(crate::FD_STDERR) {
        #[cfg(not(feature = "rustc-dep-of-std"))]
        extern crate alloc;

        let _ = crate::fs::write(crate::FD_STDERR, b"PANIC\n"); // Log w/o allocations.
        let msg = alloc::format!("PANIC: {info}\n");
        let _ = crate::fs::write(crate::FD_STDERR, msg.as_bytes());
        log_backtrace(crate::FD_STDERR);
    } else {
        log_to_kernel("PANIC"); // Log w/o allocations.
        moto_log!("PANIC: {}", info);
        log_backtrace(-1);
    }
}

#[cfg(not(feature = "base"))]
pub fn ok_or_error(val: ErrorCode) -> Result<(), ErrorCode> {
    if val == E_OK {
        Ok(())
    } else {
        Err(val)
    }
}

#[cfg(not(feature = "base"))]
#[macro_export]
macro_rules! to_result {
    ($arg:expr) => {{
        let res = $arg;
        if res < 0 {
            Err((-res) as ErrorCode)
        } else {
            Ok(unsafe { res.try_into().unwrap_unchecked() })
        }
    }};
}
