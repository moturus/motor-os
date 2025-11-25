//! Common Motor OS error codes.
pub type ErrorCode = u16;

/// Motor OS system error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Error {
    Ok = 0,
    Unspecified = 1,
    Unknown = 2,
    NotReady = 3, // Main async error, similar to E_WOULD_BLOCK in Linux.
    NotImplemented = 4,
    VersionTooHigh = 5,
    VersionTooLow = 6,
    InvalidArgument = 7,
    OutOfMemory = 8,
    NotAllowed = 9,
    NotFound = 10,
    InternalError = 11,
    TimedOut = 12,
    AlreadyInUse = 13,
    UnexpectedEof = 14,
    InvalidFilename = 15,
    NotADirectory = 16,
    BadHandle = 17,
    FileTooLarge = 18,
    BufferFull = 19,
    NotConnected = 20,
    StorageFull = 21,
    InvalidData = 22,

    // Keep this value as the last one.
    Max,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl From<Error> for ErrorCode {
    fn from(val: Error) -> ErrorCode {
        val as ErrorCode
    }
}

impl From<u16> for Error {
    fn from(val: u16) -> Self {
        if val < Error::Max.into() {
            // Safety: safe because Error is repr(u16).
            unsafe { core::mem::transmute::<u16, Error>(val) }
        } else {
            Error::Unknown
        }
    }
}

pub const E_OK: u16 = Error::Ok as u16;
pub const E_UNSPECIFIED: u16 = Error::Unspecified as u16;
pub const E_UNKNOWN: u16 = Error::Unknown as u16;
pub const E_NOT_READY: u16 = Error::NotReady as u16;
pub const E_NOT_IMPLEMENTED: u16 = Error::NotImplemented as u16;
pub const E_VERSION_TOO_HIGH: u16 = Error::VersionTooHigh as u16;
pub const E_VERSION_TOO_LOW: u16 = Error::VersionTooLow as u16;
pub const E_INVALID_ARGUMENT: u16 = Error::InvalidArgument as u16;
pub const E_OUT_OF_MEMORY: u16 = Error::OutOfMemory as u16;
pub const E_NOT_ALLOWED: u16 = Error::NotAllowed as u16;
pub const E_NOT_FOUND: u16 = Error::NotFound as u16;
pub const E_INTERNAL_ERROR: u16 = Error::InternalError as u16;
pub const E_TIMED_OUT: u16 = Error::TimedOut as u16;
pub const E_ALREADY_IN_USE: u16 = Error::AlreadyInUse as u16;
pub const E_UNEXPECTED_EOF: u16 = Error::UnexpectedEof as u16;
pub const E_INVALID_FILENAME: u16 = Error::InvalidFilename as u16;
pub const E_NOT_A_DIRECTORY: u16 = Error::NotADirectory as u16;
pub const E_BAD_HANDLE: u16 = Error::BadHandle as u16;
pub const E_FILE_TOO_LARGE: u16 = Error::FileTooLarge as u16;
pub const E_BUFFER_FULL: u16 = Error::BufferFull as u16;
pub const E_NOT_CONNECTED: u16 = Error::NotConnected as u16;
pub const E_STORAGE_FULL: u16 = Error::StorageFull as u16;
pub const E_INVALID_DATA: u16 = Error::InvalidData as u16;

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
            #[allow(unused_extern_crates)]
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
    if val == E_OK { Ok(()) } else { Err(val) }
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
