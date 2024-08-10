#![no_std]
#![feature(core_intrinsics)]
#![feature(naked_functions)]
#![allow(internal_features)]

// Syscalls.
pub mod caps;
pub mod stats;
pub mod sys_cpu;
pub mod sys_mem;
pub mod sys_obj;
pub mod sys_ray;
pub mod syscalls;
pub use sys_cpu::SysCpu;
pub use sys_mem::SysMem;
pub use sys_obj::SysObj;
pub use sys_ray::SysRay;
pub use syscalls::SysHandle;

#[cfg(feature = "userspace")]
pub mod time;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;
use alloc::string::String;

/// The maximum length of a thread name. Limited because it is
/// embedded in various structs like UserThreadControlBlock and ThreadDataV1.
pub const MAX_THREAD_NAME_LEN: usize = 32;

// Kernel/usperspace shared memory.
mod shared_mem;
pub use shared_mem::*;

#[cfg(feature = "userspace")]
pub fn align_up(addr: u64, align: u64) -> u64 {
    assert!(align.is_power_of_two(), "`align` must be a power of two");
    let align_mask = align - 1;
    if addr & align_mask == 0 {
        addr // already aligned
    } else {
        (addr | align_mask) + 1
    }
}

// #[cfg(not(feature = "rustc-dep-of-std"))]
pub fn url_encode(url: &str) -> String {
    // Replace ':' with '&col'; '=' with '&eq'; '&' with '&amp;'.
    let amps = url.replace('&', "&amp;");
    let cols = amps.replace(':', "&col;");

    cols.replace('=', "&eq;")
}

#[cfg(not(feature = "rustc-dep-of-std"))]
pub fn url_decode(encoded: &str) -> String {
    let eqs = encoded.replace("&eq;", "=");
    let cols = eqs.replace("&col;", ":");

    cols.replace("&amp;", "&")
}

#[cfg(feature = "userspace")]
pub fn current_cpu() -> u32 {
    shared_mem::UserThreadControlBlock::get()
        .current_cpu
        .load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(feature = "userspace")]
pub fn num_cpus() -> u32 {
    KernelStaticPage::get().num_cpus
}

#[cfg(feature = "userspace")]
pub fn current_pid() -> u64 {
    shared_mem::ProcessStaticPage::get().pid
}

// Most system-level APIs (syscalls, IO drivers) return 16-bit error codes
// to make things simple (errno works well enough in Linux/POSIX).
// Applications that want to use more sophisticated errors are free to do that.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Ok = 0,
    UnspecifiedError = 1, // A generic error.
    UnknownError = 2,     // Should only be used in from_u16() below.
    NotReady = 3,
    NotImplemented = 5,
    VersionTooHigh = 6,
    VersionTooLow = 7,
    InvalidArgument = 8,
    OutOfMemory = 9,
    NotAllowed = 10, // Permission error.
    NotFound = 11,
    InternalError = 12,
    TimedOut = 13,
    AlreadyInUse = 14,
    UnexpectedEof = 15,
    InvalidFilename = 16,
    NotADirectory = 17,
    BadHandle = 18,
    FileTooLarge = 19,
    BufferFull = 20,

    MaxKernelError, // Must be last, so that from_u16() below works.
}

impl ErrorCode {
    pub fn is_ok(&self) -> bool {
        *self == ErrorCode::Ok
    }

    pub fn is_err(&self) -> bool {
        *self != ErrorCode::Ok
    }

    pub fn from_u16(val: u16) -> Self {
        if val >= Self::MaxKernelError as u16 {
            Self::UnknownError
        } else {
            unsafe { core::mem::transmute(val) }
        }
    }
}

impl From<ErrorCode> for u16 {
    fn from(value: ErrorCode) -> Self {
        value as u16
    }
}

impl From<u16> for ErrorCode {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

pub fn rdrand() -> Result<u64, ErrorCode> {
    let mut val = 0_u64;
    unsafe {
        let result = core::arch::x86_64::_rdrand64_step(&mut val);
        match result {
            1 => Ok(val),
            0 => Err(ErrorCode::NotImplemented), // The hardware does not support this.
            _ => Err(ErrorCode::InternalError),  // This is unexpected.
        }
    }
}

pub fn rdseed() -> Result<u64, ErrorCode> {
    let mut val = 0_u64;
    unsafe {
        let result = core::arch::x86_64::_rdseed64_step(&mut val);
        match result {
            1 => Ok(val),
            0 => Err(ErrorCode::NotImplemented), // The hardware does not support this.
            _ => Err(ErrorCode::InternalError),  // This is unexpected.
        }
    }
}
// #[cfg(feature = "userspace")]
// #[macro_export]
// macro_rules! moturus_log {
//     ($($arg:tt)*) => {
//         {
//             extern crate alloc;
//             crate::syscalls::SysMem::log(alloc::format!($($arg)*).as_str()).ok();
//         }
//     };
// }
