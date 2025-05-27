#![no_std]
#![feature(core_intrinsics)]
#![allow(internal_features)]

// Syscalls.
pub mod caps;
pub mod stats;
pub mod sys_cpu;
pub mod sys_mem;
pub mod sys_obj;
pub mod sys_ray;
pub mod syscalls;
pub use moto_rt::ErrorCode;
pub use sys_cpu::SysCpu;
pub use sys_mem::SysMem;
pub use sys_obj::SysObj;
pub use sys_ray::SysRay;
pub use syscalls::SysHandle;

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
pub fn current_thread() -> SysHandle {
    shared_mem::UserThreadControlBlock::this_thread_handle()
}

#[cfg(feature = "userspace")]
pub fn num_cpus() -> u32 {
    KernelStaticPage::get().num_cpus
}

#[cfg(feature = "userspace")]
pub fn current_pid() -> u64 {
    shared_mem::ProcessStaticPage::get().pid
}

pub fn rdrand() -> Result<u64, ErrorCode> {
    let mut val = 0_u64;
    unsafe {
        let result = core::arch::x86_64::_rdrand64_step(&mut val);
        match result {
            1 => Ok(val),
            0 => Err(moto_rt::E_NOT_IMPLEMENTED), // The hardware does not support this.
            _ => Err(moto_rt::E_INTERNAL_ERROR),  // This is unexpected.
        }
    }
}

pub fn rdseed() -> Result<u64, ErrorCode> {
    let mut val = 0_u64;
    unsafe {
        let result = core::arch::x86_64::_rdseed64_step(&mut val);
        match result {
            1 => Ok(val),
            0 => Err(moto_rt::E_NOT_IMPLEMENTED), // The hardware does not support this.
            _ => Err(moto_rt::E_INTERNAL_ERROR),  // This is unexpected.
        }
    }
}

#[allow(unused)]
macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            crate::SysRay::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}

#[allow(unused)]
pub(crate) use moto_log;
