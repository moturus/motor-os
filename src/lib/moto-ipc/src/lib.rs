#![no_std]

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

pub mod io_channel;
pub mod sync;
pub mod sync_pipe;

#[macro_export]
macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
        moto_sys::SysMem::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}
