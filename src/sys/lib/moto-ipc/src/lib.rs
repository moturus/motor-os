#![no_std]
#![feature(maybe_uninit_write_slice)]

extern crate alloc;

pub mod io_channel;
pub mod sync;

#[cfg(feature = "stdio-pipe")]
pub mod stdio_pipe;

#[macro_export]
macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
        moto_sys::SysRay::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}
