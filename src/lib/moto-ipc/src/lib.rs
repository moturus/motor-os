#![no_std]

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

pub mod io_channel;
pub mod sync;
pub mod sync_pipe;
