#![feature(negative_impls)]
#![no_std]

extern crate alloc;

pub mod io_channel;
pub mod sync;

#[cfg(any(test, feature = "stdio-pipe"))]
pub mod stdio_pipe;
