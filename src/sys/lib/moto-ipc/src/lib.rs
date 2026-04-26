#![feature(negative_impls)]
#![no_std]

extern crate alloc;

pub mod io_channel;
pub mod sync;

#[cfg(feature = "stdio-pipe")]
pub mod stdio_pipe;
