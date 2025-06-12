//! AsyncBlockDevice and AsyncFs traits.
#![allow(async_fn_in_trait)]

#[cfg(feature = "file-dev")]
pub mod file_block_device;

mod block_device;
mod filesystem;

pub use block_device::*;
pub use filesystem::*;
