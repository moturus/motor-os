//! Simple Rust File System (core library)
//!
//! A simple filesystem impremented in Rust \[no_std\].
//!
//! This crate is a work-in-progress. It contains low-level
//! code to work directly with block devices (see trait SyncBlockDevice).
//!
//! Higher-level API, dependent on \[std\], lives in crate srfs.
//!
//! All basic filesystem features are implemented (see ```struct SyncFileSystem```),
//! with provisions for extensions.
//!
//! At the moment only synchronous interface is provided.
//! See src/tests.rs for usage examples.
//!
//! TODO:
//!
//! * crash recovery
//! * timestamps
//! * async API
//!
//! Contributions are welcome.

pub mod file_block_device;

mod block_cache;
// mod fs_async;
mod fs_sync;
mod layout;

#[cfg(test)]
mod tests;

pub use fs_sync::*;
pub use layout::*;

use std::io::Result;

pub use async_fs::BLOCK_SIZE;

// The number below is somewhat arbitrary, but we don't want it to be
// too large, as having it at, say, 2^35 will make looking up an item
// take forever, and we don't want to stall an OS by having a bad/corrupted FS.
pub const MAX_DIR_ENTRIES: u64 = 65536;
pub const MAX_FILE_SIZE: u64 = MAX_BYTES_LIST_OF_LISTS_BLOCKS; // ~500G.

/// See <https://en.wikipedia.org/wiki/Partition_type>.
/// We use an arbitrary unused number here.
pub const PARTITION_ID: u8 = 0x2d;

/// Synchronous Block Device.
pub trait SyncBlockDevice {
    /// The number of blocks in this device.
    fn num_blocks(&self) -> u64;

    /// Read a single block into buf.
    /// buf must be aligned to BLOCK_SIZE and of length BLOCK_SIZE.
    fn read_block(&mut self, block_no: u64, buf: &mut [u8]) -> Result<()>;

    /// Write a single block. Same alignment requirements as in read_block.
    fn write_block(&mut self, block_no: u64, buf: &[u8]) -> Result<()>;
}

/// Initializes the block device so that it has an SFFS with a single/empty root dir.
pub fn format(block_device: &mut dyn SyncBlockDevice) -> Result<()> {
    fs_sync::format(block_device)
}
