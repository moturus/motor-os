use crate::Block;
use std::io::Result;

/// Asynchronous Block Device.
pub trait AsyncBlockDevice {
    /// The number of blocks in this device.
    fn num_blocks(&self) -> u64;

    /// Read a single block.
    async fn read_block(&mut self, block_no: u64, block: &mut Block) -> Result<()>;

    /// Write a single block.
    async fn write_block(&mut self, block_no: u64, block: &Block) -> Result<()>;

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&mut self) -> Result<()>;
}
