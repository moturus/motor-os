use crate::Block;
use crate::Result;
use async_trait::async_trait;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// Asynchronous Block Device.
#[async_trait(?Send)]
pub trait AsyncBlockDevice {
    type Completion<'a>;

    /// The number of blocks in this device.
    fn num_blocks(&self) -> u64;

    /// Read a single block.
    async fn read_block(&mut self, block_no: u64, block: &mut Block) -> Result<()>;

    /// Write a single block.
    async fn write_block(&mut self, block_no: u64, block: &Block) -> Result<()>;

    async fn write_block_2<'a>(
        &mut self,
        block_no: u64,
        block: &'a Block,
    ) -> Result<Self::Completion<'a>>;

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&mut self) -> Result<()>;
}
