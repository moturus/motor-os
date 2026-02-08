use crate::Block;
use crate::Result;
use async_trait::async_trait;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// Asynchronous Block Device.
#[async_trait(?Send)]
pub trait AsyncBlockDevice {
    type Completion: core::future::Future<Output = Result<()>> + 'static;

    /// The number of blocks in this device.
    fn num_blocks(&self) -> u64;

    /// Read a single block.
    async fn read_block(&self, block_no: u64, block: &mut Block) -> Result<()>;

    /// Write a single block.
    async fn write_block(&self, block_no: u64, block: &Block) -> Result<()>;

    async fn write_block_with_completion(
        &self,
        block_no: u64,
        block: crate::block_cache::FlushingBlock,
    ) -> Result<Self::Completion>;

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&self) -> Result<()>;

    /// Notify the device that there is work to do.
    fn notify(&self);
}
