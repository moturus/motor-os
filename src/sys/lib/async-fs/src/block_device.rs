use crate::Result;
use crate::block_cache::CheckpointedBlock;
use async_trait::async_trait;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(not(target_os = "motor"))]
use fittings::iobuf::IoBuf;
#[cfg(target_os = "motor")]
use moto_tooling::iobuf::IoBuf;

/// Asynchronous Block Device.
#[async_trait(?Send)]
pub trait AsyncBlockDevice {
    type Completion: core::future::Future<Output = (CheckpointedBlock, Result<()>)> + 'static;

    /// The number of blocks in this device.
    fn num_blocks(&self) -> u64;

    /// Read a single block.
    async fn read_block<T: AsMut<IoBuf> + Unpin>(&self, block_no: u64, block: T)
    -> (T, Result<()>);
    async fn write_block<T: AsRef<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>);

    async fn write_block_with_completion(
        &self,
        block_no: u64,
        block: CheckpointedBlock,
    ) -> Result<Self::Completion>;

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&self) -> Result<()>;
}
