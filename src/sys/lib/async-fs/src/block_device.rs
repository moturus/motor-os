use crate::Result;
use crate::block_cache::CheckpointedBlock;
use async_trait::async_trait;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(target_os = "motor"))]
use fittings::iobuf::IoBuf;
#[cfg(target_os = "motor")]
use moto_tooling::iobuf::IoBuf;

/// The longest scatter-gather device transfer (blocks per request) callers
/// should issue: 16 blocks = 64K. Keeps descriptor chains comfortably within
/// any realistic virtio queue while amortizing the per-request cost
/// (submission, queue notification, completion interrupt).
pub const MAX_IO_RUN: usize = 16;

/// Asynchronous Block Device.
#[async_trait(?Send)]
pub trait AsyncBlockDevice {
    type Completion: core::future::Future<Output = (Vec<CheckpointedBlock>, Result<()>)> + 'static;

    /// The number of blocks in this device.
    fn num_blocks(&self) -> u64;

    /// Read a single block.
    async fn read_block<T: AsMut<IoBuf> + Unpin>(&self, block_no: u64, block: T)
    -> (T, Result<()>);

    /// Read `blocks.len()` consecutive blocks starting at `first_block_no`,
    /// scattered into the provided buffers. Devices that support it (virtio)
    /// issue ONE request for the whole run; this default reads block by
    /// block. On error, all buffers are still returned (their contents
    /// unspecified).
    async fn read_blocks<T: AsMut<IoBuf> + Unpin>(
        &self,
        first_block_no: u64,
        blocks: Vec<T>,
    ) -> (Vec<T>, Result<()>) {
        let mut result = Ok(());
        let mut done = Vec::with_capacity(blocks.len());
        for (idx, block) in blocks.into_iter().enumerate() {
            if result.is_ok() {
                let (block, res) = self.read_block(first_block_no + idx as u64, block).await;
                done.push(block);
                result = res;
            } else {
                done.push(block);
            }
        }
        (done, result)
    }
    async fn write_block<T: AsRef<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>);

    /// Write `blocks.len()` consecutive blocks starting at `first_block_no`,
    /// returning a completion future to await. Devices that support it
    /// (virtio) issue ONE scatter-gather request for the whole run.
    async fn write_blocks_with_completion(
        &self,
        first_block_no: u64,
        blocks: Vec<CheckpointedBlock>,
    ) -> Result<Self::Completion>;

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&self) -> Result<()>;
}
