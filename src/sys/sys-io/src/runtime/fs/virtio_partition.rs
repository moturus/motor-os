use async_fs::{AsyncBlockDevice, Block};
use async_trait::async_trait;
use moto_virtio::BLOCK_SIZE as VIRTIO_BLOCK_SIZE;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

const FS_BLOCK_SIZE: usize = 4096;
const VIRTIO_BLOCKS_IN_FS_BLOCK: usize = FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE; // 8

pub(super) struct VirtioPartition {
    virtio_bd: Rc<virtio_async::BlockDevice>,

    // This partition starts at `virtio_block_offset` and contains `virtio_blocks`.
    virtio_block_offset: u64,
    virtio_blocks: u64,
}

impl VirtioPartition {
    pub async fn from_virtio_bd(
        virtio_bd: Rc<virtio_async::BlockDevice>,
        virtio_block_offset: u64,
        virtio_blocks: u64,
    ) -> Result<Self> {
        // Virtio blocks/sectors are 512 bytes; everywhere else across Motor OS
        // block size is 4k, so we validate that the virtio partition was formatted properly.
        if virtio_blocks & 7 != 0 {
            log::error!(
                "A VirtIO block device partition has {virtio_blocks} sectors, which is not a multiple of 8."
            );
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(Self {
            virtio_bd,
            virtio_block_offset,
            virtio_blocks,
        })
    }
}

pub struct WrapperCompletion {
    inner: virtio_async::WriteCompletion<async_fs::block_cache::CheckpointedBlock>,
}

impl Future for WrapperCompletion {
    type Output = (async_fs::block_cache::CheckpointedBlock, Result<()>);

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // SAFETY: We are manually projecting the Pin.
        let pinned = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        match pinned.poll(cx) {
            std::task::Poll::Ready((block, res)) => std::task::Poll::Ready((
                block,
                res.map(|_sz| {
                    // Cloud Hypervisor returns 4096, Qemu returns 1.
                    // "1" is correct: the device wrote a single byte of status.
                    #[cfg(debug_assertions)]
                    if _sz != 4096 && _sz != 1 {
                        panic!("Unexpected read block sz: {_sz}.");
                    }
                    ()
                }),
            )),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[async_trait(?Send)]
impl async_fs::AsyncBlockDevice for VirtioPartition {
    type Completion = WrapperCompletion;

    fn num_blocks(&self) -> u64 {
        self.virtio_blocks >> 3
    }

    /// Read a single 4k block.
    async fn read_block(&self, block_no: u64, block: &mut Block) -> Result<()> {
        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;
        let completion = virtio_async::BlockDevice::post_read(
            self.virtio_bd.clone(),
            first_sector_no,
            block.as_bytes_mut(),
        )
        .await;
        completion.await.1.map(|_sz| {
            // Cloud Hypervisor returns 4096, Qemu returns 4097.
            // "4097" is correct: the device wrote 4096 + 1 byte status.
            #[cfg(debug_assertions)]
            if _sz != 4096 && _sz != 4097 {
                panic!("Unexpected read block sz: {_sz}.");
            }
            ()
        })
    }

    /// Write a single block.
    async fn write_block(&self, block_no: u64, block: &[u8]) -> Result<()> {
        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;

        virtio_async::BlockDevice::post_write(self.virtio_bd.clone(), first_sector_no, block)
            .await
            .await;

        Ok(())
    }

    async fn write_block_with_completion(
        &self,
        block_no: u64,
        block: async_fs::block_cache::CheckpointedBlock,
    ) -> Result<Self::Completion> {
        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;

        Ok(WrapperCompletion {
            inner: virtio_async::BlockDevice::post_write(
                self.virtio_bd.clone(),
                first_sector_no,
                block,
            )
            .await,
        })
    }

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&self) -> Result<()> {
        virtio_async::BlockDevice::post_flush(self.virtio_bd.clone()).await
    }

    fn notify(&self) {
        self.virtio_bd.notify();
    }
}
