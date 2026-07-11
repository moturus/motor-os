use super::stats;
use async_fs::{AsyncBlockDevice, Block};
use async_trait::async_trait;
use moto_tooling::iobuf::IoBuf;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

const VIRTIO_BLOCK_SIZE: usize = 512;
const FS_BLOCK_SIZE: usize = 4096;
const VIRTIO_BLOCKS_IN_FS_BLOCK: usize = FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE; // 8

pub(super) struct VirtioPartition {
    virtio_bd: Rc<virtio_async::BlockDevice>,

    // This partition starts at `virtio_block_offset` and contains `virtio_blocks`.
    virtio_block_offset: u64,
    virtio_blocks: u64,

    fs_stats: Rc<stats::FsStats>,
}

impl VirtioPartition {
    pub async fn from_virtio_bd(
        virtio_bd: Rc<virtio_async::BlockDevice>,
        virtio_block_offset: u64,
        virtio_blocks: u64,
        fs_stats: Rc<stats::FsStats>,
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
            fs_stats,
        })
    }
}

pub struct WrapperCompletion {
    inner: virtio_async::WriteCompletion<Vec<async_fs::block_cache::CheckpointedBlock>>,
}

impl Future for WrapperCompletion {
    type Output = (Vec<async_fs::block_cache::CheckpointedBlock>, Result<()>);

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // SAFETY: We are manually projecting the Pin.
        let pinned = unsafe { self.map_unchecked_mut(|s| &mut s.inner) };
        pinned.poll(cx)
    }
}

#[async_trait(?Send)]
impl async_fs::AsyncBlockDevice for VirtioPartition {
    type Completion = WrapperCompletion;

    fn num_blocks(&self) -> u64 {
        self.virtio_blocks >> 3
    }

    /// Read a single 4k block.
    async fn read_block<T: AsMut<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>) {
        let started = stats::now_ticks();
        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;
        let completion =
            virtio_async::BlockDevice::post_read(self.virtio_bd.clone(), first_sector_no, block)
                .await;
        let result = completion.await;

        let fs_stats = &self.fs_stats;
        fs_stats.device_reads.set(fs_stats.device_reads.get() + 1);
        fs_stats
            .device_read_blocks
            .set(fs_stats.device_read_blocks.get() + 1);
        if stats::TIMINGS {
            let elapsed = stats::now_ticks().wrapping_sub(started);
            fs_stats
                .device_read_ticks
                .set(fs_stats.device_read_ticks.get() + elapsed);
        }
        result
    }

    /// Read `blocks.len()` consecutive 4k blocks with one scatter-gather
    /// virtio request: one queue notification (a VM exit) and one completion
    /// interrupt for the whole run.
    async fn read_blocks<T: AsMut<IoBuf> + Unpin>(
        &self,
        first_block_no: u64,
        blocks: Vec<T>,
    ) -> (Vec<T>, Result<()>) {
        let started = stats::now_ticks();
        let first_sector_no =
            first_block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;
        let num_blocks = blocks.len() as u64;
        let completion = virtio_async::BlockDevice::post_read_many(
            self.virtio_bd.clone(),
            first_sector_no,
            blocks,
        )
        .await;
        let result = completion.await;

        let fs_stats = &self.fs_stats;
        fs_stats.device_reads.set(fs_stats.device_reads.get() + 1);
        fs_stats
            .device_read_blocks
            .set(fs_stats.device_read_blocks.get() + num_blocks);
        if stats::TIMINGS {
            let elapsed = stats::now_ticks().wrapping_sub(started);
            fs_stats
                .device_read_ticks
                .set(fs_stats.device_read_ticks.get() + elapsed);
        }
        result
    }

    /// Write a single block.
    async fn write_block<T: AsRef<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>) {
        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;

        let fs_stats = &self.fs_stats;
        fs_stats.device_writes.set(fs_stats.device_writes.get() + 1);
        virtio_async::BlockDevice::post_write(self.virtio_bd.clone(), first_sector_no, block)
            .await
            .await
    }

    /// Write `blocks.len()` consecutive 4k blocks with one scatter-gather
    /// virtio request; see `read_blocks`.
    async fn write_blocks_with_completion(
        &self,
        first_block_no: u64,
        blocks: Vec<async_fs::block_cache::CheckpointedBlock>,
    ) -> Result<Self::Completion> {
        let fs_stats = &self.fs_stats;
        fs_stats.device_writes.set(fs_stats.device_writes.get() + 1);
        fs_stats
            .device_write_blocks
            .set(fs_stats.device_write_blocks.get() + blocks.len() as u64);
        let first_sector_no =
            first_block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;

        Ok(WrapperCompletion {
            inner: virtio_async::BlockDevice::post_write_many(
                self.virtio_bd.clone(),
                first_sector_no,
                blocks,
            )
            .await,
        })
    }

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&self) -> Result<()> {
        virtio_async::BlockDevice::post_flush(self.virtio_bd.clone()).await
    }
}
