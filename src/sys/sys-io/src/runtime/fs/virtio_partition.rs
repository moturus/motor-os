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

/// Joins the write completions of the requests a block run was split into
/// (one per `seg_max` blocks; a single one on devices with a reasonable
/// `seg_max`). Resolves when all resolve, with the first error, if any.
pub struct WrapperCompletion {
    inner: std::collections::VecDeque<
        virtio_async::WriteCompletion<Vec<async_fs::block_cache::CheckpointedBlock>>,
    >,
    done: Vec<async_fs::block_cache::CheckpointedBlock>,
    result: Result<()>,
}

impl Future for WrapperCompletion {
    type Output = (Vec<async_fs::block_cache::CheckpointedBlock>, Result<()>);

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = &mut *self;
        while let Some(front) = this.inner.front_mut() {
            match std::pin::Pin::new(front).poll(cx) {
                std::task::Poll::Ready((blocks, result)) => {
                    this.done.extend(blocks);
                    if this.result.is_ok() {
                        this.result = result;
                    }
                    this.inner.pop_front();
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }

        std::task::Poll::Ready((
            core::mem::take(&mut this.done),
            core::mem::replace(&mut this.result, Ok(())),
        ))
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

    /// Read `blocks.len()` consecutive 4k blocks with scatter-gather virtio
    /// requests of up to `seg_max` blocks each — normally a single request
    /// for the whole run: one queue notification (a VM exit) and one
    /// completion interrupt. All requests are posted before any is awaited.
    async fn read_blocks<T: AsMut<IoBuf> + Unpin>(
        &self,
        first_block_no: u64,
        blocks: Vec<T>,
    ) -> (Vec<T>, Result<()>) {
        let started = stats::now_ticks();
        let mut first_sector_no =
            first_block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;
        let num_blocks = blocks.len() as u64;
        let seg_max = self.virtio_bd.seg_max();

        let mut completions = Vec::with_capacity((blocks.len()).div_ceil(seg_max));
        let mut blocks_iter = blocks.into_iter();
        loop {
            let chunk: Vec<T> = blocks_iter.by_ref().take(seg_max).collect();
            if chunk.is_empty() {
                break;
            }
            let chunk_sectors = (chunk.len() * VIRTIO_BLOCKS_IN_FS_BLOCK) as u64;
            completions.push(
                virtio_async::BlockDevice::post_read_many(
                    self.virtio_bd.clone(),
                    first_sector_no,
                    chunk,
                )
                .await,
            );
            first_sector_no += chunk_sectors;
        }

        let num_requests = completions.len() as u64;
        let mut blocks = Vec::with_capacity(num_blocks as usize);
        let mut result = Ok(());
        for completion in completions {
            let (chunk, chunk_result) = completion.await;
            blocks.extend(chunk);
            if result.is_ok() {
                result = chunk_result;
            }
        }

        let fs_stats = &self.fs_stats;
        fs_stats
            .device_reads
            .set(fs_stats.device_reads.get() + num_requests);
        fs_stats
            .device_read_blocks
            .set(fs_stats.device_read_blocks.get() + num_blocks);
        if stats::TIMINGS {
            let elapsed = stats::now_ticks().wrapping_sub(started);
            fs_stats
                .device_read_ticks
                .set(fs_stats.device_read_ticks.get() + elapsed);
        }
        (blocks, result)
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

    /// Write `blocks.len()` consecutive 4k blocks with scatter-gather virtio
    /// requests of up to `seg_max` blocks each — normally a single request
    /// for the whole run; see `read_blocks`. All requests are posted before
    /// the joined completion is returned.
    async fn write_blocks_with_completion(
        &self,
        first_block_no: u64,
        blocks: Vec<async_fs::block_cache::CheckpointedBlock>,
    ) -> Result<Self::Completion> {
        let num_blocks = blocks.len() as u64;
        let seg_max = self.virtio_bd.seg_max();
        let mut first_sector_no =
            first_block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;

        let mut inner = std::collections::VecDeque::with_capacity(blocks.len().div_ceil(seg_max));
        let mut blocks_iter = blocks.into_iter();
        loop {
            let chunk: Vec<async_fs::block_cache::CheckpointedBlock> =
                blocks_iter.by_ref().take(seg_max).collect();
            if chunk.is_empty() {
                break;
            }
            let chunk_sectors = (chunk.len() * VIRTIO_BLOCKS_IN_FS_BLOCK) as u64;
            inner.push_back(
                virtio_async::BlockDevice::post_write_many(
                    self.virtio_bd.clone(),
                    first_sector_no,
                    chunk,
                )
                .await,
            );
            first_sector_no += chunk_sectors;
        }

        let fs_stats = &self.fs_stats;
        fs_stats
            .device_writes
            .set(fs_stats.device_writes.get() + inner.len() as u64);
        fs_stats
            .device_write_blocks
            .set(fs_stats.device_write_blocks.get() + num_blocks);

        Ok(WrapperCompletion {
            inner,
            done: Vec::new(),
            result: Ok(()),
        })
    }

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&self) -> Result<()> {
        virtio_async::BlockDevice::post_flush(self.virtio_bd.clone()).await
    }
}
