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

        /*
        {
            const MEGS: u64 = 32;
            const NUM_BLOCKS: u64 = 1024 * 1024 * MEGS / 4096;
            const BATCH_SIZE: u64 = 64;

            let mut comps = Vec::with_capacity(BATCH_SIZE as usize);

            // Note: if block is allocated only once (outside the loop), write throughput
            //       on HP OmniBook 7 Aero is up to 1900 MB/sec;
            //       if the block is allocated on each loop iteration, the speed drops
            //       to 1200 MB/sec.
            // let block = async_fs::Block::new_zeroed();

            let started = std::time::Instant::now();
            let mut block_no = 0;
            while block_no < NUM_BLOCKS {
                for idx in 0..BATCH_SIZE {
                    let first_sector_no =
                        block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + virtio_block_offset;
                    block_no += 1;

                    let block = async_fs::Block::new_zeroed();
                    let completion = virtio_async::BlockDevice::post_write(
                        virtio_bd.clone(),
                        first_sector_no,
                        // block.as_bytes(),
                        block,
                    )
                    .await;

                    comps.push(completion);
                    if idx == 0 {
                        virtio_async::BlockDevice::notify(virtio_bd.clone());
                    }
                }

                while let Some(comp) = comps.pop() {
                    comp.await;
                }
                assert!(comps.is_empty());
            }
            let elapsed = started.elapsed();
            let write_mbps = (MEGS as f64) / elapsed.as_secs_f64();
            log::info!("virtio_partition: write speed {:.3} MB/sec", write_mbps);
            panic!()
        }
        */
        /*
        {
            const MEGS: u64 = 32;
            const NUM_BLOCKS: u64 = 1024 * 1024 * MEGS / 4096;
            const BATCH_SIZE: u64 = 64;

            // Note: if block is allocated only once (outside the loop), write throughput
            //       on HP OmniBook 7 Aero is up to 1900 MB/sec;
            //       if the block is allocated on each loop iteration, the speed drops
            //       to 1200 MB/sec.
            // let block = async_fs::Block::new_zeroed();

            let started = std::time::Instant::now();
            let mut block_no = 0;
            while block_no < NUM_BLOCKS {
                // let mut comps = Vec::with_capacity(BATCH_SIZE as usize);
                // for idx in 0..BATCH_SIZE {
                let first_sector_no =
                    block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + virtio_block_offset;
                block_no += 1;

                let block = async_fs::Block::new_zeroed();
                let completion = virtio_async::BlockDevice::post_write(
                    virtio_bd.clone(),
                    first_sector_no,
                    // block.as_bytes(),
                    block,
                )
                .await;

                // moto_async::LocalRuntime::spawn(async move {
                completion.await;
                // });

                // comps.push(completion);
                // if idx == 0 {
                //     virtio_async::BlockDevice::notify(virtio_bd.clone());
                // }
                // }

                // moto_async::LocalRuntime::spawn(async move {
                // while let Some(comp) = comps.pop() {
                //     comp.await;
                // }
                // });
            }
            let elapsed = started.elapsed();
            let write_mbps = (MEGS as f64) / elapsed.as_secs_f64();
            log::info!("virtio_partition: write speed {:.3} MB/sec", write_mbps);
            panic!()
        }
        */

        Ok(Self {
            virtio_bd,
            virtio_block_offset,
            virtio_blocks,
        })
    }
}

#[async_trait(?Send)]
impl async_fs::AsyncBlockDevice for VirtioPartition {
    type Completion = virtio_async::WriteCompletion<async_fs::block_cache::FlushingBlock>;

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
        completion.await?;

        Ok(())
    }

    /// Write a single block.
    async fn write_block(&self, block_no: u64, block: &Block) -> Result<()> {
        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;

        virtio_async::BlockDevice::post_write(
            self.virtio_bd.clone(),
            first_sector_no,
            block.as_bytes(),
        )
        .await
        .await;

        Ok(())
    }

    async fn write_block_with_completion(
        &self,
        block_no: u64,
        block: async_fs::block_cache::FlushingBlock,
    ) -> Result<Self::Completion> {
        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;

        Ok(
            virtio_async::BlockDevice::post_write(self.virtio_bd.clone(), first_sector_no, block)
                .await,
        )
    }

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&self) -> Result<()> {
        virtio_async::BlockDevice::post_flush(self.virtio_bd.clone()).await
    }

    fn notify(&self) {
        self.virtio_bd.notify();
    }
}
