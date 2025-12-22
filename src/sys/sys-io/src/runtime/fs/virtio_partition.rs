use async_fs::Block;
use async_trait::async_trait;
use moto_virtio::BLOCK_SIZE as VIRTIO_BLOCK_SIZE;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

const FS_BLOCK_SIZE: usize = 4096;
const VIRTIO_BLOCKS_IN_FS_BLOCK: usize = FS_BLOCK_SIZE / VIRTIO_BLOCK_SIZE; // 8

pub(super) struct VirtioPartition {
    virtio_bd: Rc<RefCell<virtio_async::BlockDevice>>,

    // This partition starts at `virtio_block_offset` and contains `virtio_blocks`.
    virtio_block_offset: u64,
    virtio_blocks: u64,
}

impl VirtioPartition {
    pub fn from_virtio_bd(
        virtio_bd: Rc<RefCell<virtio_async::BlockDevice>>,
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

#[async_trait(?Send)]
impl async_fs::AsyncBlockDevice for VirtioPartition {
    fn num_blocks(&self) -> u64 {
        self.virtio_blocks >> 3
    }

    /// Read a single 4k block.
    async fn read_block(&mut self, block_no: u64, block: &mut Block) -> Result<()> {
        use zerocopy::FromZeros;

        log::debug!("read_block {block_no}");

        // TODO: read in one go, instead of eight.
        let mut virtio_block = virtio_async::VirtioBlock::new_zeroed();

        let first_sector_no =
            block_no * (VIRTIO_BLOCKS_IN_FS_BLOCK as u64) + self.virtio_block_offset;
        for idx in 0..VIRTIO_BLOCKS_IN_FS_BLOCK {
            let completion = virtio_async::BlockDevice::post_read(
                self.virtio_bd.clone(),
                first_sector_no + (idx as u64),
                virtio_block.as_mut(),
            )
            .unwrap();
            completion.await;

            let block_offset = idx * VIRTIO_BLOCK_SIZE;
            block.as_bytes_mut()[block_offset..block_offset + VIRTIO_BLOCK_SIZE]
                .clone_from_slice(virtio_block.bytes.as_slice());
        }

        Ok(())
    }

    /// Write a single block.
    async fn write_block(&mut self, block_no: u64, block: &Block) -> Result<()> {
        todo!()
    }

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&mut self) -> Result<()> {
        todo!()
    }
}
