use super::block_io::{self, Message, Reply};
use async_fs::block_cache::CheckpointedBlock;
use async_trait::async_trait;
use moto_async::channel;
use moto_tooling::iobuf::IoBuf;
use std::io::{ErrorKind, Result};

const FS_BLOCK_SIZE: usize = 4096;
const VIRTIO_BLOCKS_IN_FS_BLOCK: u64 = 8;

pub(super) struct VirtioPartition {
    inbox: channel::Sender<Message>,
    flush_supported: bool,

    // This partition starts at `virtio_block_offset` and contains `virtio_blocks`.
    virtio_block_offset: u64,
    virtio_blocks: u64,
}

impl VirtioPartition {
    pub async fn from_virtio_bd(
        inbox: channel::Sender<Message>,
        flush_supported: bool,
        virtio_block_offset: u64,
        virtio_blocks: u64,
    ) -> Result<Self> {
        // Virtio sectors are 512 bytes; filesystem blocks are 4K.
        if virtio_blocks & 7 != 0 {
            log::error!(
                "A VirtIO block device partition has {virtio_blocks} sectors, which is not a multiple of 8."
            );
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(Self {
            inbox,
            flush_supported,
            virtio_block_offset,
            virtio_blocks,
        })
    }

    fn first_sector(&self, block_no: u64) -> u64 {
        block_no * VIRTIO_BLOCKS_IN_FS_BLOCK + self.virtio_block_offset
    }
}

#[async_trait(?Send)]
impl async_fs::AsyncBlockDevice for VirtioPartition {
    type Completion = Reply<Vec<CheckpointedBlock>>;

    fn num_blocks(&self) -> u64 {
        self.virtio_blocks >> 3
    }

    async fn read_block<T: AsMut<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        mut block: T,
    ) -> (T, Result<()>) {
        assert_eq!(block.as_mut().len(), FS_BLOCK_SIZE);
        let pages = vec![block.as_mut().phys_addr() as u64];
        let reply = block_io::send(&self.inbox, block, |reply| Message::Read {
            first_sector: self.first_sector(block_no),
            pages,
            reply,
        })
        .await;
        let (mut block, result) = match reply {
            Ok(reply) => reply.await,
            Err((block, error)) => return (block, Err(error)),
        };
        if result.is_ok() {
            block.as_mut().set_len(FS_BLOCK_SIZE);
        }
        (block, result)
    }

    async fn read_blocks<T: AsMut<IoBuf> + Unpin>(
        &self,
        first_block_no: u64,
        mut blocks: Vec<T>,
    ) -> (Vec<T>, Result<()>) {
        let pages = blocks
            .iter_mut()
            .map(|block| {
                assert_eq!(block.as_mut().len(), FS_BLOCK_SIZE);
                block.as_mut().phys_addr() as u64
            })
            .collect();
        let reply = block_io::send(&self.inbox, blocks, |reply| Message::Read {
            first_sector: self.first_sector(first_block_no),
            pages,
            reply,
        })
        .await;
        let (mut blocks, result) = match reply {
            Ok(reply) => reply.await,
            Err((blocks, error)) => return (blocks, Err(error)),
        };
        if result.is_ok() {
            for block in &mut blocks {
                block.as_mut().set_len(FS_BLOCK_SIZE);
            }
        }
        (blocks, result)
    }

    async fn write_block<T: AsRef<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>) {
        assert_eq!(block.as_ref().len(), FS_BLOCK_SIZE);
        let pages = vec![block.as_ref().phys_addr() as u64];
        match block_io::send(&self.inbox, block, |reply| Message::Write {
            first_sector: self.first_sector(block_no),
            pages,
            reply,
        })
        .await
        {
            Ok(reply) => reply.await,
            Err((block, error)) => (block, Err(error)),
        }
    }

    /// The caller retains only the buffers and reply, never descriptors.
    async fn write_blocks_with_completion(
        &self,
        first_block_no: u64,
        blocks: Vec<CheckpointedBlock>,
    ) -> Result<Self::Completion> {
        let pages = blocks
            .iter()
            .map(|block| {
                let buffer: &IoBuf = block.as_ref();
                assert_eq!(buffer.len(), FS_BLOCK_SIZE);
                buffer.phys_addr() as u64
            })
            .collect();
        block_io::send(&self.inbox, blocks, |reply| Message::Write {
            first_sector: self.first_sector(first_block_no),
            pages,
            reply,
        })
        .await
        .map_err(|(_, error)| error)
    }

    async fn flush(&self) -> Result<()> {
        if !self.flush_supported {
            return Err(ErrorKind::Unsupported.into());
        }
        let reply = block_io::send(&self.inbox, (), |reply| Message::Flush { reply })
            .await
            .map_err(|(_, error)| error)?;
        reply.await.1
    }
}
