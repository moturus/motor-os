use super::block_io::{self, Message, Reply};
use async_trait::async_trait;
use moto_sdk::async_fs::block_cache::CheckpointedBlock;
use moto_sdk::async_runtime::channel;
use moto_sdk::iobuf::VirtioIoBuf;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};

const FS_BLOCK_SIZE: usize = 4096;
const VIRTIO_BLOCKS_IN_FS_BLOCK: u64 = 8;

pub(super) struct VirtioPartition {
    inbox: channel::Sender<Message>,
    flush_supported: bool,

    // This partition starts at `virtio_block_offset` and contains `virtio_blocks`.
    virtio_block_offset: u64,
    virtio_blocks: u64,
    first_block: RefCell<Option<VirtioIoBuf>>,
}

impl VirtioPartition {
    pub async fn from_virtio_bd(
        inbox: channel::Sender<Message>,
        flush_supported: bool,
        virtio_block_offset: u64,
        virtio_blocks: u64,
    ) -> Result<Self> {
        // Virtio sectors are 512 bytes; filesystem blocks are 4K.
        if virtio_blocks == 0
            || virtio_blocks & 7 != 0
            || virtio_block_offset.checked_add(virtio_blocks).is_none()
        {
            log::error!(
                "Invalid VirtIO extent: offset {virtio_block_offset}, sectors {virtio_blocks}."
            );
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(Self {
            inbox,
            flush_supported,
            virtio_block_offset,
            virtio_blocks,
            first_block: RefCell::new(None),
        })
    }

    pub(super) fn seed_first_block(&mut self, block: VirtioIoBuf) {
        assert_eq!(self.virtio_block_offset, 0);
        *self.first_block.get_mut() = Some(block);
    }

    fn first_sector(&self, block_no: u64, count: usize) -> Result<u64> {
        // Validate the whole range before translating addresses or touching DMA.
        if block_no
            .checked_add(count as u64)
            .is_none_or(|end| end > self.virtio_blocks / VIRTIO_BLOCKS_IN_FS_BLOCK)
        {
            return Err(ErrorKind::InvalidInput.into());
        }
        Ok(block_no * VIRTIO_BLOCKS_IN_FS_BLOCK + self.virtio_block_offset)
    }
}

#[async_trait(?Send)]
impl moto_sdk::async_fs::AsyncBlockDevice for VirtioPartition {
    type Completion = Reply<Vec<CheckpointedBlock>>;

    fn num_blocks(&self) -> u64 {
        self.virtio_blocks >> 3
    }

    async fn read_block<T: AsMut<VirtioIoBuf> + Unpin>(
        &self,
        block_no: u64,
        mut block: T,
    ) -> (T, Result<()>) {
        let first_sector = match self.first_sector(block_no, 1) {
            Ok(sector) => sector,
            Err(error) => return (block, Err(error)),
        };
        assert_eq!(block.as_mut().len(), FS_BLOCK_SIZE);
        if block_no == 0
            && let Some(first) = self.first_block.borrow_mut().take()
        {
            AsMut::<[u8]>::as_mut(block.as_mut()).copy_from_slice(AsRef::<[u8]>::as_ref(&first));
            return (block, Ok(()));
        }
        let pages = vec![block.as_mut().phys_addr() as u64];
        let reply = block_io::send(&self.inbox, block, |reply| Message::Read {
            first_sector,
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

    async fn read_blocks<T: AsMut<VirtioIoBuf> + Unpin>(
        &self,
        first_block_no: u64,
        mut blocks: Vec<T>,
    ) -> (Vec<T>, Result<()>) {
        let first_sector = match self.first_sector(first_block_no, blocks.len()) {
            Ok(sector) => sector,
            Err(error) => return (blocks, Err(error)),
        };
        let pages = blocks
            .iter_mut()
            .map(|block| {
                assert_eq!(block.as_mut().len(), FS_BLOCK_SIZE);
                block.as_mut().phys_addr() as u64
            })
            .collect();
        let reply = block_io::send(&self.inbox, blocks, |reply| Message::Read {
            first_sector,
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

    async fn write_block<T: AsRef<VirtioIoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>) {
        let first_sector = match self.first_sector(block_no, 1) {
            Ok(sector) => sector,
            Err(error) => return (block, Err(error)),
        };
        if block_no == 0 {
            self.first_block.borrow_mut().take();
        }
        assert_eq!(block.as_ref().len(), FS_BLOCK_SIZE);
        let pages = vec![block.as_ref().phys_addr() as u64];
        match block_io::send(&self.inbox, block, |reply| Message::Write {
            first_sector,
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
        let first_sector = self.first_sector(first_block_no, blocks.len())?;
        if first_block_no == 0 && !blocks.is_empty() {
            self.first_block.borrow_mut().take();
        }
        let pages = blocks
            .iter()
            .map(|block| {
                let buffer: &VirtioIoBuf = block.as_ref();
                assert_eq!(buffer.len(), FS_BLOCK_SIZE);
                buffer.phys_addr() as u64
            })
            .collect();
        block_io::send(&self.inbox, blocks, |reply| Message::Write {
            first_sector,
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

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};
    use moto_sdk::async_fs::AsyncBlockDevice;

    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] =
        &[("fs::partition_bounds", run)];

    fn run() -> std::result::Result<(), String> {
        moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
            let (sender, receiver) = channel::channel(4);
            drop(receiver);
            for (offset, sectors) in [(0, 0), (0, 7), (u64::MAX - 7, 8)] {
                st_assert!(
                    VirtioPartition::from_virtio_bd(sender.clone(), false, offset, sectors)
                        .await
                        .is_err()
                );
            }
            // Sector-aligned extents need not start at a filesystem-block boundary.
            let device = VirtioPartition::from_virtio_bd(sender, false, 5, 16)
                .await
                .unwrap();
            st_assert_eq!(device.first_sector(0, 1).unwrap(), 5);
            st_assert_eq!(device.first_sector(1, 1).unwrap(), 13);
            st_assert_eq!(device.first_sector(2, 0).unwrap(), 21);
            for (first, count) in [(2, 1), (1, 2), (u64::MAX, 0), (1, usize::MAX)] {
                st_assert_eq!(
                    device.first_sector(first, count).unwrap_err().kind(),
                    ErrorKind::InvalidInput
                );
            }
            // Invalid requests must fail before reaching the closed device inbox.
            let buffer = || VirtioIoBuf::new_from_size_align(FS_BLOCK_SIZE).unwrap();
            let (block, result) = device.read_block(2, buffer()).await;
            st_assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
            let (_, result) = device.write_block(2, block).await;
            st_assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
            let (blocks, result) = device.read_blocks(1, vec![buffer(), buffer()]).await;
            st_assert_eq!(blocks.len(), 2);
            st_assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
            st_assert!(
                device
                    .write_blocks_with_completion(u64::MAX, Vec::new())
                    .await
                    .is_err_and(|error| error.kind() == ErrorKind::InvalidInput)
            );
            let (sender, receiver) = channel::channel(4);
            drop(receiver);
            let mut whole = VirtioPartition::from_virtio_bd(sender, false, 0, 16)
                .await
                .unwrap();
            let mut header = buffer();
            AsMut::<[u8]>::as_mut(&mut header).fill(0x5a);
            whole.seed_first_block(header);
            let (block, result) = whole.read_block(0, buffer()).await;
            st_assert!(result.is_ok());
            st_assert!(
                AsRef::<[u8]>::as_ref(&block)
                    .iter()
                    .all(|byte| *byte == 0x5a)
            );
            // The probe read seeds only the first open, never later reads.
            let (_, result) = whole.read_block(0, block).await;
            st_assert_eq!(result.unwrap_err().kind(), ErrorKind::NotConnected);
            Ok(())
        })
    }
}
