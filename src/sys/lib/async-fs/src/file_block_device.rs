use crate::AsyncBlockDevice;
use crate::BLOCK_SIZE;
use crate::Block;
use async_trait::async_trait;
use camino::Utf8Path;
use std::io::ErrorKind;
use std::io::Result;

pub struct AsyncFileBlockDevice {
    file: std::cell::RefCell<tokio::fs::File>,
    num_blocks: u64,
}

impl AsyncFileBlockDevice {
    pub async fn open(path: &Utf8Path) -> Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .await?;

        let len = file.metadata().await?.len();
        if len & ((BLOCK_SIZE as u64) - 1) != 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }

        Ok(Self {
            file: std::cell::RefCell::new(file),
            num_blocks: len >> BLOCK_SIZE.ilog2(),
        })
    }

    pub async fn create(path: &Utf8Path, num_blocks: u64) -> std::io::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .await?;

        file.set_len(num_blocks << BLOCK_SIZE.ilog2()).await?;

        Ok(Self {
            file: std::cell::RefCell::new(file),
            num_blocks,
        })
    }
}

#[async_trait(?Send)]
impl AsyncBlockDevice for AsyncFileBlockDevice {
    type Completion = core::future::Ready<Result<()>>;

    fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    async fn read_block(&self, block_no: u64, block: &mut Block) -> Result<()> {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncSeekExt;

        if block_no >= self.num_blocks {
            log::debug!("Block number {block_no} out of range.");
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut file = self.file.borrow_mut();
        file.seek(std::io::SeekFrom::Start(block_no * (BLOCK_SIZE as u64)))
            .await?;

        file.read_exact(block.as_bytes_mut()).await.map(|_| {})
    }

    async fn write_block(&self, block_no: u64, block: &Block) -> Result<()> {
        use tokio::io::AsyncSeekExt;
        use tokio::io::AsyncWriteExt;

        if block_no >= self.num_blocks {
            log::debug!("Block number {block_no} out of range.");
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut file = self.file.borrow_mut();
        file.seek(std::io::SeekFrom::Start(block_no * (BLOCK_SIZE as u64)))
            .await?;

        file.write_all(block.as_bytes()).await
    }

    async fn write_block_with_completion(
        &self,
        block_no: u64,
        block: crate::block_cache::FlushingBlock,
    ) -> Result<Self::Completion> {
        self.write_block(block_no, block.block()).await?;
        Ok(core::future::ready(Ok(())))
    }

    async fn flush(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.file.borrow_mut().flush().await
    }

    fn notify(&self) {}
}
