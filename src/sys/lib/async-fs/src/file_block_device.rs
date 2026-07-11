use crate::AsyncBlockDevice;
use crate::BLOCK_SIZE;
use crate::block_cache::CheckpointedBlock;
use async_trait::async_trait;
use camino::Utf8Path;
use fittings::iobuf::IoBuf;
use std::io::ErrorKind;
use std::io::Result;

pub struct AsyncFileBlockDevice {
    file: tokio::sync::Mutex<tokio::fs::File>,
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
            file: tokio::sync::Mutex::new(file),
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
            file: tokio::sync::Mutex::new(file),
            num_blocks,
        })
    }
}

#[async_trait(?Send)]
impl AsyncBlockDevice for AsyncFileBlockDevice {
    type Completion = core::future::Ready<(Vec<CheckpointedBlock>, Result<()>)>;

    fn num_blocks(&self) -> u64 {
        self.num_blocks
    }

    async fn read_block<T: AsMut<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        mut block: T,
    ) -> (T, Result<()>) {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncSeekExt;

        if block_no >= self.num_blocks {
            log::debug!("Block number {block_no} out of range.");
            return (block, Err(ErrorKind::InvalidInput.into()));
        }

        let mut file = self.file.lock().await;
        if let Err(err) = file
            .seek(std::io::SeekFrom::Start(block_no * (BLOCK_SIZE as u64)))
            .await
        {
            return (block, Err(err));
        }

        let res = file
            .read_exact(AsMut::<[u8]>::as_mut(block.as_mut()))
            .await
            .map(|_| {});

        (block, res)
    }

    async fn write_block<T: AsRef<IoBuf> + Unpin>(
        &self,
        block_no: u64,
        block: T,
    ) -> (T, Result<()>) {
        use tokio::io::AsyncSeekExt;
        use tokio::io::AsyncWriteExt;

        if block_no >= self.num_blocks {
            log::debug!("Block number {block_no} out of range.");
            return (block, Err(ErrorKind::InvalidInput.into()));
        }

        let mut file = self.file.lock().await;
        let res = file
            .seek(std::io::SeekFrom::Start(block_no * (BLOCK_SIZE as u64)))
            .await;

        if let Err(err) = res {
            return (block, Err(err));
        }

        let res = file.write_all(block.as_ref().as_ref()).await;
        (block, res)
    }

    async fn write_blocks_with_completion(
        &self,
        first_block_no: u64,
        blocks: Vec<CheckpointedBlock>,
    ) -> Result<Self::Completion> {
        let mut result = Ok(());
        for (idx, block) in blocks.iter().enumerate() {
            if result.is_ok() {
                let (_, res) = self
                    .write_block(first_block_no + idx as u64, block.clone())
                    .await;
                result = res;
            }
        }
        Ok(core::future::ready((blocks, result)))
    }

    async fn flush(&self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.file.lock().await.flush().await
    }
}
