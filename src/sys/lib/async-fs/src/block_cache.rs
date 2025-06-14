//! Block cache for async block devices.

use crate::{AsyncBlockDevice, Block};
use lru::LruCache;
use std::io::Result;
use std::num::NonZero;

#[derive(Clone)]
pub struct CachedBlock {
    block: Box<Block>,
}

impl Default for CachedBlock {
    fn default() -> Self {
        Self {
            block: Box::new(Block::new_zeroed()),
        }
    }
}

impl CachedBlock {
    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn block_mut(&mut self) -> &mut Block {
        &mut self.block
    }
}

pub struct BlockCache<Dev: AsyncBlockDevice> {
    block_dev: Dev,

    cache: LruCache<u64, CachedBlock>,

    // We always keep the first two blocks cached.
    block_0: CachedBlock,
    block_1: CachedBlock,

    free_blocks: Vec<CachedBlock>,
}

impl<Dev: AsyncBlockDevice> BlockCache<Dev> {
    pub async fn new(mut block_dev: Dev, max_len: usize) -> Result<Self> {
        let mut block_0 = CachedBlock::default();
        block_dev.read_block(0, block_0.block_mut()).await?;

        let mut block_1 = CachedBlock::default();
        block_dev.read_block(1, block_1.block_mut()).await?;

        Ok(Self {
            cache: LruCache::new(NonZero::new(max_len).unwrap()),
            block_dev,
            block_0,
            block_1,
            free_blocks: Vec::new(),
        })
    }

    pub async fn get_block(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        if block_no == 0 {
            return Ok(&mut self.block_0);
        } else if block_no == 1 {
            return Ok(&mut self.block_1);
        }

        {
            // Unfortunately, the code below leads to a borrow checker error, even in 2024:
            //
            // if let Some(block) = self.cache.get_mut(&block_no) {
            //     return Ok(block);
            // }
            //
            // So we have to use the ugly workaround with contains + get_mut.
            //
            // TODO: fix this.
            if self.cache.contains(&block_no) {
                return Ok(self.cache.get_mut(&block_no).unwrap());
            }
        }

        self.get_new_block(block_no).await
    }

    pub fn get_empty_block(&mut self, block_no: u64) -> &mut CachedBlock {
        let block = if let Some(mut block) = self.free_blocks.pop() {
            block.block.clear();
            block
        } else {
            CachedBlock::default()
        };

        if let Some((_, prev)) = self.cache.push(block_no, block) {
            self.free_blocks.push(prev);
        }

        self.cache.get_mut(&block_no).unwrap()
    }

    pub async fn write_block(&mut self, block_no: u64) -> Result<()> {
        let block = if block_no == 0 {
            &self.block_0
        } else if block_no == 1 {
            &self.block_1
        } else {
            self.cache.get(&block_no).expect("block not found")
        };

        self.block_dev.write_block(block_no, block.block()).await
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.block_dev.flush().await
    }

    async fn get_new_block(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        let mut block = if let Some(mut block) = self.free_blocks.pop() {
            block.block.clear();
            block
        } else {
            CachedBlock::default()
        };

        self.block_dev
            .read_block(block_no, &mut block.block)
            .await?;

        if let Some((_, prev)) = self.cache.push(block_no, block) {
            self.free_blocks.push(prev);
        }

        Ok(self.cache.get_mut(&block_no).unwrap())
    }
}
