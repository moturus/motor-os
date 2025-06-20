//! Block cache for async block devices.

use crate::{AsyncBlockDevice, Block};
use lru::LruCache;
use std::io::Result;
use std::num::NonZero;

#[derive(Clone)]
pub struct CachedBlock {
    block: Box<Block>,
    block_no: u64,
    dirty: bool,
}

impl Drop for CachedBlock {
    fn drop(&mut self) {
        assert!(
            !self.dirty,
            "Block {} is dirty when dropped.",
            self.block_no
        );
    }
}

impl CachedBlock {
    fn new_empty(block_no: u64) -> Self {
        Self {
            block: Box::new(Block::new_zeroed()),
            block_no,
            dirty: false,
        }
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn block_mut(&mut self) -> &mut Block {
        self.dirty = true;
        &mut self.block
    }

    fn mark_clean(&mut self) {
        assert!(self.dirty);
        self.dirty = false;
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
        let mut block_0 = CachedBlock::new_empty(0);
        block_dev.read_block(0, &mut block_0.block).await?;

        let mut block_1 = CachedBlock::new_empty(1);
        block_dev.read_block(1, &mut block_1.block).await?;

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

        self.internal_read_uncached_block(block_no).await
    }

    pub fn get_empty_block(&mut self, block_no: u64) -> &mut CachedBlock {
        let block = self.internal_get_empty_block(block_no);
        self.internal_push_block(block)
    }

    async fn internal_read_uncached_block(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        let mut block = self.internal_get_empty_block(block_no);

        self.block_dev
            .read_block(block_no, &mut block.block)
            .await?;

        Ok(self.internal_push_block(block))
    }

    fn internal_get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        if let Some(mut block) = self.free_blocks.pop() {
            block.block.clear();
            assert!(!block.dirty);
            block.block_no = block_no;
            block
        } else {
            CachedBlock::new_empty(block_no)
        }
    }

    fn internal_push_block(&mut self, block: CachedBlock) -> &mut CachedBlock {
        let block_no = block.block_no;

        if let Some((_, prev)) = self.cache.push(block_no, block) {
            assert!(!prev.dirty, "Block {} is dirty.", prev.block_no);
            self.free_blocks.push(prev);
        }

        self.cache.get_mut(&block_no).unwrap()
    }

    pub async fn write_block(&mut self, block_no: u64) -> Result<()> {
        let block = if block_no == 0 {
            &mut self.block_0
        } else if block_no == 1 {
            &mut self.block_1
        } else {
            self.cache.get_mut(&block_no).expect("block not found")
        };

        self.block_dev.write_block(block_no, block.block()).await?;
        block.mark_clean();
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        // #[cfg(debug_assertions)]
        {
            assert!(!self.block_0.dirty);
            assert!(!self.block_1.dirty);
            for (block_no, block) in self.cache.iter() {
                assert!(!block.dirty, "Block {block_no} is dirty.");
            }
        }

        self.block_dev.flush().await
    }

    pub fn device(&mut self) -> &mut Dev {
        &mut self.block_dev
    }
}
