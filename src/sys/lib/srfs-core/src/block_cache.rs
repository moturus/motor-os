use async_fs::Block;
use lru::LruCache;

use crate::*;

const CACHE_SIZE: usize = 128;

#[derive(Clone)]
pub(crate) struct CachedBlock {
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
    pub(crate) fn block(&self) -> &Block {
        &self.block
    }

    pub(crate) fn block_mut(&mut self) -> &mut Block {
        &mut self.block
    }
}

pub(crate) struct BlockCache {
    cache: LruCache<u64, CachedBlock>,
    block_device: Box<dyn SyncBlockDevice>,
    // We cache the superblock and the root block.
    block_0: CachedBlock,
    block_1: CachedBlock,
    free_blocks: Vec<CachedBlock>,
}

impl BlockCache {
    pub(crate) fn new(mut block_device: Box<dyn SyncBlockDevice>) -> Self {
        let mut block_0 = CachedBlock::default();
        block_device
            .read_block(0, block_0.block.as_bytes_mut())
            .unwrap();

        let mut block_1 = CachedBlock::default();
        block_device
            .read_block(1, block_1.block.as_bytes_mut())
            .unwrap();

        Self {
            cache: LruCache::new(std::num::NonZero::new(CACHE_SIZE).unwrap()),
            block_device,
            block_0,
            block_1,
            free_blocks: Vec::new(),
        }
    }

    pub(crate) fn read(&mut self, block_no: u64) -> Result<&CachedBlock> {
        self.read_mut(block_no).map(|e| &*e)
    }

    pub(crate) fn read_mut(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        if block_no == 0 {
            return Ok(&mut self.block_0);
        } else if block_no == 1 {
            return Ok(&mut self.block_1);
        }

        {
            if self.cache.contains(&block_no) {
                return Ok(self.cache.get_mut(&block_no).unwrap());
            }
        }

        self.read_new_block(block_no)
    }

    fn read_new_block(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        let mut block = if let Some(block) = self.free_blocks.pop() {
            block
        } else {
            CachedBlock::default()
        };

        self.block_device
            .read_block(block_no, block.block.as_bytes_mut())?;

        if let Some((_, prev)) = self.cache.push(block_no, block) {
            self.free_blocks.push(prev);
        }

        Ok(self.cache.get_mut(&block_no).unwrap())
    }

    pub(crate) fn get(&mut self, block_no: u64) -> &CachedBlock {
        if block_no == 0 {
            return &self.block_0;
        } else if block_no == 1 {
            return &self.block_1;
        }

        self.cache.get(&block_no).unwrap()
    }

    pub(crate) fn get_mut(&mut self, block_no: u64) -> &mut CachedBlock {
        if block_no == 0 {
            return &mut self.block_0;
        } else if block_no == 1 {
            return &mut self.block_1;
        }

        self.cache.get_mut(&block_no).unwrap()
    }

    pub(crate) fn get_block_uninit(&mut self, block_no: u64) -> &mut CachedBlock {
        assert_ne!(block_no, 0);
        assert_ne!(block_no, 1);

        {
            if self.cache.contains(&block_no) {
                return self.cache.get_mut(&block_no).unwrap();
            }
        }

        self.get_new_block(block_no)
    }

    fn get_new_block(&mut self, block_no: u64) -> &mut CachedBlock {
        let block = if let Some(block) = self.free_blocks.pop() {
            block
        } else {
            CachedBlock::default()
        };

        if let Some((_, prev)) = self.cache.push(block_no, block) {
            self.free_blocks.push(prev);
        }

        self.cache.get_mut(&block_no).unwrap()
    }

    pub(crate) fn write(&mut self, block_no: u64) -> Result<()> {
        if block_no == 0 {
            self.block_device
                .write_block(0, self.block_0.block.as_bytes())?;
            return Ok(());
        } else if block_no == 1 {
            self.block_device
                .write_block(1, self.block_1.block.as_bytes())?;
            return Ok(());
        }

        let Some(block) = self.cache.get_mut(&block_no) else {
            panic!("block not found")
        };

        self.block_device
            .write_block(block_no, block.block.as_bytes())
    }
}
