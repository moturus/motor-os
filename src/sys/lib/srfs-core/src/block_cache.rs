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
    superblock: CachedBlock, // #0
}

impl BlockCache {
    pub(crate) fn new(mut block_device: Box<dyn SyncBlockDevice>) -> Self {
        let mut superblock = CachedBlock::default();

        block_device
            .read_block(0, superblock.block.as_bytes_mut())
            .unwrap();

        Self {
            cache: LruCache::new(std::num::NonZero::new(CACHE_SIZE).unwrap()),
            block_device,
            superblock,
        }
    }

    pub(crate) fn read(&mut self, block_no: u64) -> Result<&CachedBlock> {
        self.read_mut(block_no).map(|e| &*e)
    }

    pub(crate) fn read_mut(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        if block_no == 0 {
            return Ok(&mut self.superblock);
        }

        self.cache.try_get_or_insert_mut(block_no, || {
            // Not found: read.
            let mut block = CachedBlock::default();
            self.block_device
                .read_block(block_no, block.block.as_bytes_mut())?;

            Ok(block)
        })
    }

    pub(crate) fn get(&mut self, block_no: u64) -> &CachedBlock {
        if block_no == 0 {
            return &self.superblock;
        }

        self.cache.get(&block_no).unwrap()
    }

    pub(crate) fn get_mut(&mut self, block_no: u64) -> &mut CachedBlock {
        if block_no == 0 {
            return &mut self.superblock;
        }

        self.cache.get_mut(&block_no).unwrap()
    }

    pub(crate) fn get_block_uninit(&mut self, block_no: u64) -> &mut CachedBlock {
        assert_ne!(block_no, 0);

        self.cache
            .try_get_or_insert_mut::<_, ()>(block_no, || Ok(CachedBlock::default()))
            .unwrap()
    }

    pub(crate) fn write(&mut self, block_no: u64) -> Result<()> {
        if block_no == 0 {
            self.block_device
                .write_block(0, self.superblock.block.as_bytes())?;
            return Ok(());
        }

        let Some(block) = self.cache.get_mut(&block_no) else {
            panic!("block not found")
        };

        self.block_device
            .write_block(block_no, block.block.as_bytes())
    }
}
