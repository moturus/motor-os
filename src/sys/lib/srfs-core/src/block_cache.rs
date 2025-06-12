use async_fs::Block;

use crate::*;
use core::pin::Pin;

const CACHE_SIZE: usize = 16;

pub(crate) struct CachedBlock {
    block_no: u64,
    dirty: bool,
    block: Pin<Box<Block>>,
}

impl Default for CachedBlock {
    fn default() -> Self {
        Self {
            block_no: u64::MAX,
            dirty: false,
            block: Box::pin(Block::new_zeroed()),
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
    blocks: [CachedBlock; CACHE_SIZE],
    block_device: Box<dyn SyncBlockDevice>,
    block_reads: u64,
    block_writes: u64,
    superblock: CachedBlock, // #0
}

impl BlockCache {
    pub(crate) fn new(mut block_device: Box<dyn SyncBlockDevice>) -> Self {
        let mut superblock = CachedBlock::default();

        block_device
            .read_block(0, superblock.block.as_bytes_mut())
            .unwrap();

        Self {
            blocks: Default::default(),
            block_device,
            block_reads: 0,
            block_writes: 0,
            superblock,
        }
    }

    pub(crate) fn read(&mut self, block_no: u64) -> Result<&CachedBlock> {
        if block_no == 0 {
            return Ok(&self.superblock);
        }
        for idx in 0..CACHE_SIZE {
            if self.blocks[idx].block_no == block_no {
                self.push_top(idx);
                return Ok(&self.blocks[0]);
            }
        }

        // Not found: read.
        let block = unsafe { self.blocks.last_mut().unwrap_unchecked() };
        assert!(!block.dirty);
        block.block_no = block_no;

        self.block_reads += 1;
        self.block_device
            .read_block(block_no, block.block.as_bytes_mut())?;
        self.push_top(CACHE_SIZE - 1);
        Ok(&self.blocks[0])
    }

    pub(crate) fn read_mut(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        if block_no == 0 {
            return Ok(&mut self.superblock);
        }
        for idx in 0..CACHE_SIZE {
            if self.blocks[idx].block_no == block_no {
                self.push_top(idx);
                self.blocks[0].dirty = true;
                return Ok(&mut self.blocks[0]);
            }
        }

        // Not found: read.
        let block = unsafe { self.blocks.last_mut().unwrap_unchecked() };
        assert!(!block.dirty);
        block.block_no = block_no;

        self.block_reads += 1;
        self.block_device
            .read_block(block_no, block.block.as_bytes_mut())?;
        self.push_top(CACHE_SIZE - 1);
        self.blocks[0].dirty = true;
        Ok(&mut self.blocks[0])
    }

    pub(crate) fn get(&mut self, block_no: u64) -> &CachedBlock {
        if block_no == 0 {
            return &self.superblock;
        }
        for idx in 0..CACHE_SIZE {
            if self.blocks[idx].block_no == block_no {
                self.push_top(idx);
                return &self.blocks[0];
            }
        }

        panic!("block not found")
    }

    pub(crate) fn get_mut(&mut self, block_no: u64) -> &mut CachedBlock {
        if block_no == 0 {
            return &mut self.superblock;
        }
        for idx in 0..CACHE_SIZE {
            if self.blocks[idx].block_no == block_no {
                self.push_top(idx);
                self.blocks[0].dirty = true;
                return &mut self.blocks[0];
            }
        }

        panic!("block not found")
    }

    pub(crate) fn get_block_uninit(&mut self, block_no: u64) -> &mut CachedBlock {
        assert_ne!(block_no, 0);
        let block = unsafe { self.blocks.last_mut().unwrap_unchecked() };
        block.block_no = block_no;
        assert!(!block.dirty);
        self.push_top(CACHE_SIZE - 1);
        self.blocks[0].dirty = true;
        &mut self.blocks[0]
    }

    pub(crate) fn write(&mut self, block_no: u64) -> Result<()> {
        if block_no == 0 {
            self.block_writes += 1;
            self.block_device
                .write_block(0, self.superblock.block.as_bytes())?;
            self.superblock.dirty = false;
            return Ok(());
        }
        for idx in 0..CACHE_SIZE {
            if self.blocks[idx].block_no == block_no {
                self.push_top(idx);
                debug_assert!(self.blocks[0].dirty);
                self.block_writes += 1;
                self.block_device
                    .write_block(block_no, self.blocks[0].block.as_bytes())?;
                self.blocks[0].dirty = false;
                return Ok(());
            }
        }

        panic!("block not found")
    }

    fn push_top(&mut self, idx: usize) {
        debug_assert!(idx < CACHE_SIZE);
        let mut pos = idx;
        while pos > 0 {
            self.blocks.swap(pos - 1, pos);
            pos -= 1;
        }
    }
}
