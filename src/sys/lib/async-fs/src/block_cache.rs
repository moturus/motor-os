//! Block cache for async block devices.

use crate::{AsyncBlockDevice, Block};
use lru::LruCache;
use std::io::Result;
use std::num::NonZero;

/// Cached block. Internally keeps dirty (= modified) or clean state.
/// Panics if dropped when dirty.
///
/// The only way to mark a dirty block as clean is to save it
/// via BlockCache::write_block().
///
/// NOT clone/copy to make the dirty state tracking robust.
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

    pub fn block_no(&self) -> u64 {
        self.block_no
    }

    /// Get a read-only reference to the underlying data. Does not
    /// modify dirty/clean state.
    pub fn block(&self) -> &Block {
        &self.block
    }

    /// Get a read/write reference to the underlying data. Marks
    /// the block dirty.
    pub fn block_mut(&mut self) -> &mut Block {
        self.dirty = true;
        &mut self.block
    }

    fn mark_clean(&mut self) {
        assert!(self.dirty);
        self.dirty = false;
    }

    /// Dispose of the block even if it is dirty.
    pub fn forget(mut self) {
        self.dirty = false;
    }
}

/// LRU-based block cache.
pub struct BlockCache {
    block_dev: Box<dyn AsyncBlockDevice>,
    cache: LruCache<u64, CachedBlock>,

    free_blocks: Vec<CachedBlock>,
}

// TODO: add batch writes.
impl BlockCache {
    pub async fn new(block_dev: Box<dyn AsyncBlockDevice>, max_len: usize) -> Result<Self> {
        Ok(Self {
            cache: LruCache::new(NonZero::new(max_len).unwrap()),
            block_dev,
            free_blocks: Vec::new(),
        })
    }

    /// Get a reference to a cached block.
    pub async fn get_block(&mut self, block_no: u64) -> Result<&mut CachedBlock> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        unsafe {
            {
                let this = self as *mut Self;
                let this = this.as_mut().unwrap_unchecked();
                if let Some(block) = this.cache.get_mut(&block_no) {
                    return Ok(block);
                }
            }
        }

        let mut block = self.internal_get_empty_block(block_no);

        self.block_dev
            .read_block(block_no, &mut block.block)
            .await?;

        Ok(self.internal_push_block(block))
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&mut self, block_no: u64) -> &mut CachedBlock {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        unsafe {
            {
                let this = self as *mut Self;
                let this = this.as_mut().unwrap_unchecked();
                if let Some(block) = this.cache.get_mut(&block_no) {
                    assert!(!block.dirty);
                    log::trace!("BlockCache::get_empty_block(): clearing cached block {block_no}");
                    block.block.clear();
                    return block;
                }
            }
        }
        let block = self.internal_get_empty_block(block_no);
        self.internal_push_block(block)
    }

    pub async fn write_block(&mut self, block_no: u64) -> Result<()> {
        let block = self.cache.get_mut(&block_no).expect("block not found");

        self.block_dev.write_block(block_no, block.block()).await?;
        block.mark_clean();
        Ok(())
    }

    pub async fn write_block_if_dirty(&mut self, block_no: u64) -> Result<bool> {
        let block = self.cache.get_mut(&block_no).expect("block not found");

        if block.dirty {
            self.block_dev.write_block(block_no, block.block()).await?;
            block.mark_clean();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get a cached block that is managed by the caller, in case the caller
    /// needs to operate multiple cached blocks (borrow checker won't allow
    /// working with multiple borrowed blocks).
    ///
    /// Dirty pinned blocks must be unpinned to be saved later.
    /// Clean pinned blocks can be safely dropped.
    pub async fn pin_block(&mut self, block_no: u64) -> Result<CachedBlock> {
        if let Some(block) = self.cache.pop(&block_no) {
            return Ok(block);
        }

        let mut block = self.internal_get_empty_block(block_no);
        self.block_dev
            .read_block(block_no, &mut block.block)
            .await?;

        Ok(block)
    }

    pub fn pin_empty_block(&mut self, block_no: u64) -> CachedBlock {
        if let Some(mut block) = self.cache.pop(&block_no) {
            assert!(!block.dirty);
            block.block.clear();
            return block;
        }

        self.internal_get_empty_block(block_no)
    }

    /// Put a pinned block back into the cache. Note that if the block is dirty,
    /// it must be saved via write_block() later.
    pub fn unpin_block(&mut self, block: CachedBlock) -> &mut CachedBlock {
        self.internal_push_block(block)
    }

    pub async fn flush(&mut self) -> Result<()> {
        // #[cfg(debug_assertions)]
        {
            for (block_no, block) in self.cache.iter() {
                assert!(!block.dirty, "Block {block_no} is dirty.");
            }
        }

        self.block_dev.flush().await
    }

    pub fn device_mut(&mut self) -> &mut dyn AsyncBlockDevice {
        self.block_dev.as_mut()
    }

    pub fn device(&self) -> &dyn AsyncBlockDevice {
        self.block_dev.as_ref()
    }

    fn internal_get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        if let Some(mut block) = self.free_blocks.pop() {
            assert!(!block.dirty);
            block.block.clear();
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
}
