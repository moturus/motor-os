//! Block cache for async block devices.

use crate::{AsyncBlockDevice, Block};
use lru::LruCache;
use std::cell::RefCell;
use std::io::Result;
use std::num::NonZero;
use std::rc::Rc;

struct InnerCachedBlock {
    block_no: u64,
    dirty: bool,
    block: Block,
}

impl Drop for InnerCachedBlock {
    fn drop(&mut self) {
        assert!(
            !self.dirty,
            "Block {} is dirty when dropped.",
            self.block_no
        );
    }
}

/// Cached block. Internally keeps dirty (= modified) or clean state.
/// Panics if dropped when dirty.
#[derive(Clone)]
pub struct CachedBlock {
    block: Rc<RefCell<InnerCachedBlock>>, // (dirty, Block)
}

impl CachedBlock {
    fn new_empty(block_no: u64) -> Self {
        Self {
            block: Rc::new(RefCell::new(InnerCachedBlock {
                dirty: true,
                block: Block::new_zeroed(),
                block_no,
            })),
        }
    }

    pub fn block_no(&self) -> u64 {
        self.block.borrow().block_no
    }

    /// Get a read-only reference to the underlying data. Does not
    /// modify dirty/clean state.
    pub fn block(&self) -> std::cell::Ref<'_, Block> {
        std::cell::Ref::map(self.block.borrow(), |inner| &inner.block)
    }

    /// Get a read/write reference to the underlying data. Marks
    /// the block dirty.
    pub fn block_mut(&mut self) -> std::cell::RefMut<'_, Block> {
        let mut mut_ref = self.block.borrow_mut();
        mut_ref.dirty = true;
        std::cell::RefMut::map(mut_ref, |inner| &mut inner.block)
    }

    fn mark_clean(&mut self) {
        self.block.borrow_mut().dirty = false;
    }

    fn mark_dirty(&mut self) {
        self.block.borrow_mut().dirty = true;
    }

    pub fn is_dirty(&self) -> bool {
        self.block.borrow().dirty
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
    pub async fn get_block(&mut self, block_no: u64) -> Result<&CachedBlock> {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        unsafe {
            {
                let this = self as *mut Self;
                let this = this.as_mut().unwrap_unchecked();
                if let Some(block) = this.cache.get(&block_no) {
                    return Ok(block);
                }
            }
        }

        let mut block = self.internal_get_empty_block(block_no);

        self.block_dev
            .read_block(block_no, &mut *block.block_mut())
            .await?;
        block.mark_clean();

        Ok(self.internal_push_block(block))
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&mut self, block_no: u64) -> &CachedBlock {
        // TODO: remove unsafe when NLL Problem #3 is solved.
        // See https://www.reddit.com/r/rust/comments/1lhrptf/compiling_iflet_temporaries_in_rust_2024_187/
        unsafe {
            {
                let this = self as *mut Self;
                let this = this.as_mut().unwrap_unchecked();
                if let Some(block) = this.cache.get_mut(&block_no) {
                    log::trace!("BlockCache::get_empty_block(): clearing cached block {block_no}");
                    block.block_mut().clear();
                    block.mark_dirty();
                    return block;
                }
            }
        }
        let block = self.internal_get_empty_block(block_no);
        self.internal_push_block(block)
    }

    pub async fn write_block(&mut self, block_no: u64) -> Result<()> {
        let block = self.cache.get_mut(&block_no).expect("block not found");

        self.block_dev
            .write_block(block_no, &*block.block())
            .await?;
        block.mark_clean();
        Ok(())
    }

    pub async fn write_block_if_dirty(&mut self, block_no: u64) -> Result<bool> {
        let block = self.cache.get_mut(&block_no).expect("block not found");

        if block.is_dirty() {
            self.block_dev
                .write_block(block_no, &*block.block())
                .await?;
            block.mark_clean();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn push(&mut self, block: CachedBlock) {
        if let Some(existing) = self.cache.get(&block.block_no()) {
            assert_eq!(
                existing.block.as_ptr() as usize,
                block.block.as_ptr() as usize
            );
        } else {
            self.cache.push(block.block_no(), block);
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        // #[cfg(debug_assertions)]
        {
            for (block_no, block) in self.cache.iter() {
                assert!(!block.is_dirty(), "Block {block_no} is dirty.");
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
            assert!(!block.is_dirty());
            block.block_mut().clear();
            block.block.borrow_mut().block_no = block_no;
            block.mark_dirty();
            block
        } else {
            CachedBlock::new_empty(block_no)
        }
    }

    fn internal_push_block(&mut self, block: CachedBlock) -> &CachedBlock {
        let block_no = block.block_no();

        if let Some((_, prev)) = self.cache.push(block_no, block) {
            assert!(!prev.is_dirty(), "Block {} is dirty.", prev.block_no());
            self.free_blocks.push(prev);
        }

        self.cache.get(&block_no).unwrap()
    }

    #[cfg(debug_assertions)]
    pub fn debug_check_clean(&mut self) {
        for (block_no, block) in self.cache.iter() {
            assert!(!block.is_dirty(), "Block {block_no} is dirty.");
        }
    }
}
