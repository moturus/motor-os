//! Block cache for async block devices.
//!
//! The interface could probably be made cleaner/simpler, but
//! the overall design tries to ensure that modified blocks must
//! be saved or have the modifications explicitly discarded.

// TODO: investigate is clippy here should be listened to.
#![allow(clippy::await_holding_refcell_ref)]

use crate::Result;
use crate::{AsyncBlockDevice, Block};

#[cfg(feature = "std")]
use std::rc::Rc;

#[cfg(not(feature = "std"))]
use alloc::rc::Rc;

use core::cell::RefCell;
use core::num::NonZero;
use lru::LruCache;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

// Panics if dropped when dirty.
struct InnerCachedBlock {
    block_no: u64,
    dirty: bool,
    block: Block, // Note: aligned at 4096.
}

const _: () = assert!(size_of::<InnerCachedBlock>() == 8192);

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
/// Cloneable, with the actual block ref-counted and ref-celled to keep
/// the Rust's borrow-checker happy when we work with multiple modified
/// cached blocks.
#[derive(Clone)]
pub struct CachedBlock {
    inner: Rc<RefCell<InnerCachedBlock>>, // (dirty, Block)
}

// Note: Although InnerCachedBlock is large (8k bytes), it is heap-allocated,
// CachedBlock is a (ref-counted) pointer onto it, so can easily be moved around
// or allocated on stack.
const _: () = assert!(size_of::<CachedBlock>() <= 32);

impl CachedBlock {
    fn new_empty(block_no: u64) -> Self {
        Self {
            inner: Rc::new(RefCell::new(InnerCachedBlock {
                dirty: true,
                block: Block::new_zeroed(),
                block_no,
            })),
        }
    }

    pub fn block_no(&self) -> u64 {
        self.inner.borrow().block_no
    }

    /// Get a read-only reference to the underlying data. Does not
    /// modify dirty/clean state.
    pub fn block(&self) -> core::cell::Ref<'_, Block> {
        core::cell::Ref::map(self.inner.borrow(), |inner| &inner.block)
    }

    /// Get a read/write reference to the underlying data. Marks
    /// the block dirty.
    pub fn block_mut(&mut self) -> core::cell::RefMut<'_, Block> {
        let mut mut_ref = self.inner.borrow_mut();
        mut_ref.dirty = true;
        core::cell::RefMut::map(mut_ref, |inner| &mut inner.block)
    }

    fn intenal_mark_clean(&mut self) {
        self.inner.borrow_mut().dirty = false;
    }

    fn internal_mark_dirty(&mut self) {
        self.inner.borrow_mut().dirty = true;
    }

    pub fn is_dirty(&self) -> bool {
        self.inner.borrow().dirty
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

    pub fn total_blocks(&self) -> u64 {
        self.block_dev.num_blocks()
    }

    /// Get a reference to a cached block.
    pub async fn get_block(&mut self, block_no: u64) -> Result<CachedBlock> {
        if let Some(block) = self.cache.get(&block_no) {
            return Ok(block.clone());
        }

        let mut block = self.internal_get_empty_block(block_no);

        self.block_dev
            .read_block(block_no, &mut block.block_mut())
            .await?;
        block.intenal_mark_clean();

        self.internal_push_block(block.clone());
        Ok(block)
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        if let Some(block) = self.cache.get_mut(&block_no) {
            block.block_mut().clear();
            block.internal_mark_dirty();
            return block.clone();
        }

        let block = self.internal_get_empty_block(block_no);
        self.internal_push_block(block.clone());
        block
    }

    /*
    pub async fn write_block(&mut self, block_no: u64) -> Result<()> {
        let block = self.cache.get_mut(&block_no).expect("block not found");

        self.block_dev.write_block(block_no, &block.block()).await?;
        block.intenal_mark_clean();
        Ok(())
    }
    */

    pub async fn write_block_if_dirty(&mut self, block_no: u64) -> Result<bool> {
        let block = self.cache.get_mut(&block_no).expect("block not found");

        if block.is_dirty() {
            self.block_dev.write_block(block_no, &block.block()).await?;
            block.intenal_mark_clean();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn push(&mut self, block: CachedBlock) {
        if let Some(existing) = self.cache.get(&block.block_no()) {
            assert_eq!(
                existing.inner.as_ptr() as usize,
                block.inner.as_ptr() as usize
            );
        } else {
            self.cache.push(block.block_no(), block);
        }
    }

    pub fn discard(&mut self, mut block: CachedBlock) {
        if let Some(existing) = self.cache.pop(&block.block_no()) {
            assert_eq!(
                existing.inner.as_ptr() as usize,
                block.inner.as_ptr() as usize
            );
        }

        block.intenal_mark_clean();
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

    fn internal_get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        if let Some(mut block) = self.free_blocks.pop() {
            assert!(!block.is_dirty());
            block.block_mut().clear();
            block.inner.borrow_mut().block_no = block_no;
            block.internal_mark_dirty();
            block
        } else {
            CachedBlock::new_empty(block_no)
        }
    }

    fn internal_push_block(&mut self, block: CachedBlock) {
        let block_no = block.block_no();

        if let Some((_, prev)) = self.cache.push(block_no, block) {
            assert!(!prev.is_dirty(), "Block {} is dirty.", prev.block_no());
            log::trace!("Block {} pushed out of cache.", prev.block_no());
            self.free_blocks.push(prev);
        }
    }

    #[cfg(debug_assertions)]
    pub fn debug_check_clean(&mut self) {
        for (block_no, block) in self.cache.iter() {
            assert!(!block.is_dirty(), "Block {block_no} is dirty.");
        }
    }
}
