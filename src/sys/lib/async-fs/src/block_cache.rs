//! Block cache for async block devices.
//!
//! The interface could probably be made cleaner/simpler, but
//! the overall design tries to ensure that modified blocks must
//! be saved or have the modifications explicitly discarded.

// TODO: investigate is clippy here should be listened to.
#![allow(clippy::await_holding_refcell_ref)]

use crate::Result;
use crate::{AsyncBlockDevice, Block};

#[cfg(not(feature = "std"))]
use alloc::collections::VecDeque;

#[cfg(feature = "std")]
use std::collections::VecDeque;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockState {
    Clean,
    Dirty,
    Flushing,
}

// Panics if dropped when dirty.
struct InnerCachedBlock {
    block_no: u64,
    state: BlockState,
    block: Box<Block>,

    // When a dirty block goes into the block device, it's state becomes
    // "Flushing". If then a transaction wants to modify the block,
    // the flushing block goes into Self::flushing, and a copy is
    // stored in Self::block. The state then changes to Dirty.
    flushing: VecDeque<Box<Block>>,
    // discard_hint: bool,  // A hint that the block should be discarded after flushing.
}

impl Drop for InnerCachedBlock {
    fn drop(&mut self) {
        #[cfg(feature = "moto-rt")]
        {
            if self.state != BlockState::Clean {
                moto_rt::error::log_backtrace(-1);
            }
            if !self.flushing.is_empty() {
                moto_rt::error::log_backtrace(-1);
            }
        }
        assert!(
            self.state == BlockState::Clean,
            "Block 0x{:x} is {:?} when dropped.",
            self.block_no,
            self.state
        );
        assert!(self.flushing.is_empty());
    }
}

/// When a block is flushing to block dev, it may be read but not written to.
pub struct FlushingBlock {
    inner: Rc<RefCell<InnerCachedBlock>>,
    flushing_ptr: *const Block,
}

impl AsRef<[u8]> for FlushingBlock {
    fn as_ref(&self) -> &[u8] {
        self.block().as_ref()
    }
}

impl FlushingBlock {
    fn new(inner: Rc<RefCell<InnerCachedBlock>>) -> Self {
        let mut inner_ref = inner.borrow_mut();

        assert_eq!(inner_ref.state, BlockState::Dirty);
        inner_ref.state = BlockState::Flushing;
        let flushing_ptr = Box::as_ptr(&inner_ref.block);
        log::debug!(
            "new flushing block 0x{:x} at ptr 0x{:x}",
            inner_ref.block_no,
            flushing_ptr as usize
        );
        drop(inner_ref);
        Self {
            inner,
            flushing_ptr,
        }
    }

    pub fn block(&self) -> &Block {
        // Safety: safe by construction.
        unsafe { self.flushing_ptr.as_ref().unwrap() }
    }
}

impl Drop for FlushingBlock {
    fn drop(&mut self) {
        let mut inner_ref = self.inner.borrow_mut();
        log::debug!(
            "FlushingBlock drop 0x{:x} at ptr 0x{:x}",
            inner_ref.block_no,
            self.flushing_ptr as usize
        );
        if inner_ref.state == BlockState::Flushing
            && self.flushing_ptr == Box::as_ptr(&inner_ref.block)
        {
            inner_ref.state = BlockState::Clean;
            return;
        }

        // We cannot assume that completions complete serially.
        let mut idx = usize::MAX;
        let queue = &mut inner_ref.flushing;

        #[allow(clippy::needless_range_loop)]
        for pos in 0..queue.len() {
            if self.flushing_ptr == Box::as_ptr(&queue[pos]) {
                idx = pos;
                break;
            }
        }
        assert!(idx < queue.len(), "Flushing block not found??");
        queue.remove(idx);
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
                state: BlockState::Clean,
                block: Box::new(Block::new_zeroed()),
                block_no,
                flushing: VecDeque::new(),
            })),
        }
    }

    pub fn block_no(&self) -> u64 {
        self.inner.borrow().block_no
    }

    /// Get a read-only reference to the underlying data. Does not
    /// modify dirty/clean state.
    #[inline]
    pub fn block(&self) -> core::cell::Ref<'_, Block> {
        let ref_box = core::cell::Ref::map(self.inner.borrow(), |inner| &inner.block);
        core::cell::Ref::map(ref_box, |b| &**b)
    }

    /// Get a read/write reference to the underlying data. Marks
    /// the block dirty.
    #[inline]
    pub fn block_mut(&mut self) -> core::cell::RefMut<'_, Block> {
        let mut mut_ref = self.inner.borrow_mut();

        // This is important: do copy-on-write.
        if mut_ref.state == BlockState::Flushing {
            let mut copy: Box<Block> = Box::new(*mut_ref.block.as_ref());
            core::mem::swap(&mut copy, &mut mut_ref.block);
            log::trace!(
                "Pushed flushing block 0x{:x} at ptr 0x{:x}",
                mut_ref.block_no,
                Box::as_ptr(&copy) as usize
            );
            mut_ref.flushing.push_front(copy);
        }

        mut_ref.state = BlockState::Dirty;
        let ref_box = core::cell::RefMut::map(mut_ref, |inner| &mut inner.block);
        core::cell::RefMut::map(ref_box, |b| &mut **b)
    }

    pub fn is_dirty(&self) -> bool {
        self.inner.borrow().state == BlockState::Dirty
    }
}

struct InnerBlockCache {
    lru_cache: LruCache<u64, CachedBlock>,
    free_blocks: Vec<CachedBlock>,
}

impl InnerBlockCache {
    fn new(max_len: usize) -> Self {
        Self {
            lru_cache: LruCache::new(NonZero::new(max_len).unwrap()),
            free_blocks: Vec::new(),
        }
    }

    fn get_block(&mut self, block_no: u64) -> Option<CachedBlock> {
        self.lru_cache.get(&block_no).cloned()
    }

    fn push(&mut self, block_no: u64, block: CachedBlock) {
        if let Some(existing) = self.lru_cache.get(&block_no) {
            assert_eq!(
                existing.inner.as_ptr() as usize,
                block.inner.as_ptr() as usize
            );
        } else {
            self.push_new(block_no, block);
        }
    }

    fn push_new(&mut self, block_no: u64, block: CachedBlock) {
        if let Some((prev_block_no, prev)) = self.lru_cache.push(block_no, block) {
            assert_ne!(block_no, prev_block_no);
            if prev.inner.borrow().state == BlockState::Flushing {
                todo!("keep")
            }
            assert_eq!(BlockState::Clean, prev.inner.borrow().state);
        }
    }

    fn get_free_empty_block(this: &Rc<RefCell<Self>>, block_no: u64) -> CachedBlock {
        if let Some(block) = this.borrow_mut().free_blocks.pop() {
            let mut block_ref = block.inner.borrow_mut();
            assert_eq!(block_ref.state, BlockState::Clean);
            block_ref.block_no = block_no;
            block_ref.block.clear();
            block_ref.state = BlockState::Dirty;
            drop(block_ref);
            block
        } else {
            CachedBlock::new_empty(block_no)
        }
    }

    fn discard_dirty(&mut self, block: CachedBlock) {
        if let Some(existing) = self.lru_cache.pop(&block.block_no()) {
            assert_eq!(
                existing.inner.as_ptr() as usize,
                block.inner.as_ptr() as usize
            );
        }

        {
            let mut block_ref = block.inner.borrow_mut();
            // Dirty can't be Flushing.
            assert_ne!(block_ref.state, BlockState::Flushing);
            block_ref.state = BlockState::Clean;
        }
    }

    #[cfg(debug_assertions)]
    fn debug_check_clean(&mut self) {
        for (block_no, block) in self.lru_cache.iter() {
            assert!(!block.is_dirty(), "Block {block_no} is dirty.");
        }
    }
}

/// LRU-based block cache.
pub struct BlockCache<BD: AsyncBlockDevice> {
    block_dev: Box<BD>,
    inner_cache: Rc<RefCell<InnerBlockCache>>,
}

// TODO: add batch writes.
impl<BD: AsyncBlockDevice> BlockCache<BD> {
    pub async fn new(block_dev: Box<BD>, max_len: usize) -> Result<Self> {
        Ok(Self {
            block_dev,
            inner_cache: Rc::new(RefCell::new(InnerBlockCache::new(max_len))),
        })
    }

    pub fn total_blocks(&self) -> u64 {
        self.block_dev.num_blocks()
    }

    /// Get a reference to a cached block.
    pub async fn get_block(&mut self, block_no: u64) -> Result<CachedBlock> {
        if let Some(block) = self.inner_cache.borrow_mut().get_block(block_no) {
            return Ok(block);
        }

        let mut block = InnerBlockCache::get_free_empty_block(&self.inner_cache, block_no);

        self.block_dev
            .read_block(block_no, &mut block.block_mut())
            .await?;
        {
            let mut block_ref = block.inner.borrow_mut();
            block_ref.state = BlockState::Clean;
        }

        self.inner_cache
            .borrow_mut()
            .push_new(block_no, block.clone());
        Ok(block)
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        if let Some(block) = self.inner_cache.borrow_mut().get_block(block_no) {
            let mut block_ref = block.inner.borrow_mut();
            if block_ref.state == BlockState::Flushing {
                todo!("detach flushing");
            }
            assert_eq!(block_ref.state, BlockState::Clean);
            block_ref.block.clear();
            block_ref.state = BlockState::Dirty;
            drop(block_ref);
            return block;
        }

        let block = InnerBlockCache::get_free_empty_block(&self.inner_cache, block_no);
        self.inner_cache
            .borrow_mut()
            .push_new(block_no, block.clone());
        block
    }

    pub async fn write_block_if_dirty(&mut self, block: CachedBlock) -> Result<()> {
        let block_ref = block.inner.borrow();
        if block_ref.state != BlockState::Dirty {
            return Ok(());
        }

        let block_no = block_ref.block_no;
        drop(block_ref);

        let flusher = FlushingBlock::new(block.inner.clone());
        let completion = self
            .block_dev
            .write_block_with_completion(block_no, flusher)
            .await?;

        #[cfg(feature = "moto-rt")]
        {
            let _handle = moto_async::LocalRuntime::spawn(async move {
                completion.await;
            });
            // _handle.await;
        }

        #[cfg(not(feature = "moto-rt"))]
        completion.await;

        #[cfg(debug_assertions)]
        #[cfg(not(feature = "moto-rt"))]
        {
            let block_ref = block.inner.borrow_mut();
            assert_eq!(block_ref.state, BlockState::Clean);
        }
        Ok(())
    }

    pub fn push(&mut self, block_no: u64, block: CachedBlock) {
        self.inner_cache.borrow_mut().push(block_no, block);
    }

    pub fn discard_dirty(&mut self, block: CachedBlock) {
        self.inner_cache.borrow_mut().discard_dirty(block);
    }

    pub async fn flush(&mut self) -> Result<()> {
        #[cfg(debug_assertions)]
        self.debug_check_clean();

        self.block_dev.flush().await
    }

    #[cfg(debug_assertions)]
    pub fn debug_check_clean(&mut self) {
        self.inner_cache.borrow_mut().debug_check_clean();
    }
}
