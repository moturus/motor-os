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
use core::mem::ManuallyDrop;
use core::num::NonZero;
use lru::LruCache;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "moto-rt")]
const MAX_COMPLETIONS_IN_FLIGHT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockState {
    Clean,
    Dirty,
}

// Panics if dropped when dirty.
struct InnerCachedBlock {
    block_no: u64,
    state: BlockState,

    block: ManuallyDrop<Box<Block>>,

    // A "clean" copy of the mutable block in case we need to
    // roll back the transaction (see "discard_dirty_block").
    prev_clean_block: Option<Box<Block>>,

    supporting_caches: Rc<RefCell<SupportingCaches>>,
}

impl Drop for InnerCachedBlock {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        #[cfg(feature = "moto-rt")]
        {
            if self.state != BlockState::Clean {
                moto_rt::error::log_backtrace(-1);
            }
        }

        assert!(
            self.state == BlockState::Clean,
            "Block 0x{:x} is {:?} when dropped.",
            self.block_no,
            self.state
        );
        assert!(self.prev_clean_block.is_none());

        // SAFETY: safe as we are in Self::drop().
        let block = unsafe { ManuallyDrop::take(&mut self.block) };
        self.supporting_caches.borrow_mut().push_free_block(block);
    }
}

/// When a block is flushing to block dev, it may be read but not written to.
pub struct FlushingBlock {
    inner: Rc<RefCell<InnerCachedBlock>>,

    // Use an addr instead of Box<Block> so that compiler does not assume
    // anything, as we pass the addr to virtio.
    flushing_block_addr: usize,
}

impl AsRef<[u8]> for FlushingBlock {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: safe by construction.
        unsafe {
            core::slice::from_raw_parts(self.flushing_block_addr as *const u8, crate::BLOCK_SIZE)
        }
    }
}

impl FlushingBlock {
    fn new(inner: Rc<RefCell<InnerCachedBlock>>) -> Self {
        let mut inner_ref = inner.borrow_mut();

        inner_ref.state = BlockState::Clean;
        let mut flushing = inner_ref
            .prev_clean_block
            .take()
            .unwrap_or_else(|| inner_ref.supporting_caches.borrow_mut().pop_free_block());
        *flushing = **inner_ref.block;
        drop(inner_ref);
        Self {
            inner,
            flushing_block_addr: Box::into_raw(flushing) as usize,
        }
    }
}

impl Drop for FlushingBlock {
    fn drop(&mut self) {
        let block = unsafe { Box::from_raw(self.flushing_block_addr as *mut Block) };
        self.inner
            .borrow()
            .supporting_caches
            .borrow_mut()
            .push_free_block(block);
    }
}

/// Cached block. Internally keeps dirty (= modified) or clean state.
#[derive(Clone)]
pub struct CachedBlock {
    inner: Rc<RefCell<InnerCachedBlock>>,
}

const _: () = assert!(size_of::<CachedBlock>() <= 32);

impl CachedBlock {
    fn new(block_no: u64, supporting_caches: Rc<RefCell<SupportingCaches>>) -> Self {
        let block = supporting_caches.borrow_mut().pop_free_block();

        Self {
            inner: Rc::new(RefCell::new(InnerCachedBlock {
                state: BlockState::Dirty,
                block: ManuallyDrop::new(block),
                prev_clean_block: None,
                supporting_caches,
                block_no,
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
        core::cell::Ref::map(self.inner.borrow(), |inner| Box::as_ref(&inner.block))
    }

    /// Get a read/write reference to the underlying data. Marks the block dirty.
    #[inline]
    pub fn block_mut(&mut self) -> core::cell::RefMut<'_, Block> {
        let mut block_ref = self.inner.borrow_mut();

        // This is important: do copy-on-write.
        if block_ref.state == BlockState::Clean {
            let mut copy = block_ref.supporting_caches.borrow_mut().pop_free_block();
            *copy = **block_ref.block;
            block_ref.prev_clean_block = Some(copy);
            block_ref.state = BlockState::Dirty;
        }

        core::cell::RefMut::map(block_ref, |inner| inner.block.as_mut())
    }

    pub fn is_dirty(&self) -> bool {
        self.inner.borrow().state == BlockState::Dirty
    }
}

#[cfg(feature = "moto-rt")]
enum BackgroundMessage {
    Block((u64, FlushingBlock)),
    Flush,
}

struct SupportingCaches {
    free_blocks: Vec<Box<Block>>,
}

impl SupportingCaches {
    fn push_free_block(&mut self, block: Box<Block>) {
        self.free_blocks.push(block);
    }

    fn pop_free_block(&mut self) -> Box<Block> {
        self.free_blocks
            .pop()
            .unwrap_or_else(|| Box::new(Block::new_zeroed()))
    }
}

/// LRU-based block cache.
pub struct BlockCache<BD: AsyncBlockDevice> {
    block_dev: Rc<BD>,
    cache_size: usize,

    // The main cache.
    lru_cache: LruCache<u64, CachedBlock>,
    supporting_caches: Rc<RefCell<SupportingCaches>>,

    #[cfg(feature = "moto-rt")]
    completion_sink: moto_async::channel::Sender<BackgroundMessage>,

    #[allow(unused)]
    cache_misses: u64,

    // Pinned blocks are always cached. Used by txn log.
    pinned_blocks_start: u64,
    pinned_blocks_num: usize,
    pinned_blocks: Vec<CachedBlock>,
}

impl<BD: AsyncBlockDevice + 'static> BlockCache<BD> {
    pub async fn new(
        block_dev: Box<BD>,
        cache_size: usize,
        pinned_blocks_start: u64,
        pinned_blocks_num: usize,
    ) -> Result<Self> {
        let block_dev: Rc<BD> = Rc::from(block_dev);

        #[cfg(feature = "moto-rt")]
        let sender = {
            #[cfg(not(feature = "std"))]
            use alloc::collections::VecDeque;

            #[cfg(feature = "std")]
            use std::collections::VecDeque;

            let (sender, mut receiver) = moto_async::channel(MAX_COMPLETIONS_IN_FLIGHT);

            let bd = block_dev.clone();
            let _handle = moto_async::LocalRuntime::spawn(async move {
                let mut completions: VecDeque<BD::Completion> = VecDeque::new();
                while let Some(msg) = receiver.recv().await {
                    match msg {
                        BackgroundMessage::Block((block_no, flushing_block)) => {
                            let c = bd
                                .write_block_with_completion(block_no, flushing_block)
                                .await
                                .unwrap_or_else(|_| panic!("Error writing block to the device"));
                            completions.push_back(c);
                        }
                        BackgroundMessage::Flush => {
                            while let Some(c) = completions.pop_front() {
                                let _ = c.await;
                            }
                        }
                    }
                }
            });
            sender
        };

        let supporting_caches = Rc::new(RefCell::new(SupportingCaches {
            free_blocks: Vec::new(),
        }));

        let mut pinned_blocks = Vec::with_capacity(pinned_blocks_num);
        for idx in 0..pinned_blocks_num {
            let block_no = pinned_blocks_start + idx as u64;
            let mut block = CachedBlock::new(block_no, supporting_caches.clone());
            block_dev
                .read_block(block_no, &mut block.block_mut())
                .await?;
            block.inner.borrow_mut().state = BlockState::Clean; // We just read it. It's clean.
            pinned_blocks.push(block);
        }

        Ok(Self {
            block_dev,
            cache_size,
            lru_cache: LruCache::new(NonZero::new(cache_size).unwrap()),
            supporting_caches,
            #[cfg(feature = "moto-rt")]
            completion_sink: sender,
            cache_misses: 0,
            pinned_blocks_start,
            pinned_blocks_num,
            pinned_blocks,
        })
    }

    fn is_pinned(&self, block_no: u64) -> bool {
        block_no >= self.pinned_blocks_start
            && (block_no < (self.pinned_blocks_start + self.pinned_blocks_num as u64))
    }

    pub fn discard_dirty_block(&mut self, block: CachedBlock) {
        let block_no = block.block_no();
        assert!(!self.is_pinned(block_no));

        let mut block_ref = block.inner.borrow_mut();
        assert_eq!(block_ref.state, BlockState::Dirty);

        // Mark the block clean even if we are discarding it, as otherwise
        // InnerRef::drop() will panic.
        block_ref.state = BlockState::Clean;

        if let Some(mut prev_clean) = block_ref.prev_clean_block.take() {
            core::mem::swap(&mut prev_clean, &mut *block_ref.block);
            block_ref
                .supporting_caches
                .borrow_mut()
                .push_free_block(prev_clean);
        } else {
            // No clean copy, so we must remove the block from the cache.
            let existing = self.lru_cache.pop(&block_no).unwrap();
            assert_eq!(
                Rc::as_ptr(&existing.inner) as usize,
                Rc::as_ptr(&block.inner) as usize
            );
            assert_eq!(2, Rc::strong_count(&block.inner)); // block + existing.
        }
    }

    pub fn total_blocks(&self) -> u64 {
        self.block_dev.num_blocks()
    }

    pub fn pinned_blocks_start(&self) -> u64 {
        self.pinned_blocks_start
    }

    pub fn pinned_blocks_num(&self) -> usize {
        self.pinned_blocks_num
    }

    fn push_block(&mut self, block_no: u64, block: CachedBlock) {
        if let Some((_prev_block_no, prev_block)) = self.lru_cache.push(block_no, block.clone()) {
            assert_eq!(1, Rc::strong_count(&prev_block.inner));
            let prev_ref = prev_block.inner.borrow();
            assert_eq!(prev_ref.state, BlockState::Clean);
            assert!(prev_ref.prev_clean_block.is_none());
        };
    }

    /// Get a reference to a cached block.
    pub async fn get_block(&mut self, block_no: u64) -> Result<CachedBlock> {
        if self.is_pinned(block_no) {
            return Ok(self.pinned_blocks[(block_no - self.pinned_blocks_start) as usize].clone());
        }
        if let Some(block) = self.lru_cache.get(&block_no) {
            return Ok(block.clone());
        }

        self.cache_misses += 1;
        let mut block = CachedBlock::new(block_no, self.supporting_caches.clone());

        self.block_dev
            .read_block(block_no, &mut block.block_mut())
            .await?;
        {
            let mut block_ref = block.inner.borrow_mut();
            block_ref.state = BlockState::Clean;
            assert!(block_ref.prev_clean_block.is_none());
        }

        self.push_block(block_no, block.clone());
        Ok(block)
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        assert!(!self.is_pinned(block_no));

        if let Some(block) = self.lru_cache.get(&block_no) {
            let mut block_ref = block.inner.borrow_mut();
            // This is important: do copy-on-write.
            assert_eq!(block_ref.state, BlockState::Clean);
            assert!(block_ref.prev_clean_block.is_none());
            let mut copy = self.supporting_caches.borrow_mut().pop_free_block();
            copy.clear();
            core::mem::swap(&mut copy, &mut block_ref.block);
            block_ref.prev_clean_block = Some(copy);

            block_ref.state = BlockState::Dirty;
            return block.clone();
        }

        let mut block = CachedBlock::new(block_no, self.supporting_caches.clone());
        block.block_mut().clear();
        self.push_block(block_no, block.clone());
        block
    }

    /// Write CachedBlock to block_no. Note that block_no may not be equal to block.block_no();
    pub async fn write_block(&mut self, block_no: u64, block: CachedBlock) -> Result<()> {
        let flusher = FlushingBlock::new(block.inner.clone());

        #[cfg(feature = "moto-rt")]
        self.completion_sink
            .send(BackgroundMessage::Block((block_no, flusher)))
            .await
            .unwrap_or_else(|_e| panic!()); // Impossible; but we can't just unwrap().
        #[cfg(feature = "moto-rt")]
        return Ok(());

        #[cfg(not(feature = "moto-rt"))]
        {
            let completion = self
                .block_dev
                .write_block_with_completion(block_no, flusher)
                .await?;
            let (_flusher, result) = completion.await;
            result
        }
    }

    pub async fn start_flushing(&mut self) {
        // We do not restrict the size of free blocks cache because it
        // cannot grow substantially larger than the main cache size.
        // TODO: convert to debug_assert.
        assert!(self.supporting_caches.borrow().free_blocks.len() < self.cache_size);

        #[cfg(feature = "moto-rt")]
        self.completion_sink
            .send(BackgroundMessage::Flush)
            .await
            .unwrap_or_else(|_e| panic!()); // Impossible; but we can't just unwrap().
    }

    pub async fn flush(&mut self) -> Result<()> {
        #[cfg(debug_assertions)]
        self.debug_check_clean();

        #[cfg(feature = "moto-rt")]
        self.completion_sink
            .send(BackgroundMessage::Flush)
            .await
            .unwrap_or_else(|_| panic!()); // Impossible.

        let f = self.block_dev.flush();
        f.await
    }

    #[cfg(debug_assertions)]
    pub fn debug_check_clean(&mut self) {
        for (block_no, block) in self.lru_cache.iter() {
            assert!(!block.is_dirty(), "Block {block_no} is dirty.");
        }
    }
}
