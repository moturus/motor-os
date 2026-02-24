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
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::rc::Rc;
#[cfg(feature = "std")]
use std::rc::Weak;

use core::cell::RefCell;
use core::num::NonZero;
use lru::LruCache;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::rc::Rc;
#[cfg(not(feature = "std"))]
use alloc::rc::Weak;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "moto-rt")]
const MAX_COMPLETIONS_IN_FLIGHT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockState {
    Clean,
    Dirty,
}

// Panics if dropped when dirty.
struct InnerCachedBlock {
    block_no: u64,
    state: BlockState,

    dirty_block: Option<Box<Block>>,
    clean_block: Rc<Box<Block>>,

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
        assert!(self.dirty_block.is_none());

        if Rc::strong_count(&self.clean_block) == 1 {
            let mut caches = self.supporting_caches.borrow_mut();
            caches.push_free_block(self.clean_block.clone());
            // caches.clear_expiring_block(self.block_no);
        } else {
            todo!("push expiring block")
            // self.supporting_caches
            //     .borrow_mut()
            //     .push_expiring_block(self.block_no, &self.clean_block);
        }
    }
}

/// Holder of a block to be written to BD.
pub struct FlushingBlock {
    block: Rc<Box<Block>>,
    supporting_caches: Rc<RefCell<SupportingCaches>>,
}

impl AsRef<[u8]> for FlushingBlock {
    fn as_ref(&self) -> &[u8] {
        self.block.as_bytes()
    }
}

impl FlushingBlock {
    fn new(cached_block: &CachedBlock) -> Self {
        let mut inner_ref = cached_block.inner.borrow_mut();

        let block = if let Some(dirty) = inner_ref.dirty_block.take() {
            inner_ref.state = BlockState::Clean;
            let dirty = Rc::new(dirty);
            let mut clean = dirty.clone();
            core::mem::swap(&mut clean, &mut inner_ref.clean_block);
            if Rc::strong_count(&clean) == 1 {
                inner_ref
                    .supporting_caches
                    .borrow_mut()
                    .push_free_block(clean);
            }
            dirty
        } else {
            inner_ref.clean_block.clone()
        };

        Self {
            block,
            supporting_caches: inner_ref.supporting_caches.clone(),
        }
    }
}

impl Drop for FlushingBlock {
    fn drop(&mut self) {
        if Rc::strong_count(&self.block) == 1 {
            self.supporting_caches
                .borrow_mut()
                .push_free_block(self.block.clone());
        }
    }
}

/// Cached block. Internally keeps dirty (= modified) or clean state.
#[derive(Clone)]
pub struct CachedBlock {
    inner: Rc<RefCell<InnerCachedBlock>>,
}

const _: () = assert!(size_of::<CachedBlock>() <= 32);

impl CachedBlock {
    fn new(
        block_no: u64,
        clean_block: Rc<Box<Block>>,
        supporting_caches: Rc<RefCell<SupportingCaches>>,
    ) -> Self {
        Self {
            inner: Rc::new(RefCell::new(InnerCachedBlock {
                state: BlockState::Clean,
                dirty_block: None,
                clean_block,
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
        core::cell::Ref::map(self.inner.borrow(), |inner| {
            if let Some(dirty) = inner.dirty_block.as_ref() {
                dirty.as_ref()
            } else {
                inner.clean_block.as_ref()
            }
        })
    }

    /// Get a read/write reference to the underlying data. Marks the block dirty.
    #[inline]
    pub fn block_mut(&mut self) -> core::cell::RefMut<'_, Block> {
        let mut block_ref = self.inner.borrow_mut();

        // This is important: do copy-on-write.
        if block_ref.state == BlockState::Clean {
            assert!(block_ref.dirty_block.is_none());
            let rc_copy = block_ref.supporting_caches.borrow_mut().pop_free_block();
            let Ok(mut box_copy) = Rc::try_unwrap(rc_copy) else {
                panic!();
            };
            *box_copy = **block_ref.clean_block;
            block_ref.dirty_block = Some(box_copy);
            block_ref.state = BlockState::Dirty;
        }

        core::cell::RefMut::map(block_ref, |inner| {
            inner.dirty_block.as_mut().unwrap().as_mut()
        })
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
    free_blocks: Vec<Rc<Box<Block>>>,
    // expiring_blocks: BTreeMap<u64, Weak<Box<Block>>>,
}

impl SupportingCaches {
    fn push_free_block(&mut self, block: Rc<Box<Block>>) {
        self.free_blocks.push(block);
    }

    fn pop_free_block(&mut self) -> Rc<Box<Block>> {
        self.free_blocks
            .pop()
            .unwrap_or_else(|| Rc::new(Box::new(Block::new_zeroed())))
    }

    /*
    fn push_expiring_block(&mut self, block_no: u64, block: &Rc<Box<Block>>) {
        self.expiring_blocks.insert(block_no, Rc::downgrade(block));
    }

    fn pop_expiring_block(&mut self, block_no: u64) -> Option<Rc<Box<Block>>> {
        self.expiring_blocks
            .remove(&block_no)
            .map(|weak| weak.upgrade())
            .flatten()
    }

    fn clear_expiring_block(&mut self, block_no: u64) {
        self.expiring_blocks.remove(&block_no);
    }
    */
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
            // expiring_blocks: BTreeMap::new(),
        }));

        let mut pinned_blocks = Vec::with_capacity(pinned_blocks_num);
        for idx in 0..pinned_blocks_num {
            let block_no = pinned_blocks_start + idx as u64;
            let mut block = Box::new(Block::new_zeroed());
            block_dev
                .read_block(block_no, &mut block)
                .await
                .inspect_err(|err| {
                    log::error!("Error reading block 0x{block_no:x}: {err:?}.");
                })?;
            pinned_blocks.push(CachedBlock::new(
                block_no,
                Rc::new(block),
                supporting_caches.clone(),
            ));
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

        let dirty = block_ref.dirty_block.take().unwrap();
        self.supporting_caches
            .borrow_mut()
            .push_free_block(Rc::new(dirty));
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
            assert!(prev_ref.dirty_block.is_none());
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

        /*
        let expiring_block = self
            .supporting_caches
            .borrow_mut()
            .pop_expiring_block(block_no);

        if let Some(block) = expiring_block {
            let cached_block = CachedBlock::new(block_no, block, self.supporting_caches.clone());
            self.push_block(block_no, cached_block.clone());
            return Ok(cached_block);
        }
        */

        self.cache_misses += 1;
        let rc_block = self.supporting_caches.borrow_mut().pop_free_block();
        let Ok(mut box_block) = Rc::try_unwrap(rc_block) else {
            panic!()
        };

        self.block_dev.read_block(block_no, &mut box_block).await?;
        let cached_block =
            CachedBlock::new(block_no, Rc::new(box_block), self.supporting_caches.clone());

        self.push_block(block_no, cached_block.clone());

        Ok(cached_block)
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        assert!(!self.is_pinned(block_no));

        if let Some(block) = self.lru_cache.get(&block_no) {
            let mut clone = block.clone();
            clone.block_mut().clear();
            return clone;
        }

        let mut block = self.supporting_caches.borrow_mut().pop_free_block();
        Rc::get_mut(&mut block).unwrap().clear();
        let mut block = CachedBlock::new(block_no, block, self.supporting_caches.clone());
        block.block_mut().clear();
        self.push_block(block_no, block.clone());
        block
    }

    /// Write CachedBlock to block_no. Note that block_no may not be equal to block.block_no();
    pub async fn write_block(&mut self, block_no: u64, block: CachedBlock) -> Result<()> {
        let flusher = FlushingBlock::new(&block);

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
