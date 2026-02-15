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
use core::mem::ManuallyDrop;
use core::num::NonZero;
use lru::LruCache;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const MAX_FREE_BLOCKS: usize = 128;
const MAX_COMPLETIONS_IN_FLIGHT: usize = 64;

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
    block: ManuallyDrop<Box<Block>>,

    free_blocks: Rc<RefCell<Vec<Box<Block>>>>,
    // When a dirty block goes into the block device, it's state becomes
    // "Flushing". If then a transaction wants to modify the block,
    // the flushing block goes into Self::flushing, and a copy is
    // stored in Self::block. The state then changes to Dirty.
    flushing: VecDeque<Box<Block>>,
    // discard_hint: bool,  // A hint that the block should be discarded after flushing.
}

impl Drop for InnerCachedBlock {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
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

        // Safety: safe because we are in drop(), so nobody will ever
        // access self.block.
        let block = unsafe { ManuallyDrop::take(&mut self.block) };

        let mut free_blocks_ref = self.free_blocks.borrow_mut();
        if free_blocks_ref.len() < MAX_FREE_BLOCKS {
            free_blocks_ref.push(block);
        } else {
            drop(block);
        }
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
        log::trace!(
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
        log::trace!(
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
        assert!(queue.len() < MAX_COMPLETIONS_IN_FLIGHT);

        #[allow(clippy::needless_range_loop)]
        for pos in 0..queue.len() {
            if self.flushing_ptr == Box::as_ptr(&queue[pos]) {
                idx = pos;
                break;
            }
        }
        assert!(idx < queue.len(), "Flushing block not found??");
        let block = queue.remove(idx).unwrap();
        let mut free_blocks_ref = inner_ref.free_blocks.borrow_mut();
        if free_blocks_ref.len() < MAX_FREE_BLOCKS {
            free_blocks_ref.push(block);
        }
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
    fn new_empty(block_no: u64, free_blocks: Rc<RefCell<Vec<Box<Block>>>>) -> Self {
        let block = free_blocks
            .borrow_mut()
            .pop()
            .map(|mut block| {
                block.clear();
                block
            })
            .unwrap_or_else(|| Box::new(Block::new_zeroed()));
        Self {
            inner: Rc::new(RefCell::new(InnerCachedBlock {
                state: BlockState::Clean,
                block: ManuallyDrop::new(block),
                free_blocks,
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
        core::cell::Ref::map(self.inner.borrow(), |inner| &**inner.block)
    }

    /// Get a read/write reference to the underlying data. Marks
    /// the block dirty.
    #[inline]
    pub fn block_mut(&mut self) -> core::cell::RefMut<'_, Block> {
        let mut mut_ref = self.inner.borrow_mut();

        // This is important: do copy-on-write.
        if mut_ref.state == BlockState::Flushing {
            let mut copy = if let Some(mut block) = mut_ref.free_blocks.borrow_mut().pop() {
                *block.as_mut() = *mut_ref.block.as_ref();
                block
            } else {
                Box::new(*mut_ref.block.as_ref())
            };
            core::mem::swap(&mut copy, &mut mut_ref.block);
            log::trace!(
                "Pushed flushing block 0x{:x} at ptr 0x{:x}",
                mut_ref.block_no,
                Box::as_ptr(&copy) as usize
            );
            mut_ref.flushing.push_back(copy);
        }

        mut_ref.state = BlockState::Dirty;
        core::cell::RefMut::map(mut_ref, |inner| &mut **inner.block)
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

/// LRU-based block cache.
pub struct BlockCache<BD: AsyncBlockDevice> {
    block_dev: Rc<BD>,
    lru_cache: LruCache<u64, CachedBlock>,
    free_blocks: Rc<RefCell<Vec<Box<Block>>>>,

    #[cfg(feature = "moto-rt")]
    completion_sink: moto_async::channel::Sender<BackgroundMessage>,

    #[allow(unused)]
    cache_misses: u64,

    // Pinned blocks are always cached. Used for txn log.
    pinned_blocks_start: u64,
    pinned_blocks_num: usize,
    pinned_blocks: Vec<CachedBlock>,
}

impl<BD: AsyncBlockDevice + 'static> BlockCache<BD> {
    pub async fn new(
        block_dev: Box<BD>,
        max_len: usize,
        pinned_blocks_start: u64,
        pinned_blocks_num: usize,
    ) -> Result<Self> {
        let block_dev: Rc<BD> = Rc::from(block_dev);

        #[cfg(feature = "moto-rt")]
        let sender = {
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
                            // c.await;
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
        /*
        #[cfg(feature = "moto-rt")]
        {
            let mut self_ = Self {
                block_dev,
                lru_cache: LruCache::new(NonZero::new(max_len).unwrap()),
                free_blocks: Default::default(),
                completion_sink: sender,
                cache_misses: 0,
            };
            const MEGS: u64 = 32;
            const NUM_BLOCKS: u64 = 1024 * 1024 * MEGS / 4096;

            let started = moto_rt::time::Instant::now();
            let mut block_no = 0;
            while block_no < NUM_BLOCKS {
                let block = self_.get_empty_block(block_no);
                self_.write_block_if_dirty(block).await.unwrap();
                block_no += 1;
                if block_no % 64 == 0 {
                    let _ = self_.completion_sink.send(BackgroundMessage::Flush).await;
                }
            }
            self_.flush().await.unwrap();
            let elapsed = started.elapsed();
            let write_mbps = (MEGS as f64) / elapsed.as_secs_f64();
            log::info!(
                "block_cache: write speed {:.3} MB/sec; cache_misses: {}",
                write_mbps,
                self_.cache_misses
            );
            panic!()
        }
        */

        let free_blocks = Rc::new(RefCell::new(Vec::new()));

        let mut pinned_blocks = Vec::with_capacity(pinned_blocks_num);
        for idx in 0..pinned_blocks_num {
            let block_no = pinned_blocks_start + idx as u64;
            let mut block = CachedBlock::new_empty(block_no, free_blocks.clone());
            block_dev
                .read_block(block_no, &mut block.block_mut())
                .await?;
            block.inner.borrow_mut().state = BlockState::Clean;
            pinned_blocks.push(block);
        }

        Ok(Self {
            block_dev,
            lru_cache: LruCache::new(NonZero::new(max_len).unwrap()),
            free_blocks,
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

    fn get_free_empty_block(&mut self, block_no: u64) -> CachedBlock {
        assert!(!self.is_pinned(block_no));

        let block = CachedBlock::new_empty(block_no, self.free_blocks.clone());
        block.inner.borrow_mut().state = BlockState::Dirty;
        block
    }

    pub fn discard_dirty(&mut self, block: CachedBlock) {
        let block_no = block.block_no();
        assert!(!self.is_pinned(block_no));

        if let Some(existing) = self.lru_cache.pop(&block_no) {
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

    pub fn total_blocks(&self) -> u64 {
        self.block_dev.num_blocks()
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
        let mut block = self.get_free_empty_block(block_no);

        self.block_dev
            .read_block(block_no, &mut block.block_mut())
            .await?;
        {
            let mut block_ref = block.inner.borrow_mut();
            block_ref.state = BlockState::Clean;
        }

        if let Some((_prev_block_no, prev_block)) = self.lru_cache.push(block_no, block.clone()) {
            debug_assert!(!prev_block.is_dirty());
        };
        Ok(block)
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&mut self, block_no: u64) -> CachedBlock {
        assert!(!self.is_pinned(block_no));

        if let Some(block) = self.lru_cache.get(&block_no) {
            let mut block_ref = block.inner.borrow_mut();
            if block_ref.state == BlockState::Flushing {
                todo!("detach flushing");
            }
            assert_eq!(block_ref.state, BlockState::Clean);
            block_ref.block.clear();
            block_ref.state = BlockState::Dirty;
            drop(block_ref);
            return block.clone();
        }

        let block = self.get_free_empty_block(block_no);
        if let Some((_prev_block_no, prev_block)) = self.lru_cache.push(block_no, block.clone()) {
            debug_assert!(!prev_block.is_dirty());
        };
        block
    }

    pub async fn write_block_if_dirty(&mut self, block: CachedBlock) -> Result<()> {
        let block_ref = block.inner.borrow();
        if block_ref.state != BlockState::Dirty {
            return Ok(());
        }

        let block_no = block_ref.block_no;
        drop(block_ref);
        assert!(!self.is_pinned(block_no));

        let flusher = FlushingBlock::new(block.inner.clone());

        #[cfg(feature = "moto-rt")]
        self.completion_sink
            .send(BackgroundMessage::Block((block_no, flusher)))
            .await
            .unwrap_or_else(|_e| panic!()); // Impossible; but we can't just unwrap().

        #[cfg(not(feature = "moto-rt"))]
        {
            let completion = self
                .block_dev
                .write_block_with_completion(block_no, flusher)
                .await?;
            completion.await?;
        }

        Ok(())
    }

    pub async fn start_flushing(&mut self) {
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
