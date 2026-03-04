//! Block cache for async block devices.
//!
//! The interface could probably be made cleaner/simpler, but
//! the overall design tries to ensure that modified blocks must
//! be saved or have the modifications explicitly discarded.

#![allow(clippy::redundant_allocation)]

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

const MAX_COMPLETIONS_IN_FLIGHT: usize = 128;

// Panics if dropped when dirty (= dirty_block.is_some()).
struct InnerCachedBlock {
    block_no: u64,

    dirty_block: Option<Box<Block>>,
    clean_block: Rc<Box<Block>>,

    supporting_caches: Rc<RefCell<SupportingCaches>>,
}

impl Drop for InnerCachedBlock {
    fn drop(&mut self) {
        if self.dirty_block.is_some() {
            panic!("Block 0x{:x} is dirty when dropped.", self.block_no)
        }

        if Rc::strong_count(&self.clean_block) == 1 {
            let mut caches = self.supporting_caches.borrow_mut();
            caches.push_free_block(self.clean_block.clone());
            caches.clear_expiring_block(self.block_no);
        } else {
            todo!()
            // self.supporting_caches
            //     .borrow_mut()
            //     .push_expiring_block(self.block_no, &self.clean_block);
        }
    }
}

/// Holder of a block to be written to BD.
#[derive(Clone)]
pub struct CheckpointedBlock {
    block: Rc<Box<Block>>, // This is what we are writing.

    // Need to keep a reference of the cached block, otherwise
    // it may get dropped and a read will return old data.
    inner: Rc<RefCell<InnerCachedBlock>>,
    caches: Rc<RefCell<SupportingCaches>>,
}

impl AsRef<[u8]> for CheckpointedBlock {
    fn as_ref(&self) -> &[u8] {
        self.block.as_bytes()
    }
}

impl CheckpointedBlock {
    pub fn new(cached_block: &CachedBlock) -> Self {
        debug_assert!(!cached_block.is_dirty());

        let block = cached_block.inner.borrow().clean_block.clone();
        Self {
            block,
            inner: cached_block.inner.clone(),
            caches: cached_block.inner.borrow().supporting_caches.clone(),
        }
    }

    pub fn block_mut(&mut self) -> &mut Block {
        if Rc::strong_count(&self.block) > 1 {
            let mut block = self.caches.borrow_mut().pop_free_block();
            {
                let block_ref: &mut Block = Rc::get_mut(&mut block).unwrap().as_mut();
                *block_ref = **self.block;
            }
            core::mem::swap(&mut block, &mut self.block);
        }
        Rc::get_mut(&mut self.block).unwrap().as_mut()
    }
}

impl Drop for CheckpointedBlock {
    fn drop(&mut self) {
        if Rc::strong_count(&self.block) == 1 {
            let mut caches = self.caches.borrow_mut();
            caches.push_free_block(self.block.clone());
        }
    }
}

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
        if block_ref.dirty_block.is_none() {
            let rc_copy = block_ref.supporting_caches.borrow_mut().pop_free_block();
            let Ok(mut box_copy) = Rc::try_unwrap(rc_copy) else {
                panic!();
            };
            *box_copy = **block_ref.clean_block;
            block_ref.dirty_block = Some(box_copy);
        }

        core::cell::RefMut::map(block_ref, |inner| {
            inner.dirty_block.as_mut().unwrap().as_mut()
        })
    }

    pub fn is_dirty(&self) -> bool {
        self.inner.borrow().dirty_block.is_some()
    }

    #[inline(always)]
    pub fn unique_id(&self) -> usize {
        Rc::as_ptr(&self.inner) as usize
    }

    pub fn consume_dirty(&self) {
        let mut inner_ref = self.inner.borrow_mut();

        let dirty = inner_ref.dirty_block.take().unwrap();
        let dirty = Rc::new(dirty);
        let mut clean = dirty.clone();
        core::mem::swap(&mut clean, &mut inner_ref.clean_block);
        if Rc::strong_count(&clean) == 1 {
            inner_ref
                .supporting_caches
                .borrow_mut()
                .push_free_block(clean);
        }
    }

    pub fn discard_dirty(&self) {
        let mut block_ref = self.inner.borrow_mut();
        let dirty = block_ref.dirty_block.take().unwrap();
        block_ref
            .supporting_caches
            .borrow_mut()
            .push_free_block(Rc::new(dirty));
    }
}

enum BackgroundMessage {
    WriteBlock((u64, CheckpointedBlock)),
    Commit,

    #[cfg(target_os = "motor")]
    Flush(moto_async::oneshot::Sender<()>),

    #[cfg(not(target_os = "motor"))]
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl core::fmt::Debug for BackgroundMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WriteBlock(_) => f.debug_tuple("WriteBlock").finish(),
            Self::Commit => write!(f, "Commit"),
            Self::Flush(_) => f.debug_tuple("Flush").finish(),
        }
    }
}

struct SupportingCaches {
    free_blocks: Vec<Rc<Box<Block>>>,
    expiring_blocks: BTreeMap<u64, Weak<RefCell<InnerCachedBlock>>>,
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

    fn push_expiring_block(&mut self, block_no: u64, block: &Rc<RefCell<InnerCachedBlock>>) {
        self.expiring_blocks.insert(block_no, Rc::downgrade(block));
    }

    fn pop_expiring_block(&mut self, block_no: u64) -> Option<Rc<RefCell<InnerCachedBlock>>> {
        self.expiring_blocks
            .remove(&block_no)
            .and_then(|weak| weak.upgrade())
    }

    fn clear_expiring_block(&mut self, block_no: u64) {
        self.expiring_blocks.remove(&block_no);
    }
}

#[derive(Clone)]
pub struct AsyncStub {
    num_blocks: u64,

    #[cfg(target_os = "motor")]
    completion_sink: moto_async::channel::Sender<BackgroundMessage>,
    #[cfg(not(target_os = "motor"))]
    completion_sink: tokio::sync::mpsc::Sender<BackgroundMessage>,
}

impl AsyncStub {
    pub async fn write_block(&self, block_no: u64, block: CheckpointedBlock) -> Result<()> {
        self.completion_sink
            .send(BackgroundMessage::WriteBlock((block_no, block)))
            .await
            .unwrap();
        Ok(())
    }

    pub async fn commit(&self) {
        self.completion_sink
            .send(BackgroundMessage::Commit)
            .await
            .unwrap_or_else(|_e| panic!()); // Impossible; but we can't just unwrap().
    }

    pub async fn flush(&self) -> Result<()> {
        #[cfg(target_os = "motor")]
        let (sender, receiver) = moto_async::oneshot();

        #[cfg(not(target_os = "motor"))]
        let (sender, receiver) = tokio::sync::oneshot::channel();

        self.completion_sink
            .send(BackgroundMessage::Flush(sender))
            .await
            .unwrap();

        // We need to wait for flush to complete.
        receiver.await.unwrap();

        Ok(())
    }

    pub fn num_blocks(&self) -> u64 {
        self.num_blocks
    }
}

/// LRU-based block cache.
pub struct BlockCache<BD: AsyncBlockDevice> {
    block_dev: Rc<BD>,
    #[allow(unused)]
    cache_size: usize,

    // The main cache.
    lru_cache: LruCache<u64, CachedBlock>,
    supporting_caches: Rc<RefCell<SupportingCaches>>,

    async_stub: AsyncStub,

    #[allow(unused)]
    cache_misses: u64,

    // Pinned blocks are always cached. Used by txn log.
    pinned_blocks_start: u64,
    pinned_blocks_num: usize,
    pinned_blocks: Vec<CachedBlock>,

    // Block 0.
    superblock: CachedBlock,
}

impl<BD: AsyncBlockDevice + 'static> BlockCache<BD> {
    pub async fn new(
        block_dev: Box<BD>,
        cache_size: usize,
        pinned_blocks_start: u64,
        pinned_blocks_num: usize,
    ) -> Result<Self> {
        let block_dev: Rc<BD> = Rc::from(block_dev);

        let sender = {
            #[cfg(target_os = "motor")]
            let (sender, mut receiver) = moto_async::channel(MAX_COMPLETIONS_IN_FLIGHT);

            #[cfg(not(target_os = "motor"))]
            let (sender, mut receiver) = tokio::sync::mpsc::channel(MAX_COMPLETIONS_IN_FLIGHT);

            let bd = block_dev.clone();
            let background_task = async move {
                #[cfg(not(feature = "std"))]
                use alloc::collections::VecDeque;

                #[cfg(feature = "std")]
                use std::collections::VecDeque;

                let mut completions: VecDeque<BD::Completion> = VecDeque::new();
                while let Some(msg) = receiver.recv().await {
                    match msg {
                        BackgroundMessage::WriteBlock((block_no, flushing_block)) => {
                            let c = bd
                                .write_block_with_completion(block_no, flushing_block)
                                .await
                                .unwrap_or_else(|_| panic!("Error writing block to the device"));
                            completions.push_back(c);
                        }
                        BackgroundMessage::Commit => {
                            while let Some(c) = completions.pop_front() {
                                let (block, result) = c.await;
                                if let Err(err) = result {
                                    log::error!(
                                        "Failed to write block 0x{:x}: {err:?}.",
                                        block.inner.borrow().block_no
                                    );
                                }
                            }
                        }
                        BackgroundMessage::Flush(sender) => {
                            let _ = bd.flush().await;
                            log::debug!("BD: flushed.");
                            sender.send(()).unwrap();
                        }
                    }
                }
            };

            #[cfg(target_os = "motor")]
            let _handle = moto_async::LocalRuntime::spawn(background_task);

            #[cfg(not(target_os = "motor"))]
            let _handle = tokio::task::spawn_local(background_task);

            sender
        };

        let supporting_caches = Rc::new(RefCell::new(SupportingCaches {
            free_blocks: Vec::new(),
            expiring_blocks: BTreeMap::new(),
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

        let mut block = Box::new(Block::new_zeroed());
        block_dev
            .read_block(0, &mut block)
            .await
            .inspect_err(|err| {
                log::error!("Error reading superblock: {err:?}.");
            })?;
        let superblock = CachedBlock::new(0, Rc::new(block), supporting_caches.clone());

        let async_stub = AsyncStub {
            num_blocks: block_dev.num_blocks(),
            completion_sink: sender,
        };

        Ok(Self {
            block_dev,
            cache_size,
            lru_cache: LruCache::new(NonZero::new(cache_size).unwrap()),
            supporting_caches,
            async_stub,
            cache_misses: 0,
            pinned_blocks_start,
            pinned_blocks_num,
            pinned_blocks,
            superblock,
        })
    }

    pub fn async_stub(&self) -> AsyncStub {
        self.async_stub.clone()
    }

    fn is_pinned(&self, block_no: u64) -> bool {
        block_no >= self.pinned_blocks_start
            && (block_no < (self.pinned_blocks_start + self.pinned_blocks_num as u64))
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
        assert_ne!(0, block_no);

        if let Some((prev_block_no, prev_block)) = self.lru_cache.push(block_no, block.clone()) {
            let prev_ref = prev_block.inner.borrow();
            if 1 == Rc::strong_count(&prev_block.inner) {
                assert!(prev_ref.dirty_block.is_none());
            } else {
                drop(prev_ref);
                self.supporting_caches
                    .borrow_mut()
                    .push_expiring_block(prev_block_no, &prev_block.inner);
            }
        };
    }

    /// Get a reference to a cached block.
    pub async fn get_block(&mut self, block_no: u64) -> Result<CachedBlock> {
        if block_no == 0 {
            return Ok(self.superblock.clone());
        }

        if self.is_pinned(block_no) {
            return Ok(self.pinned_blocks[(block_no - self.pinned_blocks_start) as usize].clone());
        }
        if let Some(block) = self.lru_cache.get(&block_no) {
            return Ok(block.clone());
        }

        let expiring_block = self
            .supporting_caches
            .borrow_mut()
            .pop_expiring_block(block_no);

        if let Some(block) = expiring_block {
            let cached_block = CachedBlock { inner: block };
            self.push_block(block_no, cached_block.clone());
            return Ok(cached_block);
        }

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
        assert_ne!(0, block_no);
        assert!(!self.is_pinned(block_no));

        if let Some(block) = self.lru_cache.get(&block_no) {
            let mut clone = block.clone();
            clone.block_mut().clear();
            return clone;
        }

        let expiring_block = self
            .supporting_caches
            .borrow_mut()
            .pop_expiring_block(block_no);

        if let Some(block) = expiring_block {
            let mut cached_block = CachedBlock { inner: block };
            cached_block.block_mut().clear();
            self.push_block(block_no, cached_block.clone());
            return cached_block;
        }

        let mut block = self.supporting_caches.borrow_mut().pop_free_block();
        Rc::get_mut(&mut block).unwrap().clear();
        let mut block = CachedBlock::new(block_no, block, self.supporting_caches.clone());
        block.block_mut().clear();
        self.push_block(block_no, block.clone());
        block
    }

    #[cfg(debug_assertions)]
    pub fn debug_check_clean(&mut self) {
        for (block_no, block) in self.lru_cache.iter() {
            assert!(!block.is_dirty(), "Block {block_no} is dirty.");
        }
    }
}
