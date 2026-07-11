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

use core::cell::{Cell, RefCell};
use core::num::NonZero;
use core::task::{Poll, Waker};
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

#[cfg(not(target_os = "motor"))]
use fittings::iobuf::IoBuf;
#[cfg(target_os = "motor")]
use moto_tooling::iobuf::IoBuf;

const MAX_COMPLETIONS_IN_FLIGHT: usize = 64;

use crate::block_device::MAX_IO_RUN;

pub struct BlockHolder {
    iobuf: IoBuf,
}

impl AsMut<IoBuf> for BlockHolder {
    fn as_mut(&mut self) -> &mut IoBuf {
        &mut self.iobuf
    }
}

impl AsRef<IoBuf> for BlockHolder {
    fn as_ref(&self) -> &IoBuf {
        &self.iobuf
    }
}

impl BlockHolder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            iobuf: IoBuf::new_from_size_align(4096).unwrap(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.iobuf.as_ref()
    }

    pub fn as_block_mut(&mut self) -> &mut Block {
        let bytes_mut = self.iobuf.raw_ptr_mut();
        debug_assert!(!bytes_mut.is_null());
        debug_assert_eq!(0, (bytes_mut as usize) & 4095);
        debug_assert_eq!(self.iobuf.len(), 4096);

        // SAFETY: safe by construction.
        unsafe {
            (bytes_mut as *mut _ as usize as *mut Block)
                .as_mut()
                .unwrap_unchecked()
        }
    }

    pub fn as_block(&self) -> &Block {
        let bytes = self.iobuf.raw_ptr();
        debug_assert!(!bytes.is_null());
        debug_assert_eq!(0, (bytes as usize) & 4095);
        debug_assert_eq!(self.iobuf.len(), 4096);

        // SAFETY: safe by construction.
        unsafe {
            (bytes as *const _ as usize as *const Block)
                .as_ref()
                .unwrap_unchecked()
        }
    }

    pub fn clear(&mut self) {
        self.as_mut().clear();
    }
}

// Panics if dropped when dirty (= dirty_block.is_some()).
struct InnerCachedBlock {
    block_no: u64,

    dirty_block: Option<BlockHolder>,
    clean_block: Rc<BlockHolder>,

    supporting_caches: Rc<RefCell<SupportingCaches>>,
}

impl Drop for InnerCachedBlock {
    fn drop(&mut self) {
        if self.dirty_block.is_some() {
            panic!("Block 0x{:x} is dirty when dropped.", self.block_no)
        }

        let mut caches = self.supporting_caches.borrow_mut();
        caches.clear_expiring_block(self.block_no);
        if Rc::strong_count(&self.clean_block) == 1 {
            caches.push_free_block(self.clean_block.clone());
        }
        // else: the block data is still referenced, e.g. by a CheckpointedBlock
        // held by the background writer; the last holder returns it to the
        // free list when it drops (see CheckpointedBlock::drop).
    }
}

/// Holder of a block to be written to BD.
#[derive(Clone)]
pub struct CheckpointedBlock {
    block: Rc<BlockHolder>, // This is what we are writing.

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

impl AsRef<IoBuf> for CheckpointedBlock {
    fn as_ref(&self) -> &IoBuf {
        self.block.as_ref().as_ref()
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
                let block_ref: &mut Block = Rc::get_mut(&mut block).unwrap().as_block_mut();
                *block_ref = *self.block.as_ref().as_block();
            }
            core::mem::swap(&mut block, &mut self.block);
        }
        Rc::get_mut(&mut self.block).unwrap().as_block_mut()
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
        clean_block: Rc<BlockHolder>,
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
                dirty.as_block()
            } else {
                inner.clean_block.as_ref().as_block()
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
            *box_copy.as_block_mut() = *block_ref.clean_block.as_ref().as_block();
            block_ref.dirty_block = Some(box_copy);
        }

        core::cell::RefMut::map(block_ref, |inner| {
            inner.dirty_block.as_mut().unwrap().as_block_mut()
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
    /// Write blocks to consecutive device blocks starting at the given one.
    WriteBlocks((u64, Vec<CheckpointedBlock>)),
    Commit,

    #[cfg(target_os = "motor")]
    Flush(moto_async::oneshot::Sender<()>),

    #[cfg(not(target_os = "motor"))]
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl core::fmt::Debug for BackgroundMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WriteBlocks(_) => f.debug_tuple("WriteBlocks").finish(),
            Self::Commit => write!(f, "Commit"),
            Self::Flush(_) => f.debug_tuple("Flush").finish(),
        }
    }
}

struct SupportingCaches {
    free_blocks: Vec<Rc<BlockHolder>>,
    expiring_blocks: BTreeMap<u64, Weak<RefCell<InnerCachedBlock>>>,
}

impl SupportingCaches {
    fn push_free_block(&mut self, block: Rc<BlockHolder>) {
        self.free_blocks.push(block);
    }

    fn pop_free_block(&mut self) -> Rc<BlockHolder> {
        self.free_blocks
            .pop()
            .unwrap_or_else(|| Rc::new(BlockHolder::new()))
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
        self.write_blocks(block_no, Vec::from([block])).await
    }

    /// Write `blocks.len()` consecutive device blocks starting at
    /// `first_block_no` (one scatter-gather request on devices that support
    /// it). Durability is not awaited here; see [`Self::commit`].
    pub async fn write_blocks(
        &self,
        first_block_no: u64,
        blocks: Vec<CheckpointedBlock>,
    ) -> Result<()> {
        self.completion_sink
            .send(BackgroundMessage::WriteBlocks((first_block_no, blocks)))
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

/// A device read in flight; concurrent `get_block()` callers for the same
/// block number wait on this instead of issuing a duplicate device read
/// (which would also create a second, divergent `CachedBlock` identity for
/// the same on-disk block).
#[derive(Default)]
struct PendingRead {
    wakers: Vec<Waker>,
}

/// LRU-based block cache.
///
/// All methods take `&self`: the cache supports concurrent (cooperatively
/// interleaved, single-threaded) readers. Interior borrows are never held
/// across an await; concurrent misses of the same block are deduplicated via
/// `pending_reads`.
pub struct BlockCache<BD: AsyncBlockDevice> {
    block_dev: Rc<BD>,
    #[allow(unused)]
    cache_size: usize,

    // The main cache.
    lru_cache: RefCell<LruCache<u64, CachedBlock>>,
    supporting_caches: Rc<RefCell<SupportingCaches>>,

    // Device reads in flight, keyed by block number.
    pending_reads: RefCell<BTreeMap<u64, PendingRead>>,

    async_stub: AsyncStub,

    cache_misses: Cell<u64>,
    cache_hits: Cell<u64>,
    dedup_waits: Cell<u64>,

    // Pinned blocks are always cached. Used by txn log.
    pinned_blocks_start: u64,
    pinned_blocks_num: usize,
    pinned_blocks: Vec<CachedBlock>,

    // Block 0.
    superblock: CachedBlock,
}

/// Counters of [`BlockCache::get_block`] outcomes, for diagnostics.
/// Every `get_block` call increments exactly one of these.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockCacheStats {
    /// Served from the cache without waiting.
    pub hits: u64,
    /// Read from the device by this call.
    pub misses: u64,
    /// Waited for another task's in-flight device read of the same block.
    pub dedup_waits: u64,
}

/// Cancel-safety for pending-read deduplication: whatever happens to the
/// first reader (success, device error, or its future being dropped at the
/// await point), the pending entry must be removed and the waiters woken so
/// one of them can retry.
struct PendingReadGuard<'a, BD: AsyncBlockDevice> {
    cache: &'a BlockCache<BD>,
    block_no: u64,
}

impl<BD: AsyncBlockDevice> Drop for PendingReadGuard<'_, BD> {
    fn drop(&mut self) {
        let pending = self
            .cache
            .pending_reads
            .borrow_mut()
            .remove(&self.block_no);
        // Wake outside of the borrow.
        if let Some(pending) = pending {
            for waker in pending.wakers {
                waker.wake();
            }
        }
    }
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
                        BackgroundMessage::WriteBlocks((first_block_no, flushing_blocks)) => {
                            let c = bd
                                .write_blocks_with_completion(first_block_no, flushing_blocks)
                                .await
                                .unwrap_or_else(|_| panic!("Error writing blocks to the device"));
                            completions.push_back(c);
                        }
                        BackgroundMessage::Commit => {
                            while let Some(c) = completions.pop_front() {
                                let (blocks, result) = c.await;
                                if let Err(err) = result {
                                    log::error!(
                                        "Failed to write {} blocks at 0x{:x}: {err:?}.",
                                        blocks.len(),
                                        blocks
                                            .first()
                                            .map(|b| b.inner.borrow().block_no)
                                            .unwrap_or(u64::MAX)
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
            let (block, result) = block_dev.read_block(block_no, BlockHolder::new()).await;

            result.inspect_err(|err| {
                log::error!("Error reading block 0x{block_no:x}: {err:?}.");
            })?;

            pinned_blocks.push(CachedBlock::new(
                block_no,
                Rc::new(block),
                supporting_caches.clone(),
            ));
        }

        let (block, result) = block_dev.read_block(0, BlockHolder::new()).await;

        result.inspect_err(|err| {
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
            lru_cache: RefCell::new(LruCache::new(NonZero::new(cache_size).unwrap())),
            supporting_caches,
            pending_reads: RefCell::new(BTreeMap::new()),
            async_stub,
            cache_misses: Cell::new(0),
            cache_hits: Cell::new(0),
            dedup_waits: Cell::new(0),
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

    fn push_block(&self, block_no: u64, block: CachedBlock) {
        assert_ne!(0, block_no);

        let evicted = self.lru_cache.borrow_mut().push(block_no, block.clone());
        if let Some((prev_block_no, prev_block)) = evicted {
            // LruCache::push() also returns the previous value if the key was
            // already present; that must not happen here (it would mean two
            // CachedBlock identities exist for one on-disk block).
            debug_assert_ne!(prev_block_no, block_no);
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

    /// The synchronous fast path of get_block(): the block is pinned, cached,
    /// or expiring. Never awaits, never leaves a borrow live on return.
    fn get_cached(&self, block_no: u64) -> Option<CachedBlock> {
        if block_no == 0 {
            return Some(self.superblock.clone());
        }

        if self.is_pinned(block_no) {
            return Some(
                self.pinned_blocks[(block_no - self.pinned_blocks_start) as usize].clone(),
            );
        }

        if let Some(block) = self.lru_cache.borrow_mut().get(&block_no) {
            return Some(block.clone());
        }

        let expiring_block = self
            .supporting_caches
            .borrow_mut()
            .pop_expiring_block(block_no);

        if let Some(block) = expiring_block {
            let cached_block = CachedBlock { inner: block };
            self.push_block(block_no, cached_block.clone());
            return Some(cached_block);
        }

        None
    }

    /// Try to become the (sole) task reading `block_no` from the device.
    fn try_claim_pending_read(&self, block_no: u64) -> bool {
        let mut claimed = false;
        self.pending_reads
            .borrow_mut()
            .entry(block_no)
            .or_insert_with(|| {
                claimed = true;
                PendingRead::default()
            });
        claimed
    }

    /// Wait until the in-flight device read of `block_no` (if any) completes
    /// (successfully or not).
    async fn wait_pending_read(&self, block_no: u64) {
        core::future::poll_fn(|cx| {
            let mut pending = self.pending_reads.borrow_mut();
            if let Some(p) = pending.get_mut(&block_no) {
                if !p.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                    p.wakers.push(cx.waker().clone());
                }
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await
    }

    /// Counters of `get_block` outcomes since creation. Diagnostics only.
    pub fn cache_stats(&self) -> BlockCacheStats {
        BlockCacheStats {
            hits: self.cache_hits.get(),
            misses: self.cache_misses.get(),
            dedup_waits: self.dedup_waits.get(),
        }
    }

    /// Whether `block_no` is currently cached, without promoting it in the
    /// LRU order or reading it from the device. Used by readahead to skip
    /// already-cached windows.
    pub fn is_cached(&self, block_no: u64) -> bool {
        block_no == 0 || self.is_pinned(block_no) || self.lru_cache.borrow().contains(&block_no)
    }

    /// Get a reference to a cached block.
    pub async fn get_block(&self, block_no: u64) -> Result<CachedBlock> {
        let mut waited = false;
        loop {
            if let Some(block) = self.get_cached(block_no) {
                if waited {
                    self.dedup_waits.set(self.dedup_waits.get() + 1);
                } else {
                    self.cache_hits.set(self.cache_hits.get() + 1);
                }
                return Ok(block);
            }

            // The block must be read from the device. If another task is
            // already reading it, wait for that read and re-check the cache;
            // otherwise claim the read for ourselves.
            if self.try_claim_pending_read(block_no) {
                break;
            }
            waited = true;
            self.wait_pending_read(block_no).await;
        }

        // We hold the pending-read claim for block_no. The guard releases the
        // claim and wakes waiters on every exit path, including cancellation.
        let _guard = PendingReadGuard {
            cache: self,
            block_no,
        };

        self.cache_misses.set(self.cache_misses.get() + 1);
        let rc_block = self.supporting_caches.borrow_mut().pop_free_block();
        let Ok(block) = Rc::try_unwrap(rc_block) else {
            panic!()
        };

        let (block, result) = self.block_dev.read_block(block_no, block).await;
        if let Err(err) = result {
            self.supporting_caches
                .borrow_mut()
                .push_free_block(Rc::new(block));
            return Err(err);
        }
        let cached_block =
            CachedBlock::new(block_no, Rc::new(block), self.supporting_caches.clone());

        // Publish the block before the guard wakes the waiters (on drop), so
        // that they find it in the cache.
        self.push_block(block_no, cached_block.clone());

        Ok(cached_block)
    }

    /// Read `count` consecutive device blocks starting at `first_block_no`
    /// into the cache with as few device requests as possible: blocks that
    /// are cached or already being read are skipped, and each remaining run
    /// (up to [`MAX_IO_RUN`] blocks) is read with one scatter-gather
    /// device request. Best-effort: device errors are swallowed here —
    /// waiters retry via `get_block` and surface them there.
    pub async fn prefetch_range(&self, first_block_no: u64, count: u64) {
        let end = first_block_no + count;
        let mut next = first_block_no;
        while next < end {
            // Skip blocks that are cached or have a device read in flight.
            // (`get_cached`, not `is_cached`: it also resurrects expiring
            // blocks, which must not be re-read into a second identity.)
            if self.get_cached(next).is_some()
                || self.pending_reads.borrow().contains_key(&next)
            {
                next += 1;
                continue;
            }

            // Claim a maximal run of blocks needing a device read. No awaits
            // while claiming, so the checks cannot go stale.
            let run_first = next;
            let mut guards: Vec<PendingReadGuard<'_, BD>> = Vec::new();
            while next < end
                && guards.len() < MAX_IO_RUN
                && self.get_cached(next).is_none()
                && self.try_claim_pending_read(next)
            {
                guards.push(PendingReadGuard {
                    cache: self,
                    block_no: next,
                });
                next += 1;
            }
            debug_assert!(!guards.is_empty());

            self.read_claimed_run(run_first, guards.len()).await;
            // The guards drop here: pending entries are removed and their
            // waiters woken — after the blocks were published above.
        }
    }

    /// Read `count` blocks at `first_block_no` — all claimed in
    /// `pending_reads` by the caller — with one device request, and publish
    /// them in the cache.
    async fn read_claimed_run(&self, first_block_no: u64, count: usize) {
        let mut bufs = Vec::with_capacity(count);
        for _ in 0..count {
            let rc_block = self.supporting_caches.borrow_mut().pop_free_block();
            let Ok(block) = Rc::try_unwrap(rc_block) else {
                panic!()
            };
            bufs.push(block);
        }

        self.cache_misses
            .set(self.cache_misses.get() + count as u64);
        let (bufs, result) = self.block_dev.read_blocks(first_block_no, bufs).await;
        match result {
            Ok(()) => {
                for (idx, block) in bufs.into_iter().enumerate() {
                    let block_no = first_block_no + idx as u64;
                    let cached_block = CachedBlock::new(
                        block_no,
                        Rc::new(block),
                        self.supporting_caches.clone(),
                    );
                    self.push_block(block_no, cached_block);
                }
            }
            Err(err) => {
                log::error!(
                    "Error reading {count} blocks at 0x{first_block_no:x}: {err:?}."
                );
                let mut caches = self.supporting_caches.borrow_mut();
                for block in bufs {
                    caches.push_free_block(Rc::new(block));
                }
            }
        }
    }

    /// Get an empty block. Use with caution: any previously stored
    /// data in the block on the block device will be lost.
    pub fn get_empty_block(&self, block_no: u64) -> CachedBlock {
        assert_ne!(0, block_no);
        assert!(!self.is_pinned(block_no));
        // Only the (exclusive) write path uses empty blocks, and freshly
        // allocated blocks are never concurrently read.
        debug_assert!(!self.pending_reads.borrow().contains_key(&block_no));

        let cached = self.lru_cache.borrow_mut().get(&block_no).cloned();
        if let Some(block) = cached {
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
    pub fn debug_check_clean(&self) {
        for (block_no, block) in self.lru_cache.borrow().iter() {
            assert!(!block.is_dirty(), "Block {block_no} is dirty.");
        }
    }
}
