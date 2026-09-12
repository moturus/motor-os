use core::sync::atomic::{AtomicUsize, Ordering};
use std::boxed::Box;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use crate::block::Block;
use crate::sync::{ReaderShard, RwLock, SHARDS, SpinLock};

fn shards() -> [ReaderShard; SHARDS] {
    [const { ReaderShard::new() }; SHARDS]
}

#[test]
fn rwlock_readers_share_and_exclude_writers() {
    let lock = RwLock::new();
    let shards = shards();
    lock.read_lock(&shards[0]);
    assert!(lock.try_read_lock(&shards[3]));
    assert!(!lock.is_write_locked());
    lock.read_unlock(&shards[0]);
    lock.read_unlock(&shards[3]);

    assert!(lock.try_write_lock(&shards));
    assert!(!lock.try_read_lock(&shards[5]));
    assert!(!lock.try_write_lock(&shards));
    lock.write_unlock();
    assert!(lock.try_read_lock(&shards[5]));
    lock.read_unlock(&shards[5]);
}

#[test]
fn rwlock_writer_waits_for_readers_to_drain() {
    // The reader sits in the last shard; the writer must drain them all.
    let lock = Arc::new((RwLock::new(), shards()));
    lock.0.read_lock(&lock.1[SHARDS - 1]);
    let writer = {
        let lock = lock.clone();
        std::thread::spawn(move || {
            lock.0.write_lock(&lock.1);
            let held = lock.0.is_write_locked();
            lock.0.write_unlock();
            held
        })
    };
    // Once the writer has taken its bit it cannot proceed, and new readers
    // back off. Wait for the bit rather than for a fixed time.
    let start = std::time::Instant::now();
    while !lock.0.is_write_locked() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "writer never took its bit"
        );
        std::thread::yield_now();
    }
    assert!(!lock.0.try_read_lock(&lock.1[0]));
    lock.0.read_unlock(&lock.1[SHARDS - 1]);
    assert!(writer.join().unwrap());
    lock.0.read_lock(&lock.1[0]);
    lock.0.read_unlock(&lock.1[0]);
}

#[test]
fn spinlock_excludes() {
    static LOCK: SpinLock = SpinLock::new();
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..10_000 {
                    let _guard = LOCK.lock();
                    let v = COUNT.load(Ordering::Relaxed);
                    COUNT.store(v + 1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(COUNT.load(Ordering::Relaxed), 80_000);
    assert!(!LOCK.is_locked());
}

fn synthetic_block(entry_sz_log2: u32) -> (Box<Block>, Vec<u8>) {
    let mut data = vec![0u8; Block::ENTRIES << entry_sz_log2];
    let mut block: Box<Block> = unsafe { Box::new(core::mem::zeroed()) };
    block.init(entry_sz_log2, 0, 1, data.as_mut_ptr());
    (block, data)
}

#[test]
fn block_alloc_fills_in_order_and_reports_transitions() {
    let (block, data) = synthetic_block(5);
    assert!(block.is_empty());
    let mut expected = data.as_ptr() as usize;
    for slot in 0..Block::ENTRIES {
        let (ptr, became_full) = block.alloc().unwrap();
        assert_eq!(ptr as usize, expected);
        assert_eq!(became_full, slot == Block::ENTRIES - 1);
        expected += 32;
    }
    assert!(block.is_full());
    assert!(block.alloc().is_none());

    let ptr = unsafe { data.as_ptr().add(32 * 13) } as *mut u8;
    assert!(block.dealloc(ptr));
    assert!(!block.is_full());
    assert_eq!(block.alloc().unwrap(), (ptr, true));
    assert!(block.dealloc(ptr));
    assert!(!block.dealloc(unsafe { data.as_ptr().add(32 * 7) } as *mut u8));
    drop(data);
}

#[test]
fn block_rejects_foreign_and_misaligned_pointers() {
    let (block, data) = synthetic_block(4);
    let base = data.as_ptr() as *mut u8;
    assert_eq!(block.slot_of(base), Some(0));
    assert_eq!(block.slot_of(unsafe { base.add(16 * 63) }), Some(63));
    assert_eq!(block.slot_of(unsafe { base.add(16 * 64) }), None);
    assert_eq!(block.slot_of(unsafe { base.add(8) }), None);
    assert_eq!(block.slot_of(unsafe { base.sub(16) }), None);
    drop(data);
}

#[test]
#[should_panic(expected = "double free")]
fn block_double_free_panics() {
    let (block, data) = synthetic_block(4);
    let (ptr, _) = block.alloc().unwrap();
    block.dealloc(ptr);
    block.dealloc(ptr);
    drop(data);
}

#[test]
#[should_panic(expected = "bad ptr")]
fn block_foreign_free_panics() {
    let (block, data) = synthetic_block(4);
    block.dealloc(unsafe { (data.as_ptr() as *mut u8).add(8) });
    drop(data);
}

#[test]
fn block_flags_and_links_start_clear() {
    let (block, data) = synthetic_block(4);
    assert!(!block.on_stack());
    assert!(block.owner.load(Ordering::Relaxed).is_null());
    assert!(block.partial_next.load(Ordering::Relaxed).is_null());
    block.set_on_stack(true);
    assert!(block.on_stack());
    assert_eq!(block.entry_size(), 16);
    assert_eq!(block.block_size(), 1024);
    drop(data);
}

// ---- slab ----

use crate::slab::{INDEX_MIN_CAP, Slab};

/// Blocks for a synthetic slab: `batches` batches of `per_batch` contiguous
/// 1 KiB blocks (16-byte entries), each batch its own buffer, descriptors
/// kept alive by the returned vectors.
struct SyntheticSlab {
    slab: Box<Slab>,
    descriptors: Vec<Box<[Block]>>,
    buffers: Vec<Vec<u8>>,
    index: Vec<*mut Block>,
}

impl SyntheticSlab {
    fn new(batches: usize, per_batch: usize) -> Self {
        let slab = Box::new(Slab::new(4, 0));
        // Addresses in the first half of the array, block pointers in the
        // second: two words per entry.
        let mut index = Vec::with_capacity(2 * INDEX_MIN_CAP);
        index.resize(2 * INDEX_MIN_CAP, core::ptr::null_mut());
        slab.index_install(index.as_mut_ptr(), INDEX_MIN_CAP);
        let mut this = Self {
            slab,
            descriptors: Vec::new(),
            buffers: Vec::new(),
            index,
        };
        for _ in 0..batches {
            this.add_batch(per_batch);
        }
        this
    }

    /// Links and indexes one batch, and pushes its blocks on the stack.
    fn add_batch(&mut self, per_batch: usize) {
        let mut buffer = vec![0u8; per_batch * 1024];
        let mut descriptors: Box<[Block]> =
            unsafe { Box::new_zeroed_slice(per_batch).assume_init() };
        for (pos, block) in descriptors.iter_mut().enumerate() {
            block.init(4, pos as u16, per_batch as u16, unsafe {
                buffer.as_mut_ptr().add(pos * 1024)
            });
        }
        for pos in 0..per_batch - 1 {
            let next = &mut descriptors[pos + 1] as *mut Block;
            descriptors[pos].next.store(next, Ordering::Release);
        }
        let first = &mut descriptors[0] as *mut Block;
        let last = &mut descriptors[per_batch - 1] as *mut Block;
        self.slab.link_batch(first, last);
        self.slab.index_insert_batch(first, per_batch);
        for block in Slab::batch(first, per_batch) {
            self.slab.stack_push(block);
        }
        self.slab
            .bytes_total
            .fetch_add(per_batch * 1024, Ordering::Relaxed);
        self.descriptors.push(descriptors);
        self.buffers.push(buffer);
    }

    fn block(&self, batch: usize, pos: usize) -> *mut Block {
        &self.descriptors[batch][pos] as *const Block as *mut Block
    }
}

#[test]
fn slab_stack_push_is_idempotent_and_pop_clears() {
    let s = SyntheticSlab::new(1, 3);
    s.slab.check_stack();
    let top = s.slab.partial_head.load(Ordering::Relaxed);
    s.slab.stack_push(top);
    s.slab.stack_push(s.block(0, 1));
    s.slab.check_stack();
    assert_eq!(s.slab.stack_pop(), top);
    assert!(!unsafe { (*top).on_stack() });
    assert_eq!(s.slab.stack_pop(), s.block(0, 1));
    assert_eq!(s.slab.stack_pop(), s.block(0, 0));
    assert!(s.slab.stack_pop().is_null());
    assert!(s.slab.alloc().is_null());
}

#[test]
fn slab_alloc_drains_the_top_block_then_pops_it() {
    let s = SyntheticSlab::new(1, 2);
    let top = s.slab.partial_head.load(Ordering::Relaxed);
    let mut ptrs = Vec::new();
    for _ in 0..Block::ENTRIES {
        let p = s.slab.alloc();
        assert!(!p.is_null());
        assert_eq!(s.slab.lookup(p), top);
        ptrs.push(p);
    }
    assert!(unsafe { (*top).is_full() });
    assert!(!unsafe { (*top).on_stack() });
    s.slab.check_stack();
    let p = s.slab.alloc();
    assert_ne!(s.slab.lookup(p), top);
    // A free that makes the full block non-full is what pushes it back.
    assert!(unsafe { (*top).dealloc(ptrs[5]) });
    {
        let _lock = s.slab.partial_lock.lock();
        s.slab.stack_push(top);
    }
    s.slab.check_stack();
    assert_eq!(s.slab.alloc(), ptrs[5]);
    assert_eq!(s.slab.in_use_bytes(), (Block::ENTRIES + 1) * 16);
}

#[test]
fn slab_index_finds_every_block_boundary() {
    let s = SyntheticSlab::new(4, 3);
    s.slab.check_index();
    for batch in 0..4 {
        for pos in 0..3 {
            let block = s.block(batch, pos);
            let data = unsafe { (*block).data };
            assert_eq!(s.slab.lookup(data), block);
            assert_eq!(s.slab.lookup(unsafe { data.add(1023) }), block);
            assert_eq!(unsafe { (*block).slot_of(data.add(1023)) }, None);
            assert_eq!(unsafe { (*block).slot_of(data.add(1008)) }, Some(63));
        }
    }
    let lowest = s
        .slab
        .blocks()
        .map(|b| unsafe { (*b).data } as usize)
        .min()
        .unwrap();
    assert!(s.slab.lookup((lowest - 1) as *mut u8).is_null());
    assert!(s.slab.lookup(core::ptr::null_mut()).is_null());
}

#[test]
fn slab_index_probes_are_logarithmic() {
    let s = SyntheticSlab::new(16, 8);
    let blocks: Vec<*mut Block> = s.slab.blocks().collect();
    let before = crate::index_probes();
    for block in &blocks {
        assert_eq!(s.slab.lookup(unsafe { (**block).data }), *block);
    }
    let probes = crate::index_probes() - before;
    let bound = (128usize.ilog2() as usize + 1) * blocks.len();
    assert!(
        probes <= bound,
        "{probes} probes for {} lookups",
        blocks.len()
    );
}

#[test]
fn slab_index_growth_and_replacement_keep_entries() {
    let mut s = SyntheticSlab::new(1, 4);
    assert_eq!(s.slab.index_growth(INDEX_MIN_CAP - 4), None);
    assert_eq!(
        s.slab.index_growth(INDEX_MIN_CAP - 3),
        Some(2 * INDEX_MIN_CAP)
    );
    let mut bigger = vec![core::ptr::null_mut(); 2 * 2 * INDEX_MIN_CAP];
    let (old, old_cap) = s.slab.index_install(bigger.as_mut_ptr(), 2 * INDEX_MIN_CAP);
    assert_eq!(old, s.index.as_mut_ptr());
    assert_eq!(old_cap, INDEX_MIN_CAP);
    s.index = bigger;
    s.add_batch(2);
    s.slab.check_index();
    assert_eq!(s.slab.index_len.load(Ordering::Relaxed), 6);
}

#[test]
fn slab_rebuild_matches_incremental_state() {
    let mut s = SyntheticSlab::new(3, 2);
    // Take a few slots so the stack has full and non-full blocks.
    for _ in 0..Block::ENTRIES {
        assert!(!s.slab.alloc().is_null());
    }
    let full = s
        .slab
        .blocks()
        .filter(|b| unsafe { (**b).is_full() })
        .count();
    assert_eq!(full, 1);
    let stacked_before: Vec<*mut Block> = {
        let mut v = Vec::new();
        let mut cur = s.slab.partial_head.load(Ordering::Relaxed);
        while !cur.is_null() {
            v.push(cur);
            cur = unsafe { (*cur).partial_next.load(Ordering::Relaxed) };
        }
        v
    };
    // Drop the middle batch from the list as reclaim would, then rebuild.
    let first = s.block(1, 0);
    let after = unsafe { (*s.block(1, 1)).next.load(Ordering::Relaxed) };
    let mut prev = core::ptr::null_mut::<Block>();
    for block in s.slab.blocks() {
        if block == first {
            break;
        }
        prev = block;
    }
    unsafe { (*prev).next.store(after, Ordering::Release) };
    s.slab.index_rebuild();
    s.slab.stack_rebuild();
    s.slab.check_index();
    s.slab.check_stack();
    assert_eq!(s.slab.index_len.load(Ordering::Relaxed), 4);
    let mut stacked_after = 0;
    let mut cur = s.slab.partial_head.load(Ordering::Relaxed);
    while !cur.is_null() {
        assert!(stacked_before.contains(&cur));
        stacked_after += 1;
        cur = unsafe { (*cur).partial_next.load(Ordering::Relaxed) };
    }
    assert_eq!(stacked_after, 3);
    s.descriptors.remove(1);
    s.buffers.remove(1);
}

// ---- allocator ----

use core::alloc::{GlobalAlloc, Layout};
use std::time::Instant;

use crate::{Cache2M, Frusa, Frusa2M, Frusa4K};

/// How many data slabs `frusa` has.
fn num_slabs<const SLABS: usize>(_frusa: &Frusa<SLABS>) -> usize {
    SLABS
}

/// The largest allocation served inside rather than by the back end.
fn max_inside_size<const SLABS: usize>(_frusa: &Frusa<SLABS>) -> usize {
    Frusa::<SLABS>::MAX_SIZE
}

struct BackEndAllocator {}

unsafe impl Send for BackEndAllocator {}
unsafe impl Sync for BackEndAllocator {}

unsafe impl GlobalAlloc for BackEndAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static BACK_END: BackEndAllocator = BackEndAllocator {};

const PAGE: usize = 4096;

#[test]
fn test_init() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let slabs = num_slabs(&frusa.inner);
    // stats() forces the lazy init: one metadata page holding its own
    // descriptor and the slab table.
    // Reader shards for every slab take three more pages, and the free
    // lists of the data slabs another three.
    let shard_pages = ((slabs + 1) * SHARDS * 64).next_multiple_of(PAGE)
        + (slabs * SHARDS * 64).next_multiple_of(PAGE);
    let stats = frusa.stats();
    assert_eq!(PAGE + shard_pages, stats.allocated_from_fallback);
    assert_eq!(PAGE + shard_pages, stats.allocated_metadata);
    assert_eq!((slabs + 1) * 64, stats.in_use_metadata);
    assert_eq!(stats.in_use, stats.in_use_metadata);

    let layout = Layout::from_size_align(1, 1).unwrap();
    let ptr = unsafe { frusa.alloc(layout) };
    assert!(!ptr.is_null());

    // Plus one page for the smallest slab's first batch (four 1 KiB blocks,
    // hence four descriptors) and one page for its index.
    let blocks = PAGE / (16 * Block::ENTRIES);
    let stats = frusa.stats();
    assert_eq!(PAGE * 3 + shard_pages, stats.allocated_from_fallback);
    assert_eq!(PAGE * 2 + shard_pages, stats.allocated_metadata);
    assert_eq!((slabs + 1 + blocks) * 64, stats.in_use_metadata);
    assert_eq!(stats.in_use, stats.in_use_metadata + 16);

    unsafe { frusa.dealloc(ptr, layout) };
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
    assert_eq!(PAGE * 3 + shard_pages, stats.allocated_from_fallback);
}

fn fill_and_check(ptr: *mut u8, size: usize) {
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr, size) };
    for (idx, byte) in buf.iter_mut().enumerate() {
        *byte = (idx % 251) as u8;
    }
    for (idx, byte) in buf.iter().enumerate() {
        assert_eq!((idx % 251) as u8, *byte);
    }
}

fn basic_test_impl(frusa: &dyn GlobalAlloc, max_size: usize) {
    let mut live: Vec<(*mut u8, Layout)> = Vec::new();
    for size in (1..max_size).step_by(7) {
        for align_step in 0..8 {
            let align: usize = 1 << align_step;
            let layout = Layout::from_size_align(size, align).unwrap();
            let ptr = unsafe { frusa.alloc(layout) };
            assert!(!ptr.is_null());
            assert_eq!(0, (ptr as usize) & (align - 1));
            fill_and_check(ptr, size);
            live.push((ptr, layout));
        }
    }
    for (ptr, layout) in live {
        unsafe { frusa.dealloc(ptr, layout) };
    }
}

#[test]
fn basic_test() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    basic_test_impl(&frusa, 5000);
    assert_eq!(frusa.stats().in_use, frusa.stats().in_use_metadata);
}

#[test]
fn basic_test_2m() {
    let frusa: Frusa2M = Frusa2M::new(&BACK_END);
    assert_eq!(max_inside_size(&frusa.inner), 1 << 20);
    basic_test_impl(&frusa, 3000);
    let big = Layout::from_size_align(1 << 20, 8).unwrap();
    let ptr = unsafe { frusa.alloc(big) };
    assert!(!ptr.is_null());
    fill_and_check(ptr, 1 << 20);
    unsafe { frusa.dealloc(ptr, big) };
}

#[test]
fn realloc_keeps_the_slot_within_a_class() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(40, 8).unwrap();
    let ptr = unsafe { frusa.alloc(layout) };
    fill_and_check(ptr, 40);
    let same = unsafe { frusa.realloc(ptr, layout, 64) };
    assert_eq!(same, ptr);
    let moved = unsafe { frusa.realloc(same, Layout::from_size_align(64, 8).unwrap(), 65) };
    assert_ne!(moved, ptr);
    let buf = unsafe { core::slice::from_raw_parts(moved, 40) };
    for (idx, byte) in buf.iter().enumerate() {
        assert_eq!((idx % 251) as u8, *byte);
    }
    unsafe { frusa.dealloc(moved, Layout::from_size_align(65, 8).unwrap()) };
    assert_eq!(frusa.stats().in_use, frusa.stats().in_use_metadata);
}

/// Sorts the pointers and checks that no two live objects overlap.
fn assert_disjoint(ptrs: &[*mut u8], size: usize) {
    let mut sorted: Vec<usize> = ptrs.iter().map(|p| *p as usize).collect();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        assert!(pair[1] - pair[0] >= size, "overlapping allocations");
    }
}

struct Xorshift(u64);

impl Xorshift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

fn shuffle<T>(items: &mut [T], seed: u64) {
    let mut rng = Xorshift(seed);
    for i in (1..items.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

#[cfg(debug_assertions)]
const RETAINED: usize = 16 * 1024;
#[cfg(not(debug_assertions))]
const RETAINED: usize = 64 * 1024;

/// The §1.1 reproduction: a retained population, churn on its oldest slot,
/// then whole-population frees in several orders. Correctness is asserted;
/// timings are printed for the baseline record, never asserted.
#[test]
fn retained_population_test() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(64, 8).unwrap();
    for order in ["insertion", "reverse", "random"] {
        let start = Instant::now();
        let mut ptrs = Vec::with_capacity(RETAINED);
        for i in 0..RETAINED {
            let ptr = unsafe { frusa.alloc(layout) };
            assert!(!ptr.is_null());
            unsafe { ptr.write(i as u8) };
            ptrs.push(ptr);
        }
        let populate = start.elapsed();
        assert_disjoint(&ptrs, 64);
        assert_eq!(
            frusa.stats().in_use - frusa.stats().in_use_metadata,
            RETAINED * 64
        );

        let start = Instant::now();
        for _ in 0..10_000 {
            unsafe { frusa.dealloc(ptrs[0], layout) };
            ptrs[0] = unsafe { frusa.alloc(layout) };
            assert!(!ptrs[0].is_null());
        }
        let churn = start.elapsed();
        assert_disjoint(&ptrs, 64);
        for (i, ptr) in ptrs.iter().enumerate().skip(1) {
            assert_eq!(unsafe { ptr.read() }, i as u8);
        }

        match order {
            "reverse" => ptrs.reverse(),
            "random" => shuffle(&mut ptrs, 0x9E3779B97F4A7C15),
            _ => {}
        }
        let start = Instant::now();
        for ptr in ptrs {
            unsafe { frusa.dealloc(ptr, layout) };
        }
        let free_all = start.elapsed();
        assert_eq!(frusa.stats().in_use, frusa.stats().in_use_metadata);
        println!(
            "retained {RETAINED} x 64 B, {order} order: populate {populate:?}, churn {churn:?}, free-all {free_all:?}"
        );
    }
}

/// One slot freed in every block, then reallocated: allocation must find
/// the holes through the partial stack, not by scanning.
#[test]
fn sparse_holes_test() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(64, 8).unwrap();
    let mut ptrs: Vec<*mut u8> = (0..RETAINED)
        .map(|_| unsafe { frusa.alloc(layout) })
        .collect();
    let holes: Vec<*mut u8> = ptrs.iter().copied().step_by(Block::ENTRIES).collect();
    for hole in &holes {
        unsafe { frusa.dealloc(*hole, layout) };
    }
    let total_before = frusa.stats().allocated_from_fallback;
    let refilled: Vec<*mut u8> = holes
        .iter()
        .map(|_| unsafe { frusa.alloc(layout) })
        .collect();
    assert_eq!(
        total_before,
        frusa.stats().allocated_from_fallback,
        "holes not reused"
    );
    let mut hole_set = holes.clone();
    hole_set.sort_unstable();
    for ptr in &refilled {
        assert!(hole_set.binary_search(ptr).is_ok());
    }
    for (slot, hole) in holes.iter().enumerate() {
        let idx = ptrs.iter().position(|p| p == hole).unwrap();
        ptrs[idx] = refilled[slot];
    }
    assert_disjoint(&ptrs, 64);
    for ptr in ptrs {
        unsafe { frusa.dealloc(ptr, layout) };
    }
}

/// A backend that allocates from the allocator it backs, once per request,
/// as a logging or instrumented backend would. This deadlocks in frusa 0.1,
/// whose slab lock is held across the backend call.
struct NestingBackEnd;

static NESTED: Frusa4K = Frusa4K::new(&NestingBackEnd);

thread_local! {
    static NESTING: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

unsafe impl GlobalAlloc for NestingBackEnd {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !NESTING.with(|n| n.replace(true)) {
            let inner = Layout::from_size_align(layout.size().min(4096), 8).unwrap();
            let ptr = unsafe { NESTED.alloc(inner) };
            assert!(!ptr.is_null());
            unsafe { NESTED.dealloc(ptr, inner) };
            NESTING.with(|n| n.set(false));
        }
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !NESTING.with(|n| n.replace(true)) {
            let inner = Layout::from_size_align(64, 8).unwrap();
            let p = unsafe { NESTED.alloc(inner) };
            unsafe { NESTED.dealloc(p, inner) };
            NESTING.with(|n| n.set(false));
        }
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

#[test]
fn backend_may_allocate_from_the_allocator_it_backs() {
    // Initialization itself must not re-enter: it holds the slab table
    // marker, so a nested request would spin on it. Run it with nesting
    // suppressed, as a real backend would be quiet until the runtime is up.
    NESTING.with(|n| n.set(true));
    NESTED.stats();
    NESTING.with(|n| n.set(false));
    let mut live = Vec::new();
    for size in [16usize, 64, 4096, 512, 32] {
        let layout = Layout::from_size_align(size, 8).unwrap();
        for _ in 0..200 {
            let ptr = unsafe { NESTED.alloc(layout) };
            assert!(!ptr.is_null());
            live.push((ptr, layout));
        }
    }
    for (ptr, layout) in live {
        unsafe { NESTED.dealloc(ptr, layout) };
    }
    assert_eq!(NESTED.stats().in_use, NESTED.stats().in_use_metadata);

    // Reclaim frees through the same backend, which nests on that path too.
    let layout = Layout::from_size_align(128, 8).unwrap();
    let ptrs: Vec<*mut u8> = (0..4096).map(|_| unsafe { NESTED.alloc(layout) }).collect();
    for ptr in ptrs {
        unsafe { NESTED.dealloc(ptr, layout) };
    }
    NESTED.reclaim();
    NESTED.inner.check_invariants();
    // The backend's nested request during reclaim's second phase can grow
    // the class that was just emptied by one batch; nothing else remains.
    let stats = NESTED.stats();
    assert!(stats.allocated_from_fallback - stats.allocated_metadata <= PAGE);
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

// ---- reclaim ----

#[test]
fn reclaim_returns_empty_batches_and_keeps_used_ones() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptrs: Vec<*mut u8> = (0..RETAINED)
        .map(|_| unsafe { frusa.alloc(layout) })
        .collect();
    let stats = frusa.stats();
    let data_bytes = stats.allocated_from_fallback - stats.allocated_metadata;
    assert!(data_bytes >= RETAINED * 64);

    // Reclaim with everything live frees nothing.
    frusa.reclaim();
    assert_eq!(
        frusa.stats().allocated_from_fallback,
        stats.allocated_from_fallback
    );

    // Keep one object in every 64th block; only batches without one go.
    let keep: Vec<*mut u8> = ptrs.iter().copied().step_by(Block::ENTRIES * 64).collect();
    for ptr in &ptrs {
        if !keep.contains(ptr) {
            unsafe { frusa.dealloc(*ptr, layout) };
        }
    }
    frusa.reclaim();
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    let kept_bytes = stats.allocated_from_fallback - stats.allocated_metadata;
    assert!(kept_bytes < data_bytes, "nothing reclaimed");
    assert!(kept_bytes > 0);
    for ptr in &keep {
        assert_eq!(unsafe { ptr.read_volatile() }, unsafe {
            ptr.read_volatile()
        });
        unsafe { frusa.dealloc(*ptr, layout) };
    }
    frusa.reclaim();
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.allocated_from_fallback, stats.allocated_metadata);
    assert_eq!(stats.in_use, stats.in_use_metadata);

    // Growth works again afterwards and addresses are reusable.
    let again = unsafe { frusa.alloc(layout) };
    assert!(!again.is_null());
    unsafe { again.write(7) };
    unsafe { frusa.dealloc(again, layout) };
}

#[test]
fn reclaim_test() {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let frusa: Frusa4K = Frusa4K::new(&BACK_END);

    #[cfg(not(debug_assertions))]
    const ALLOCS: usize = 1_000_000;
    #[cfg(debug_assertions)]
    const ALLOCS: usize = 10_000;

    let mut ptrs: Vec<(*mut u8, Layout)> = Vec::with_capacity(ALLOCS);
    for _ in 0..ALLOCS {
        let alloc_bucket: usize = 4 + (rng.r#gen::<u16>() % 8) as usize;
        let sz = 1 << alloc_bucket;
        let layout = Layout::from_size_align(sz, 8).unwrap();
        let ptr = unsafe { frusa.alloc(layout) };
        assert!(!ptr.is_null());
        ptrs.push((ptr, layout));
    }
    let peak = frusa.stats();
    println!(
        "alloc: allocated from system: {} used bytes: {}",
        peak.allocated_from_fallback, peak.in_use
    );
    for (ptr, layout) in &ptrs {
        unsafe { frusa.dealloc(*ptr, *layout) };
    }
    frusa.reclaim();
    let after = frusa.stats();
    println!(
        "reclaim: allocated from system: {} used bytes: {} of these metadata: {} - {}",
        after.allocated_from_fallback,
        after.in_use,
        after.allocated_metadata,
        after.in_use_metadata
    );
    assert_eq!(after.allocated_from_fallback, after.allocated_metadata);
    assert_eq!(after.in_use, after.in_use_metadata);
    frusa.inner.check_invariants();
}

struct FlakyBackEndAllocator {}

unsafe impl Send for FlakyBackEndAllocator {}
unsafe impl Sync for FlakyBackEndAllocator {}

unsafe impl GlobalAlloc for FlakyBackEndAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FLAKY.load(Ordering::Relaxed) {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            if rng.r#gen::<u8>() < 50 {
                return core::ptr::null_mut();
            }
        }
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static FLAKY_BACK_END: FlakyBackEndAllocator = FlakyBackEndAllocator {};
static FLAKY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[test]
fn stress_test() {
    FLAKY.store(false, Ordering::Relaxed);
    static STRESSED_FRUSA: Frusa4K = Frusa4K::new(&FLAKY_BACK_END);

    #[cfg(debug_assertions)]
    const STEPS: usize = 1_000;
    #[cfg(not(debug_assertions))]
    const STEPS: usize = 1_000_000;

    let thread_fn = || {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for step in 0..STEPS {
            let alloc_bucket: usize = 4 + (rng.r#gen::<u16>() % 20) as usize;
            let sz = 1 << alloc_bucket;

            if step == 50 {
                // Don't fail during the init phase, but fail later.
                FLAKY.store(true, Ordering::Relaxed);
            }

            let layout = Layout::from_size_align(sz, 8).unwrap();
            let ptr = loop {
                let ptr = unsafe { STRESSED_FRUSA.alloc(layout) };
                if !ptr.is_null() {
                    break ptr;
                }
            };
            if sz < 1024 {
                fill_and_check(ptr, sz);
            }
            unsafe { STRESSED_FRUSA.dealloc(ptr, layout) };
        }
    };

    let mut threads = vec![];
    for _ in 0..8 {
        threads.push(std::thread::spawn(thread_fn));
    }

    // Concurrently with threads above, do alloc + reclaim.
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        const ALLOCS: usize = STEPS / 100;
        let mut ptrs: Vec<(*mut u8, Layout)> = Vec::with_capacity(ALLOCS);
        for _ in 0..ALLOCS {
            let alloc_bucket: usize = 4 + (rng.r#gen::<u16>() % 10) as usize;
            let sz = 1 << alloc_bucket;
            let layout = Layout::from_size_align(sz, 8).unwrap();
            let ptr = loop {
                let ptr = unsafe { STRESSED_FRUSA.alloc(layout) };
                if !ptr.is_null() {
                    break ptr;
                }
            };
            ptrs.push((ptr, layout));
        }
        for (ptr, layout) in &ptrs {
            unsafe { STRESSED_FRUSA.dealloc(*ptr, *layout) };
        }
        STRESSED_FRUSA.reclaim();
    }

    for handle in threads {
        handle.join().unwrap();
    }
    FLAKY.store(false, Ordering::Relaxed);
    STRESSED_FRUSA.inner.check_invariants();
    let stats = STRESSED_FRUSA.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

/// Many threads growing one empty class at once: every request succeeds,
/// accounting stays exact, and the structures stay consistent even when
/// concurrent growers add duplicate batches.
#[test]
fn concurrent_growth_test() {
    static GROWN: Frusa4K = Frusa4K::new(&BACK_END);
    const PER_THREAD: usize = 20_000;
    let layout = Layout::from_size_align(64, 8).unwrap();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(move || {
                let ptrs: Vec<usize> = (0..PER_THREAD)
                    .map(|_| {
                        let p = unsafe { GROWN.alloc(layout) };
                        assert!(!p.is_null());
                        unsafe { p.write(1) };
                        p as usize
                    })
                    .collect();
                ptrs
            })
        })
        .collect();
    let mut all: Vec<*mut u8> = Vec::new();
    for t in threads {
        all.extend(t.join().unwrap().into_iter().map(|p| p as *mut u8));
    }
    assert_disjoint(&all, 64);
    let stats = GROWN.stats();
    assert_eq!(stats.in_use - stats.in_use_metadata, all.len() * 64);
    assert!(stats.allocated_from_fallback >= stats.in_use);
    // Growers that lost a race give their batch back, so slack stays
    // within a few batches instead of one per contending thread per event.
    let slack = stats.allocated_from_fallback
        - stats.allocated_metadata
        - (stats.in_use - stats.in_use_metadata);
    assert!(slack <= 4 * 256 * 1024, "slack {slack}");
    GROWN.inner.check_invariants();
    for ptr in all {
        unsafe { GROWN.dealloc(ptr, layout) };
    }
    GROWN.reclaim();
    let stats = GROWN.stats();
    assert_eq!(stats.allocated_from_fallback, stats.allocated_metadata);
}

// ---- coverage: work bounds, fault injection, cross-thread frees, Frusa2M ----

/// Every allocation examines exactly one stack entry, and every free of a
/// retained population probes the index at most log2(len) + 1 times.
#[test]
fn work_bounds_end_to_end() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let layout = Layout::from_size_align(64, 8).unwrap();
    let examined_before = crate::stack_examined();
    let mut ptrs: Vec<*mut u8> = (0..RETAINED)
        .map(|_| unsafe { frusa.alloc(layout) })
        .collect();
    // One entry per allocation, plus one per block for its descriptor.
    let examined = crate::stack_examined() - examined_before;
    assert!(
        (RETAINED..=RETAINED + RETAINED / Block::ENTRIES).contains(&examined),
        "{examined}"
    );

    shuffle(&mut ptrs, 0x1234_5678_9ABC_DEF1);
    let len = frusa
        .inner
        .slab_for_sz(64)
        .index_len
        .load(Ordering::Relaxed) as usize;
    let probes_before = crate::index_probes();
    for ptr in &ptrs {
        unsafe { frusa.dealloc(*ptr, layout) };
    }
    let probes = crate::index_probes() - probes_before;
    assert!(
        probes <= RETAINED * (len.ilog2() as usize + 1),
        "{probes} probes over {len} blocks"
    );
}

thread_local! {
    static BACKEND_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static FAIL_AT: core::cell::Cell<usize> = const { core::cell::Cell::new(usize::MAX) };
}

/// Fails exactly one backend allocation, chosen by call number, so a test
/// can fail every stage of growth in turn.
struct FailingBackEnd;

unsafe impl GlobalAlloc for FailingBackEnd {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let call = BACKEND_CALLS.with(|c| {
            c.set(c.get() + 1);
            c.get()
        });
        if FAIL_AT.with(|f| f.get()) == call {
            return core::ptr::null_mut();
        }
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static FAILING: FailingBackEnd = FailingBackEnd;

/// Allocates across three classes; enough 64-byte objects to outgrow the
/// first metadata page, so metadata growth is on the path too.
fn injection_scenario(frusa: &Frusa4K) -> (Vec<(*mut u8, Layout)>, usize) {
    let mut live = Vec::new();
    let mut refused = 0;
    for (size, count) in [(16usize, 300usize), (4096, 100), (64, 4000)] {
        let layout = Layout::from_size_align(size, 8).unwrap();
        for _ in 0..count {
            let ptr = unsafe { frusa.alloc(layout) };
            if ptr.is_null() {
                refused += 1;
            } else {
                unsafe { ptr.write(1) };
                live.push((ptr, layout));
            }
        }
    }
    (live, refused)
}

#[test]
fn every_backend_failure_rolls_back_cleanly() {
    BACKEND_CALLS.with(|c| c.set(0));
    FAIL_AT.with(|f| f.set(usize::MAX));
    let frusa: Frusa4K = Frusa4K::new(&FAILING);
    let (live, refused) = injection_scenario(&frusa);
    assert_eq!(refused, 0);
    let calls = BACKEND_CALLS.with(|c| c.get());
    assert!(calls > 20, "scenario makes only {calls} backend calls");
    for (ptr, layout) in live {
        unsafe { frusa.dealloc(ptr, layout) };
    }

    for fail_at in 1..=calls {
        BACKEND_CALLS.with(|c| c.set(0));
        FAIL_AT.with(|f| f.set(fail_at));
        let frusa: Frusa4K = Frusa4K::new(&FAILING);
        if fail_at <= 3 {
            // Initialization makes three backend calls, for the reader
            // shards, the free lists, and the first metadata page; it cannot
            // fail softly and panics.
            continue;
        }
        let (mut live, refused) = injection_scenario(&frusa);
        assert!(refused <= 1, "one failed call refused {refused} requests");
        FAIL_AT.with(|f| f.set(usize::MAX));
        frusa.inner.check_invariants();
        let ptrs: Vec<*mut u8> = live.iter().map(|(p, _)| *p).collect();
        assert_disjoint(&ptrs, 16);
        let stats = frusa.stats();
        let live_bytes: usize = live.iter().map(|(_, l)| l.size().next_power_of_two()).sum();
        assert_eq!(stats.in_use - stats.in_use_metadata, live_bytes);
        // The allocator keeps working once the backend recovers.
        let layout = Layout::from_size_align(64, 8).unwrap();
        let ptr = unsafe { frusa.alloc(layout) };
        assert!(!ptr.is_null(), "fail_at {fail_at}");
        live.push((ptr, layout));
        for (ptr, layout) in live {
            unsafe { frusa.dealloc(ptr, layout) };
        }
        frusa.reclaim();
        frusa.inner.check_invariants();
        let stats = frusa.stats();
        assert_eq!(
            stats.allocated_from_fallback, stats.allocated_metadata,
            "fail_at {fail_at}"
        );
        assert_eq!(stats.in_use, stats.in_use_metadata);
    }
    FAIL_AT.with(|f| f.set(usize::MAX));
}

#[test]
fn cross_thread_frees() {
    static SHARED: Frusa4K = Frusa4K::new(&BACK_END);
    const OBJECTS: usize = 100_000;
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<(usize, Layout)>>(16);
    let producer = std::thread::spawn(move || {
        let mut rng = Xorshift(0x0bad_5eed_0bad_5eed);
        let mut batch = Vec::with_capacity(1024);
        for i in 0..OBJECTS {
            let layout = Layout::from_size_align(4096 >> (rng.next() % 9), 8).unwrap();
            let ptr = unsafe { SHARED.alloc(layout) };
            assert!(!ptr.is_null());
            unsafe { ptr.write(1) };
            batch.push((ptr as usize, layout));
            if batch.len() == 1024 || i + 1 == OBJECTS {
                tx.send(core::mem::replace(&mut batch, Vec::with_capacity(1024)))
                    .unwrap();
            }
        }
    });
    let consumer = std::thread::spawn(move || {
        let mut freed = 0;
        for batch in rx {
            for (ptr, layout) in batch {
                unsafe { SHARED.dealloc(ptr as *mut u8, layout) };
                freed += 1;
            }
        }
        freed
    });
    producer.join().unwrap();
    assert_eq!(consumer.join().unwrap(), OBJECTS);
    SHARED.inner.check_invariants();
    // Listed slots count as in use until reclaim drains the lists.
    SHARED.reclaim();
    let stats = SHARED.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
    assert_eq!(stats.allocated_from_fallback, stats.allocated_metadata);
}

#[test]
fn reclaim_2m() {
    let frusa: Frusa2M = Frusa2M::new(&BACK_END);
    let layout = Layout::from_size_align(256 * 1024, 8).unwrap();
    let ptrs: Vec<*mut u8> = (0..100)
        .map(|_| {
            let p = unsafe { frusa.alloc(layout) };
            assert!(!p.is_null());
            unsafe { p.write(1) };
            p
        })
        .collect();
    assert_disjoint(&ptrs, 256 * 1024);
    for ptr in ptrs {
        unsafe { frusa.dealloc(ptr, layout) };
    }
    frusa.reclaim();
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.allocated_from_fallback, stats.allocated_metadata);
}

// ---- per-thread private blocks ----

use crate::Cache4K;

#[test]
fn cached_allocation_owns_one_block_per_class() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptrs: Vec<*mut u8> = (0..10)
        .map(|_| unsafe { frusa.alloc_cached(&cache, layout) })
        .collect();
    assert_disjoint(&ptrs, 64);
    let slab = frusa.inner.slab_for_sz(64);
    let block = slab.lookup(ptrs[0]);
    for ptr in &ptrs {
        assert_eq!(slab.lookup(*ptr), block);
    }
    assert_eq!(
        unsafe { (*block).owner.load(Ordering::Relaxed) },
        cache.id()
    );
    assert!(!unsafe { (*block).on_stack() });
    assert_eq!(cache.current[slab.table_idx as usize].get(), block);
    frusa.inner.check_invariants();

    // Freed but still owned: reclaim must leave the block's batch alone.
    for ptr in &ptrs {
        unsafe { frusa.dealloc_cached(&cache, *ptr, layout) };
    }
    let before = frusa.stats();
    frusa.reclaim();
    assert_eq!(
        frusa.stats().allocated_from_fallback,
        before.allocated_from_fallback
    );

    // Released: the block rejoins the stack and reclaim can free it.
    frusa.release_cache(&cache);
    assert!(unsafe { (*block).owner.load(Ordering::Relaxed) }.is_null());
    assert!(unsafe { (*block).on_stack() });
    assert!(cache.current[slab.table_idx as usize].get().is_null());
    frusa.inner.check_invariants();
    frusa.reclaim();
    let stats = frusa.stats();
    assert_eq!(stats.allocated_from_fallback, stats.allocated_metadata);
}

#[test]
fn classes_above_the_threshold_use_the_shared_path() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    // 4096 is the only 4K class above the 2 KiB threshold.
    for size in [4096usize] {
        let layout = Layout::from_size_align(size, 8).unwrap();
        let ptr = unsafe { frusa.alloc_cached(&cache, layout) };
        let slab = frusa.inner.slab_for_sz(size);
        let block = slab.lookup(ptr);
        assert!(unsafe { (*block).owner.load(Ordering::Relaxed) }.is_null());
        assert!(cache.current[slab.table_idx as usize].get().is_null());
        unsafe { frusa.dealloc_cached(&cache, ptr, layout) };
    }
    // The largest cached class is 2048 bytes.
    let layout = Layout::from_size_align(2048, 8).unwrap();
    let ptr = unsafe { frusa.alloc_cached(&cache, layout) };
    let slab = frusa.inner.slab_for_sz(2048);
    assert_eq!(
        unsafe { (*slab.lookup(ptr)).owner.load(Ordering::Relaxed) },
        cache.id()
    );
    unsafe { frusa.dealloc_cached(&cache, ptr, layout) };
    frusa.release_cache(&cache);
    frusa.inner.check_invariants();
}

#[test]
fn a_full_private_block_is_dropped_and_comes_back_through_a_free() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let slab = frusa.inner.slab_for_sz(64);
    let class = slab.table_idx as usize;
    let ptrs: Vec<*mut u8> = (0..Block::ENTRIES)
        .map(|_| unsafe { frusa.alloc_cached(&cache, layout) })
        .collect();
    let block = slab.lookup(ptrs[0]);
    assert!(unsafe { (*block).is_full() });
    // The claim that filled the block dropped it: no owner, off the stack.
    assert!(cache.current[class].get().is_null());
    assert!(unsafe { (*block).owner.load(Ordering::Relaxed) }.is_null());
    assert!(!unsafe { (*block).on_stack() });

    // An uncached free from "another thread" pushes it, and the cache takes
    // it back on its next allocation and gets that very slot.
    unsafe { frusa.dealloc(ptrs[7], layout) };
    assert!(unsafe { (*block).on_stack() });
    let again = unsafe { frusa.alloc_cached(&cache, layout) };
    assert_eq!(again, ptrs[7]);
    assert_eq!(cache.current[class].get(), core::ptr::null_mut());
    frusa.inner.check_invariants();
    for ptr in ptrs {
        unsafe { frusa.dealloc(ptr, layout) };
    }
    frusa.release_cache(&cache);
    frusa.inner.check_invariants();
}

#[test]
fn remote_frees_into_a_private_block_are_reused_by_its_owner() {
    static SHARED: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let slab = SHARED.inner.slab_for_sz(64);
    let ptrs: Vec<*mut u8> = (0..40)
        .map(|_| unsafe { SHARED.alloc_cached(&cache, layout) })
        .collect();
    let block = slab.lookup(ptrs[0]);
    let remote: Vec<usize> = ptrs[..10].iter().map(|p| *p as usize).collect();
    std::thread::spawn(move || {
        for ptr in remote {
            unsafe { SHARED.dealloc(ptr as *mut u8, layout) };
        }
    })
    .join()
    .unwrap();
    // Not pushed (owned), and the owner keeps allocating from it: the 24
    // untouched slots plus the 10 freed ones all come from this block.
    assert!(!unsafe { (*block).on_stack() });
    let mut reused = 0;
    for _ in 0..34 {
        let ptr = unsafe { SHARED.alloc_cached(&cache, layout) };
        assert_eq!(slab.lookup(ptr), block);
        if ptrs[..10].contains(&ptr) {
            reused += 1;
        }
    }
    assert_eq!(reused, 10);
    assert!(unsafe { (*block).is_full() });
    SHARED.release_cache(&cache);
    SHARED.inner.check_invariants();
}

/// Eight caching threads exchange objects through a shared pool and free
/// each other's, while a coordinator reclaims; caches are released and
/// reused along the way. Every invariant must hold at the end and all
/// memory must come back.
#[test]
fn private_blocks_survive_cross_thread_churn() {
    static SHARED: Frusa4K = Frusa4K::new(&BACK_END);
    static POOL: std::sync::Mutex<Vec<(usize, Layout)>> = std::sync::Mutex::new(Vec::new());
    #[cfg(debug_assertions)]
    const STEPS: usize = 20_000;
    #[cfg(not(debug_assertions))]
    const STEPS: usize = 200_000;

    let workers: Vec<_> = (0..8)
        .map(|t| {
            std::thread::spawn(move || {
                let mut rng = Xorshift(0x1357_9bdf_2468_ace0 ^ (t as u64 + 1));
                let mut cache = Cache4K::new();
                for step in 0..STEPS {
                    let size = 256 >> (rng.next() % 5);
                    let layout = Layout::from_size_align(size, 8).unwrap();
                    let ptr = unsafe { SHARED.alloc_cached(&cache, layout) };
                    assert!(!ptr.is_null());
                    unsafe { ptr.write(t as u8) };
                    let victim = {
                        let mut pool = POOL.lock().unwrap();
                        pool.push((ptr as usize, layout));
                        if pool.len() > 64 {
                            let k = (rng.next() % pool.len() as u64) as usize;
                            Some(pool.swap_remove(k))
                        } else {
                            None
                        }
                    };
                    if let Some((victim, layout)) = victim {
                        unsafe { SHARED.dealloc_cached(&cache, victim as *mut u8, layout) };
                    }
                    if step % 5_000 == 4_999 {
                        SHARED.release_cache(&cache);
                        cache = Cache4K::new();
                    }
                }
                SHARED.release_cache(&cache);
            })
        })
        .collect();
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(5));
        SHARED.reclaim();
    }
    for w in workers {
        w.join().unwrap();
    }
    for (ptr, layout) in POOL.lock().unwrap().drain(..) {
        unsafe { SHARED.dealloc(ptr as *mut u8, layout) };
    }
    SHARED.inner.check_invariants();
    // Listed slots count as in use until reclaim drains the lists.
    SHARED.reclaim();
    let stats = SHARED.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
    assert_eq!(stats.allocated_from_fallback, stats.allocated_metadata);
}

#[test]
fn cached_realloc_keeps_the_slot_within_a_class() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(40, 8).unwrap();
    let ptr = unsafe { frusa.alloc_cached(&cache, layout) };
    fill_and_check(ptr, 40);
    assert_eq!(
        unsafe { frusa.realloc_cached(&cache, ptr, layout, 64) },
        ptr
    );
    let moved =
        unsafe { frusa.realloc_cached(&cache, ptr, Layout::from_size_align(64, 8).unwrap(), 200) };
    assert_ne!(moved, ptr);
    let buf = unsafe { core::slice::from_raw_parts(moved, 40) };
    for (idx, byte) in buf.iter().enumerate() {
        assert_eq!((idx % 251) as u8, *byte);
    }
    unsafe { frusa.dealloc_cached(&cache, moved, Layout::from_size_align(200, 8).unwrap()) };
    frusa.release_cache(&cache);
    // Listed slots count as in use until reclaim drains the lists.
    frusa.reclaim();
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

#[test]
fn private_block_fast_paths_take_no_guard() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    // 512-byte slots: one block of 64, and a list limit of 32.
    let layout = Layout::from_size_align(512, 8).unwrap();
    let first = unsafe { frusa.alloc_cached(&cache, layout) };
    let slab = frusa.inner.slab_for_sz(512);
    let class = slab.table_idx as usize;
    let block = cache.current[class].get();
    assert!(!block.is_null());
    let list = frusa.inner.list(slab, 0);

    // Allocations from the block and frees back into it touch nothing
    // shared: no guard, and no list either.
    let before = crate::guards_taken();
    let ptrs: Vec<*mut u8> = (0..Block::ENTRIES - 2)
        .map(|_| unsafe { frusa.alloc_cached(&cache, layout) })
        .collect();
    for ptr in &ptrs {
        unsafe { frusa.dealloc_cached(&cache, *ptr, layout) };
    }
    assert_eq!(crate::guards_taken(), before, "guard on the fast path");
    assert_eq!(list.len(), 0);
    assert_eq!(cache.current[class].get(), block);

    // Filling the block gives it up under the guard.
    let again: Vec<*mut u8> = (0..Block::ENTRIES - 1)
        .map(|_| unsafe { frusa.alloc_cached(&cache, layout) })
        .collect();
    assert_eq!(crate::guards_taken(), before + 1);
    assert!(cache.current[class].get().is_null());
    assert!(unsafe { (*block).is_full() });

    // Frees into the old block go to the list without a guard, up to its
    // limit; the next one goes through the slab and puts the block back
    // on the stack.
    let extra = unsafe { frusa.alloc_cached(&cache, layout) };
    let before = crate::guards_taken();
    let limit = Frusa::<9>::free_list_limit(9) as usize;
    for ptr in &again[..limit] {
        unsafe { frusa.dealloc_cached(&cache, *ptr, layout) };
    }
    assert_eq!(list.len() as usize, limit);
    assert_eq!(crate::guards_taken(), before);
    unsafe { frusa.dealloc_cached(&cache, again[limit], layout) };
    assert_eq!(crate::guards_taken(), before + 1);
    assert!(unsafe { (*block).on_stack() });

    for ptr in again[limit + 1..].iter().chain([first, extra].iter()) {
        unsafe { frusa.dealloc_cached(&cache, *ptr, layout) };
    }
    frusa.release_cache(&cache);
    frusa.reclaim();
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

#[test]
fn shard_lists_reuse_slots_last_in_first_out() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    cache.set_shard(3);
    let layout = Layout::from_size_align(48, 8).unwrap();
    let slab = frusa.inner.slab_for_sz(64);
    let a = unsafe { frusa.alloc_cached(&cache, layout) };
    let b = unsafe { frusa.alloc_cached(&cache, layout) };
    let c = unsafe { frusa.alloc_cached(&cache, layout) };
    // Once the block is no longer the cache's own, frees go to the list.
    frusa.release_cache(&cache);
    unsafe { frusa.dealloc_cached(&cache, a, layout) };
    unsafe { frusa.dealloc_cached(&cache, b, layout) };
    let list = frusa.inner.list(slab, 3);
    assert_eq!(list.len(), 2);

    // Served from the list: no guard, no stack entry, no index probe.
    let counters = (
        crate::guards_taken(),
        crate::stack_examined(),
        crate::index_probes(),
    );
    assert_eq!(unsafe { frusa.alloc_cached(&cache, layout) }, b);
    assert_eq!(unsafe { frusa.alloc_cached(&cache, layout) }, a);
    assert_eq!(
        counters,
        (
            crate::guards_taken(),
            crate::stack_examined(),
            crate::index_probes()
        )
    );
    assert_eq!(list.len(), 0);

    for ptr in [a, b, c] {
        unsafe { frusa.dealloc_cached(&cache, ptr, layout) };
    }
    frusa.release_cache(&cache);
    frusa.reclaim();
    assert_eq!(list.len(), 0);
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

#[test]
fn shard_lists_are_bounded_per_class() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    for (size, limit) in [(16usize, 64u32), (256, 64), (512, 32), (2048, 8), (4096, 4)] {
        assert_eq!(Frusa::<9>::free_list_limit(size.ilog2()), limit);
        let layout = Layout::from_size_align(size, 8).unwrap();
        let ptrs: Vec<*mut u8> = (0..limit as usize + 3)
            .map(|_| unsafe { frusa.alloc_cached(&cache, layout) })
            .collect();
        // With no private block, every free is a candidate for the list.
        frusa.release_cache(&cache);
        let before = frusa.stats().in_use;
        for ptr in &ptrs {
            unsafe { frusa.dealloc_cached(&cache, *ptr, layout) };
        }
        let slab = frusa.inner.slab_for_sz(size);
        assert_eq!(frusa.inner.list(slab, 0).len(), limit);
        // Listed slots stay in use; the three beyond the limit reached
        // their blocks.
        assert_eq!(frusa.stats().in_use, before - 3 * size);
    }
    frusa.reclaim();
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

#[test]
fn shard_lists_serve_their_class_at_its_alignment() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let small = Layout::from_size_align(40, 8).unwrap();
    let ptr = unsafe { frusa.alloc_cached(&cache, small) };
    frusa.release_cache(&cache);
    unsafe { frusa.dealloc_cached(&cache, ptr, small) };
    assert_eq!(frusa.inner.list(frusa.inner.slab_for_sz(64), 0).len(), 1);
    // Another class does not see the slot.
    let other = unsafe { frusa.alloc_cached(&cache, Layout::from_size_align(100, 8).unwrap()) };
    assert_ne!(other, ptr);
    // The same class does, at any alignment the class satisfies.
    let aligned = Layout::from_size_align(16, 64).unwrap();
    let again = unsafe { frusa.alloc_cached(&cache, aligned) };
    assert_eq!(again, ptr);
    assert_eq!(again as usize % 64, 0);
    unsafe { frusa.dealloc_cached(&cache, again, aligned) };
    unsafe { frusa.dealloc_cached(&cache, other, Layout::from_size_align(100, 8).unwrap()) };
    frusa.release_cache(&cache);
    frusa.reclaim();
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

/// A backend that refuses every request while `REFUSE` is set.
struct RefusingBackEnd;

static REFUSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

unsafe impl GlobalAlloc for RefusingBackEnd {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if REFUSE.load(Ordering::Relaxed) {
            return core::ptr::null_mut();
        }
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

static REFUSING: RefusingBackEnd = RefusingBackEnd;

#[test]
fn a_slot_freed_on_one_shard_is_taken_on_another_before_growth() {
    static FRUSA: Frusa4K = Frusa4K::new(&REFUSING);
    let layout = Layout::from_size_align(64, 8).unwrap();
    let slab = FRUSA.inner.slab_for_sz(64);
    let class = slab.table_idx as usize;
    let a = Cache4K::new();
    a.set_shard(1);
    let b = Cache4K::new();
    b.set_shard(2);

    // Shard 1 takes eight slots of the first block, gives the block up
    // (56 free slots: back on the stack), then lists the eight.
    let freed: Vec<*mut u8> = (0..8)
        .map(|_| unsafe { FRUSA.alloc_cached(&a, layout) })
        .collect();
    FRUSA.release_cache(&a);
    for ptr in &freed {
        unsafe { FRUSA.dealloc_cached(&a, *ptr, layout) };
    }
    assert_eq!(FRUSA.inner.list(slab, 1).len(), 8);

    // Shard 2 takes the block and fills it, which gives it up.
    let fill: Vec<*mut u8> = (0..Block::ENTRIES - 8)
        .map(|_| unsafe { FRUSA.alloc_cached(&b, layout) })
        .collect();
    assert!(b.current[class].get().is_null());

    // With the backend refusing, the slab cannot grow: shard 2's next
    // allocations are the slots shard 1 listed, and only then nothing.
    REFUSE.store(true, Ordering::Relaxed);
    let taken: Vec<*mut u8> = (0..8)
        .map(|_| unsafe { FRUSA.alloc_cached(&b, layout) })
        .collect();
    for ptr in &taken {
        assert!(freed.contains(ptr));
    }
    assert_eq!(FRUSA.inner.list(slab, 1).len(), 0);
    assert!(unsafe { FRUSA.alloc_cached(&b, layout) }.is_null());
    REFUSE.store(false, Ordering::Relaxed);

    for ptr in fill.iter().chain(taken.iter()) {
        unsafe { FRUSA.dealloc_cached(&b, *ptr, layout) };
    }
    FRUSA.release_cache(&b);
    FRUSA.reclaim();
    FRUSA.inner.check_invariants();
    let stats = FRUSA.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

#[test]
fn reclaim_drains_the_lists_first() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptrs: Vec<*mut u8> = (0..10)
        .map(|_| unsafe { frusa.alloc_cached(&cache, layout) })
        .collect();
    frusa.release_cache(&cache);
    for ptr in &ptrs {
        unsafe { frusa.dealloc_cached(&cache, *ptr, layout) };
    }
    let slab = frusa.inner.slab_for_sz(64);
    assert_eq!(frusa.inner.list(slab, 0).len(), 10);
    let stats = frusa.stats();
    assert!(stats.allocated_from_fallback > stats.allocated_metadata);
    assert_eq!(stats.in_use, stats.in_use_metadata + 10 * 64);
    // The listed slots go back to their block, and the block's batch goes
    // back to the backend.
    frusa.reclaim();
    assert_eq!(frusa.inner.list(slab, 0).len(), 0);
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.allocated_from_fallback, stats.allocated_metadata);
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

#[test]
fn a_busy_list_is_skipped() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let slab = frusa.inner.slab_for_sz(64);
    let a = unsafe { frusa.alloc_cached(&cache, layout) };
    let b = unsafe { frusa.alloc_cached(&cache, layout) };
    frusa.release_cache(&cache);
    unsafe { frusa.dealloc_cached(&cache, a, layout) };
    let list = frusa.inner.list(slab, 0);
    assert_eq!(list.len(), 1);
    {
        // Another thread holds the list: allocation and free go around it.
        let _held = list.hold_for_test();
        let c = unsafe { frusa.alloc_cached(&cache, layout) };
        assert_ne!(c, a);
        frusa.release_cache(&cache);
        unsafe { frusa.dealloc_cached(&cache, c, layout) };
        assert_eq!(list.len(), 1);
    }
    assert_eq!(unsafe { frusa.alloc_cached(&cache, layout) }, a);
    unsafe { frusa.dealloc_cached(&cache, a, layout) };
    unsafe { frusa.dealloc_cached(&cache, b, layout) };
    frusa.release_cache(&cache);
    frusa.reclaim();
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}

#[test]
#[should_panic(expected = "double free")]
fn a_double_free_through_a_list_panics() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = unsafe { frusa.alloc_cached(&cache, layout) };
    frusa.release_cache(&cache);
    unsafe { frusa.dealloc_cached(&cache, ptr, layout) };
    unsafe { frusa.dealloc_cached(&cache, ptr, layout) };
}

#[test]
#[should_panic(expected = "corrupted free list")]
fn a_corrupted_list_link_panics() {
    let frusa: Frusa4K = Frusa4K::new(&BACK_END);
    let cache = Cache4K::new();
    let layout = Layout::from_size_align(64, 8).unwrap();
    let ptr = unsafe { frusa.alloc_cached(&cache, layout) };
    frusa.release_cache(&cache);
    unsafe { frusa.dealloc_cached(&cache, ptr, layout) };
    // Decodes to 1, which is no slot boundary of the class.
    unsafe { *(ptr as *mut usize) = 1 ^ (ptr as usize >> 12) };
    let _ = unsafe { frusa.alloc_cached(&cache, layout) };
}

#[test]
fn frusa_2m_keeps_no_list_above_16_kib() {
    let frusa: Frusa2M = Frusa2M::new(&BACK_END);
    let cache = Cache2M::new();
    for (size, listed) in [(8192usize, 1u32), (16384, 1), (32768, 0)] {
        let layout = Layout::from_size_align(size, 8).unwrap();
        let ptr = unsafe { frusa.alloc_cached(&cache, layout) };
        unsafe { frusa.dealloc_cached(&cache, ptr, layout) };
        let slab = frusa.inner.slab_for_sz(size);
        assert_eq!(frusa.inner.list(slab, 0).len(), listed);
    }
    frusa.release_cache(&cache);
    frusa.reclaim();
    frusa.inner.check_invariants();
    let stats = frusa.stats();
    assert_eq!(stats.in_use, stats.in_use_metadata);
}
