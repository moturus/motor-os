//! The production pool: built once from boot inputs, low RAM released at
//! stage 2, and runtime cursors selected by CPU identity.

use super::layout::{Budget, Layout, Shaped};
use super::*;
use crate::mm::{MemorySegment, KERNEL_PHYS_START, PAGE_SIZE_SMALL, PAGING_DIRECT_MAP_OFFSET};
use alloc::vec::Vec;

pub(crate) type BlockPool = Pool<'static, DirectLinks>;

static CURSORS: [AtomicUsize; crate::config::MAX_CPUS as usize] =
    [const { AtomicUsize::new(NO_CURSOR) }; crate::config::MAX_CPUS as usize];

// GS CPU identity is valid only after the all-CPU initialization publication.
fn cursor() -> Option<&'static AtomicUsize> {
    crate::mm::cpu_initialized().then(|| &CURSORS[usize::from(crate::arch::current_cpu())])
}

// Boot memory inputs, retained for stage 2 and debug recounts.
pub(crate) struct BootInputs {
    pub available: Vec<MemorySegment>,
    pub initrd: MemorySegment,
    pub raw: Vec<MemorySegment>,
}

impl BootInputs {
    fn layout(&self, reserved: &[MemorySegment]) -> Layout {
        Layout::new(&self.available, reserved, self.initrd, &self.raw)
            .unwrap_or_else(|err| panic!("phys: invalid boot memory layout: {err:?}"))
    }
}

// The boot heap for RAM ending at `ram_end`: the descriptor lines of its
// span, plus 512 KiB for every other startup allocation. Those measure under
// 400 KiB up to the span cap: the startup allocator serves small requests in
// batches of 64 slots, so the bitmaps of a large span alone take 256 KiB.
pub(crate) fn boot_heap_bytes(ram_end: u64) -> u64 {
    let blocks = ram_end.div_ceil(1 << BLOCK_SHIFT).min(MAX_BLOCKS as u64);
    let lines = blocks.div_ceil(4) * size_of::<BlockLine>() as u64;
    (lines + (512 << 10)).next_multiple_of(PAGE_SIZE_SMALL)
}

const LOW_BLOCKS: usize = (128 << 20) >> BLOCK_SHIFT;

const LOW_RESERVED: MemorySegment = MemorySegment {
    start: 0,
    size: KERNEL_PHYS_START,
};

impl BlockPool {
    pub(crate) fn build(inputs: &BootInputs) -> Self {
        let mut layout = inputs.layout(core::slice::from_ref(&LOW_RESERVED));
        let budget = Budget::preflight(layout.blocks)
            .unwrap_or_else(|err| panic!("phys: {} blocks: {err:?}", layout.blocks));
        let (table_block, table_page) = layout
            .carve_table(budget.table_pages)
            .unwrap_or_else(|err| panic!("phys: shaping: {err:?}"))
            .unwrap_or_else(|| {
                panic!(
                    "phys: no free run of {} pages for the list-state table",
                    budget.table_pages
                )
            });
        let table_phys =
            ((table_block as u64) << BLOCK_SHIFT) + (u64::from(table_page) << PAGE_SHIFT);
        // The table pages are managed RAM recorded as allocated in their
        // block, reachable through the direct map, and never freed.
        let lists = unsafe {
            core::slice::from_raw_parts(
                (PAGING_DIRECT_MAP_OFFSET + table_phys) as *const ListWords,
                layout.blocks,
            )
        };
        // Nothing else can see the pool yet: descriptors are constructed in
        // place, and the counters and index words are accumulated locally.
        let (mut total, mut used, mut reserved, mut discarded, mut split) = (0, 0, 0, 0, 0);
        let mut free_words = alloc::vec![0_u64; budget.words];
        let mut whole_words = alloc::vec![0_u64; budget.words];
        let mut build_block = |index: usize| {
            if index >= layout.blocks {
                return Block::absent();
            }
            let mut shaped = layout
                .block(index)
                .unwrap_or_else(|err| panic!("phys: block {index}: {err:?}"));
            if index == table_block {
                shaped.shape.carve(budget.table_pages).unwrap();
            }
            let shape = &shaped.shape;
            let free = match shape.state {
                SPLIT => {
                    // Split is the only state that reads these words.
                    unsafe {
                        (*lists[index].0.get()).write([0; 8]);
                    }
                    split += 1;
                    if shape.inner.used < PAGES {
                        free_words[index / 64] |= 1 << (index % 64);
                    }
                    u64::from(PAGES - shape.inner.used)
                }
                WHOLE => {
                    whole_words[index / 64] |= 1 << (index % 64);
                    u64::from(PAGES)
                }
                _ => 0,
            };
            total += u64::from(shape.managed);
            used += u64::from(shape.managed) - free;
            reserved += u64::from(shape.reserved);
            discarded += u64::from(shape.discarded);
            Block {
                inner: SpinLock::new(shape.inner),
                state: AtomicU8::new(shape.state),
                flags: AtomicU8::new(shaped.flags),
            }
        };
        let lines: Vec<BlockLine> = (0..budget.lines)
            .map(|line| BlockLine(core::array::from_fn(|slot| build_block(line * 4 + slot))))
            .collect();
        let lines = Vec::leak(lines);
        debug_assert_eq!(lines.as_ptr() as usize % align_of::<BlockLine>(), 0);
        let bitmap = |words: Vec<u64>| &*Vec::leak(words.into_iter().map(AtomicU64::new).collect());
        let pool = Pool {
            lines,
            block_count: layout.blocks,
            lists,
            free: bitmap(free_words),
            whole: bitmap(whole_words),
            counters: Counters {
                total,
                used: AtomicU64::new(used),
                high_water: AtomicU64::new(used),
                reserved: AtomicU64::new(reserved),
                discarded: AtomicU64::new(discarded),
                split: AtomicU64::new(split),
                taken: AtomicU64::new(0),
                splits: AtomicU64::new(0),
                recombined: AtomicU64::new(0),
            },
            links: DirectLinks,
            #[cfg(debug_assertions)]
            trace: None,
        };
        #[cfg(debug_assertions)]
        {
            let retained = pool.verify(&mut layout);
            assert_eq!(retained - u64::from(budget.table_pages), pool.free_pages());
            crate::raw_log!(
                "phys: {} blocks, {} whole, {} split, {} pages reserved, table at 0x{:x}",
                layout.blocks,
                pool.whole_count(),
                pool.counters.split.load(Ordering::Relaxed),
                pool.counters.reserved.load(Ordering::Relaxed),
                table_phys
            );
        }
        pool
    }

    // Publish one block's shape while nothing can allocate from it, replacing
    // `was_reserved` pages of earlier reservations. Returns its free count.
    fn install(&self, index: usize, shaped: &Shaped, was_reserved: u64) -> u64 {
        let block = &self.lines[index / 4].0[index % 4];
        let mut inner = block.inner.lock(line!());
        let reserved = u64::from(shaped.shape.reserved);
        self.counters
            .reserved
            .fetch_add(reserved.wrapping_sub(was_reserved), Ordering::Relaxed);
        self.counters
            .discarded
            .fetch_add(u64::from(shaped.shape.discarded), Ordering::Relaxed);
        *inner = shaped.shape.inner;
        block.flags.store(shaped.flags, Ordering::Relaxed);
        block.state.store(shaped.shape.state, Ordering::Relaxed);
        match shaped.shape.state {
            SPLIT => {
                // Split is the only state that reads these words.
                unsafe {
                    (*self.lists[index].0.get()).write([0; 8]);
                }
                self.counters.split.fetch_add(1, Ordering::Relaxed);
                if inner.used < PAGES {
                    self.publish(index, Publication::FreeSet);
                }
                u64::from(PAGES - inner.used)
            }
            WHOLE => {
                self.publish(index, Publication::WholeSet);
                u64::from(PAGES)
            }
            _ => 0,
        }
    }

    // Stage 2: RAM below the kernel becomes allocatable, except page zero and
    // the two kloader page tables still in use. Managed totals do not change.
    pub(crate) fn release_low(&self, inputs: &BootInputs, keep: [u64; 2]) {
        let mut pages = [0, keep[0], keep[1]];
        pages.sort_unstable();
        let reserved = pages.map(|start| {
            assert!(
                start < KERNEL_PHYS_START,
                "phys: kloader table at 0x{start:x}"
            );
            MemorySegment {
                start,
                size: PAGE_SIZE_SMALL,
            }
        });
        #[cfg(debug_assertions)]
        let before = (
            self.free_pages(),
            self.verify(&mut inputs.layout(core::slice::from_ref(&LOW_RESERVED))),
        );
        let mut layout = inputs.layout(&reserved);
        let low_blocks = (KERNEL_PHYS_START >> BLOCK_SHIFT) as usize;
        for index in 0..low_blocks.min(layout.blocks) {
            let shaped = layout
                .block(index)
                .unwrap_or_else(|err| panic!("phys: block {index}: {err:?}"));
            let block = &self.lines[index / 4].0[index % 4];
            {
                let inner = block.inner.lock(line!());
                let state = block.state.load(Ordering::Relaxed);
                if state == ABSENT {
                    assert_eq!(shaped.shape.state, ABSENT);
                    continue;
                }
                assert!(
                    state == SPLIT && inner.used == PAGES && inner.alloc_lo == inner.alloc_hi,
                    "phys: low block {index} changed before stage 2"
                );
            }
            // A fully reserved block's reservation was all of its managed RAM.
            self.counters.split.fetch_sub(1, Ordering::Relaxed);
            let free = self.install(index, &shaped, u64::from(shaped.shape.managed));
            self.release(free as u16);
        }
        #[cfg(debug_assertions)]
        {
            let after = (self.free_pages(), self.verify(&mut layout));
            assert_eq!(after.0 - before.0, after.1 - before.1);
            let inner = *self.lines[0].0[0].inner.lock(line!());
            assert!(inner.alloc_lo >= 1, "phys: page zero became allocatable");
            crate::raw_log!(
                "phys: stage 2 released {} low pages; {} whole, {} split, {} reserved",
                after.0 - before.0,
                self.whole_count(),
                self.counters.split.load(Ordering::Relaxed),
                self.counters.reserved.load(Ordering::Relaxed)
            );
        }
    }

    pub(crate) fn alloc_small(&self, count: u16) -> Option<u64> {
        self.allocate(count, cursor())
            .unwrap_or_else(|err| panic!("phys: corrupt allocator: {err:?} ({count} pages)"))
    }

    pub(crate) fn free_small(&self, addr: u64) {
        self.push(addr)
            .unwrap_or_else(|err| panic!("phys: corrupt free of 0x{addr:x}: {err:?}"));
    }

    // A whole dual-purpose block, or None: a recoverable fallback signal.
    pub(crate) fn alloc_huge(&self) -> Option<u64> {
        self.allocate_huge()
            .unwrap_or_else(|err| panic!("phys: corrupt allocator: {err:?} (huge)"))
    }

    pub(crate) fn free_huge(&self, addr: u64) {
        self.return_huge(addr)
            .unwrap_or_else(|err| panic!("phys: corrupt huge free of 0x{addr:x}: {err:?}"));
    }

    pub(crate) fn total_pages(&self) -> u64 {
        self.counters.total
    }

    pub(crate) fn used_pages(&self) -> u64 {
        self.counters.used.load(Ordering::Relaxed)
    }

    pub(crate) fn free_pages(&self) -> u64 {
        self.counters.total - self.used_pages()
    }

    pub(crate) fn high_water_pages(&self) -> u64 {
        self.counters.high_water.load(Ordering::Relaxed)
    }

    pub(crate) fn reserved_pages(&self) -> u64 {
        self.counters.reserved.load(Ordering::Relaxed)
    }

    pub(crate) fn discarded_pages(&self) -> u64 {
        self.counters.discarded.load(Ordering::Relaxed)
    }

    pub(crate) fn whole_count(&self) -> u64 {
        self.whole
            .iter()
            .map(|word| u64::from(word.load(Ordering::Relaxed).count_ones()))
            .sum()
    }

    pub(crate) fn split_count(&self) -> u64 {
        self.counters.split.load(Ordering::Relaxed)
    }

    pub(crate) fn block_count(&self) -> usize {
        self.block_count
    }

    pub(crate) fn taken_count(&self) -> u64 {
        self.counters.taken.load(Ordering::Relaxed)
    }

    pub(crate) fn split_events(&self) -> u64 {
        self.counters.splits.load(Ordering::Relaxed)
    }

    pub(crate) fn recombine_events(&self) -> u64 {
        self.counters.recombined.load(Ordering::Relaxed)
    }

    // Whole blocks and free pages among the first 64 blocks (the 128 MiB
    // small-only region), each read under its lock; not a snapshot.
    pub(crate) fn low_memory(&self) -> (u64, u64) {
        let (mut whole, mut free) = (0, 0);
        for index in 0..self.block_count.min(LOW_BLOCKS) {
            let block = &self.lines[index / 4].0[index % 4];
            let inner = block.inner.lock(line!());
            match block.state.load(Ordering::Relaxed) {
                WHOLE => {
                    whole += 1;
                    free += u64::from(PAGES);
                }
                SPLIT => free += u64::from(PAGES - inner.used),
                _ => {}
            }
        }
        (whole, free)
    }

    // Any raw RAM or managed page in the block, for MMIO validation.
    pub(crate) fn is_ram(&self, index: usize) -> bool {
        self.block(index).is_ok_and(|block| {
            block.flags.load(Ordering::Relaxed) & RAM != 0
                || block.state.load(Ordering::Relaxed) != ABSENT
        })
    }
}

#[cfg(debug_assertions)]
impl BlockPool {
    // Recount managed, reserved and retained pages from the normalized input
    // intervals by walking the pages of every block that a reservation or the
    // initrd touches, then check every descriptor, list and index invariant.
    // Returns the independently retained free page total.
    fn verify(&self, layout: &mut Layout) -> u64 {
        let (mut managed, mut reserved, mut retained) = (0, 0, 0);
        for index in 0..layout.blocks {
            let (block_managed, block_initrd, block_retained) = recount(layout, index);
            managed += block_managed;
            reserved += block_managed - block_initrd - block_retained;
            retained += block_retained;
        }
        assert_eq!(managed, self.counters.total);
        assert_eq!(reserved, self.reserved_pages());
        self.check_invariants();
        retained
    }

    fn check_invariants(&self) {
        let (mut free, mut split, mut whole) = (0, 0, 0);
        for index in 0..self.block_count {
            let block = self.block(index).unwrap();
            let inner = block.inner.lock(line!());
            let state = block.state.load(Ordering::Relaxed);
            let bit = |map: &[AtomicU64]| {
                map[index / 64].load(Ordering::Relaxed) >> (index % 64) & 1 != 0
            };
            inner.check_bounds().unwrap();
            match state {
                ABSENT => assert!(!bit(self.free) && !bit(self.whole)),
                WHOLE => {
                    inner.check_whole(0).unwrap();
                    assert!(!bit(self.free) && bit(self.whole));
                    whole += 1;
                    free += u64::from(PAGES);
                }
                SPLIT => {
                    // The lock and split state guarantee initialized words.
                    let words = unsafe { (*self.lists[index].0.get()).assume_init_ref() };
                    let listed: u32 = words.iter().map(|word| word.count_ones()).sum();
                    assert!(inner.used > 0);
                    assert_eq!(
                        listed + u32::from(inner.unused_hi - inner.unused_lo),
                        u32::from(PAGES - inner.used)
                    );
                    assert_eq!(bit(self.free), inner.used < PAGES);
                    assert!(!bit(self.whole));
                    split += 1;
                    free += u64::from(PAGES - inner.used);
                }
                TAKEN => {
                    inner.check_whole(PAGES).unwrap();
                    assert!(!bit(self.free) && !bit(self.whole));
                }
                _ => panic!("phys: block {index} state {state}"),
            }
        }
        assert_eq!(free, self.free_pages());
        assert_eq!(split, self.split_count());
        assert_eq!(whole, self.whole_count());
    }
}

// One block's managed, initrd and retained page counts by page walk. Blocks
// without reservations or initrd pages are counted directly.
#[cfg(debug_assertions)]
fn recount(layout: &Layout, index: usize) -> (u64, u64, u64) {
    use core::ops::Range;
    let base = index as u64 * u64::from(PAGES);
    let end = base + u64::from(PAGES);
    let touches = |ranges: &[Range<u64>]| ranges.iter().any(|r| r.start < end && base < r.end);
    let covers = |ranges: &[Range<u64>]| ranges.iter().any(|r| r.start <= base && end <= r.end);
    let initrd = core::slice::from_ref(&layout.initrd);
    if !touches(&layout.managed) {
        return (0, 0, 0);
    }
    if covers(&layout.managed) && !touches(&layout.reserved) && !touches(initrd) {
        return (u64::from(PAGES), 0, u64::from(PAGES));
    }
    let within = |ranges: &[Range<u64>], page: u64| ranges.iter().any(|r| r.contains(&page));
    let (mut managed, mut initrd_pages) = (0, 0);
    let (mut initrd_lo, mut initrd_hi) = (u64::MAX, 0);
    let mut runs: Vec<Range<u64>> = Vec::new();
    for page in base..end {
        if !within(&layout.managed, page) {
            continue;
        }
        managed += 1;
        if within(initrd, page) {
            initrd_pages += 1;
            initrd_lo = initrd_lo.min(page);
            initrd_hi = page + 1;
        } else if !within(&layout.reserved, page) {
            match runs.last_mut() {
                Some(run) if run.end == page => run.end = page + 1,
                _ => runs.push(page..page + 1),
            }
        }
    }
    let retained = runs
        .iter()
        .filter(|run| initrd_pages == 0 || run.end == initrd_lo || run.start == initrd_hi)
        .map(|run| run.end - run.start)
        .fold(0, |best, len| if len > best { len } else { best });
    (managed, initrd_pages, retained)
}
