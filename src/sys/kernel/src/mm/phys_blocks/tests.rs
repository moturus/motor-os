use super::*;
use alloc::vec::Vec;
use core::sync::atomic::AtomicUsize;

const BLOCKS: usize = 66;
const HIGH: usize = 64;
const BASE: u64 = (HIGH as u64) << BLOCK_SHIFT;

pub(super) struct Trace {
    next: AtomicUsize,
    events: [AtomicU64; 8],
}

impl Trace {
    const fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
            events: [const { AtomicU64::new(0) }; 8],
        }
    }

    fn encode(event: Publication) -> u64 {
        match event {
            Publication::FreeSet => 1,
            Publication::FreeClear => 2,
            Publication::WholeSet => 3,
            Publication::WholeClear => 4,
            Publication::Charge(count) => 5 | (u64::from(count) << 16),
            Publication::Release(count) => 6 | (u64::from(count) << 16),
        }
    }

    pub(super) fn record(&self, event: Publication) {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = self.events.get(index) {
            slot.store(Self::encode(event), Ordering::Relaxed);
        }
    }

    fn expect(&self, events: &[Publication]) {
        assert!(events.len() <= self.events.len());
        assert_eq!(self.next.swap(0, Ordering::Relaxed), events.len());
        for (slot, event) in self.events.iter().zip(events) {
            assert_eq!(slot.load(Ordering::Relaxed), Self::encode(*event));
        }
    }
}

struct ScratchLinks {
    words: Vec<AtomicU64>,
    reads: AtomicUsize,
}

impl PageLinks for &ScratchLinks {
    fn read(&self, addr: u64) -> u64 {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.words[(addr >> PAGE_SHIFT) as usize].load(Ordering::Relaxed)
    }

    fn write(&self, addr: u64, word: u64) {
        self.words[(addr >> PAGE_SHIFT) as usize].store(word, Ordering::Relaxed);
    }
}

struct Fixture {
    lines: Vec<BlockLine>,
    lists: Vec<ListWords>,
    free: [AtomicU64; 2],
    whole: [AtomicU64; 2],
    links: ScratchLinks,
}

impl Fixture {
    fn new() -> Self {
        Self {
            lines: (0..BLOCKS.div_ceil(4))
                .map(|_| BlockLine(core::array::from_fn(|_| Block::absent())))
                .collect(),
            lists: (0..BLOCKS).map(|_| ListWords::uninit()).collect(),
            free: [const { AtomicU64::new(0) }; 2],
            whole: [const { AtomicU64::new(0) }; 2],
            links: ScratchLinks {
                words: (0..BLOCKS * usize::from(PAGES))
                    .map(|_| AtomicU64::new(0))
                    .collect(),
                reads: AtomicUsize::new(0),
            },
        }
    }

    fn shape(&mut self, index: usize, lo: u16, hi: u16) {
        let full = lo == 0 && hi == PAGES;
        let block = &mut self.lines[index / 4].0[index % 4];
        *block.inner.lock(line!()) = Inner {
            head: 0,
            used: PAGES - (hi - lo),
            unused_lo: if full { 0 } else { lo },
            unused_hi: if full { 0 } else { hi },
            alloc_lo: lo,
            alloc_hi: hi,
        };
        block
            .state
            .store(if full { WHOLE } else { SPLIT }, Ordering::Relaxed);
        block.flags.store(
            RAM | if index < HIGH { SMALL_ONLY } else { 0 },
            Ordering::Relaxed,
        );
        let map = if full { &self.whole } else { &self.free };
        if hi > lo {
            map[index / 64].fetch_or(1 << (index % 64), Ordering::Relaxed);
        }
        if !full {
            // Exclusive fixture construction, before a pool can borrow it.
            self.lists[index].0.get_mut().write([0; 8]);
        }
    }

    fn pool(&self) -> Pool<'_, &ScratchLinks> {
        let mut total = 0;
        let mut split = 0;
        for index in 0..BLOCKS {
            let block = &self.lines[index / 4].0[index % 4];
            if block.state.load(Ordering::Relaxed) != ABSENT {
                let inner = block.inner.lock(line!());
                total += u64::from(inner.alloc_hi - inner.alloc_lo);
                split += u64::from(block.state.load(Ordering::Relaxed) == SPLIT);
            }
        }
        Pool {
            lines: &self.lines,
            block_count: BLOCKS,
            lists: &self.lists,
            free: &self.free,
            whole: &self.whole,
            links: &self.links,
            counters: Counters {
                total,
                used: AtomicU64::new(0),
                high_water: AtomicU64::new(0),
                reserved: AtomicU64::new(0),
                discarded: AtomicU64::new(0),
                split: AtomicU64::new(split),
                taken: AtomicU64::new(0),
            },
            trace: None,
        }
    }
}

fn check(pool: &Pool<'_, &ScratchLinks>, used: u64) {
    let mut free = 0;
    let mut split = 0;
    let mut taken = 0;
    for index in 0..BLOCKS {
        let block = pool.block(index).unwrap();
        let (inner, state, words) = {
            let inner = block.inner.lock(line!());
            let state = block.state.load(Ordering::Relaxed);
            let words = if state == SPLIT {
                // Same lock and initialized-state contract as production.
                Some(unsafe { *(*pool.lists[index].0.get()).assume_init_ref() })
            } else {
                None
            };
            (*inner, state, words)
        };
        inner.check_bounds().unwrap();
        match state {
            ABSENT => {}
            WHOLE => {
                inner.check_whole(0).unwrap();
                free += u64::from(PAGES);
            }
            SPLIT => {
                assert!(inner.used > 0);
                let listed: u32 = words.unwrap().iter().map(|word| word.count_ones()).sum();
                assert_eq!(
                    listed + u32::from(inner.unused_hi - inner.unused_lo),
                    u32::from(PAGES - inner.used)
                );
                split += 1;
                free += u64::from(PAGES - inner.used);
            }
            TAKEN => {
                inner.check_whole(PAGES).unwrap();
                taken += 1;
            }
            _ => panic!("invalid scratch state"),
        }
        let mask = 1 << (index % 64);
        assert_eq!(
            pool.free[index / 64].load(Ordering::Acquire) & mask != 0,
            state == SPLIT && inner.used < PAGES
        );
        assert_eq!(
            pool.whole[index / 64].load(Ordering::Acquire) & mask != 0,
            state == WHOLE
        );
    }
    assert_eq!(pool.counters.used.load(Ordering::Acquire), used);
    assert_eq!(pool.counters.total - used, free);
    assert_eq!(pool.counters.split.load(Ordering::Relaxed), split);
    assert_eq!(pool.counters.taken.load(Ordering::Relaxed), taken);
}

fn links() {
    let last = ((MAX_BLOCKS as u64) << BLOCK_SHIFT) - 4096;
    assert_eq!(link_decode(last, link_encode(last, 0)), Ok(0));
    assert_eq!((link_encode(last, 0) >> 16) & 0xff_ffff, 0xff_ffff);
    for page in [0, 1, 63, 64, 511] {
        let addr = BASE + (page << PAGE_SHIFT);
        for next in [0, 1, 2, 64, 65, 512] {
            if u64::from(next) == page + 1 {
                continue;
            }
            let word = link_encode(addr, next);
            assert_eq!(link_decode(addr, word), Ok(next));
            for bit in 0..64 {
                assert_eq!(link_decode(addr, word ^ (1 << bit)), Err(Corruption::Link));
            }
            assert_eq!(
                link_decode(addr + (1 << BLOCK_SHIFT), word),
                Err(Corruption::Link)
            );
        }
        assert_eq!(
            link_decode(addr, link_encode(addr, page as u16 + 1)),
            Err(Corruption::Link)
        );
        assert_eq!(
            link_decode(addr, link_encode(addr, 513)),
            Err(Corruption::Link)
        );
    }
    assert_eq!(
        link_decode(BASE + 4096, link_encode(BASE, 0)),
        Err(Corruption::Link)
    );
}

fn ownership_and_runs() {
    for block in [0, HIGH] {
        for count in [1, 2, 64, 65, 256, 512] {
            let mut fixture = Fixture::new();
            fixture.shape(block, 0, PAGES);
            let pool = fixture.pool();
            let base = (block as u64) << BLOCK_SHIFT;
            check(&pool, 0);
            assert_eq!(pool.split(block, 0), Ok(None));
            assert_eq!(pool.split(block, 513), Ok(None));
            assert_eq!(pool.split(block, count), Ok(Some(base)));
            check(&pool, u64::from(count));
            for page in 0..count {
                pool.push(base + (u64::from(page) << PAGE_SHIFT)).unwrap();
                check(&pool, u64::from(count - page - 1));
            }
            assert_eq!(
                pool.counters.high_water.load(Ordering::Relaxed),
                u64::from(count)
            );
            assert_eq!(pool.split(block, 65), Ok(Some(base)));
            assert_eq!(pool.run(block, 448), Ok(None));
            assert_eq!(pool.run(block, 447), Ok(Some(base + (65 << PAGE_SHIFT))));
            assert_eq!(pool.pop(block), Ok(None));
            check(&pool, 512);
        }
    }
}

fn publication() {
    use Publication::*;
    let mut fixture = Fixture::new();
    fixture.shape(HIGH, 0, PAGES);
    let trace = Trace::new();
    let mut pool = fixture.pool();
    pool.trace = Some(&trace);
    assert_eq!(pool.split(HIGH, 2), Ok(Some(BASE)));
    trace.expect(&[FreeSet, WholeClear, Charge(2)]);
    pool.push(BASE).unwrap();
    trace.expect(&[FreeSet, Release(1)]);
    assert_eq!(pool.pop(HIGH), Ok(Some(BASE)));
    trace.expect(&[Charge(1)]);
    // A one-page run follows the same list-first rule as a small request.
    pool.push(BASE).unwrap();
    trace.expect(&[FreeSet, Release(1)]);
    assert_eq!(pool.run(HIGH, 1), Ok(Some(BASE)));
    trace.expect(&[Charge(1)]);
    pool.push(BASE).unwrap();
    trace.expect(&[FreeSet, Release(1)]);
    pool.push(BASE + 4096).unwrap();
    trace.expect(&[WholeSet, FreeClear, Release(1)]);
    check(&pool, 0);
    assert_eq!(pool.split(HIGH, 512), Ok(Some(BASE)));
    trace.expect(&[FreeSet, WholeClear, Charge(512), FreeClear]);
    for page in 0..511 {
        pool.push(BASE + (page << PAGE_SHIFT)).unwrap();
        trace.expect(&[FreeSet, Release(1)]);
    }
    pool.push(BASE + (511 << PAGE_SHIFT)).unwrap();
    trace.expect(&[WholeSet, FreeClear, Release(1)]);
    assert_eq!(pool.take_huge(HIGH), Ok(Some(BASE)));
    trace.expect(&[Charge(512), WholeClear]);
    check(&pool, 512);
    pool.return_huge(BASE).unwrap();
    trace.expect(&[WholeSet, Release(512)]);
    check(&pool, 0);
}

fn rejection_and_lifo() {
    let mut fixture = Fixture::new();
    fixture.shape(HIGH, 0, PAGES);
    let pool = fixture.pool();
    assert_eq!(pool.push(BASE), Err(Corruption::State));
    assert_eq!(pool.push(BASE + 1), Err(Corruption::Address));
    assert_eq!(
        pool.push((BLOCKS as u64) << BLOCK_SHIFT),
        Err(Corruption::Address)
    );
    assert_eq!(pool.push(!4095_u64), Err(Corruption::Address));
    assert_eq!(pool.pop(1), Ok(None));
    assert_eq!(pool.run(HIGH, 2), Ok(None));
    assert_eq!(pool.split(HIGH, 3), Ok(Some(BASE)));
    assert_eq!(pool.push(BASE + 3 * 4096), Err(Corruption::NeverUsed));
    pool.push(BASE).unwrap();
    assert_eq!(pool.push(BASE), Err(Corruption::ListBit));
    pool.push(BASE + 4096).unwrap();
    check(&pool, 1);
    let block = pool.block(HIGH).unwrap();
    let reads = fixture.links.reads.load(Ordering::Relaxed);
    block.inner.lock(line!()).head = 513;
    assert_eq!(pool.pop(HIGH), Err(Corruption::Head));
    assert_eq!(fixture.links.reads.load(Ordering::Relaxed), reads);
    block.inner.lock(line!()).head = 2;
    block.inner.lock(line!()).alloc_lo = 2;
    assert_eq!(pool.pop(HIGH), Err(Corruption::Bounds));
    assert_eq!(fixture.links.reads.load(Ordering::Relaxed), reads);
    block.inner.lock(line!()).alloc_lo = 0;
    let head_addr = BASE + 4096;
    let original = pool.links.read(head_addr);
    for bad in [
        original ^ (1 << 40),
        link_encode(BASE, 1),
        link_encode(head_addr, 2),
    ] {
        pool.links.write(head_addr, bad);
        assert_eq!(pool.pop(HIGH), Err(Corruption::Link));
        check(&pool, 1);
    }
    // A correctly encoded link still cannot name a live or never-used page.
    pool.links.write(head_addr, link_encode(head_addr, 3));
    assert_eq!(pool.pop(HIGH), Err(Corruption::ListBit));
    pool.links.write(head_addr, link_encode(head_addr, 4));
    assert_eq!(pool.pop(HIGH), Err(Corruption::NeverUsed));
    pool.links.write(head_addr, original);
    assert_eq!(pool.pop(HIGH), Ok(Some(head_addr)));
    assert_eq!(pool.pop(HIGH), Ok(Some(BASE)));
    assert_eq!(pool.run(HIGH, 509), Ok(Some(BASE + 3 * 4096)));
    check(&pool, 512);
    pool.push(BASE).unwrap();
    block.inner.lock(line!()).head = 0;
    assert_eq!(pool.pop(HIGH), Err(Corruption::Empty));
    assert_eq!(pool.run(HIGH, 2), Err(Corruption::Empty));
    block.inner.lock(line!()).head = 1;
    check(&pool, 511);
}

fn partial_and_recombination() {
    let mut fixture = Fixture::new();
    fixture.shape(0, 0, PAGES);
    fixture.shape(1, 16, 496);
    fixture.shape(HIGH, 0, PAGES);
    fixture.shape(HIGH + 1, 0, 0);
    let pool = fixture.pool();
    let partial = 1 << BLOCK_SHIFT;
    check(&pool, 0);
    assert_eq!(pool.push(partial), Err(Corruption::Bounds));
    assert_eq!(pool.push(partial + 500 * 4096), Err(Corruption::Bounds));
    assert_eq!(
        pool.push(BASE + (1 << BLOCK_SHIFT)),
        Err(Corruption::Bounds)
    );
    assert_eq!(pool.pop(1), Ok(Some(partial + 16 * 4096)));
    pool.push(partial + 16 * 4096).unwrap();
    assert_eq!(pool.block(1).unwrap().state.load(Ordering::Relaxed), SPLIT);
    check(&pool, 0);
    assert_eq!(pool.take_huge(0), Ok(None));
    for index in [0, HIGH] {
        let base = (index as u64) << BLOCK_SHIFT;
        assert_eq!(pool.split(index, 2), Ok(Some(base)));
        let block = pool.block(index).unwrap();
        {
            let _guard = block.inner.lock(line!());
            block.flags.fetch_or(CLAIMED, Ordering::Relaxed);
        }
        pool.push(base).unwrap();
        pool.push(base + 4096).unwrap();
        assert_eq!(block.flags.load(Ordering::Relaxed) & CLAIMED, 0);
        assert_eq!(pool.pop(index), Ok(None));
        check(&pool, 0);
        assert_eq!(pool.split(index, 65), Ok(Some(base)));
        for page in 0..65 {
            pool.push(base + page * 4096).unwrap();
        }
        check(&pool, 0);
    }
    assert_eq!(pool.take_huge(0), Ok(None));

    // Corrupt metadata must not promote a partial block to whole.
    assert_eq!(pool.pop(1), Ok(Some(partial + 16 * 4096)));
    pool.block(1).unwrap().inner.lock(line!()).used = 1;
    assert_eq!(pool.push(partial + 16 * 4096), Err(Corruption::Recombine));
}

fn huge_and_lazy_words() {
    let mut fixture = Fixture::new();
    fixture.shape(HIGH, 0, PAGES);
    fixture.lists[HIGH].0.get_mut().write([u64::MAX; 8]);
    let pool = fixture.pool();
    assert_eq!(pool.pop(HIGH), Ok(None));
    assert_eq!(pool.return_huge(BASE), Err(Corruption::State));
    assert_eq!(pool.take_huge(HIGH), Ok(Some(BASE)));
    check(&pool, 512);
    assert_eq!(pool.pop(HIGH), Ok(None));
    assert_eq!(pool.run(HIGH, 2), Ok(None));
    assert_eq!(pool.split(HIGH, 1), Ok(None));
    assert_eq!(pool.take_huge(HIGH), Ok(None));
    assert_eq!(pool.push(BASE), Err(Corruption::State));
    assert_eq!(pool.return_huge(BASE + 4096), Err(Corruption::Address));
    assert_eq!(
        pool.return_huge(BASE + (1 << BLOCK_SHIFT)),
        Err(Corruption::State)
    );
    pool.return_huge(BASE).unwrap();
    assert_eq!(pool.return_huge(BASE), Err(Corruption::State));
    check(&pool, 0);
    // Deliberately initialized poison may be inspected by this fixture. The
    // production whole/taken paths must neither validate nor clear its bits.
    let words = {
        let _guard = pool.block(HIGH).unwrap().inner.lock(line!());
        unsafe { *(*pool.lists[HIGH].0.get()).assume_init_ref() }
    };
    assert_eq!(words, [u64::MAX; 8]);
    assert_eq!(pool.split(HIGH, 1), Ok(Some(BASE)));
    check(&pool, 1);
    pool.push(BASE).unwrap();
    let words = {
        let _guard = pool.block(HIGH).unwrap().inner.lock(line!());
        unsafe { *(*pool.lists[HIGH].0.get()).assume_init_ref() }
    };
    assert_eq!(words, [0; 8]);
    check(&pool, 0);
}

fn malformed_bounds_and_state() {
    let mut fixture = Fixture::new();
    fixture.shape(HIGH, 0, PAGES);
    let pool = fixture.pool();
    let block = pool.block(HIGH).unwrap();
    {
        let _guard = block.inner.lock(line!());
        block.state.store(255, Ordering::Relaxed);
    }
    assert_eq!(pool.pop(HIGH), Err(Corruption::State));
    assert_eq!(pool.take_huge(HIGH), Err(Corruption::State));
    {
        let _guard = block.inner.lock(line!());
        block.state.store(WHOLE, Ordering::Relaxed);
    }
    block.inner.lock(line!()).alloc_hi = 513;
    assert_eq!(pool.split(HIGH, 1), Err(Corruption::Bounds));
    assert_eq!(pool.take_huge(HIGH), Err(Corruption::Bounds));
    block.inner.lock(line!()).alloc_hi = PAGES;
    assert_eq!(pool.split(HIGH, 1), Ok(Some(BASE)));
    block.inner.lock(line!()).used = 513;
    assert_eq!(pool.pop(HIGH), Err(Corruption::Used));
    block.inner.lock(line!()).used = 1;
    {
        let _guard = block.inner.lock(line!());
        let words = unsafe { (*pool.lists[HIGH].0.get()).assume_init_mut() };
        words[0] |= 1 << 1;
    }
    assert_eq!(pool.run(HIGH, 2), Err(Corruption::ListBit));
    assert_eq!(pool.push(BASE), Err(Corruption::Recombine));
    let used = block.inner.lock(line!()).used;
    assert_eq!(used, 1);
}

#[path = "search_tests.rs"]
mod search;

pub(super) fn run() {
    links();
    ownership_and_runs();
    publication();
    rejection_and_lifo();
    partial_and_recombination();
    huge_and_lazy_words();
    malformed_bounds_and_state();
    search::run();
    super::shaping::test();
    super::layout::test();
    crate::raw_log!("phys_blocks core tests PASS");
}
