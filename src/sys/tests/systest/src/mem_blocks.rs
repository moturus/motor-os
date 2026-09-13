//! Physical placement and churn over the kernel's block allocator: fresh
//! eager allocations pack into few 2 MiB blocks, and mixed-size churn across
//! threads never aliases live pages.

use moto_sys::SysMem;
use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use std::collections::VecDeque;
use std::sync::mpsc;

const BLOCK_SHIFT: u64 = 21;

struct Mapping {
    addr: u64,
    pages: u64,
}

impl Mapping {
    fn alloc(pages: u64) -> Self {
        let addr = SysMem::alloc(PAGE_SIZE_SMALL, pages).unwrap();
        Self { addr, pages }
    }

    // Two words per page carry a mapping-specific pattern; a page shared
    // between two live mappings would fail the other one's readback.
    fn fill(&self, seed: u64) {
        for page in 0..self.pages {
            let base = (self.addr + page * PAGE_SIZE_SMALL) as *mut u64;
            unsafe {
                base.write_volatile(seed ^ page);
                base.add(511).write_volatile(!(seed ^ page));
            }
        }
    }

    fn verify(&self, seed: u64) {
        for page in 0..self.pages {
            let base = (self.addr + page * PAGE_SIZE_SMALL) as *const u64;
            let (first, last) = unsafe { (base.read_volatile(), base.add(511).read_volatile()) };
            assert_eq!((first, last), (seed ^ page, !(seed ^ page)));
        }
    }

    fn blocks(&self, out: &mut Vec<u64>) {
        for page in 0..self.pages {
            let phys = SysMem::virt_to_phys(self.addr + page * PAGE_SIZE_SMALL).unwrap();
            out.push(phys >> BLOCK_SHIFT);
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        SysMem::free(self.addr).unwrap();
    }
}

// Eight 1 MiB pieces: ideal packing needs four blocks. The allocator drains
// every split block that boot left partially free before splitting a whole
// one: the page-zero block, the kloader page-table block, up to two initrd
// boundary blocks and the list-state table block, at most six. Each CPU adds
// the block its cursor was filling plus one more when a piece straddles two
// fresh blocks. The budget is asserted only on a fresh boot (the focused
// subcommand); the full suite reports placement.
const IDEAL_BLOCKS: usize = 4;
const BOOT_SPLIT_BLOCKS: usize = 6;

fn placement(assert_budget: bool) {
    let mut blocks = Vec::with_capacity(8 * 256);
    let pieces: [Mapping; 8] = core::array::from_fn(|_| Mapping::alloc(256));
    for (idx, piece) in pieces.iter().enumerate() {
        piece.fill(0x5eed_0000 + idx as u64);
    }
    for (idx, piece) in pieces.iter().enumerate() {
        piece.verify(0x5eed_0000 + idx as u64);
        piece.blocks(&mut blocks);
    }
    blocks.sort_unstable();
    blocks.dedup();
    let budget = IDEAL_BLOCKS + BOOT_SPLIT_BLOCKS + 2 * moto_sys::num_cpus() as usize;
    println!(
        "mem_blocks: 8 MiB of fresh pages in {} distinct 2 MiB blocks (budget {budget})",
        blocks.len()
    );
    if assert_budget {
        assert!(
            blocks.len() <= budget,
            "placement spread over {} blocks, budget {budget}",
            blocks.len()
        );
    }
}

struct Prng(u64);

impl Prng {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % bound
    }
}

// Four threads in a ring: each retains its newest allocations, verifies the
// oldest before releasing it, and hands every other release to its neighbor
// so frees cross CPUs and cursors. Sizes up to 4 MiB cover huge-eligible
// mappings; every constituent small page carries its own pattern, so an
// aliased huge page cannot pass as a touched one.
fn churn() {
    const THREADS: usize = 4;
    const ITERATIONS: u32 = 512;
    let mut senders = Vec::new();
    let mut receivers = VecDeque::new();
    for _ in 0..THREADS {
        let (tx, rx) = mpsc::channel::<(Mapping, u64)>();
        senders.push(tx);
        receivers.push_back(rx);
    }
    let handles: Vec<_> = (0..THREADS)
        .map(|thread| {
            let rx = receivers.pop_front().unwrap();
            let tx = senders[(thread + 1) % THREADS].clone();
            std::thread::spawn(move || {
                let mut prng = Prng(0x9e37_79b9_7f4a_7c15_u64.wrapping_mul(thread as u64 + 1));
                let mut retained = VecDeque::new();
                for iteration in 0..ITERATIONS {
                    let pages = 1 + prng.next(1024);
                    let seed = (thread as u64) << 32 | u64::from(iteration);
                    let mapping = Mapping::alloc(pages);
                    mapping.fill(seed);
                    retained.push_back((mapping, seed));
                    if retained.len() > 8 {
                        let (old, seed) = retained.pop_front().unwrap();
                        old.verify(seed);
                        if iteration % 2 == 1 {
                            tx.send((old, seed)).unwrap();
                        }
                    }
                    while let Ok((mapping, seed)) = rx.try_recv() {
                        mapping.verify(seed);
                    }
                }
                drop(tx);
                for (mapping, seed) in retained {
                    mapping.verify(seed);
                }
                for (mapping, seed) in rx {
                    mapping.verify(seed);
                }
            })
        })
        .collect();
    drop(senders);
    for handle in handles {
        handle.join().unwrap();
    }
    println!("mem_blocks: churn PASS");
}

// The block allocator's metrics, read in one query.
#[derive(Debug)]
struct BlockMetrics {
    total: u64,
    whole: u64,
    split: u64,
    taken: u64,
    whole_low: u64,
    reserved: u64,
    free_low: u64,
    splits: u64,
    recombined: u64,
    huge_mapped: u64,
    huge_fallbacks: u64,
}

impl BlockMetrics {
    fn read() -> Self {
        use moto_stats::Collector;

        let kernel = Collector::kernel();
        let descs = Collector::describe(&kernel).unwrap();
        let entries = Collector::query(&kernel).unwrap();
        let m = |name: &str| {
            let desc = descs
                .iter()
                .find(|d| d.name == name)
                .unwrap_or_else(|| panic!("no kernel metric '{name}'"));
            entries
                .iter()
                .find(|e| e.metric == desc.id && e.scope == moto_stats::SCOPE_GLOBAL)
                .map(|e| e.value)
                .unwrap_or_else(|| panic!("kernel metric '{name}' not reported"))
        };
        Self {
            total: m("mem.blocks_total"),
            whole: m("mem.blocks_whole"),
            split: m("mem.blocks_split"),
            taken: m("mem.blocks_taken"),
            whole_low: m("mem.blocks_whole_low"),
            reserved: m("mem.pages_reserved"),
            free_low: m("mem.pages_free_low"),
            splits: m("mem.block_splits"),
            recombined: m("mem.block_recombined"),
            huge_mapped: m("mem.huge_pages_mapped"),
            huge_fallbacks: m("mem.huge_fallbacks"),
        }
    }

    // Individual bounds that hold at any moment: the gauges are collected
    // without a common lock, so no relation between two of them is checked
    // outside a quiescent point.
    fn check_bounds(&self) {
        assert!(self.total > 0, "{self:?}");
        assert!(self.whole <= self.total, "{self:?}");
        assert!(self.split <= self.total, "{self:?}");
        assert!(self.taken <= self.total, "{self:?}");
        assert!(self.whole_low <= 64, "{self:?}");
        assert!(self.free_low <= 64 * 512, "{self:?}");
        assert!(self.reserved > 0, "{self:?}");
    }

    // Event counters only grow; other processes may add to them at any time.
    fn check_monotonic(&self, later: &Self) {
        assert!(self.splits <= later.splits, "{self:?} {later:?}");
        assert!(self.recombined <= later.recombined, "{self:?} {later:?}");
        assert!(self.huge_mapped <= later.huge_mapped, "{self:?} {later:?}");
        assert!(
            self.huge_fallbacks <= later.huge_fallbacks,
            "{self:?} {later:?}"
        );
    }
}

// Every metric reports; the event counters only grow; reserved pages and the
// block count never move. A controlled cycle cannot promise a split or a
// re-combination: boot-split capacity may absorb it, and metadata pages can
// pin a block.
fn metrics() {
    let before = BlockMetrics::read();
    before.check_bounds();
    let pieces: [Mapping; 8] = core::array::from_fn(|_| Mapping::alloc(256));
    for (idx, piece) in pieces.iter().enumerate() {
        piece.fill(idx as u64);
    }
    let held = BlockMetrics::read();
    held.check_bounds();
    drop(pieces);
    let after = BlockMetrics::read();
    after.check_bounds();
    for (a, b) in [(&before, &held), (&held, &after)] {
        assert_eq!((a.total, a.reserved), (b.total, b.reserved), "{a:?} {b:?}");
        a.check_monotonic(b);
    }
    println!(
        "mem_blocks: {} blocks, {} whole, {} split, {} reserved pages, {} splits, {} recombined",
        after.total, after.whole, after.split, after.reserved, after.splits, after.recombined
    );
}

const MID: u64 = 1 << 21;

struct Handle(moto_sys::SysHandle);

impl Drop for Handle {
    fn drop(&mut self) {
        moto_sys::SysObj::put(self.0).unwrap();
    }
}

// Physical pages of a mapping, and how many of them sit in whole 2 MiB
// runs that are physically contiguous and aligned: those can be huge.
fn physical_runs(mapping: &Mapping) -> (Vec<u64>, u64) {
    let mut phys = Vec::with_capacity(mapping.pages as usize);
    for page in 0..mapping.pages {
        phys.push(SysMem::virt_to_phys(mapping.addr + page * PAGE_SIZE_SMALL).unwrap());
    }
    let mut runs = 0;
    for chunk in phys.as_chunks::<512>().0 {
        if chunk[0] % MID == 0
            && chunk
                .iter()
                .enumerate()
                .all(|(i, p)| *p == chunk[0] + i as u64 * PAGE_SIZE_SMALL)
        {
            runs += 1;
        }
    }
    (phys, runs)
}

// Eager heap sizes through map2: the sizing table's returned sizes, 2 MiB
// alignment for requests above 1 MiB, every page mapped and touched, and the
// huge event counters moving by at least the candidate count (other
// processes may add to them). Huge success is reported, never required.
fn sizes() -> u64 {
    let mut huge_runs = 0;
    for (pages, mapped, candidates) in [
        (16, 16, 0),
        (256, 256, 0),
        (257, 512, 1),
        (384, 512, 1),
        (512, 512, 1),
        (768, 768, 1),
        (769, 1024, 2),
        (1408, 1536, 3),
    ] {
        let before = BlockMetrics::read();
        let (addr, size) = SysMem::map2(
            moto_sys::SysHandle::SELF,
            SysMem::F_READABLE | SysMem::F_WRITABLE,
            u64::MAX,
            u64::MAX,
            PAGE_SIZE_SMALL,
            pages,
        )
        .unwrap();
        let pages = mapped;
        let mapping = Mapping { addr, pages };
        assert_eq!(size, mapped * PAGE_SIZE_SMALL);
        if pages > 256 {
            assert_eq!(addr % MID, 0, "eligible segment not 2 MiB aligned");
        }
        mapping.fill(0xc0de + pages);
        mapping.verify(0xc0de + pages);
        let (phys, runs) = physical_runs(&mapping);
        assert_eq!(phys.len() as u64, pages);
        huge_runs += runs;
        let after = BlockMetrics::read();
        let events = (after.huge_mapped - before.huge_mapped)
            + (after.huge_fallbacks - before.huge_fallbacks);
        assert!(
            events >= candidates,
            "{pages} pages: {events} huge events, {candidates} candidates"
        );
        assert!(
            runs <= candidates,
            "{pages} pages: {runs} huge runs without candidates"
        );
    }
    huge_runs
}

// Frames come back zeroed: a dirtied 2 MiB mapping freed and reallocated
// must read zero even when it lands on the same physical pages.
fn reuse_is_zeroed() {
    let first = Mapping::alloc(512);
    first.fill(0xdead_beef);
    let (phys_first, _) = physical_runs(&first);
    drop(first);
    let second = Mapping::alloc(512);
    let (phys_second, _) = physical_runs(&second);
    for page in 0..512 {
        let base = (second.addr + page * PAGE_SIZE_SMALL) as *const u64;
        let (lo, hi) = unsafe { (base.read_volatile(), base.add(511).read_volatile()) };
        assert_eq!((lo, hi), (0, 0), "reused page {page} not zeroed");
    }
    let reused = phys_first
        .iter()
        .filter(|p| phys_second.contains(p))
        .count();
    println!("mem_blocks: reallocation reused {reused} of 512 physical pages, all zero");
}

// Sharing is refused for an eligible source whatever its backing, subranges
// included, while sharing of a 1 MiB segment still works.
fn sharing() {
    let target = Handle(
        moto_sys::SysObj::create(
            moto_sys::SysHandle::NONE,
            0,
            "address_space:debug_name=mem-blocks",
        )
        .unwrap(),
    );
    let dest = moto_sys::CUSTOM_USERSPACE_REGION_START;
    let share = |source: u64, pages: u64| {
        SysMem::map(
            target.0,
            SysMem::F_SHARE_SELF | SysMem::F_READABLE,
            source,
            dest,
            PAGE_SIZE_SMALL,
            pages,
        )
    };
    let small = Mapping::alloc(256);
    let huge = Mapping::alloc(512);
    let odd = Mapping::alloc(768);
    let invalid = Err(moto_rt::E_INVALID_ARGUMENT);
    assert_eq!(share(huge.addr, 512), invalid);
    assert_eq!(share(huge.addr + PAGE_SIZE_SMALL, 2), invalid);
    assert_eq!(share(odd.addr, 768), invalid);
    assert_eq!(share(odd.addr + MID, 1), invalid);
    assert_eq!(share(small.addr, 256), Ok(dest));
    SysMem::unmap(target.0, 0, u64::MAX, dest).unwrap();
    println!("mem_blocks: sharing refusals PASS");
}

// The 64 MiB launcher leg: no dual-purpose block exists, so every candidate
// falls back. Larger guests only report.
pub fn huge_sizes_subcommand() {
    let before = BlockMetrics::read();
    let runs = sizes();
    reuse_is_zeroed();
    let after = BlockMetrics::read();
    let small_guest = moto_sys::stats::MemoryStats::get().unwrap().available <= 128 << 20;
    println!(
        "mem_blocks: {} huge runs, {} huge pages mapped, {} fallbacks, small guest: {small_guest}",
        runs,
        after.huge_mapped - before.huge_mapped,
        after.huge_fallbacks - before.huge_fallbacks
    );
    if small_guest {
        assert_eq!(after.huge_mapped, before.huge_mapped);
        assert!(after.huge_fallbacks >= before.huge_fallbacks + 9);
        assert_eq!(runs, 0);
    }
    println!("mem_blocks: huge sizes PASS");
}

pub fn placement_subcommand() {
    placement(true);
    println!("mem_blocks: placement PASS");
}

pub fn run_all_tests() {
    placement(false);
    metrics();
    let runs = sizes();
    println!("mem_blocks: {runs} huge runs in the sizing table");
    reuse_is_zeroed();
    sharing();
    churn();
    BlockMetrics::read().check_bounds();
}
