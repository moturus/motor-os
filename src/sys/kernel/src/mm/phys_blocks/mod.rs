//! Block ownership core. P1a2 adds shaping/search; P1b replaces phys.rs callers.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::util::SpinLock;

const PAGES: u16 = 512;
const BLOCK_SHIFT: u32 = 21;
const PAGE_SHIFT: u32 = 12;
const MAX_BLOCKS: usize = 32768;
const SMALL_ONLY: u8 = 1;
const CLAIMED: u8 = 2;
const RAM: u8 = 4;
const ABSENT: u8 = 0;
const WHOLE: u8 = 1;
const SPLIT: u8 = 2;
const TAKEN: u8 = 3;
const NO_CURSOR: usize = usize::MAX;

#[derive(Clone, Copy)]
enum SmallSource {
    Split,
    Unclaimed,
    Whole,
}

#[derive(Clone, Copy)]
struct Inner {
    head: u16,
    used: u16,
    unused_lo: u16,
    unused_hi: u16,
    alloc_lo: u16,
    alloc_hi: u16,
}

struct Block {
    inner: SpinLock<Inner>,
    state: AtomicU8,
    flags: AtomicU8,
}

#[repr(C, align(64))]
struct BlockLine([Block; 4]);

#[repr(transparent)]
struct ListWords(UnsafeCell<MaybeUninit<[u64; 8]>>);

// Each entry is accessed only under its corresponding Block lock. Whole,
// taken and absent entries need not contain initialized integers.
unsafe impl Sync for ListWords {}

impl ListWords {
    const fn uninit() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

const _: () = assert!(core::mem::size_of::<Block>() == 16);
const _: () = assert!(core::mem::size_of::<BlockLine>() == 64);
const _: () = assert!(core::mem::align_of::<BlockLine>() == 64);
const _: () = assert!(core::mem::size_of::<ListWords>() == 64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corruption {
    Address,
    State,
    Bounds,
    Used,
    NeverUsed,
    ListBit,
    Head,
    Link,
    Empty,
    Recombine,
}

fn link_encode(addr: u64, next: u16) -> u64 {
    u64::from(next) | ((addr >> PAGE_SHIFT) << 16) | (u64::from(!next) << 40) | (0xa5 << 56)
}

fn link_decode(addr: u64, word: u64) -> Result<u16, Corruption> {
    let next = word as u16;
    let index = ((addr >> PAGE_SHIFT) & 511) as u16;
    if next > PAGES || next == index + 1 || word != link_encode(addr, next) {
        return Err(Corruption::Link);
    }
    Ok(next)
}

fn bit_is_set(words: &[u64; 8], index: u16) -> bool {
    words[usize::from(index / 64)] & (1 << (index % 64)) != 0
}

fn flip_bit(words: &mut [u64; 8], index: u16) {
    words[usize::from(index / 64)] ^= 1 << (index % 64);
}

impl Inner {
    fn check_bounds(&self) -> Result<(), Corruption> {
        if self.alloc_lo > self.alloc_hi
            || self.alloc_hi > PAGES
            || self.unused_lo > self.unused_hi
            || self.unused_hi > PAGES
            || (self.unused_lo != self.unused_hi
                && (self.unused_lo < self.alloc_lo || self.unused_hi > self.alloc_hi))
        {
            return Err(Corruption::Bounds);
        }
        if self.used > PAGES {
            return Err(Corruption::Used);
        }
        Ok(())
    }

    fn allocatable(&self, index: u16) -> bool {
        self.alloc_lo <= index && index < self.alloc_hi
    }

    fn never_used(&self, index: u16) -> bool {
        self.unused_lo <= index && index < self.unused_hi
    }

    fn check_list_index(&self, words: &[u64; 8], index: u16) -> Result<(), Corruption> {
        if !self.allocatable(index) {
            return Err(Corruption::Bounds);
        }
        if self.never_used(index) {
            return Err(Corruption::NeverUsed);
        }
        if !bit_is_set(words, index) {
            return Err(Corruption::ListBit);
        }
        Ok(())
    }

    fn check_push(&self, words: &[u64; 8], index: u16) -> Result<(), Corruption> {
        self.check_bounds()?;
        if !self.allocatable(index) {
            return Err(Corruption::Bounds);
        }
        if self.used == 0 {
            return Err(Corruption::Used);
        }
        if self.never_used(index) {
            return Err(Corruption::NeverUsed);
        }
        if bit_is_set(words, index) {
            return Err(Corruption::ListBit);
        }
        self.check_pop(words)?;
        if self.used == 1 {
            let listed: u32 = words.iter().map(|word| word.count_ones()).sum();
            if self.alloc_lo != 0
                || self.alloc_hi != PAGES
                || listed + u32::from(self.unused_hi - self.unused_lo) + 1 != u32::from(PAGES)
            {
                return Err(Corruption::Recombine);
            }
        }
        Ok(())
    }

    // Validate a head before the caller reads the linked page's first word.
    fn check_pop(&self, words: &[u64; 8]) -> Result<Option<u16>, Corruption> {
        self.check_bounds()?;
        if self.head > PAGES {
            return Err(Corruption::Head);
        }
        if self.head != 0 {
            let index = self.head - 1;
            self.check_list_index(words, index)?;
            Ok(Some(index))
        } else if self.unused_lo == self.unused_hi && self.used != PAGES {
            Err(Corruption::Empty)
        } else {
            Ok(None)
        }
    }

    fn check_run(&self, words: &[u64; 8], count: u16) -> Result<bool, Corruption> {
        self.check_bounds()?;
        if count > self.unused_hi - self.unused_lo {
            self.check_pop(words)?;
            return Ok(false);
        }
        if self.used + count > PAGES {
            return Err(Corruption::Used);
        }
        for index in self.unused_lo..self.unused_lo + count {
            if bit_is_set(words, index) {
                return Err(Corruption::ListBit);
            }
        }
        Ok(true)
    }

    fn check_whole(&self, used: u16) -> Result<(), Corruption> {
        self.check_bounds()?;
        if self.alloc_lo != 0
            || self.alloc_hi != PAGES
            || self.used != used
            || self.head != 0
            || self.unused_lo != self.unused_hi
        {
            return Err(Corruption::State);
        }
        Ok(())
    }
}

// Only free, validated pages reach this interface. The scratch implementation
// stores one word per page and never dereferences its synthetic addresses.
trait PageLinks {
    fn read(&self, addr: u64) -> u64;
    fn write(&self, addr: u64, word: u64);
}

struct DirectLinks;

impl PageLinks for DirectLinks {
    fn read(&self, addr: u64) -> u64 {
        unsafe { *((super::PAGING_DIRECT_MAP_OFFSET + addr) as *const u64) }
    }

    fn write(&self, addr: u64, word: u64) {
        unsafe { *((super::PAGING_DIRECT_MAP_OFFSET + addr) as *mut u64) = word }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Publication {
    FreeSet,
    FreeClear,
    WholeSet,
    WholeClear,
    Charge(u16),
    Release(u16),
}

struct Counters {
    total: u64,
    used: AtomicU64,
    high_water: AtomicU64,
    reserved: AtomicU64,
    split: AtomicU64,
    taken: AtomicU64,
}

// Storage is permanent in production and private to one pool. Construction
// must initialize every SPLIT entry's list words before publishing its state.
struct Pool<'a, L> {
    lines: &'a [BlockLine],
    block_count: usize,
    lists: &'a [ListWords],
    free: &'a [AtomicU64],
    whole: &'a [AtomicU64],
    counters: Counters,
    links: L,
    #[cfg(debug_assertions)]
    trace: Option<&'a tests::Trace>,
}

impl<L: PageLinks> Pool<'_, L> {
    fn block(&self, index: usize) -> Result<&Block, Corruption> {
        if index >= self.block_count || index >= MAX_BLOCKS {
            return Err(Corruption::Address);
        }
        Ok(&self.lines[index / 4].0[index % 4])
    }

    fn page_location(&self, addr: u64) -> Result<(usize, u16), Corruption> {
        if addr & ((1 << PAGE_SHIFT) - 1) != 0 || addr >> BLOCK_SHIFT >= MAX_BLOCKS as u64 {
            return Err(Corruption::Address);
        }
        let block = (addr >> BLOCK_SHIFT) as usize;
        self.block(block)?;
        Ok((block, ((addr >> PAGE_SHIFT) & 511) as u16))
    }

    fn publish(&self, block: usize, event: Publication) {
        let (map, set) = match event {
            Publication::FreeSet => (self.free, true),
            Publication::FreeClear => (self.free, false),
            Publication::WholeSet => (self.whole, true),
            Publication::WholeClear => (self.whole, false),
            _ => unreachable!(),
        };
        let mask = 1 << (block % 64);
        if set {
            map[block / 64].fetch_or(mask, Ordering::AcqRel);
        } else {
            map[block / 64].fetch_and(!mask, Ordering::AcqRel);
        }
        #[cfg(debug_assertions)]
        if let Some(trace) = self.trace {
            trace.record(event);
        }
    }

    fn charge(&self, count: u16) {
        let used = self
            .counters
            .used
            .fetch_add(u64::from(count), Ordering::Release)
            + u64::from(count);
        self.counters.high_water.fetch_max(used, Ordering::Relaxed);
        #[cfg(debug_assertions)]
        if let Some(trace) = self.trace {
            trace.record(Publication::Charge(count));
        }
    }

    fn release(&self, count: u16) {
        self.counters
            .used
            .fetch_sub(u64::from(count), Ordering::Release);
        #[cfg(debug_assertions)]
        if let Some(trace) = self.trace {
            trace.record(Publication::Release(count));
        }
    }

    fn pop(&self, block: usize) -> Result<Option<u64>, Corruption> {
        self.take_small(block, 1, SmallSource::Split, false)
    }

    fn run(&self, block: usize, count: u16) -> Result<Option<u64>, Corruption> {
        self.take_small(block, count, SmallSource::Split, false)
    }

    fn split(&self, block: usize, count: u16) -> Result<Option<u64>, Corruption> {
        self.take_small(block, count, SmallSource::Whole, false)
    }

    fn take_small(
        &self,
        index: usize,
        count: u16,
        source: SmallSource,
        claim: bool,
    ) -> Result<Option<u64>, Corruption> {
        if count == 0 || count > PAGES {
            return Ok(None);
        }
        let block = self.block(index)?;
        let mut inner = block.inner.lock(line!());
        match (block.state.load(Ordering::Relaxed), source) {
            (WHOLE, SmallSource::Whole) => {
                inner.check_whole(0)?;
                // The block lock excludes all access to this entry. Initialize
                // all words before switching to the only state that reads them.
                unsafe {
                    (*self.lists[index].0.get()).write([0; 8]);
                }
                inner.unused_lo = 0;
                inner.unused_hi = PAGES;
                block.state.store(SPLIT, Ordering::Relaxed);
                self.counters.split.fetch_add(1, Ordering::Relaxed);
                self.publish(index, Publication::FreeSet);
                self.publish(index, Publication::WholeClear);
            }
            (SPLIT, SmallSource::Split | SmallSource::Unclaimed) => {
                if matches!(source, SmallSource::Unclaimed)
                    && block.flags.load(Ordering::Relaxed) & CLAIMED != 0
                {
                    return Ok(None);
                }
            }
            (ABSENT | WHOLE | SPLIT | TAKEN, _) => return Ok(None),
            _ => return Err(Corruption::State),
        }
        // SPLIT guarantees initialized words; its lock gives exclusive access.
        let words = unsafe { (*self.lists[index].0.get()).assume_init_mut() };
        let base = (index as u64) << BLOCK_SHIFT;
        let head = inner.check_pop(words)?;
        let page = if let (1, Some(page)) = (count, head) {
            if inner.used == PAGES {
                return Err(Corruption::Used);
            }
            let addr = base + (u64::from(page) << PAGE_SHIFT);
            let next = link_decode(addr, self.links.read(addr))?;
            if next != 0 {
                inner.check_list_index(words, next - 1)?;
            }
            flip_bit(words, page);
            inner.head = next;
            page
        } else {
            if !inner.check_run(words, count)? {
                return Ok(None);
            }
            let page = inner.unused_lo;
            inner.unused_lo += count;
            page
        };
        inner.used += count;
        if claim {
            block.flags.fetch_or(CLAIMED, Ordering::Relaxed);
        }
        self.charge(count);
        if inner.used == PAGES {
            self.publish(index, Publication::FreeClear);
        }
        Ok(Some(base + (u64::from(page) << PAGE_SHIFT)))
    }

    fn push(&self, addr: u64) -> Result<(), Corruption> {
        let (index, page) = self.page_location(addr)?;
        let block = self.block(index)?;
        let mut inner = block.inner.lock(line!());
        if block.state.load(Ordering::Relaxed) != SPLIT {
            return Err(Corruption::State);
        }
        // SPLIT guarantees initialized words; its lock gives exclusive access.
        let words = unsafe { (*self.lists[index].0.get()).assume_init_mut() };
        inner.check_push(words, page)?;
        self.links.write(addr, link_encode(addr, inner.head));
        flip_bit(words, page);
        inner.head = page + 1;
        inner.used -= 1;
        if inner.used == 0 {
            // check_push validated the prospective combined capacity before
            // changing ownership, so an error never unlocks a used=0 split.
            words.fill(0);
            inner.head = 0;
            inner.unused_lo = 0;
            inner.unused_hi = 0;
            block.flags.fetch_and(!CLAIMED, Ordering::Relaxed);
            block.state.store(WHOLE, Ordering::Relaxed);
            self.counters.split.fetch_sub(1, Ordering::Relaxed);
            self.publish(index, Publication::WholeSet);
            self.publish(index, Publication::FreeClear);
        } else {
            self.publish(index, Publication::FreeSet);
        }
        self.release(1);
        Ok(())
    }

    fn take_huge(&self, index: usize) -> Result<Option<u64>, Corruption> {
        let block = self.block(index)?;
        let mut inner = block.inner.lock(line!());
        match block.state.load(Ordering::Relaxed) {
            WHOLE => {}
            ABSENT | SPLIT | TAKEN => return Ok(None),
            _ => return Err(Corruption::State),
        }
        if block.flags.load(Ordering::Relaxed) & SMALL_ONLY != 0 {
            return Ok(None);
        }
        inner.check_whole(0)?;
        inner.used = PAGES;
        block.state.store(TAKEN, Ordering::Relaxed);
        self.counters.taken.fetch_add(1, Ordering::Relaxed);
        self.charge(PAGES);
        self.publish(index, Publication::WholeClear);
        Ok(Some((index as u64) << BLOCK_SHIFT))
    }

    fn return_huge(&self, addr: u64) -> Result<(), Corruption> {
        let (index, page) = self.page_location(addr)?;
        if page != 0 {
            return Err(Corruption::Address);
        }
        let block = self.block(index)?;
        let mut inner = block.inner.lock(line!());
        if block.state.load(Ordering::Relaxed) != TAKEN
            || block.flags.load(Ordering::Relaxed) & SMALL_ONLY != 0
        {
            return Err(Corruption::State);
        }
        inner.check_whole(PAGES)?;
        inner.used = 0;
        block.state.store(WHOLE, Ordering::Relaxed);
        self.counters.taken.fetch_sub(1, Ordering::Relaxed);
        self.publish(index, Publication::WholeSet);
        self.release(PAGES);
        Ok(())
    }
}

mod search;
mod shaping;

#[cfg(debug_assertions)]
mod tests;

#[cfg(debug_assertions)]
pub(crate) fn test() {
    tests::run();
}
