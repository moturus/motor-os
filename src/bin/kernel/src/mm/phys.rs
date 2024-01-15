use super::slab::*;
use super::*;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::*;
use moto_sys::ErrorCode;

pub fn init(available: &[MemorySegment], in_use: &[MemorySegment]) {
    PhysicalMemory::init(available, in_use);
}

// Physical frame.
pub struct Frame {
    start: u64,
    kind: PageType,
}

impl Frame {
    pub fn start(&self) -> u64 {
        self.start
    }
    pub fn kind(&self) -> PageType {
        self.kind
    }
}

impl Slabbable for Frame {
    fn inplace_init(&mut self) {
        self.start = 0;
        self.kind = PageType::Unknown;
    }

    fn drop_slabbable(&mut self) {
        PhysicalMemory::inst().deallocate_frame(self)
    }
}

pub fn allocate_frame(kind: PageType) -> Result<SlabArc<Frame>, ErrorCode> {
    let res = PhysicalMemory::inst().allocate_frame(kind);
    if res.is_err() {
        log::debug!("OOM");
        #[cfg(debug_assertions)]
        dump_stats();
    }
    res
}

// Allocate a physical page without allocating struct Frame.
// Used internally in mm for page table and slab allocations.
pub fn phys_allocate_frameless(kind: PageType) -> Result<u64, ErrorCode> {
    #[cfg(debug_assertions)]
    {
        let res = PhysicalMemory::inst().allocate_frameless(kind);
        if res.is_err() {
            log::warn!("OOM!");
            dump_serial();
        }
        res
    }
    #[cfg(not(debug_assertions))]
    PhysicalMemory::inst().allocate_frameless(kind)
}

pub fn phys_deallocate_frameless(phys_addr: u64, kind: PageType) {
    PhysicalMemory::inst().deallocate_frameless(phys_addr, kind);
}

// Reserve a page at a fixed physical address, e.g. for MMIO.
pub fn fixed_addr_reserve(phys_addr: u64, kind: PageType) -> Result<(), ErrorCode> {
    PhysicalMemory::inst().fixed_addr_reserve(phys_addr, kind)
}

pub fn phys_allocate_contiguous_frames(
    kind: PageType,
    num_frames: u64,
) -> Result<Vec<SlabArc<Frame>>, ErrorCode> {
    PhysicalMemory::inst().allocate_contiguous_frames(kind, num_frames)
}

pub fn mark_unused(seg: &MemorySegment) {
    PhysicalMemory::inst().small_pages.mark_unused(seg)
}

#[cfg(debug_assertions)]
pub fn dump_serial() {
    PhysicalMemory::inst().dump_serial();
}

// All available physical memory is partitioned into static regions
// for small and mid pages.
struct DesignatedSegment<S: PageSize> {
    segment: MemorySegment,
    used_bitmap: AtomicU64, // bit per page, so at most 64 pages.
    num_pages: u8,
    _unused: PhantomData<S>,
}

impl<S: PageSize> DesignatedSegment<S> {
    fn new(segment: &MemorySegment) -> Self {
        let res = DesignatedSegment {
            segment: segment.clone(),
            used_bitmap: AtomicU64::new(0),
            num_pages: (segment.size >> S::SIZE_LOG2) as u8,
            _unused: PhantomData {},
        };

        if segment.start == 0 {
            // Mark the first physical page as used, to never
            // allocate at zero phys address.
            res.used_bitmap.store(1, Ordering::Relaxed);
        }

        res
    }

    fn mark_used(&self, segment: &MemorySegment) -> u64 {
        let mut start = align_down(segment.start, S::SIZE).max(self.segment.start);
        let end = align_up(segment.end(), S::SIZE).min(self.segment.end());

        let mut used_frames = 0_u64;
        while start < end {
            if self.fixed_addr_reserve(start).is_ok() {
                used_frames += 1;
            }
            start += S::SIZE;
        }

        used_frames
    }

    fn mark_unused(&self, segment: &MemorySegment) -> u64 {
        let mut start = align_down(segment.start, S::SIZE).max(self.segment.start);
        let end = align_up(segment.end(), S::SIZE).min(self.segment.end());

        // mark_unused is called once during bootup to park pages in [0..34M) available.
        // The only page that is still in use there is the L4 page table (=kpt).
        let l4_phys_addr = crate::arch::paging::kpt_phys_addr();
        let l3_phys_addr = crate::arch::paging::l3_direct_phys_table_phys_addr();

        let mut freed_frames = 0_u64;
        while start < end {
            if start != l4_phys_addr && start != l3_phys_addr {
                if self.deallocate_frame(start) {
                    freed_frames += 1;
                }
            }
            start += S::SIZE;
        }

        freed_frames
    }

    #[cfg(debug_assertions)]
    fn dump_serial(&self, prefix: &str, suffix: &str) {
        crate::raw_log!(
            "{}seg::{}: [0x{:x}, 0x{:x}) used: {:064b} pages: {} {}",
            prefix,
            S::as_str(),
            self.segment.start,
            self.segment.end(),
            self.used_bitmap.load(Ordering::Relaxed),
            self.segment.size >> S::SIZE_LOG2,
            suffix
        );
    }

    fn allocate_frame(&self) -> Result<u64, ErrorCode> {
        let mut iters = 0_u64;
        loop {
            iters += 1;
            if iters > 10000 {
                panic!("allocate_frame looping");
            }
            let prev = self.used_bitmap.load(Ordering::Relaxed);
            if prev == u64::MAX {
                return Err(ErrorCode::OutOfMemory);
            }

            let ones = prev.trailing_ones() as u8;
            if ones == self.num_pages {
                return Err(ErrorCode::OutOfMemory);
            }
            debug_assert!(ones < self.num_pages);

            let bit = 1u64 << ones;
            assert_eq!(0, prev & bit);
            if self
                .used_bitmap
                .compare_exchange_weak(prev, prev | bit, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                let start = ((ones as u64) << S::SIZE_LOG2) + self.segment.start;
                return Ok(start);
            }
        }
    }

    fn allocate_contiguous(&self, num: u64) -> Result<u64, ErrorCode> {
        assert!(num > 1);
        let prev = self.used_bitmap.load(Ordering::Relaxed);

        let mut start = 0;
        let mut cnt = 0;
        for idx in 0..(self.num_pages - 1) {
            if (prev & (1u64 << idx)) != 0 {
                cnt = 0;
                continue;
            }
            cnt += 1;
            if cnt == 1 {
                start = idx;
            }
            if cnt == num {
                break;
            }
        }

        if cnt < num {
            log::debug!("Contiguous OOM: requested {} in use: 0b{:b}", num, prev);
            return Err(ErrorCode::OutOfMemory);
        }

        let mut mask = 0_u64;
        for idx in start..(num as u8 + start) {
            mask |= 1u64 << idx;
        }

        let res = self.used_bitmap.compare_exchange(
            prev,
            prev | mask,
            Ordering::Release,
            Ordering::Relaxed,
        );

        if let Err(prev) = res {
            log::debug!("Contiguous OOM: requested {} in use: 0b{:b}", num, prev);
            return Err(ErrorCode::OutOfMemory);
        }

        log::trace!(
            "Contiguos Alloc OK: num {} prev 0b{:b} next 0b{:b}",
            num,
            prev,
            prev | mask
        );
        Ok(((start as u64) << S::SIZE_LOG2) + self.segment.start)
    }

    fn fixed_addr_reserve(&self, addr: u64) -> Result<(), ErrorCode> {
        assert!(addr >= self.segment.start);
        assert!(addr < self.segment.end());

        let bit_num = (addr - self.segment.start) >> S::SIZE_LOG2;
        assert!(bit_num < 64);
        let bit = 1u64 << bit_num;

        let mut iters = 0_u64;
        loop {
            iters += 1;
            if iters > 10000 {
                panic!("fixed_addr_reserve looping");
            }
            let prev = self.used_bitmap.load(Ordering::Relaxed);
            if prev & bit == bit {
                log::warn!("fixed_addr_reserve: already in use: addr: 0x{:x}", addr);
                return Err(ErrorCode::AlreadyInUse);
            }
            let next = prev | bit;

            let result = self.used_bitmap.compare_exchange_weak(
                prev,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            if result.is_ok() {
                return Ok(());
            }
        }
    }

    fn deallocate_frame(&self, addr: u64) -> bool {
        assert!(addr >= self.segment.start);
        assert!(addr < self.segment.end());

        if addr == 0 {
            // Never allow zero address to be used.
            return false;
        }
        let bit_num = (addr - self.segment.start) >> S::SIZE_LOG2;
        assert!(bit_num < 64);
        let bit = 1u64 << bit_num;

        let mut iters = 0_u64;
        loop {
            iters += 1;
            if iters > 100 {
                panic!("deallocate_frame looping");
            }
            let prev = self.used_bitmap.load(Ordering::Relaxed);
            assert_eq!(prev & bit, bit);
            let next = prev ^ bit;

            let result = self.used_bitmap.compare_exchange_weak(
                prev,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            if result.is_ok() {
                return true;
            }
        }
    }
}

struct MemoryArea<S: PageSize> {
    segments: Vec<DesignatedSegment<S>>,

    total_pages: u64,
    used_pages: AtomicU64, // A counter.

    // A free-list consisting of a single frame. Note that the free_frame is still counted as used.
    free_frame: AtomicU64, // Zero means empty.
}

impl<S: PageSize> MemoryArea<S> {
    fn new() -> Self {
        MemoryArea {
            segments: vec![],
            total_pages: 0,
            used_pages: AtomicU64::new(0),
            free_frame: AtomicU64::new(0),
        }
    }

    fn add_segment(&mut self, segment: &MemorySegment) {
        debug_assert_eq!(0, segment.start & (S::SIZE - 1));
        debug_assert_eq!(0, segment.size & (S::SIZE - 1));
        debug_assert!(self.segments.len() < self.segments.capacity());

        self.segments.push(DesignatedSegment::new(segment));

        self.total_pages += segment.size >> S::SIZE_LOG2;
    }

    fn mark_used(&self, segment: &MemorySegment) {
        // Not efficient, but used only during bootup, so OK.
        for seg in &self.segments {
            self.used_pages
                .fetch_add(seg.mark_used(segment), Ordering::Relaxed);
        }
    }

    fn mark_unused(&self, segment: &MemorySegment) {
        // Not efficient, but used only during bootup, so OK.
        for seg in &self.segments {
            self.used_pages
                .fetch_sub(seg.mark_unused(segment), Ordering::Relaxed);
        }
    }

    fn sort(&mut self) {
        // Stable sort allocates, and this is called during bootups, so we don't want to allocate.
        self.segments
            .sort_unstable_by(|a, b| a.segment.start.cmp(&b.segment.start));
    }

    #[cfg(debug_assertions)]
    fn dump_serial(&self, prefix: &str) {
        crate::raw_log!(
            "{}Area::{}: total pages: 0x{:x} used pages: 0x{:x}\n",
            prefix,
            S::as_str(),
            self.total_pages,
            self.used_pages.load(Ordering::Relaxed)
        );

        for seg in &self.segments {
            seg.dump_serial("    ", "\n");
        }
    }

    fn _contains(&self, addr: u64) -> bool {
        for seg in &self.segments {
            if seg.segment.contains(addr) {
                return true;
            }
        }
        false
    }

    fn fixed_addr_reserve(&self, phys_addr: u64) -> Result<(), ErrorCode> {
        if self
            .free_frame
            .compare_exchange(phys_addr, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.used_pages.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        for seg in &self.segments {
            if !seg.segment.contains(phys_addr) {
                continue;
            }
            let result = seg.fixed_addr_reserve(phys_addr);
            if result.is_ok() {
                self.used_pages.fetch_add(1, Ordering::Relaxed);
            }
            return result;
        }

        log::debug!("phys: fixed_addr_reserve: 0x{:x}: not found", phys_addr);

        // VirtIO/MMIO sometimes tries to map pages that are not in our memory map.
        // TODO: figure out how to confirm that the requested address is indeed
        //       available for MMIO.
        Ok(())
        // Err(ErrorCode::OutOfMemory)
    }

    fn do_allocate_frame(&self) -> Result<u64, ErrorCode> {
        let start = self.free_frame.swap(0u64, Ordering::Relaxed);
        if start != 0 {
            // Found a cached frame.
            self.used_pages.fetch_add(1, Ordering::Relaxed);
            return Ok(start);
        }

        if self.total_pages == self.used_pages.load(Ordering::Relaxed) {
            return Err(ErrorCode::OutOfMemory);
        }

        // Try allocating from a random segment several times.
        {
            const RANDOM_TRIES: u8 = 3;
            for _attempt in 0..RANDOM_TRIES {
                let idx = crate::util::prng(false) as usize % self.segments.len();
                let segment = self.segments.get(idx).unwrap();

                let frame = segment.allocate_frame();

                if frame.is_ok() {
                    self.used_pages.fetch_add(1, Ordering::Relaxed);
                    return frame;
                }
            }
        }

        // Try linear search.
        for segment in &self.segments {
            let frame = segment.allocate_frame();
            if frame.is_ok() {
                self.used_pages.fetch_add(1, Ordering::Relaxed);
                return frame;
            }
        }

        Err(ErrorCode::OutOfMemory)
    }

    fn allocate_frame(&self) -> Result<u64, ErrorCode> {
        match self.do_allocate_frame() {
            Ok(f) => Ok(f),
            Err(err) => {
                log::error!(
                    "OOM: failed to allocate {} frame.\nTotal pages: {}; used pages: {}.\n",
                    S::as_str(),
                    self.total_pages,
                    self.used_pages.load(Ordering::Acquire),
                );
                Err(err)
            }
        }
    }

    fn allocate_contiguous_frames(&self, num_frames: u64) -> Result<u64, ErrorCode> {
        if num_frames > 64 {
            log::debug!(
                "Alloc: OOM: too many contiguous frames requested: {}.",
                num_frames
            );
            Err(ErrorCode::OutOfMemory)
        } else if num_frames == 1 {
            self.allocate_frame()
        } else {
            // Linear search is fine as this is used during bootup in VirtIO setup.
            for segment in &self.segments {
                let start = segment.allocate_contiguous(num_frames);
                if start.is_ok() {
                    self.used_pages.fetch_add(num_frames, Ordering::Relaxed);
                    return start;
                }
            }
            log::debug!(
                "Alloc: OOM: frame size: {} num frames: {} total frames: {} used frames: {}.",
                S::SIZE,
                num_frames,
                self.total_pages,
                self.used_pages.load(Ordering::Relaxed)
            );
            Err(ErrorCode::OutOfMemory)
        }
    }

    fn deallocate_frame(&self, addr: u64) {
        assert!(self.total_pages != 0);
        self.used_pages.fetch_sub(1, Ordering::Relaxed);

        #[cfg(debug_assertions)]
        let to_free = addr;

        #[cfg(not(debug_assertions))]
        let to_free = {
            let prev_cached = self.free_frame.swap(addr, Ordering::Relaxed);
            if prev_cached == 0 {
                // Cached our frame. No previously cached frames. Life is good.
                return;
            }
            prev_cached
        };

        let owner = self.segments.as_slice().binary_search_by(|seg| {
            use core::cmp::Ordering;

            if seg.segment.start > to_free {
                Ordering::Greater
            } else if seg.segment.end() <= to_free {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        });

        if owner.is_err() {
            panic!("failed to deallocate address 0x{:x}", to_free);
        }

        let owner = owner.unwrap();

        self.segments.get(owner).unwrap().deallocate_frame(to_free);
    }
}

// Contains everything. Has a single instantiation.
struct PhysicalMemory {
    total_size: u64, // does not change once initialized

    slab: MMSlab<Frame>,

    small_pages: MemoryArea<PageSizeSmall>,
    // mid_pages: DesignatedSegment<PageSizeMid>,
}

// A pointer to the one and only instance of struct PhysicalMemory.
static mut PHYS_MEM: usize = 0;

impl PhysicalMemory {
    // The number of MID pages we reserve. At the moment only the kernel
    // and, maybe, sys-io are allowed to use MID pages, so the number is small.
    // const MID_PAGES: usize = 8;
    // const MID_PAGES_SEGMENT: MemorySegment = MemorySegment {
    //     start: (super::ONE_MB * 2) as u64,
    //     size: (Self::MID_PAGES << PAGE_SIZE_MID_LOG2) as u64,
    // };

    fn inst() -> &'static Self {
        let addr = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PHYS_MEM) as *const usize) };
        assert_ne!(addr, 0);
        unsafe { (addr as *const Self).as_ref().unwrap_unchecked() }
    }

    fn allocate_frame(&'static self, kind: PageType) -> Result<SlabArc<Frame>, ErrorCode> {
        let frame_start = self.allocate_frameless(kind)?;

        let frame_result = self.slab.alloc_arc();

        if let Ok(frame) = frame_result {
            frame.get_mut().unwrap().start = frame_start;
            frame.get_mut().unwrap().kind = kind;
            Ok(frame)
        } else {
            self.deallocate_frameless(frame_start, kind);
            frame_result
        }
    }

    fn allocate_frameless(&'static self, kind: PageType) -> Result<u64, ErrorCode> {
        let result = match kind {
            PageType::SmallPage => self.small_pages.allocate_frame(),
            // PageType::MidPage => self.mid_pages.allocate_frame(),
            _ => panic!(),
        };

        result
    }

    fn fixed_addr_reserve(&'static self, phys_addr: u64, kind: PageType) -> Result<(), ErrorCode> {
        const LAPIC_BASE: u64 = 0xfee0_0000_u64; // The default Local APIC address.
        const IOAPIC_BASE: u64 = 0xfec0_0000_u64; // The default IO APIC address.

        if phys_addr == LAPIC_BASE || phys_addr == IOAPIC_BASE {
            return Ok(());
        }
        match kind {
            PageType::SmallPage => self.small_pages.fixed_addr_reserve(phys_addr),
            // PageType::MidPage => self.mid_pages.fixed_addr_reserve(phys_addr),
            _ => panic!(),
        }
    }

    fn deallocate_frameless(&'static self, phys_addr: u64, kind: PageType) {
        match kind {
            PageType::SmallPage => self.small_pages.deallocate_frame(phys_addr),
            /*
            PageType::MidPage => {
                if self.mid_pages.segment.contains(phys_addr) {
                    self.mid_pages.deallocate_frame(phys_addr)
                } else {
                    let segment = MemorySegment {
                        start: phys_addr,
                        size: PAGE_SIZE_MID,
                    };
                    self.small_pages.mark_unused(&segment);
                }
            }
            */
            // PageType::MidPage => {
            //     let segment = MemorySegment {
            //         start: phys_addr,
            //         size: PAGE_SIZE_MID,
            //     };
            //     self.small_pages.mark_unused(&segment);
            // }
            _ => panic!(),
        };
    }

    fn deallocate_frame(&self, frame: &Frame) {
        match frame.kind {
            PageType::SmallPage => self.small_pages.deallocate_frame(frame.start),
            // PageType::MidPage => self.mid_pages.deallocate_frame(frame.start),
            _ => panic!(),
        };

        // Note that the frame is deallocated from its slab automatically.
    }

    fn allocate_contiguous_frames(
        &self,
        kind: PageType,
        num_frames: u64,
    ) -> Result<Vec<SlabArc<Frame>>, ErrorCode> {
        // At the moment we only support allocating contiguous small pages.
        assert!(num_frames <= 256);
        assert_eq!(kind, PageType::SmallPage);

        let start = self.small_pages.allocate_contiguous_frames(num_frames)?;

        let mut frame_start = start;
        let mut result = vec![];
        result.reserve(num_frames as usize);

        let mut failed = false;

        for _idx in 0..num_frames {
            if failed {
                match kind {
                    PageType::SmallPage => self.small_pages.deallocate_frame(frame_start),
                    // PageType::MidPage => self.mid_pages.deallocate_frame(frame_start),
                    _ => panic!(), // Only small and mid pages are allocated here.
                }
            } else {
                let frame_result = self.slab.alloc_arc();

                if let Ok(frame) = frame_result {
                    frame.get_mut().unwrap().start = frame_start;
                    frame.get_mut().unwrap().kind = kind;
                    result.push(frame);
                } else {
                    // Frames already pushed onto result will be auto-freed;
                    // we need to free the unslabbed ones, including the current.
                    failed = true;
                    continue;
                }
            }

            frame_start += kind.page_size();
        }

        if failed {
            Err(ErrorCode::OutOfMemory)
        } else {
            Ok(result)
        }
    }

    fn init(available: &[MemorySegment], in_use: &[MemorySegment]) {
        assert_eq!(0, unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(PHYS_MEM) as *const usize)
        });

        let mut total_size: u64 = 0;
        let mut prev: u64 = 0; // to validate that the vector is sorted.
        for segment in available {
            assert!(prev <= segment.start);
            prev = segment.start + segment.size;

            total_size += segment.size;
        }

        use alloc::boxed::Box;
        let self_ = Box::leak(Box::new(PhysicalMemory {
            total_size,
            slab: MMSlab::<Frame>::new(true),
            small_pages: MemoryArea::new(),
            // mid_pages: DesignatedSegment::new(&Self::MID_PAGES_SEGMENT),
        }));

        let ptr = self_ as *mut PhysicalMemory;
        let ptr = ptr as usize;
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(PHYS_MEM) as *mut usize, ptr);
        }

        PhysicalMemory::assign_pages_to_area(available, &mut self_.small_pages);
        self_.small_pages.sort();
        self_.mark_used(in_use);
    }

    fn assign_pages_to_area<S: PageSize>(available: &[MemorySegment], area: &mut MemoryArea<S>) {
        // This happens during bootup memory setup, so heap is just a bump allocator.
        // Because of that we don't want area.segments to reallocate, during area.add_segment().
        // So we first count the number of segments we will add, then add them.
        //
        // The outer loop goes through the input.
        let mut segment_count: usize = 0;

        let mut loop_closure = |count: bool| {
            for segment in available {
                let mut segment = segment.clone();
                // The inner loop splits the segment in chunks of 64 pages.
                loop {
                    if segment.size < S::SIZE {
                        break;
                    }

                    let start = super::align_up(segment.start, S::SIZE);
                    if segment.end() <= start {
                        break;
                    }
                    let mut pages = (segment.end() - start) >> S::SIZE_LOG2;

                    if pages == 0 {
                        break;
                    }

                    if start > segment.start {
                        segment.size -= start - segment.start;
                        segment.start = start;
                    }

                    if pages > 64 {
                        pages = 64;
                    }

                    let size = pages << S::SIZE_LOG2;
                    let seg = MemorySegment { start, size };
                    if count {
                        segment_count += 1;
                    } else {
                        area.add_segment(&seg);
                    }

                    segment.size -= seg.size;
                    segment.start = seg.end();
                }
            }

            if count {
                area.segments.reserve_exact(segment_count);
            }
        };

        loop_closure(true);
        loop_closure(false);
    }

    fn mark_used(&self, in_use: &[MemorySegment]) {
        for segment in in_use {
            self.small_pages.mark_used(segment);
            // self.mid_pages.mark_used(segment);
        }
    }

    #[cfg(debug_assertions)]
    fn dump_serial(&self) {
        crate::raw_log!(
            "Physical Memory: total size: 0x{:x} = {} bytes",
            self.total_size,
            self.total_size
        );

        self.small_pages.dump_serial("  ");
        // self.mid_pages.dump_serial("-", "-");
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct PhysStats {
    pub total_size: u64,

    pub small_pages: u64,
    pub mid_pages: u64,

    pub small_pages_used: u64,
    pub mid_pages_used: u64,
}

impl PhysStats {
    pub fn get() -> Self {
        let inst = PhysicalMemory::inst();
        Self {
            total_size: inst.total_size,

            small_pages: inst.small_pages.total_pages,
            mid_pages: 0, // PhysicalMemory::MID_PAGES as u64,

            small_pages_used: inst.small_pages.used_pages.load(Ordering::Relaxed),
            mid_pages_used: 0, /* inst
                               .mid_pages
                               .used_bitmap
                               .load(Ordering::Relaxed)
                               .count_ones() as u64 */
        }
    }

    pub fn used(&self) -> u64 {
        (self.small_pages_used << PAGE_SIZE_SMALL_LOG2)
            + (self.mid_pages_used << PAGE_SIZE_MID_LOG2)
    }

    pub fn available(&self) -> u64 {
        self.total_size - self.used()
    }
}

#[cfg(debug_assertions)]
pub fn dump_stats() {
    log::debug!("phys mem stats:\n{:#?}", PhysStats::get());
}
