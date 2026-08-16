use core::alloc::{GlobalAlloc, Layout};
struct BackEndAllocator {}

unsafe impl Send for BackEndAllocator {}
unsafe impl Sync for BackEndAllocator {}

pub fn sys_alloc(size: usize) -> *mut u8 {
    const PAGE_4K: u64 = 1 << 12;
    assert_eq!(moto_sys::sys_mem::PAGE_SIZE_SMALL, PAGE_4K);

    let alloc_size = moto_sys::align_up(size as u64, PAGE_4K);
    if let Ok(start) = moto_sys::SysMem::alloc(PAGE_4K, alloc_size >> 12) {
        start as usize as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

unsafe impl GlobalAlloc for BackEndAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        sys_alloc(layout.size())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        moto_sys::SysMem::free(ptr as usize as u64).unwrap()
    }
}

static BACK_END: BackEndAllocator = BackEndAllocator {};

#[global_allocator]
static FRUSA: frusa::Frusa4K = frusa::Frusa4K::new(&BACK_END);

/// Slack -- pages the slabs hold beyond what is in use -- tolerated before
/// the housekeeping resident returns it to the kernel. Frusa reclaims only
/// on explicit request, so without this a burst of small allocations stays
/// resident forever: a listener flood left sys-io holding ~76 MB of freed
/// slab memory (2026-08-15 probe, networking-remaining-steps.md step 2).
const RECLAIM_SLACK_BYTES: usize = 1 << 20;

/// The housekeeping resident, spawned with the process's IO runtime thread
/// (a process without one allocates too little to matter). Kernel memory
/// pressure drops the threshold to a single page: under pressure every
/// process gives back what it can.
///
/// A reclaim pass write-locks each slab it shrinks against concurrent
/// allocation, so the cadence stays coarse; the pass itself skips slabs
/// with less than a page of slack.
pub(crate) async fn reclaim_resident() {
    const TICK: core::time::Duration = core::time::Duration::from_secs(5);
    loop {
        moto_async::sleep(TICK).await;

        let stats = FRUSA.stats();
        // Metadata is never reclaimed; counting its slack would make every
        // tick call reclaim() to free nothing.
        let slack = stats
            .allocated_from_fallback
            .saturating_sub(stats.allocated_metadata)
            .saturating_sub(stats.in_use.saturating_sub(stats.in_use_metadata));
        let threshold = if moto_sys::memory_pressure() {
            moto_sys::sys_mem::PAGE_SIZE_SMALL as usize
        } else {
            RECLAIM_SLACK_BYTES
        };
        if slack >= threshold {
            FRUSA.reclaim();
        }
    }
}

pub unsafe extern "C" fn alloc(size: u64, align: u64) -> u64 {
    if align == 0 {
        sys_alloc(size as usize) as usize as u64
    } else {
        unsafe {
            FRUSA.alloc(Layout::from_size_align(size as usize, align as usize).unwrap()) as usize
                as u64
        }
    }
}

pub unsafe extern "C" fn alloc_zeroed(size: u64, align: u64) -> u64 {
    unsafe {
        FRUSA.alloc_zeroed(Layout::from_size_align(size as usize, align as usize).unwrap()) as usize
            as u64
    }
}

pub unsafe extern "C" fn dealloc(ptr: u64, size: u64, align: u64) {
    if size == 0 && align == 0 {
        moto_sys::SysMem::free(ptr).unwrap();
        return;
    }
    unsafe {
        FRUSA.dealloc(
            ptr as usize as *mut u8,
            Layout::from_size_align(size as usize, align as usize).unwrap(),
        )
    }
}

pub unsafe extern "C" fn realloc(ptr: u64, size: u64, align: u64, new_size: u64) -> u64 {
    unsafe {
        FRUSA.realloc(
            ptr as usize as *mut u8,
            Layout::from_size_align(size as usize, align as usize).unwrap(),
            new_size as usize,
        ) as usize as u64
    }
}

pub extern "C" fn release_handle(handle: u64) -> moto_rt::ErrorCode {
    match moto_sys::SysObj::put(handle.into()) {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}
