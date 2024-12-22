use core::{alloc::Layout, sync::atomic::Ordering};

use crate::RtVdsoVtable;

#[inline(always)]
pub fn alloc(layout: Layout) -> *mut u8 {
    let vdso_alloc: extern "C" fn(u64, u64) -> u64 = unsafe {
        core::mem::transmute(RtVdsoVtable::get().alloc.load(Ordering::Relaxed) as usize as *const ())
    };

    vdso_alloc(layout.size() as u64, layout.align() as u64) as usize as *mut u8
}

#[inline(always)]
pub fn alloc_zeroed(layout: Layout) -> *mut u8 {
    let vdso_alloc_zeroed: extern "C" fn(u64, u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().alloc_zeroed.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_alloc_zeroed(layout.size() as u64, layout.align() as u64) as usize as *mut u8
}

/// # Safety
///
/// ptr should be properly allocated.
#[inline(always)]
pub unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
    let vdso_dealloc: extern "C" fn(u64, u64, u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().dealloc.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    vdso_dealloc(
        ptr as usize as u64,
        layout.size() as u64,
        layout.align() as u64,
    )
}

/// # Safety
///
/// ptr should be properly allocated.
#[inline(always)]
pub unsafe fn realloc(ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let vdso_realloc: extern "C" fn(u64, u64, u64, u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().realloc.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    vdso_realloc(
        ptr as usize as u64,
        layout.size() as u64,
        layout.align() as u64,
        new_size as u64,
    ) as usize as *mut u8
}

// Deallocate a buffer provided by vdso (i.e. no layout info).
#[doc(hidden)]
pub(crate) fn raw_dealloc(addr: u64) {
    let vdso_dealloc: extern "C" fn(u64, u64, u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().dealloc.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    vdso_dealloc(addr, 0, 0);
}

#[inline(always)]
pub fn release_handle(handle: u64) -> Result<(), crate::ErrorCode> {
    let vdso_release_handle: extern "C" fn(u64) -> crate::ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().release_handle.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    match vdso_release_handle(handle) {
        crate::E_OK => Ok(()),
        err => Err(err),
    }
}
