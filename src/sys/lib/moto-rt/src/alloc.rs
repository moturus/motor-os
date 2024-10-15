use core::{alloc::Layout, sync::atomic::Ordering};

use crate::RtVdsoVtableV1;

#[inline(always)]
pub unsafe fn alloc(layout: Layout) -> *mut u8 {
    let vdso_alloc: extern "C" fn(u64, u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().alloc.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    vdso_alloc(layout.size() as u64, layout.align() as u64) as usize as *mut u8
}

#[inline(always)]
pub unsafe fn alloc_zeroed(layout: Layout) -> *mut u8 {
    let vdso_alloc_zeroed: extern "C" fn(u64, u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().alloc_zeroed.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_alloc_zeroed(layout.size() as u64, layout.align() as u64) as usize as *mut u8
}

#[inline(always)]
pub unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
    let vdso_dealloc: extern "C" fn(u64, u64, u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().dealloc.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_dealloc(
        ptr as usize as u64,
        layout.size() as u64,
        layout.align() as u64,
    )
}

#[inline(always)]
pub unsafe fn realloc(ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    let vdso_realloc: extern "C" fn(u64, u64, u64, u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().realloc.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_realloc(
        ptr as usize as u64,
        layout.size() as u64,
        layout.align() as u64,
        new_size as u64,
    ) as usize as *mut u8
}