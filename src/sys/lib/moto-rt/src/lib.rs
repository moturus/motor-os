//! Motor OS Runtime Library. It is a stub/proxy to Motor OS Runtime VDSO
//! (Virtual Dynamic Shared Object) which is loaded into every userspace process.
//!
//! The Runtime API surface is explicitly designed to provide Rust standard
//! library PAL (platform abstraction layer); while it may evolve later into
//! a more universal Runtime API (e.g. to be used in Go runtime, Java runtime,
//! libc, etc.), at the moment only supporting Rust Standard Library PAL
//! is on the roadmap.
//!
//! Note: RT.VDSO is a "fat" runtime: it creates an IO thread to interact with
//!       sys-io, and stdio threads to provide stdin/stdout/stderr abstractions,
//!       if needed.
//!
//! While it is possible to do everything RT.VDSO does by directly interacting
//! with the OS kernel and sys-io, there are two main benefits of using a VDSO
//! and this RT library as its proxy:
//! - simplified integration with Rust Standard Library: instead of a "fat"
//!   Motor OS PAL that needs heavy maintenance, this "thin" RT library
//!   is designed to be relatively stable, even if the underlying system code
//!   and runtime undergo extensive changes;
//! - OS/runtime updates are automatically picked up by existing/compiled
//!   binaries without recompilation; while this is common in Windows and Linux
//!   with dll/so libraries, this benefit is worth mentioning here, as
//!   Motor OS, which is based on Rust, does not support dynamic libraries,
//!   as Rust does not support them "natively" (as in rdylib).
#![no_std]

use core::{
    alloc::Layout,
    sync::atomic::{AtomicU64, Ordering},
};

// Constants from moto-sys: we replicate them here to avoid depending on moto-sys.
// NOTE: do not change these numbers unless they are also changed in moto-sys!
const MOTO_SYS_CUSTOM_USERSPACE_REGION_START: u64 = (1_u64 << 45) + (1_u64 << 40);
const MOTO_SYS_CUSTOM_USERSPACE_REGION_END: u64 =
    MOTO_SYS_CUSTOM_USERSPACE_REGION_START + (1_u64 << 40);
const MOTO_SYS_PAGE_SIZE_SMALL: u64 = 4096;

// At this address rt.vdso object will be mapped/loaded into every process/binary.
#[doc(hidden)]
pub const RT_VDSO_START: u64 = MOTO_SYS_CUSTOM_USERSPACE_REGION_END - (1_u64 << 32); // 4GB for RT_VDSO.

// At this address rt.vdso bytes will be mapped/loaded into every process/binary.
// NOTE: this is a temporary arrangement; when process start is moved to sys-io (or another binary),
//       having the bytes in every process will no longer be needed.
#[doc(hidden)]
pub const RT_VDSO_BYTES_ADDR: u64 = RT_VDSO_START - (1_u64 << 32); // 4GB for RT_VDSO.

// At this address the loader will initialize RtVdsoVtable.
#[doc(hidden)]
pub const RT_VDSO_VTABLE_VADDR: u64 = RT_VDSO_START - MOTO_SYS_PAGE_SIZE_SMALL;

const RT_VERSION: u64 = 1;

#[doc(hidden)]
#[repr(C)]
pub struct RtVdsoVtableV1 {
    pub vdso_entry: AtomicU64,
    pub vdso_bytes_sz: AtomicU64,

    // Self-replicate into a remote address space.
    pub load_vdso: AtomicU64,

    // Memory allocations.
    pub alloc: AtomicU64,
    pub alloc_zeroed: AtomicU64,
    pub realloc: AtomicU64,
    pub dealloc: AtomicU64,
}

#[doc(hidden)]
impl RtVdsoVtableV1 {
    pub fn get() -> &'static Self {
        // Safety: sys-io is supposed to have taken care of this.
        unsafe {
            (RT_VDSO_VTABLE_VADDR as usize as *const RtVdsoVtableV1)
                .as_ref()
                .unwrap_unchecked()
        }
    }
}

#[doc(hidden)]
pub fn init() {
    assert_ne!(0, RtVdsoVtableV1::get().vdso_entry.load(Ordering::Acquire));
    let vdso_entry: extern "C" fn(u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().vdso_entry.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_entry(RT_VERSION)
}

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

// This is a temporary function that takes a remote address space handle
// and loads vdso into it. The function will be removed once load_program()
// is implemented in vdso.
// Returns the u16 representation of moto_sys::ErrorCode.
#[doc(hidden)]
pub fn load_vdso(address_space: u64) -> Result<(), u16> {
    let vdso_load: extern "C" fn(u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().load_vdso.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let result = vdso_load(address_space) as u16;
    if result == 0 {
        Ok(())
    } else {
        Err(result)
    }
}
