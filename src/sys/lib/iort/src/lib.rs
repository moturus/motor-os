#![no_std]

use core::sync::atomic::AtomicU64;

/// At this address IO Runtime VDSO object will be mapped/loaded into every process/binary.
pub const IORT_VDSO_START: u64 = moto_sys::CUSTOM_USERSPACE_REGION_END - (1_u64 << 32); // 4GB for IORT_VDSO.

#[repr(C)]
pub struct IortVdsoVtable {
    pub vdso_entry: AtomicU64,
}

impl IortVdsoVtable {
    pub const VADDR: u64 = IORT_VDSO_START - moto_sys::sys_mem::PAGE_SIZE_SMALL;

    pub fn get() -> &'static Self {
        // Safety: sys-io is supposed to have taken care of this.
        unsafe {
            (Self::VADDR as usize as *const IortVdsoVtable)
                .as_ref()
                .unwrap_unchecked()
        }
    }
}

#[inline(always)]
pub fn iort_entry(arg: u64) -> u64 {
    let vsdo_entry: extern "C" fn(u64) -> u64 = unsafe {
        core::mem::transmute(
            IortVdsoVtable::get()
                .vdso_entry
                .load(core::sync::atomic::Ordering::Relaxed) as usize as *const (),
        )
    };

    vsdo_entry(arg)
}
