#![no_std]
#![no_main]

mod load;

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use moto_rt::RtVdsoVtableV1;

#[macro_export]
macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            moto_sys::SysRay::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}

struct BackEndAllocator {}

unsafe impl Send for BackEndAllocator {}
unsafe impl Sync for BackEndAllocator {}

unsafe impl GlobalAlloc for BackEndAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        const PAGE_4K: u64 = 1 << 12;
        assert_eq!(moto_sys::sys_mem::PAGE_SIZE_SMALL, PAGE_4K);

        let alloc_size = moto_sys::align_up(layout.size() as u64, PAGE_4K);
        if let Ok(start) = moto_sys::SysMem::alloc(PAGE_4K, alloc_size >> 12) {
            start as usize as *mut u8
        } else {
            core::ptr::null_mut()
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        moto_sys::SysMem::free(ptr as usize as u64).unwrap()
    }
}

static BACK_END: BackEndAllocator = BackEndAllocator {};

#[global_allocator]
static FRUSA: frusa::Frusa4K = frusa::Frusa4K::new(&BACK_END);

use core::panic::PanicInfo;

#[no_mangle]
pub fn moturus_log_panic(info: &PanicInfo<'_>) {
    moto_sys::SysRay::log("PANIC").ok(); // Log w/o allocations.
    let msg = alloc::format!("PANIC: {}", info);
    moto_sys::SysRay::log(msg.as_str()).ok();
}

#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &PanicInfo<'_>) -> ! {
    moturus_log_panic(info);
    moto_sys::SysCpu::exit(u64::MAX)
}

// The entry point.
#[no_mangle]
pub extern "C" fn _rt_entry(version: u64) {
    assert_eq!(version, 1);

    let vtable = RtVdsoVtableV1::get();
    let self_addr = _rt_entry as *const () as usize as u64;
    assert_eq!(
        vtable
            .vdso_entry
            .load(core::sync::atomic::Ordering::Acquire),
        self_addr
    );

    vtable.load_vdso.store(
        load::load_vdso as *const () as usize as u64,
        core::sync::atomic::Ordering::Relaxed,
    );

    vtable.alloc.store(
        alloc as *const () as usize as u64,
        core::sync::atomic::Ordering::Relaxed,
    );
    vtable.alloc_zeroed.store(
        alloc_zeroed as *const () as usize as u64,
        core::sync::atomic::Ordering::Relaxed,
    );
    vtable.dealloc.store(
        dealloc as *const () as usize as u64,
        core::sync::atomic::Ordering::Relaxed,
    );
    vtable.realloc.store(
        realloc as *const () as usize as u64,
        core::sync::atomic::Ordering::Release,
    );
}

unsafe extern "C" fn alloc(size: u64, align: u64) -> u64 {
    FRUSA.alloc(Layout::from_size_align(size as usize, align as usize).unwrap()) as usize as u64
}

unsafe extern "C" fn alloc_zeroed(size: u64, align: u64) -> u64 {
    FRUSA.alloc_zeroed(Layout::from_size_align(size as usize, align as usize).unwrap()) as usize
        as u64
}

unsafe extern "C" fn dealloc(ptr: u64, size: u64, align: u64) {
    FRUSA.dealloc(
        ptr as usize as *mut u8,
        Layout::from_size_align(size as usize, align as usize).unwrap(),
    )
}

unsafe extern "C" fn realloc(ptr: u64, size: u64, align: u64, new_size: u64) -> u64 {
    FRUSA.realloc(
        ptr as usize as *mut u8,
        Layout::from_size_align(size as usize, align as usize).unwrap(),
        new_size as usize,
    ) as usize as u64
}
