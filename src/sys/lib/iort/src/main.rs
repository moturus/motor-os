#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::GlobalAlloc;

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
pub fn moturus_log_panic(_info: &PanicInfo<'_>) {}

#[panic_handler]
fn _panic(info: &PanicInfo<'_>) -> ! {
    moturus_log_panic(info);
    moto_sys::SysCpu::exit(u64::MAX)
}

// The entry point.
#[no_mangle]
pub extern "C" fn _iort_entry(arg: u64) -> u64 {
    return 42 + arg;
}
