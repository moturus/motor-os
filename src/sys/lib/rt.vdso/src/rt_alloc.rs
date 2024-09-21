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

pub unsafe extern "C" fn alloc(size: u64, align: u64) -> u64 {
    if align == 0 {
        sys_alloc(size as usize) as usize as u64
    } else {
        FRUSA.alloc(Layout::from_size_align(size as usize, align as usize).unwrap()) as usize as u64
    }
}

pub unsafe extern "C" fn alloc_zeroed(size: u64, align: u64) -> u64 {
    FRUSA.alloc_zeroed(Layout::from_size_align(size as usize, align as usize).unwrap()) as usize
        as u64
}

pub unsafe extern "C" fn dealloc(ptr: u64, size: u64, align: u64) {
    if size == 0 && align == 0 {
        moto_sys::SysMem::free(ptr).unwrap();
        return;
    }
    FRUSA.dealloc(
        ptr as usize as *mut u8,
        Layout::from_size_align(size as usize, align as usize).unwrap(),
    )
}

pub unsafe extern "C" fn realloc(ptr: u64, size: u64, align: u64, new_size: u64) -> u64 {
    FRUSA.realloc(
        ptr as usize as *mut u8,
        Layout::from_size_align(size as usize, align as usize).unwrap(),
        new_size as usize,
    ) as usize as u64
}
