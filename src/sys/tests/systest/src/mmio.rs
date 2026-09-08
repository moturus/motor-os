use moto_sys::{SysHandle, SysMem, sys_mem::PAGE_SIZE_SMALL};

struct Mapping(u64);

impl Drop for Mapping {
    fn drop(&mut self) {
        SysMem::free(self.0).unwrap();
    }
}

pub fn validation_tests() {
    assert_ne!(
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_IO_MANAGER,
        0,
        "MMIO tests require CAP_IO_MANAGER"
    );
    let page = Mapping(SysMem::alloc(PAGE_SIZE_SMALL, 1).unwrap());
    let allocated_ram = SysMem::virt_to_phys(page.0).unwrap();
    for (addr, pages) in [
        (34 << 20, 1), // Kernel RAM, excluded from the allocator.
        (2 << 20, 1),  // Fixed-mid RAM, excluded from the small-page pool.
        (allocated_ram, 1),
        ((2 << 20) - PAGE_SIZE_SMALL, 2),
        ((1 << 37) + 1, 1),
        (1 << 37, 0),
        (u64::MAX - PAGE_SIZE_SMALL + 1, 2),
        (1 << 52, 1),
        ((1 << 63) | (34 << 20), 1),
    ] {
        // The wrapper asserts a nonzero page count before entering the kernel.
        let flags = SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_MMIO;
        let result = moto_sys::syscalls::do_syscall(
            (u64::from(moto_sys::syscalls::SYS_MEM) << 56)
                | (u64::from(SysMem::OP_MAP) << 48)
                | (u64::from(flags) << 16),
            SysHandle::SELF.as_u64(),
            addr,
            u64::MAX,
            PAGE_SIZE_SMALL,
            pages,
            0,
        );
        assert_eq!(
            result.error_code(),
            moto_rt::E_INVALID_ARGUMENT,
            "MMIO accepted address {addr:#x}, {pages} pages"
        );
    }
    assert_eq!(SysMem::virt_to_phys(page.0), Ok(allocated_ram));
    println!("mmio::validation_tests PASS");
}
