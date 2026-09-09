use moto_sys::{SysCpu, SysHandle, SysMem, SysObj, SysRay, sys_mem::PAGE_SIZE_SMALL};

const DEVICE_ADDR: u64 = 1 << 37;

struct Mapping(u64);

impl Drop for Mapping {
    fn drop(&mut self) {
        SysMem::free(self.0).unwrap();
    }
}

struct Handle(SysHandle);

impl Drop for Handle {
    fn drop(&mut self) {
        SysObj::put(self.0).unwrap();
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

pub fn ownership_tests() {
    use moto_sys::syscalls::{SYS_CPU, SYS_MEM, SYS_RAY, do_syscall};
    let invalid = moto_rt::E_INVALID_ARGUMENT;
    let device = Mapping(SysMem::mmio_map(DEVICE_ADDR, 2 * PAGE_SIZE_SMALL).unwrap());
    for offset in [
        0,
        PAGE_SIZE_SMALL - 1,
        PAGE_SIZE_SMALL,
        2 * PAGE_SIZE_SMALL - 1,
    ] {
        assert_eq!(
            SysMem::virt_to_phys(device.0 + offset),
            Ok(DEVICE_ADDR + offset)
        );
    }
    // Pass raw addresses, not Rust references to device memory.
    for (sys, op, flags, arg0, arg1) in [
        (
            SYS_RAY,
            SysRay::OP_LOG,
            0,
            device.0 + PAGE_SIZE_SMALL - 1,
            2,
        ),
        (
            SYS_MEM,
            SysMem::OP_QUERY,
            SysMem::F_QUERY_STATS,
            SysHandle::NONE.as_u64(),
            device.0,
        ),
        (SYS_CPU, SysCpu::OP_QUERY_PERCPU_STATS, 0, device.0, 0),
    ] {
        let nr = (u64::from(sys) << 56) | (u64::from(op) << 48) | (u64::from(flags) << 16);
        assert_eq!(do_syscall(nr, arg0, arg1, 0, 0, 0, 0).error_code(), invalid);
    }

    let ram = Mapping(SysMem::alloc(PAGE_SIZE_SMALL, 2).unwrap());
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(ram.0 as *mut u8, 2 * PAGE_SIZE_SMALL as usize) };
    bytes.fill(0x5a);
    let ram_phys = [
        SysMem::virt_to_phys(ram.0).unwrap(),
        SysMem::virt_to_phys(ram.0 + PAGE_SIZE_SMALL).unwrap(),
    ];
    // IPC can replace an already mapped destination; refuse either MMIO end.
    for (source, dest) in [(device.0, ram.0), (ram.0, device.0)] {
        let url = |addr| {
            format!(
                "shared:url=mmio-{};address={addr};page_type=small;page_num=2",
                moto_sys::current_pid()
            )
        };
        let _listener = Handle(SysObj::create(SysHandle::SELF, 0, &url(dest)).unwrap());
        assert_eq!(SysObj::get(SysHandle::SELF, 0, &url(source)), Err(invalid));
        for (idx, phys) in ram_phys.iter().enumerate() {
            let offset = idx as u64 * PAGE_SIZE_SMALL;
            assert_eq!(SysMem::virt_to_phys(ram.0 + offset), Ok(*phys));
            assert_eq!(
                SysMem::virt_to_phys(device.0 + offset),
                Ok(DEVICE_ADDR + offset)
            );
        }
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
    }

    let target =
        Handle(SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=mmio-test").unwrap());
    let dest = moto_sys::CUSTOM_USERSPACE_REGION_START;
    let share = |source| {
        SysMem::map(
            target.0,
            SysMem::F_SHARE_SELF | SysMem::F_READABLE,
            source,
            dest,
            PAGE_SIZE_SMALL,
            2,
        )
    };
    assert_eq!(share(device.0), Err(invalid));
    // Failure must release the destination reservation; ordinary sharing works.
    assert_eq!(share(ram.0), Ok(dest));
    SysMem::unmap(target.0, 0, u64::MAX, dest).unwrap();

    let addr = device.0;
    drop(device);
    assert_eq!(SysMem::virt_to_phys(addr), Err(invalid));
    assert_eq!(SysMem::virt_to_phys(addr + PAGE_SIZE_SMALL), Err(invalid));
    println!("mmio::ownership_tests PASS");
}

pub fn unmap_fault() -> ! {
    use std::io::Write;
    let device = Mapping(SysMem::mmio_map(DEVICE_ADDR, PAGE_SIZE_SMALL).unwrap());
    let addr = device.0;
    assert_eq!(SysMem::virt_to_phys(addr), Ok(DEVICE_ADDR));
    println!("mmio::unmap_fault READY");
    std::io::stdout().flush().unwrap();
    // Output can allocate and reuse the address: do none after unmapping.
    if SysMem::free(addr).is_err() {
        std::process::exit(97);
    }
    std::mem::forget(device);
    if SysMem::virt_to_phys(addr) != Err(moto_rt::E_INVALID_ARGUMENT) {
        std::process::exit(98);
    }
    unsafe {
        std::ptr::read_volatile(addr as *const u8);
    }
    std::process::exit(99)
}
