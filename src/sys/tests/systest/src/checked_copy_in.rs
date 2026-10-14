use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use moto_sys::syscalls::{SYS_CPU, SyscallResult, do_syscall};
use moto_sys::{KernelStaticPage, ProcessStaticPage, SysCpu, SysHandle, SysMem};

struct Mapping(u64);

impl Drop for Mapping {
    fn drop(&mut self) {
        SysMem::free(self.0).unwrap();
    }
}

fn read_handle(addr: u64) -> SyscallResult {
    let flags = SysCpu::F_HANDLE_ARRAY | SysCpu::F_DONTBLOCK;
    let nr = (u64::from(SYS_CPU) << 56)
        | (u64::from(SysCpu::OP_WAIT) << 48)
        | (u64::from(flags) << 16)
        | 1;
    do_syscall(nr, addr, 1, 0, 0, 0, 0)
}

fn assert_copied(addr: u64, value: u64) {
    // Zero is skipped; an invalid handle is returned verbatim after copy-in.
    let result = read_handle(addr);
    if value == 0 {
        assert!(result.is_ok(), "copy-in at {addr:#x}: {result:?}");
    } else {
        assert_eq!(result.error_code(), moto_rt::E_BAD_HANDLE);
        assert_eq!(result.data[0], value);
    }
}

fn write_usage(addr: u64) -> SyscallResult {
    let nr = (u64::from(SYS_CPU) << 56) | (u64::from(SysCpu::OP_USAGE) << 48);
    do_syscall(nr, addr, u64::from(moto_sys::num_cpus()), 0, 0, 0, 0)
}

fn test_copy_out_permissions() {
    let invalid = moto_rt::E_INVALID_ARGUMENT;
    let readonly = moto_rt::RT_VDSO_START;
    // The vDSO header is read-only and shared with sys-io and other processes.
    let before = unsafe {
        core::slice::from_raw_parts(readonly as *const u8, PAGE_SIZE_SMALL as usize).to_vec()
    };
    assert_copied(
        readonly,
        u64::from_ne_bytes(before[..8].try_into().unwrap()),
    );

    // Pass an address directly: an &mut to read-only memory would itself be UB.
    assert_eq!(write_usage(readonly).error_code(), invalid);
    assert_eq!(
        unsafe { core::slice::from_raw_parts(readonly as *const u8, before.len()) },
        before,
        "copy-out modified a read-only vDSO page"
    );
    assert_eq!(SysCpu::get_percpu_stats_v1(readonly), Err(invalid));
    assert_eq!(
        unsafe { core::slice::from_raw_parts(readonly as *const u8, before.len()) },
        before,
        "a write-side page pin modified a read-only vDSO page"
    );

    let mut usage = vec![f32::NAN; moto_sys::num_cpus() as usize];
    assert!(write_usage(usage.as_mut_ptr() as u64).is_ok());
    assert!(usage.iter().all(|value| value.is_finite()));

    let output = Mapping(SysMem::alloc(PAGE_SIZE_SMALL, 1).unwrap());
    unsafe {
        (output.0 as *mut u64).write(u64::MAX);
    }
    assert!(SysCpu::get_percpu_stats_v1(output.0).unwrap() > 0);
    assert_eq!(unsafe { (output.0 as *const u64).read() }, 0); // System PID.
    println!("checked_copy_out_permissions PASS");
}

pub fn run_all_tests() {
    let invalid = moto_rt::E_INVALID_ARGUMENT;
    let ram = Mapping(SysMem::alloc(PAGE_SIZE_SMALL, 2).unwrap());
    let bad_handle = SysHandle::SELF.as_u64();
    unsafe {
        (ram.0 as *mut u64).write(bad_handle);
    }
    assert_copied(ram.0, bad_handle);

    // The supervisor alias names only our own RAM, never private kernel data.
    let supervisor_alias = (1 << 46) + SysMem::virt_to_phys(ram.0).unwrap();
    assert_eq!(
        read_handle(supervisor_alias).error_code(),
        invalid,
        "copy-in accepted a supervisor-only mapping"
    );
    for addr in [ram.0 | (1 << 48), ram.0 | (1 << 63), u64::MAX - 3] {
        assert_eq!(
            read_handle(addr).error_code(),
            invalid,
            "copy-in accepted an invalid address {addr:#x}"
        );
    }

    let crossing = ram.0 + PAGE_SIZE_SMALL - 4;
    unsafe {
        (crossing as *mut u64).write_unaligned(bad_handle);
    }
    assert_copied(crossing, bad_handle);
    static READ_ONLY_ZERO: u64 = 0;
    assert_copied(&READ_ONLY_ZERO as *const u64 as u64, 0);
    assert_copied(KernelStaticPage::VADDR, KernelStaticPage::get().version);
    assert_copied(ProcessStaticPage::VADDR, ProcessStaticPage::get().version);

    let lazy = Mapping(
        SysMem::map(
            SysHandle::SELF,
            SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
            u64::MAX,
            u64::MAX,
            PAGE_SIZE_SMALL,
            2,
        )
        .unwrap(),
    );
    assert_eq!(read_handle(lazy.0).error_code(), invalid);
    unsafe {
        (lazy.0 as *mut u64).write(bad_handle);
    }
    assert_copied(lazy.0, bad_handle);
    assert_eq!(
        read_handle(lazy.0 + PAGE_SIZE_SMALL - 4).error_code(),
        invalid
    );
    assert_eq!(SysMem::virt_to_phys(lazy.0 + PAGE_SIZE_SMALL), Err(invalid));
    println!("checked_copy_in PASS");
    test_copy_out_permissions();
}
