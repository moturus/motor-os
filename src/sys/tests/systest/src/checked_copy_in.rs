use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use moto_sys::syscalls::{SYS_CPU, SyscallResult, do_syscall};
use moto_sys::{KernelStaticPage, ProcessStaticPage, SysCpu, SysHandle, SysMem, SysObj};
use std::time::{Duration, Instant};

struct Mapping(u64);

impl Drop for Mapping {
    fn drop(&mut self) {
        SysMem::free(self.0).unwrap();
    }
}

fn read_handle(addr: u64) -> SyscallResult {
    wait_on_array(addr, 1)
}

fn wait_on_array(addr: u64, count: u64) -> SyscallResult {
    let flags = SysCpu::F_HANDLE_ARRAY | SysCpu::F_DONTBLOCK;
    let nr = (u64::from(SYS_CPU) << 56)
        | (u64::from(SysCpu::OP_WAIT) << 48)
        | (u64::from(flags) << 16)
        | 1;
    do_syscall(nr, addr, count, 0, 0, 0, 0)
}

pub fn bad_wait_array_child(case: usize) -> ! {
    // Fault from a worker: killing just the offending thread leaves main alive.
    std::thread::spawn(move || {
        let ram = SysMem::alloc(PAGE_SIZE_SMALL, 1).unwrap();
        let (addr, count) = match case {
            0 => ((1 << 46) + SysMem::virt_to_phys(ram).unwrap(), 1),
            1 => (ram | (1 << 48), 1),
            2 => (ram | (1 << 63), 1),
            3 => (u64::MAX - 3, 1),
            4..=6 => {
                let lazy = SysMem::map(
                    SysHandle::SELF,
                    SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
                    u64::MAX,
                    u64::MAX,
                    PAGE_SIZE_SMALL,
                    2,
                )
                .unwrap();
                unsafe { (lazy as *mut u64).write(SysHandle::SELF.as_u64()) };
                match case {
                    4 => (lazy + PAGE_SIZE_SMALL, 1),
                    5 => (lazy + PAGE_SIZE_SMALL - 4, 1),
                    _ => (lazy + PAGE_SIZE_SMALL - 4, 17),
                }
            }
            7 => {
                let (readonly, writable) = SysMem::map2(
                    SysHandle::SELF,
                    SysMem::F_SHARE_SELF | SysMem::F_READABLE,
                    u64::MAX,
                    u64::MAX,
                    PAGE_SIZE_SMALL,
                    1,
                )
                .unwrap();
                // Seven ready handles force array copy-out, rather than registers.
                for idx in 0..7 {
                    let (peer, handle) =
                        SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();
                    unsafe { (writable as *mut u64).add(idx).write(handle.as_u64()) };
                    SysCpu::wake(peer).unwrap();
                }
                (readonly, 7)
            }
            _ => unreachable!(),
        };
        println!("bad_wait_array: armed");
        let _ = wait_on_array(addr, count);
        std::process::exit(0); // Returning an error instead of killing must fail.
    });
    loop {
        std::thread::park();
    }
}

fn test_bad_wait_arrays() {
    for case in 0..8 {
        let mut child = crate::subcommand::spawn();
        child.bad_wait_array(case);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(!status.success(), "bad wait array {case} survived");
                break;
            }
            if Instant::now() >= deadline {
                child.kill();
                child.wait().unwrap();
                panic!("bad wait array {case} did not kill the whole process");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    println!("bad_wait_arrays_kill_process PASS");
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

    let crossing = ram.0 + PAGE_SIZE_SMALL - 4;
    unsafe {
        (crossing as *mut u64).write_unaligned(bad_handle);
    }
    assert_copied(crossing, bad_handle);
    static READ_ONLY_ZERO: u64 = 0;
    // Wait arrays must be resident before entering the syscall.
    unsafe { core::ptr::read_volatile(&READ_ONLY_ZERO) };
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
    unsafe {
        (lazy.0 as *mut u64).write(bad_handle);
    }
    assert_copied(lazy.0, bad_handle);
    assert_eq!(SysMem::virt_to_phys(lazy.0 + PAGE_SIZE_SMALL), Err(invalid));
    let absent = lazy.0 + PAGE_SIZE_SMALL;
    // Anonymous lazy pages are ordinary copy errors, never pager retries.
    assert_eq!(write_usage(absent).error_code(), invalid);
    assert_eq!(SysCpu::get_percpu_stats_v1(absent), Err(invalid));
    let get_object =
        (u64::from(moto_sys::syscalls::SYS_OBJ) << 56) | (u64::from(SysObj::OP_GET) << 48);
    assert_eq!(
        do_syscall(get_object, SysHandle::SELF.as_u64(), absent, 1, 0, 0, 0).error_code(),
        invalid
    );
    assert_eq!(SysMem::virt_to_phys(absent), Err(invalid));
    println!("checked_copy_in PASS");
    test_copy_out_permissions();
    test_bad_wait_arrays();
}
