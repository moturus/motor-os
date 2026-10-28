use moto_sys::{ProcessStaticPage, SysHandle, SysMem, caps, sys_mem::PAGE_SIZE_SMALL};

// x86-64: mov eax, 42; ret. No relocations or external state.
const CODE: [u8; 6] = [0xb8, 42, 0, 0, 0, 0xc3];

pub fn run_child(mode: &str) {
    assert_eq!(ProcessStaticPage::get().capabilities, 0);
    let (executable, writable) = SysMem::map2(
        SysHandle::SELF,
        SysMem::F_SHARE_SELF | SysMem::F_READABLE | SysMem::F_EXECUTABLE,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();
    assert_ne!(executable, writable);
    assert_eq!(
        SysMem::virt_to_phys(executable).unwrap(),
        SysMem::virt_to_phys(writable).unwrap()
    );
    unsafe {
        for (offset, byte) in CODE.iter().enumerate() {
            (writable as *mut u8).add(offset).write_volatile(*byte);
            assert_eq!((executable as *const u8).add(offset).read_volatile(), *byte);
        }
    }

    let execute = |addr: u64| unsafe {
        let function: extern "C" fn() -> u32 = core::mem::transmute(addr);
        function()
    };
    match mode {
        "execute" => {
            // Drop the writable alias before entering the generated code.
            SysMem::free(writable).unwrap();
            assert_eq!(
                SysMem::virt_to_phys(writable),
                Err(moto_rt::E_INVALID_ARGUMENT)
            );
            assert_eq!(execute(executable), 42);
            SysMem::free(executable).unwrap();
            assert_eq!(
                SysMem::virt_to_phys(executable),
                Err(moto_rt::E_INVALID_ARGUMENT)
            );
        }
        "write-rx" => unsafe {
            (executable as *mut u8).write_volatile(0xc3);
        },
        "execute-rw" => {
            execute(writable);
        }
        "write-unmapped" => {
            // The writes above populated the writable translation. No
            // allocation after unmap may reuse this address before the probe.
            SysMem::free(writable).unwrap();
            unsafe { (writable as *mut u8).write_volatile(0xc3) };
        }
        "execute-unmapped" => {
            SysMem::free(writable).unwrap();
            assert_eq!(execute(executable), 42);
            SysMem::free(executable).unwrap();
            execute(executable);
        }
        _ => panic!("unknown executable memory child: {mode}"),
    }
}

pub fn run_all_tests() {
    for (mode, expected) in [
        ("execute", 0),
        ("write-rx", -1),
        ("execute-rw", -1),
        ("write-unmapped", -1),
        ("execute-unmapped", -1),
    ] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["executable-memory-child", mode])
            .env(caps::MOTOR_OS_CAPS_ENV_KEY, "0")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(expected), "{mode}: {status:?}");
    }
    println!("test_self_executable_memory PASS");
}
