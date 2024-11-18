macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            moto_sys::SysRay::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}

pub(crate) use moto_log;

pub extern "C" fn log_to_kernel(ptr: *const u8, size: usize) {
    let bytes = unsafe { core::slice::from_raw_parts(ptr, size) };
    let msg = unsafe { core::str::from_utf8_unchecked(bytes) };
    moto_sys::SysRay::log(msg).ok();
}

// This panic handler is active only for code running here in VDSO.
#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &core::panic::PanicInfo<'_>) -> ! {
    moto_rt::error::log_panic(info);
    moto_sys::SysCpu::exit(u64::MAX)
}

/*
// This panic handler is active only for code running here in VDSO.
#[cfg(not(test))]
pub fn moturus_log_panic(info: &PanicInfo<'_>) {
    moto_sys::SysRay::log("PANIC VDSO").ok(); // Log w/o allocations.
    let msg = alloc::format!("PANIC VDSO: {}", info);
    moto_sys::SysRay::log(msg.as_str()).ok();
    log_backtrace(-1);
}
*/

const BT_DEPTH: usize = 64;

fn get_backtrace() -> [u64; BT_DEPTH] {
    let mut backtrace: [u64; BT_DEPTH] = [0; BT_DEPTH];

    let mut rbp: u64;
    unsafe {
        core::arch::asm!(
            "mov rdx, rbp", out("rdx") rbp, options(nomem, nostack)
        )
    };

    if rbp == 0 {
        return backtrace;
    }

    // Skip the first stack frame, which is one of the log_backtrace
    // functions below.
    rbp = unsafe { *(rbp as *mut u64) };
    let mut prev = 0_u64;

    for entry in &mut backtrace {
        if prev == rbp {
            break;
        }
        if rbp == 0 {
            break;
        }
        if rbp < 1024 * 64 {
            break;
        }
        prev = rbp;
        unsafe {
            *entry = *((rbp + 8) as *mut u64);
            rbp = *(rbp as *mut u64);
        }
    }

    backtrace
}

pub extern "C" fn log_backtrace(rt_fd: moto_rt::RtFd) {
    use core::fmt::Write;
    let mut writer = alloc::string::String::with_capacity(256);
    let backtrace = get_backtrace();
    write!(&mut writer, "backtrace: {}", unsafe {
        crate::rt_process::ProcessData::binary()
    })
    .ok();
    let mut in_vdso = false;
    for addr in backtrace {
        if addr == 0 {
            break;
        }

        if addr >= moto_rt::RT_VDSO_START {
            if !in_vdso {
                in_vdso = true;
                write!(&mut writer, " \\\n  -- rt.vdso");
            }
            write!(
                &mut writer,
                " \\\n    0x{:x}",
                addr - moto_rt::RT_VDSO_START
            )
            .ok();
        } else {
            if in_vdso {
                in_vdso = false;
                write!(&mut writer, " \\\n  ^^^");
            }
            write!(&mut writer, " \\\n  0x{:x}", addr).ok();
        }
    }

    let _ = write!(&mut writer, "\n\n");

    let msg = writer.as_str();
    if rt_fd < 0 {
        let _ = moto_sys::SysRay::log(msg);
    } else {
        let _ = crate::rt_fs::write(rt_fd, msg.as_ptr(), msg.len());
    }
}
