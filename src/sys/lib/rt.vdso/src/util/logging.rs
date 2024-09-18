macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            moto_sys::SysRay::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}

pub(crate) use moto_log;

use core::panic::PanicInfo;

fn moturus_log_panics_to_kernel() -> bool {
    true
}

#[cfg(not(test))]
pub fn moturus_log_panic(info: &PanicInfo<'_>) {
    if moturus_log_panics_to_kernel() {
        moto_sys::SysRay::log("PANIC vdso").ok(); // Log w/o allocations.
        let msg = alloc::format!("PANIC: {}", info);
        moto_sys::SysRay::log(msg.as_str()).ok();
        log_backtrace("TBD"); // crate::rt_api::process::binary().unwrap_or("<unknown>"));
    } else {
        todo!()
        /*
        use core::fmt::Write;

        let mut stderr = super::stdio::StderrRt::new();
        let _ = stderr.write_str("PANIC\n"); // Log w/o allocations.
        let msg = alloc::format!("PANIC: {}\n", info);
        let _ = stderr.write_str(msg.as_str());
        log_backtrace(crate::rt_api::process::binary().unwrap_or("<unknown>"));
        let _ = stderr.flush();

        // At the moment (2024-01-11), stderr.flush() above does nothing.
        // Wait a bit to let it flush "naturally".
        // See https://github.com/moturus/motor-os/issues/6
        moto_rt::thread::sleep_until(
            moto_rt::time::Instant::now() + core::time::Duration::from_millis(10),
        );
        */
    }
}

#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &PanicInfo<'_>) -> ! {
    moturus_log_panic(info);
    moto_sys::SysCpu::exit(u64::MAX)
}
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

    for idx in 0..BT_DEPTH {
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
            backtrace[idx] = *((rbp + 8) as *mut u64);
            rbp = *(rbp as *mut u64);
        }
    }

    backtrace
}

pub fn log_backtrace(binary: &str) {
    use core::fmt::Write;
    let mut writer = alloc::string::String::with_capacity(256);
    let backtrace = get_backtrace();
    write!(&mut writer, "backtrace: {}", binary).ok();
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

    if moturus_log_panics_to_kernel() {
        let _ = moto_sys::SysRay::log(writer.as_str());
    } else {
        todo!()
        // let _ = super::stdio::StderrRt::new().write_str(writer.as_str());
    }
}
