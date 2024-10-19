pub use moto_sys::*;

pub fn num_cpus() -> u32 {
    moto_sys::num_cpus()
}

#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn moturus_runtime_start() {
    moto_rt::init();
}

#[cfg(not(test))]
#[inline(never)]
pub fn moturus_start_rt() {
    moturus_runtime_start();
    let _ = moto_sys::set_current_thread_name("main");
}

fn binary() -> alloc::string::String {
    moto_rt::process::args().swap_remove(0)
}

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[no_mangle]
pub fn moturus_log_panic(info: &PanicInfo<'_>) {
    if moturus_log_panics_to_kernel() {
        SysRay::log("PANIC").ok(); // Log w/o allocations.
        let msg = alloc::format!("PANIC: {}", info);
        SysRay::log(msg.as_str()).ok();
        log_backtrace(binary().as_str());
    } else {
        let _ = moto_rt::fs::write(moto_rt::FD_STDERR, b"PANIC\n"); // Log w/o allocations.
        let msg = alloc::format!("PANIC: {}\n", info);
        let _ = moto_rt::fs::write(moto_rt::FD_STDERR, msg.as_str().as_bytes());
        log_backtrace(binary().as_str());
        let _ = moto_rt::fs::flush(moto_rt::FD_STDERR);

        // At the moment (2024-01-11), stderr.flush() above does nothing.
        // Wait a bit to let it flush "naturally".
        // See https://github.com/moturus/motor-os/issues/6
        moto_rt::thread::sleep_until(
            moto_rt::time::Instant::now() + core::time::Duration::from_millis(10),
        );
    }
}

#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &PanicInfo<'_>) -> ! {
    moturus_log_panic(info);
    moto_rt::process::exit(-1)
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
    for addr in backtrace {
        if addr == 0 {
            break;
        }

        if addr > (1_u64 << 40) {
            break;
        }

        write!(&mut writer, " \\\n  0x{:x}", addr).ok();
    }

    let _ = write!(&mut writer, "\n\n");

    if moturus_log_panics_to_kernel() {
        let _ = SysRay::log(writer.as_str());
    } else {
        let _ = moto_rt::fs::write(2, writer.as_str().as_bytes());
    }
}

#[no_mangle]
pub extern "C" fn moturus_print_stacktrace() {
    log_backtrace(binary().as_str());
    let _ = moto_rt::fs::flush(moto_rt::FD_STDERR);

    // At the moment (2024-01-11), stderr.flush() above does nothing.
    // Wait a bit to let it flush "naturally".
    // See https://github.com/moturus/motor-os/issues/6
    moto_rt::thread::sleep_until(
        moto_rt::time::Instant::now() + core::time::Duration::from_millis(10),
    );
}

#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn moturus_log_panics_to_kernel() -> bool {
    // Normal binaries should log panics to their stderr. But sys-io, sys-tty, and sys-init
    // don't have stdio, so they will override this function to log via SysMem::log().
    false
}
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    panic!("__stack_chk_fail")
}

#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn __assert_fail() -> ! {
    // void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
    panic!("__assert_fail")
}
