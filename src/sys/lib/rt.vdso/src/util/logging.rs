use log::{LevelFilter, SetLoggerError};
use log::{Metadata, Record};

use core::sync::atomic::{AtomicU64, Ordering};

struct MotoLogger;

impl log::Log for MotoLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let now =
                moto_rt::time::Instant::now().duration_since(moto_rt::time::Instant::from_u64(0));
            let millis = now.as_millis();
            let secs = millis / 1000;
            let millis = millis % 1000;

            crate::moto_log!(
                "{:3}:{:03}: {} {}:{}: {}\n",
                secs,
                millis,
                record.level(),
                record.file().unwrap_or("-"),
                record.line().unwrap_or(0),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

static LOGGER: MotoLogger = MotoLogger;

pub fn init() -> Result<(), SetLoggerError> {
    #[cfg(debug_assertions)]
    let res = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Debug));

    #[cfg(not(debug_assertions))]
    let res = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info));

    res
}

macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            $crate::util::logging::log_diagnostic(alloc::format!($($arg)*).as_str());
        }
    };
}

pub(crate) use moto_log;

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiagnosticRoute {
    Stderr = 1,
    Kernel = 2,
    Dropped = 3,
}

static DIAGNOSTIC_OWNER: AtomicU64 = AtomicU64::new(0);

struct DiagnosticGuard(u64);

impl DiagnosticGuard {
    fn enter() -> Result<Self, ()> {
        let tid = moto_sys::UserThreadControlBlock::this_thread_tid();
        loop {
            match DIAGNOSTIC_OWNER.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Self(tid)),
                Err(owner) if owner == tid => return Err(()),
                Err(_) => moto_sys::SysCpu::sched_yield(),
            }
        }
    }
}

impl Drop for DiagnosticGuard {
    fn drop(&mut self) {
        let owner = DIAGNOSTIC_OWNER.swap(0, Ordering::Release);
        debug_assert_eq!(owner, self.0);
    }
}

fn kernel_fallback(msg: &str) -> DiagnosticRoute {
    if moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_LOG == 0 {
        return DiagnosticRoute::Dropped;
    }
    match moto_sys::SysRay::log(msg) {
        Ok(()) => DiagnosticRoute::Kernel,
        Err(_) => DiagnosticRoute::Dropped,
    }
}

fn route_diagnostic(msg: &str) -> DiagnosticRoute {
    let Ok(_guard) = DiagnosticGuard::enter() else {
        return kernel_fallback(msg);
    };
    let written = crate::stdio::stderr_pipe()
        .ok_or(moto_rt::E_BAD_HANDLE)
        .and_then(|pipe| pipe.write(msg.as_bytes()));
    match written {
        Ok(size) if size == msg.len() => DiagnosticRoute::Stderr,
        _ => kernel_fallback(msg),
    }
}

pub(crate) fn log_diagnostic(msg: &str) {
    let _ = route_diagnostic(msg);
}

pub extern "C" fn log_to_kernel(ptr: *const u8, size: usize) {
    let bytes = unsafe { core::slice::from_raw_parts(ptr, size) };
    let msg = unsafe { core::str::from_utf8_unchecked(bytes) };
    log_diagnostic(msg);
}

pub(crate) fn internal_test(mode: u64) -> u64 {
    const MARKER: &str = "rt.vdso diagnostic test marker\n";
    let route = match mode {
        0 => crate::stdio::with_stderr_claim(|| route_diagnostic(MARKER))
            .unwrap_or(DiagnosticRoute::Dropped),
        1 => {
            let Ok(_guard) = DiagnosticGuard::enter() else {
                return DiagnosticRoute::Dropped as u64;
            };
            route_diagnostic(MARKER)
        }
        2 => route_diagnostic(MARKER),
        3 => route_diagnostic(
            alloc::string::String::from_utf8(alloc::vec![b'x'; 4096])
                .unwrap()
                .as_str(),
        ),
        _ => return 0,
    };
    route as u64
}

// This panic handler is active only for code running here in VDSO.
#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &core::panic::PanicInfo<'_>) -> ! {
    moto_rt::error::log_panic(info);

    // Sleep a bit to let the panic output propagate.
    #[cfg(debug_assertions)]
    crate::rt_thread::sleep(
        (moto_rt::time::Instant::now() + core::time::Duration::from_millis(100)).as_u64(),
    );

    moto_sys::SysCpu::exit_process(0xbadc0de)
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

/// Log a backtrace to `rt_fd`.
///
/// A negative descriptor selects the process diagnostic sink: stderr first,
/// with a kernel-log fallback only when stderr fails and the process holds
/// `CAP_LOG`.
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
            write!(&mut writer, " \\\n  0x{addr:x}").ok();
        }
    }

    let _ = write!(&mut writer, "\n\n");

    let msg = writer.as_str();
    if rt_fd < 0 {
        log_diagnostic(msg);
    } else {
        let _ = crate::posix::posix_write(rt_fd, msg.as_ptr(), msg.len());
    }
}
