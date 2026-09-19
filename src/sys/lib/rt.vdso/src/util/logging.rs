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

    fn write(&self, msg: &str) -> DiagnosticRoute {
        let written = crate::stdio::stderr_pipe()
            .ok_or(moto_rt::E_BAD_HANDLE)
            .and_then(|pipe| pipe.write(msg.as_bytes()));
        match written {
            Ok(size) if size == msg.len() => DiagnosticRoute::Stderr,
            _ => kernel_fallback(msg),
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
    let Ok(guard) = DiagnosticGuard::enter() else {
        return kernel_fallback(msg);
    };
    guard.write(msg)
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
        4 => panic!("rt.vdso panic test marker"),
        5 => panic!("{}", PanicsWhenShown),
        6 => panic!("multibyte panic test marker {}", "é🦀".repeat(128)),
        // A first panic on a thread that owns the diagnostic sink.
        7 => {
            let Ok(_guard) = DiagnosticGuard::enter() else {
                return DiagnosticRoute::Dropped as u64;
            };
            panic!("rt.vdso guarded panic test marker")
        }
        // A backtrace to a descriptor from a thread that owns the sink.
        8 => {
            let Ok(_guard) = DiagnosticGuard::enter() else {
                return DiagnosticRoute::Dropped as u64;
            };
            log_backtrace(moto_rt::FD_STDERR);
            return 0;
        }
        _ => return 0,
    };
    route as u64
}

/// A panic message that panics whenever the handler formats it, with a
/// message that does the same: a report of it can never complete.
struct PanicsWhenShown;

impl core::fmt::Display for PanicsWhenShown {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        panic!("{}", PanicsWhenShown)
    }
}

/// A small `fmt::Write` buffer in front of a diagnostic sink, for reports that
/// must not allocate: a panic may be an allocation failure. It is flushed
/// whenever it fills, so a report of any length costs the same small piece of
/// stack. That matters as much as the heap: at the memory floor a fault on a
/// fresh stack page kills the thread, and with it the report.
struct SinkWriter {
    sink: Sink,
    buf: [u8; 256],
    len: usize,
}

/// Where a [`SinkWriter`] sends its chunks.
enum Sink {
    /// The process diagnostic sink, owned across formatting and every chunk.
    Diagnostic(DiagnosticGuard),
    /// This thread already owns the diagnostic sink. The write it interrupted
    /// may own the pipe, so only the kernel fallback is safe.
    Reentered,
    /// A descriptor the caller chose. It takes no part in the ownership of
    /// the diagnostic sink: a write to it neither waits for the owner nor is
    /// diverted because this thread is the owner.
    Fd(moto_rt::RtFd),
}

impl SinkWriter {
    /// As for [`log_backtrace`]: a negative `rt_fd` selects the diagnostic sink.
    fn new(rt_fd: moto_rt::RtFd) -> Self {
        let sink = if rt_fd >= 0 {
            Sink::Fd(rt_fd)
        } else {
            match DiagnosticGuard::enter() {
                Ok(guard) => Sink::Diagnostic(guard),
                Err(()) => Sink::Reentered,
            }
        };
        Self {
            sink,
            buf: [0; 256],
            len: 0,
        }
    }

    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        // Safety: write_str() copies only whole characters of valid strings.
        let text = unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) };
        match &self.sink {
            Sink::Diagnostic(guard) => {
                guard.write(text);
            }
            Sink::Reentered => {
                kernel_fallback(text);
            }
            Sink::Fd(rt_fd) => {
                let _ = crate::posix::posix_write(*rt_fd, text.as_ptr(), text.len());
            }
        }
        self.len = 0;
    }
}

impl core::fmt::Write for SinkWriter {
    fn write_str(&mut self, mut s: &str) -> core::fmt::Result {
        while !s.is_empty() {
            let mut n = s.len().min(self.buf.len() - self.len);
            while !s.is_char_boundary(n) {
                n -= 1;
            }
            if n == 0 {
                self.flush(); // No character is wider than the empty buffer.
                continue;
            }
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            s = &s[n..];
        }
        Ok(())
    }
}

// This panic handler is active only for code running here in VDSO.
#[cfg(not(test))]
#[panic_handler]
fn _panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;

    let mut out = SinkWriter::new(-1);
    if let Sink::Reentered = out.sink {
        // This thread panicked inside its own diagnostic write, or inside the
        // report of an earlier panic. Formatting the message may be what
        // panicked, and doing it again could go on until the stack is gone.
        // So say only what needs no code but core's: where, and the message
        // if it is a literal.
        let _ = out.write_str("PANIC: panicked while reporting a diagnostic");
        if let Some(location) = info.location() {
            let _ = write!(out, " at {location}");
        }
        if let Some(message) = info.message().as_str() {
            let _ = write!(out, ": {message}");
        }
        let _ = out.write_str("\n");
        out.flush();
        moto_sys::SysCpu::exit_process(0xbadc0de);
    }

    // Publish a marker before arbitrary Display code can panic. Keep the
    // whole report on the stack: the original panic may be an allocation failure.
    let _ = out.write_str("PANIC\n");
    out.flush();
    let _ = writeln!(out, "{info}");
    out.flush();
    write_backtrace(&mut out);
    out.flush();

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
///
/// Does not allocate: panic reports end here, and the panic may be an
/// allocation failure.
pub extern "C" fn log_backtrace(rt_fd: moto_rt::RtFd) {
    let mut writer = SinkWriter::new(rt_fd);
    write_backtrace(&mut writer);
    writer.flush();
}

fn write_backtrace(writer: &mut SinkWriter) {
    use core::fmt::Write;

    let backtrace = get_backtrace();
    write!(writer, "backtrace: {}", unsafe {
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
                write!(writer, " \\\n  -- rt.vdso");
            }
            write!(writer, " \\\n    0x{:x}", addr - moto_rt::RT_VDSO_START).ok();
        } else {
            if in_vdso {
                in_vdso = false;
                write!(writer, " \\\n  ^^^");
            }
            write!(writer, " \\\n  0x{addr:x}").ok();
        }
    }

    let _ = write!(writer, "\n\n");
}
