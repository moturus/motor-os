use core::mem::MaybeUninit;
use core::sync::atomic::*;

use core::arch::asm;
use core::time::Duration;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    tsc_val: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemTime {
    nanos: u64, // Note that SystemTime uses nanos vs Instant which uses tsc.
}

#[allow(unused)]
pub const UNIX_EPOCH: SystemTime = SystemTime { nanos: 0u64 };
pub const NANOS_IN_SEC: u64 = 1_000_000_000;

impl Instant {
    pub const fn nan() -> Self {
        Instant { tsc_val: 0 }
    }
    pub fn is_nan(&self) -> bool {
        self.tsc_val == 0
    }

    pub fn from_u64(val: u64) -> Self {
        Instant { tsc_val: val }
    }
    pub fn as_u64(&self) -> u64 {
        self.tsc_val
    }

    pub fn from_nanos(nanos: u64) -> Self {
        Instant {
            tsc_val: nanos_to_tsc(nanos),
        }
    }

    pub fn now() -> Self {
        Instant { tsc_val: rdtsc() }
    }

    pub fn raw_tsc(&self) -> u64 {
        self.tsc_val
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        if earlier.tsc_val > self.tsc_val {
            // TODO: figure out why this happens in hyperv + qemu.
            log::error!(
                "time goes back: earlier: {:x} > later: {:x}",
                earlier.tsc_val,
                self.tsc_val
            );
            panic!();
        }

        let tsc_diff = self.tsc_val - earlier.tsc_val;
        if tsc_diff == 0 {
            return Duration::ZERO;
        }

        let tsc_in_sec = GLOBALS.tsc_in_sec.load(Ordering::Relaxed);
        if core::intrinsics::unlikely(tsc_in_sec == 0) {
            return Duration::ZERO;
        }
        let secs = tsc_diff / tsc_in_sec;
        let nanos = tsc_to_nanos(tsc_diff % tsc_in_sec);

        Duration::new(secs, nanos as u32)
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.clone())
    }

    pub const fn infinite_future() -> Self {
        Instant { tsc_val: u64::MAX }
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        let tsc_secs = other.as_secs() * GLOBALS.tsc_in_sec.load(Ordering::Relaxed);
        let tsc_diff = nanos_to_tsc(other.subsec_nanos() as u64) + tsc_secs;

        Instant {
            tsc_val: self.tsc_val + tsc_diff,
        }
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Self::Output {
        let tsc_secs = other.as_secs() * GLOBALS.tsc_in_sec.load(Ordering::Relaxed);
        let tsc_diff = nanos_to_tsc(other.subsec_nanos() as u64) + tsc_secs;

        if tsc_diff > self.tsc_val {
            Instant::nan()
        } else {
            Instant {
                tsc_val: self.tsc_val - tsc_diff,
            }
        }
    }
}

#[allow(unused)]
impl SystemTime {
    pub fn now() -> Self {
        SystemTime {
            nanos: abs_nanos_from_tsc(rdtsc()),
        }
    }
    pub fn as_unix_ts(&self) -> u64 {
        self.nanos
    }
}

fn abs_nanos_from_tsc(tsc_val: u64) -> u64 {
    update_globals();
    /*  see https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
        time = (current_tsc - tsc_timestamp)
        if (tsc_shift >= 0)
            time <<= tsc_shift;
        else
            time >>= -tsc_shift;
        time = (time * tsc_to_system_mul) >> 32
        time = time + system_time
    */
    let mut time = tsc_val - GLOBALS.tsc_ts.load(Ordering::Relaxed);
    let tsc_shift = GLOBALS.tsc_shift.load(Ordering::Relaxed);
    if tsc_shift >= 0 {
        time <<= tsc_shift;
    } else {
        time >>= -tsc_shift;
    }

    time = (time * (GLOBALS.tsc_mul.load(Ordering::Relaxed) as u64)) >> 32;
    time += GLOBALS.system_time.load(Ordering::Relaxed);

    GLOBALS.base_nsec.load(Ordering::Relaxed) + time
}

fn rdtsc() -> u64 {
    let mut eax: u32;
    let mut edx: u32;

    // core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    unsafe {
        asm!(
            "lfence",  // Prevent the CPU from reordering.
            "rdtsc",
            lateout("eax") eax,
            lateout("edx") edx,
            options(nostack)  // Don't say "nomem", otherwise the compiler might reorder.
        );
    }
    ((edx as u64) << 32) | (eax as u64)
}

// see https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
// see https://www.kernel.org/doc/html/latest/virt/kvm/cpuid.html
pub fn init_pvclock() {
    // Enable KVM wall clock: this is a global setting, not per-cpu.
    let ptr_wc: *const PvClockWallClock = &GLOBALS.wall_clock as *const _;
    let addr_wc = crate::arch::paging::virt_to_phys(ptr_wc as usize as u64).unwrap();
    assert_eq!(addr_wc % 4, 0);

    const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b564d00;

    // The global clock is updated by kvm only once, so we read the value only once.
    let (mut sec, mut nsec): (u32, u32);

    let mut iters = 0_u64;
    loop {
        if iters > 1_000_000 {
            panic!("init_pvclock() looping.");
        }
        if iters % 10_000 == 0 {
            super::wrmsr(MSR_KVM_WALL_CLOCK_NEW, addr_wc as u64);
            if iters > 0 {
                // If we don't trigger a VM exit, the host KVM sometimes
                // does not update system time. Which is a bug on their side, as
                // wrmsr above should trigger a VM exit.
                crate::raw_log!("\n");
            }
        }
        iters += 1;
        let ver = GLOBALS.wall_clock.version.load(Ordering::Acquire);
        if (ver == 0) || (ver & 1 != 0) {
            continue;
        }

        sec = GLOBALS.wall_clock.sec.load(Ordering::Relaxed);
        nsec = GLOBALS.wall_clock.nsec.load(Ordering::Relaxed);

        if GLOBALS.wall_clock.version.load(Ordering::Acquire) == ver {
            break;
        }
    }

    const NSEC_IN_SEC: u64 = 1_000_000_000;
    let base = (sec as u64) * NSEC_IN_SEC + (nsec as u64);

    GLOBALS.base_nsec.store(base, Ordering::Release);

    enable_kvm_system_time();

    // Note: because we count the full boot time from zero TSC as kernel CPU
    // usage, we also have to use zero TSC as system start time to have
    // `uptime` match total CPU usage.
    GLOBALS.system_start_time_tsc.store(0, Ordering::Relaxed);
    // .store(rdtsc(), Ordering::Relaxed);

    update_globals();
}

fn enable_kvm_system_time() {
    // Enable KVM system time.
    let ti = &GLOBALS.vcpu_time_info;
    let ptr_ti: *const PvClockVcpuTimeInfo = ti;
    let addr_ti = crate::arch::paging::virt_to_phys(ptr_ti as u64).unwrap();
    assert_eq!(addr_ti % 4, 0);

    const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b564d01;
    // Addr + 1 to enable.
    super::wrmsr(MSR_KVM_SYSTEM_TIME_NEW, addr_ti as u64 + 1);
}

fn update_globals() {
    // TODO: figure out how often this should be done. Most likely
    //       less often than it is done now.
    let ti = &GLOBALS.vcpu_time_info;
    let mut tsc_mul: u32;
    let mut tsc_shift: i8;
    let mut tsc_ts: u64;
    let mut system_time: u64;

    let mut iter = 0_u64;
    loop {
        iter += 1;
        let ver = ti.version.load(Ordering::Acquire);
        if iter > 100_000_000 {
            panic!("update_globals looping: ver = {}", ver);
        }
        // if ver == 0 {
        //     enable_kvm_system_time();
        //     super::serial::write_to_port(0x1000, b'.');
        //     continue;
        // }
        if ver == 0 || ver & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }

        tsc_mul = ti.tsc_to_system_mul.load(Ordering::Relaxed);
        tsc_shift = ti.tsc_shift.load(Ordering::Relaxed);
        tsc_ts = ti.tsc_timestamp.load(Ordering::Relaxed);
        system_time = ti.system_time.load(Ordering::Relaxed);

        if ti.version.load(Ordering::Acquire) == ver {
            break;
        }
    }

    if tsc_mul == 0 {
        panic!("PvClockVcpuTimeInfo (KVM clock) not working.");
    }

    GLOBALS.tsc_ts.store(tsc_ts, Ordering::Relaxed);
    GLOBALS.tsc_mul.store(tsc_mul, Ordering::Relaxed);
    GLOBALS.tsc_shift.store(tsc_shift, Ordering::Relaxed);
    GLOBALS.system_time.store(system_time, Ordering::Relaxed);
    GLOBALS
        .tsc_in_sec
        .store(nanos_to_tsc(NANOS_IN_SEC), Ordering::Relaxed);
}

fn tsc_to_nanos(tsc: u64) -> u64 {
    let mut nanos = tsc;
    let tsc_shift = GLOBALS.tsc_shift.load(Ordering::Relaxed);
    if tsc_shift >= 0 {
        nanos <<= tsc_shift;
    } else {
        nanos >>= -tsc_shift;
    }

    // TODO: this may overflow and panic. Fix.
    nanos * (GLOBALS.tsc_mul.load(Ordering::Relaxed) as u64) >> 32
}

fn nanos_to_tsc(nanos: u64) -> u64 {
    let tsc_shift = GLOBALS.tsc_shift.load(Ordering::Relaxed);

    // TODO: optimize?
    // TODO: fix panic on overflow.
    let mut res = if nanos >= (1u64 << 32) {
        (nanos >> 4) * ((1u64 << 36) / (GLOBALS.tsc_mul.load(Ordering::Relaxed) as u64))
    } else {
        (nanos << 32) / (GLOBALS.tsc_mul.load(Ordering::Relaxed) as u64)
    };

    if tsc_shift >= 0 {
        res >>= tsc_shift;
    } else {
        res <<= -tsc_shift;
    }

    return res;
}

pub fn system_start_time() -> super::time::Instant {
    // Instant { tsc_val: 0 }
    Instant {
        tsc_val: GLOBALS.system_start_time_tsc.load(Ordering::Relaxed),
    }
}

pub fn populate_kernel_static_page(page: &mut moto_sys::KernelStaticPage) {
    update_globals();

    page.tsc_in_sec = GLOBALS.tsc_in_sec.load(Ordering::Acquire);
    page.tsc_mul = GLOBALS.tsc_mul.load(Ordering::Relaxed);
    page.tsc_shift = GLOBALS.tsc_shift.load(Ordering::Relaxed);
    page.tsc_ts = GLOBALS.tsc_ts.load(Ordering::Relaxed);
    page.system_time = GLOBALS.system_time.load(Ordering::Relaxed);
    page.base_nsec = GLOBALS.base_nsec.load(Ordering::Relaxed);

    page.system_start_time_tsc = GLOBALS.system_start_time_tsc.load(Ordering::Relaxed);

    assert_ne!(0, page.tsc_in_sec);
}

/*
#[cfg(debug_assertions)]
fn test_tsc_to_nanos() {
    fn test(val: u64) {
        fn assert_fuzzy_equal(val1: u64, val2: u64) {
            let diff = if val1 > val2 {
                val1 - val2
            } else {
                val2 - val1
            };
            // assert!(diff < 10 || (diff as f64 / ((val1 + val2) as f64) < 0.01));
        }

        let nanos1 = tsc_to_nanos(val);
        let tsc1 = nanos_to_tsc(nanos1);

        assert_fuzzy_equal(val, tsc1);

        let tsc2 = nanos_to_tsc(val);
        let nanos2 = tsc_to_nanos(tsc2);

        assert_fuzzy_equal(val, nanos2);
    }

    test(5);
    test(50);
    test(234);
    test(1_000);
    test(1_000_000);
    test(1_234_567_899);
    //    test(4_444_444_444_444);
}

#[cfg(debug_assertions)]
pub fn selftest() {
    test_tsc_to_nanos();
}
*/

#[derive(Debug)]
pub struct Globals {
    pub system_time: AtomicU64,
    pub tsc_ts: AtomicU64,
    pub tsc_in_sec: AtomicU64,
    pub tsc_mul: AtomicU32,
    pub tsc_shift: AtomicI8,

    pub system_start_time_tsc: AtomicU64,

    // Wallclock base.
    pub base_nsec: AtomicU64,

    wall_clock: PvClockWallClock,
    vcpu_time_info: super::time::PvClockVcpuTimeInfo,
}

#[derive(core::fmt::Debug)]
#[repr(C, align(8))]
struct PvClockWallClock {
    version: AtomicU32,
    sec: AtomicU32,
    nsec: AtomicU32,
}

// See https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst.
#[derive(core::fmt::Debug)]
#[repr(C, align(8))]
struct PvClockVcpuTimeInfo {
    version: AtomicU32,
    pad0: u32,
    tsc_timestamp: AtomicU64,
    system_time: AtomicU64,
    tsc_to_system_mul: AtomicU32,
    tsc_shift: AtomicI8,
    flags: AtomicU8,
    pad: [u8; 2],
}

static GLOBALS: Globals = unsafe { MaybeUninit::<Globals>::zeroed().assume_init() };
