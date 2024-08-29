use core::arch::asm;
use core::sync::atomic::*;
use core::time::Duration;

use super::KernelStaticPage;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct Instant {
    tsc_val: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct SystemTime {
    nanos: u128, // Note that SystemTime uses nanos vs Instant which uses tsc.
}

#[allow(unused)]
pub const UNIX_EPOCH: SystemTime = SystemTime { nanos: 0u128 };
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
            #[cfg(all(not(feature = "rustc-dep-of-std"), feature = "userspace"))]
            crate::SysRay::log(
                alloc::format!(
                    "time goes back: earlier: {:x} > later: {:x}",
                    earlier.tsc_val,
                    self.tsc_val
                )
                .as_str(),
            )
            .ok();

            #[cfg(feature = "rustc-dep-of-std")]
            crate::SysRay::log("fros-sys: time: time goes back").ok();
            return Duration::ZERO;
        }

        let tsc_diff = self.tsc_val - earlier.tsc_val;
        if tsc_diff == 0 {
            return Duration::ZERO;
        }

        let tsc_in_sec = KernelStaticPage::get().tsc_in_sec;
        if core::intrinsics::unlikely(tsc_in_sec == 0) {
            return Duration::ZERO;
        }
        let secs = tsc_diff / tsc_in_sec;
        let nanos = tsc_to_nanos_128(tsc_diff % tsc_in_sec);

        Duration::new(secs, nanos as u32)
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.clone())
    }

    pub const fn infinite_future() -> Self {
        Instant { tsc_val: u64::MAX }
    }

    pub fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        if *self < *other {
            return None;
        }

        let result_tsc = self.tsc_val - other.tsc_val;
        let result_nanos = tsc_to_nanos_128(result_tsc);
        if result_nanos > (u64::MAX as u128) {
            None
        } else {
            Some(Duration::from_nanos(result_nanos as u64))
        }
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<Instant> {
        let tsc_secs = other
            .as_secs()
            .checked_mul(KernelStaticPage::get().tsc_in_sec)?;
        let tsc_diff = nanos_to_tsc(other.subsec_nanos() as u64).checked_add(tsc_secs)?;

        Some(Instant {
            tsc_val: self.tsc_val.checked_add(tsc_diff)?,
        })
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<Instant> {
        let tsc_secs = other
            .as_secs()
            .checked_mul(KernelStaticPage::get().tsc_in_sec)?;
        let tsc_diff = nanos_to_tsc(other.subsec_nanos() as u64).checked_add(tsc_secs)?;

        if tsc_diff > self.tsc_val {
            None
        } else {
            Some(Instant {
                tsc_val: self.tsc_val - tsc_diff,
            })
        }
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        let tsc_secs = other.as_secs() * KernelStaticPage::get().tsc_in_sec;
        let tsc_diff = nanos_to_tsc(other.subsec_nanos() as u64) + tsc_secs;

        Instant {
            tsc_val: self.tsc_val + tsc_diff,
        }
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Self::Output {
        let tsc_secs = other.as_secs() * KernelStaticPage::get().tsc_in_sec;
        let tsc_diff = nanos_to_tsc(other.subsec_nanos() as u64) + tsc_secs;

        Instant {
            tsc_val: self.tsc_val - tsc_diff,
        }
    }
}

pub fn system_start_time() -> super::time::Instant {
    Instant {
        tsc_val: KernelStaticPage::get().system_start_time_tsc,
    }
}

pub fn since_system_start() -> Duration {
    Instant::now()
        .checked_sub_instant(&Instant {
            tsc_val: KernelStaticPage::get().system_start_time_tsc,
        })
        .unwrap()
}

#[allow(unused)]
impl SystemTime {
    pub fn now() -> Self {
        SystemTime {
            nanos: abs_nanos_from_tsc(rdtsc()),
        }
    }

    pub fn as_unix_ts(&self) -> u64 {
        (self.nanos & (u64::MAX as u128)) as u64
    }

    pub fn from_unix_ts(val: u64) -> Self {
        Self { nanos: val as u128 }
    }

    pub fn sub_time(&self, other: &SystemTime) -> Result<Duration, Duration> {
        if self.nanos >= other.nanos {
            let total_nanos = self.nanos - other.nanos;
            let secs = total_nanos / (NANOS_IN_SEC as u128);
            let nanos = total_nanos % (NANOS_IN_SEC as u128);
            Ok(Duration::new(secs as u64, nanos as u32))
        } else {
            let total_nanos = other.nanos - self.nanos;
            let secs = total_nanos / (NANOS_IN_SEC as u128);
            let nanos = total_nanos % (NANOS_IN_SEC as u128);
            Err(Duration::new(secs as u64, nanos as u32))
        }
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<SystemTime> {
        self.nanos
            .checked_add(other.as_nanos())
            .map(|nanos| Self { nanos })
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<SystemTime> {
        self.nanos
            .checked_sub(other.as_nanos())
            .map(|nanos| Self { nanos })
    }
}

fn abs_nanos_from_tsc(tsc_val: u64) -> u128 {
    /*  see https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
        time = (current_tsc - tsc_timestamp)
        if (tsc_shift >= 0)
            time <<= tsc_shift;
        else
            time >>= -tsc_shift;
        time = (time * tsc_to_system_mul) >> 32
        time = time + system_time
    */
    fence(Ordering::Acquire);

    let page = KernelStaticPage::get();
    let mut time = tsc_val - page.tsc_ts;
    let tsc_shift = page.tsc_shift;
    if tsc_shift >= 0 {
        time <<= tsc_shift;
    } else {
        time >>= -tsc_shift;
    }

    // The multiplication below MUST be done with higher precision, as
    // doing it in u64 overflows and leads to wrong time.
    let mul = (time as u128) * (page.tsc_mul as u128);

    let mut time = mul >> 32;
    time += page.system_time as u128;

    page.base_nsec as u128 + time
}

fn rdtsc() -> u64 {
    let mut eax: u32;
    let mut edx: u32;

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

fn tsc_to_nanos_128(tsc: u64) -> u128 {
    fence(Ordering::Acquire);
    let page = KernelStaticPage::get();

    let mut nanos = tsc as u128;
    let tsc_shift = page.tsc_shift;
    if tsc_shift >= 0 {
        nanos <<= tsc_shift;
    } else {
        nanos >>= -tsc_shift;
    }

    nanos * (page.tsc_mul as u128) >> 32
}

fn nanos_to_tsc(nanos: u64) -> u64 {
    fence(Ordering::Acquire);
    let page = KernelStaticPage::get();

    let tsc_shift = page.tsc_shift;

    // TODO: optimize?
    // TODO: fix panic on overflow.
    let mut res = if nanos >= (1u64 << 32) {
        (nanos >> 4) * ((1u64 << 36) / (page.tsc_mul as u64))
    } else {
        (nanos << 32) / (page.tsc_mul as u64)
    };

    if tsc_shift >= 0 {
        res >>= tsc_shift;
    } else {
        res <<= -tsc_shift;
    }

    return res;
}

#[derive(Debug)]
pub struct UtcDateTime {
    pub year: u32,
    pub month: u8, // starts with 1
    pub day: u8,   // starts with 1
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
}

impl core::fmt::Display for UtcDateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}Z",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.nanosecond / (1000 * 1000)
        )
    }
}

impl UtcDateTime {
    pub fn from_unix_nanos(nanos: u128) -> Self {
        let st = nanos as u64;
        let nanosecond = (st % (1000 * 1000 * 1000)) as u32;

        let seconds = (st - (nanosecond as u64)) / (1000 * 1000 * 1000);
        let time = seconds % (24 * 60 * 60);

        let second = (time % 60) as u8;
        let minutes = (time - (second as u64)) / 60;
        let minute = (minutes % 60) as u8;
        let hour = ((minutes - (minute as u64)) / 60) as u8;

        let mut days = (seconds - time) / (24 * 60 * 60);
        let mut year: u32 = 1970;

        fn leap_year(year: u32) -> bool {
            (year % 400 == 0) || ((year % 4 == 0) && (year % 100 != 0))
        }

        // Find the year.
        loop {
            if leap_year(year) {
                if days < 366 {
                    break;
                }
                days -= 366; // leap year
            } else if days < 365 {
                break;
            } else {
                days -= 365; // normal year
            }
            year += 1;
        }

        // Find the month and day.
        const MONTHS: [u8; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut month: u8 = 0;
        loop {
            if month == 1 {
                if leap_year(year) {
                    if days < 29 {
                        break;
                    }
                    days -= 29;
                    month += 1;
                    continue;
                } else if days < 28 {
                    break;
                }
                days -= 28;
                month += 1;
                continue;
            }
            if days < MONTHS[month as usize] as u64 {
                break;
            }
            days -= MONTHS[month as usize] as u64;
            month += 1;
        }

        Self {
            year,
            month: month + 1,
            day: (days + 1) as u8,
            hour,
            minute,
            second,
            nanosecond,
        }
    }
}
