use core::{sync::atomic::Ordering, time::Duration};

use crate::RtVdsoVtableV1;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct Instant {
    ticks: u64, // Currently tsc. Subject to change.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct SystemTime {
    nanos: u128, // Note that SystemTime uses nanos vs Instant which uses "ticks".
}

#[allow(unused)]
pub const UNIX_EPOCH: SystemTime = SystemTime { nanos: 0u128 };
const NANOS_IN_SEC: u64 = 1_000_000_000;

impl Instant {
    pub const fn nan() -> Self {
        Instant { ticks: 0 }
    }
    pub fn is_nan(&self) -> bool {
        self.ticks == 0
    }

    pub fn from_u64(val: u64) -> Self {
        Instant { ticks: val }
    }

    pub fn as_u64(&self) -> u64 {
        self.ticks
    }

    pub fn now() -> Self {
        let vdso_time_instant_now: extern "C" fn() -> u64 = unsafe {
            core::mem::transmute(
                RtVdsoVtableV1::get()
                    .time_instant_now
                    .load(Ordering::Relaxed) as usize as *const (),
            )
        };

        Self {
            ticks: vdso_time_instant_now(),
        }
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        if earlier.ticks > self.ticks {
            return Duration::ZERO;
        }

        let ticks_diff = self.ticks - earlier.ticks;
        if ticks_diff == 0 {
            return Duration::ZERO;
        }

        let nanos = ticks_to_nanos(ticks_diff);

        Duration::new(
            (nanos / (NANOS_IN_SEC as u128)) as u64,
            (nanos % (NANOS_IN_SEC as u128)) as u32,
        )
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now().duration_since(self.clone())
    }

    pub const fn infinite_future() -> Self {
        Instant { ticks: u64::MAX }
    }

    pub fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        if *self < *other {
            return None;
        }

        let result_ticks = self.ticks - other.ticks;
        let result_nanos = ticks_to_nanos(result_ticks);
        if result_nanos > (u64::MAX as u128) {
            None
        } else {
            Some(Duration::from_nanos(result_nanos as u64))
        }
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<Instant> {
        let tsc_secs = other.as_secs().checked_mul(ticks_in_sec())?;
        let tsc_diff = nanos_to_ticks(other.subsec_nanos() as u64).checked_add(tsc_secs)?;

        Some(Instant {
            ticks: self.ticks.checked_add(tsc_diff)?,
        })
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<Instant> {
        let tsc_secs = other.as_secs().checked_mul(ticks_in_sec())?;
        let tsc_diff = nanos_to_ticks(other.subsec_nanos() as u64).checked_add(tsc_secs)?;

        if tsc_diff > self.ticks {
            None
        } else {
            Some(Instant {
                ticks: self.ticks - tsc_diff,
            })
        }
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, other: Duration) -> Instant {
        let tsc_secs = other.as_secs() * ticks_in_sec();
        let tsc_diff = nanos_to_ticks(other.subsec_nanos() as u64) + tsc_secs;

        Instant {
            ticks: self.ticks + tsc_diff,
        }
    }
}

impl core::ops::Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Self::Output {
        let tsc_secs = other.as_secs() * ticks_in_sec();
        let tsc_diff = nanos_to_ticks(other.subsec_nanos() as u64) + tsc_secs;

        Instant {
            ticks: self.ticks - tsc_diff,
        }
    }
}

pub fn since_system_start() -> Duration {
    Instant::now()
        .checked_sub_instant(&Instant { ticks: 0 })
        .unwrap()
}

#[allow(unused)]
impl SystemTime {
    pub fn now() -> Self {
        SystemTime {
            nanos: abs_ticks_to_nanos(Instant::now().ticks),
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

// This is "Duration".
fn ticks_to_nanos(ticks: u64) -> u128 {
    let vdso_ticks_to_nanos: extern "C" fn(u64, *mut u64, *mut u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .time_ticks_to_nanos
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut hi = 0_u64;
    let mut lo = 0_u64;

    vdso_ticks_to_nanos(ticks, &mut hi, &mut lo);

    ((hi as u128) << 64) + (lo as u128)
}

// This is "system time".
fn abs_ticks_to_nanos(ticks: u64) -> u128 {
    let vdso_abs_ticks_to_nanos: extern "C" fn(u64, *mut u64, *mut u64) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .time_abs_ticks_to_nanos
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut hi = 0_u64;
    let mut lo = 0_u64;

    vdso_abs_ticks_to_nanos(ticks, &mut hi, &mut lo);

    ((hi as u128) << 64) + (lo as u128)
}

fn nanos_to_ticks(nanos: u64) -> u64 {
    let vdso_nanos_to_ticks: extern "C" fn(u64) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .time_nanos_to_ticks
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_nanos_to_ticks(nanos)
}

fn ticks_in_sec() -> u64 {
    RtVdsoVtableV1::get()
        .time_ticks_in_sec
        .load(Ordering::Relaxed)
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
