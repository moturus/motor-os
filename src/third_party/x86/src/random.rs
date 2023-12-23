//! Instructions to generate random bits directly from the hardware (RDRAND and RDSEED).
//!
//! The decision process for which instruction to use is based on what
//! the output will be used for. If you wish to seed another pseudorandom
//! number generator (PRNG), use RDSEED. For all other purposes, use RDRAND
//!
//! See also: https://software.intel.com/en-us/blogs/2012/11/17/the-difference-between-rdrand-and-rdseed
//!
//! * RDRAND: Cryptographically secure pseudorandom number generator NIST:SP 800-90A
//! * RDSEED: Non-deterministic random bit generator NIST: SP 800-90B & C (drafts)
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    _rdrand16_step, _rdrand32_step, _rdrand64_step, _rdseed16_step, _rdseed32_step, _rdseed64_step,
};

#[cfg(target_arch = "x86")]
use core::arch::x86::{_rdrand16_step, _rdrand32_step, _rdseed16_step, _rdseed32_step};

/// Generates a 16-bit random value and stores it in `e`.
///
/// # Safety
/// Will crash if RDRAND instructions are not supported.
#[inline(always)]
pub unsafe fn rdrand16(e: &mut u16) -> bool {
    _rdrand16_step(e) == 1
}

/// Generates a 32-bit random value and stores it in `e`.
///
/// # Safety
/// Will crash if RDRAND instructions are not supported.
#[inline(always)]
pub unsafe fn rdrand32(e: &mut u32) -> bool {
    _rdrand32_step(e) == 1
}

/// Generates a 64-bit random value and stores it in `e`.
///
/// # Safety
/// Will crash if RDRAND instructions are not supported.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn rdrand64(e: &mut u64) -> bool {
    _rdrand64_step(e) == 1
}

/// RdRand trait to implement the generic rdrand_slice function.
pub trait RdRand {
    /// Fills `self` with random bits. Returns true on success or false otherwise
    ///
    /// # Safety
    /// RDRAND is not supported on all architctures, so using this may crash you.
    unsafe fn fill_random(&mut self) -> bool;
}

impl RdRand for u8 {
    /// Fills the 16-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDSEED instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        let mut r: u16 = 0;
        let ret = rdrand16(&mut r);
        *self = r as u8;
        ret
    }
}

impl RdRand for u16 {
    /// Fills the 16-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDRAND instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        rdrand16(self)
    }
}

impl RdRand for u32 {
    /// Fills the 32-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDRAND instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        rdrand32(self)
    }
}

#[cfg(target_arch = "x86_64")]
impl RdRand for u64 {
    /// Fills the 64-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDRAND instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        rdrand64(self)
    }
}

/// Fill a slice with random values.
///
/// Returns true if the iterator was successfully filled with
/// random values, otherwise false.
/// # Safety
/// Will crash if RDRAND instructions are not supported.
pub unsafe fn rdrand_slice<T: RdRand>(buffer: &mut [T]) -> bool {
    let mut worked = true;
    for element in buffer {
        worked &= element.fill_random();
    }
    worked
}

/// Generates a 16-bit random value and stores it in `e`.
///
/// # Safety
/// Will crash if RDSEED instructions are not supported.
#[inline(always)]
pub unsafe fn rdseed16(e: &mut u16) -> bool {
    _rdseed16_step(e) == 1
}

/// Generates a 32-bit random value and stores it in `e`.
///
/// # Safety
/// Will crash if RDSEED instructions are not supported.
#[inline(always)]
pub unsafe fn rdseed32(e: &mut u32) -> bool {
    _rdseed32_step(e) == 1
}

/// Generates a 64-bit random value and stores it in `e`.
///
/// # Safety
/// Will crash if RDSEED instructions are not supported.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn rdseed64(e: &mut u64) -> bool {
    _rdseed64_step(e) == 1
}

/// RdSeed trait to implement the generic rdseed_slice function.
pub trait RdSeed {
    /// Fills `self` with random bits. Returns true on success or false otherwise
    ///
    /// # Safety
    /// RDSEED is not supported on all architctures, so using this may crash you.
    unsafe fn fill_random(&mut self) -> bool;
}

impl RdSeed for u8 {
    /// Fills the 16-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDSEED instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        let mut r: u16 = 0;
        let ret = rdseed16(&mut r);
        *self = r as u8;
        ret
    }
}

impl RdSeed for u16 {
    /// Fills the 16-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDSEED instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        rdseed16(self)
    }
}

impl RdSeed for u32 {
    /// Fills the 32-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDSEED instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        rdseed32(self)
    }
}

#[cfg(target_arch = "x86_64")]
impl RdSeed for u64 {
    /// Fills the 64-bit value with a random bit string
    ///
    /// # Safety
    /// Will crash if RDSEED instructions are not supported.
    unsafe fn fill_random(&mut self) -> bool {
        rdseed64(self)
    }
}

/// Fill a slice with random values.
///
/// Returns true if the iterator was successfully filled with
/// random values, otherwise false.
///
/// # Safety
/// Will crash if RDSEED instructions are not supported.
pub unsafe fn rdseed_slice<T: RdSeed>(buffer: &mut [T]) -> bool {
    let mut worked = true;
    for element in buffer {
        worked &= element.fill_random();
    }
    worked
}

#[cfg(all(test, feature = "utest"))]
mod test {
    use super::*;

    #[test]
    fn rdrand_u64() {
        let has_rdrand = crate::cpuid::CpuId::new()
            .get_feature_info()
            .map_or(false, |finfo| finfo.has_rdrand());
        if !has_rdrand {
            return;
        }

        unsafe {
            let mut buf: [u64; 4] = [0, 0, 0, 0];
            rdrand_slice(&mut buf);

            assert_ne!(buf[0], 0);
            assert_ne!(buf[1], 0);
            assert_ne!(buf[2], 0);
            assert_ne!(buf[3], 0);
        }
    }

    #[test]
    fn rdrand_u32() {
        let has_rdrand = crate::cpuid::CpuId::new()
            .get_feature_info()
            .map_or(false, |finfo| finfo.has_rdrand());
        if !has_rdrand {
            return;
        }

        unsafe {
            let mut buf: [u32; 4] = [0, 0, 0, 0];
            rdrand_slice(&mut buf);

            assert_ne!(buf[0], 0);
            assert_ne!(buf[1], 0);
            assert_ne!(buf[2], 0);
            assert_ne!(buf[3], 0);
        }
    }

    #[test]
    fn rdrand_u16() {
        let has_rdrand = crate::cpuid::CpuId::new()
            .get_feature_info()
            .map_or(false, |finfo| finfo.has_rdrand());
        if !has_rdrand {
            return;
        }

        unsafe {
            let mut buf: [u16; 4] = [0, 0, 0, 0];
            rdrand_slice(&mut buf);
            assert_ne!(buf[0], 0);
            assert_ne!(buf[1], 0);
            assert_ne!(buf[2], 0);
            assert_ne!(buf[3], 0);
        }
    }

    #[test]
    fn rdseed_u64() {
        let has_rdseed = crate::cpuid::CpuId::new()
            .get_extended_feature_info()
            .map_or(false, |efinfo| efinfo.has_rdseed());
        if !has_rdseed {
            return;
        }

        unsafe {
            let mut buf: [u64; 4] = [0, 0, 0, 0];
            rdseed_slice(&mut buf);

            assert_ne!(buf[0], 0);
            assert_ne!(buf[1], 0);
            assert_ne!(buf[2], 0);
            assert_ne!(buf[3], 0);
        }
    }

    #[test]
    fn rdseed_u32() {
        let has_rdseed = crate::cpuid::CpuId::new()
            .get_extended_feature_info()
            .map_or(false, |efinfo| efinfo.has_rdseed());
        if !has_rdseed {
            return;
        }

        unsafe {
            let mut buf: [u32; 4] = [0, 0, 0, 0];
            rdseed_slice(&mut buf);

            assert_ne!(buf[0], 0);
            assert_ne!(buf[1], 0);
            assert_ne!(buf[2], 0);
            assert_ne!(buf[3], 0);
        }
    }

    #[test]
    fn rdseed_u16() {
        let has_rdseed = crate::cpuid::CpuId::new()
            .get_extended_feature_info()
            .map_or(false, |efinfo| efinfo.has_rdseed());
        if !has_rdseed {
            return;
        }

        unsafe {
            let mut buf: [u16; 4] = [0, 0, 0, 0];
            rdseed_slice(&mut buf);
            // Not the best test in the world, but unlikely enough to fail...
            assert!(buf[0] > 0 || buf[1] > 0 || buf[2] > 0 || buf[3] > 0);
        }
    }

    #[test]
    fn rdrand_u8() {
        let has_rdseed = crate::cpuid::CpuId::new()
            .get_extended_feature_info()
            .map_or(false, |efinfo| efinfo.has_rdseed());
        if !has_rdseed {
            return;
        }

        unsafe {
            let mut buf: [u8; 4] = [0, 0, 0, 0];
            rdrand_slice(&mut buf);
            // Not the best test in the world, but unlikely enough to fail...
            assert!(buf[0] > 0 || buf[1] > 0 || buf[2] > 0 || buf[3] > 0);
        }
    }

    #[test]
    fn rdseed_u8() {
        let has_rdseed = crate::cpuid::CpuId::new()
            .get_extended_feature_info()
            .map_or(false, |efinfo| efinfo.has_rdseed());
        if !has_rdseed {
            return;
        }

        unsafe {
            let mut buf: [u8; 4] = [0, 0, 0, 0];
            rdseed_slice(&mut buf);
            // Not the best test in the world, but unlikely enough to fail...
            assert!(buf[0] > 0 || buf[1] > 0 || buf[2] > 0 || buf[3] > 0);
        }
    }
}
