//! Support for build-in RNGs

#[derive(Copy, Clone, Debug)]
/// Used to obtain random numbers using x86_64's RDRAND opcode
pub struct RdRand(());

impl RdRand {
    /// Creates Some(RdRand) if RDRAND is supported, None otherwise
    #[inline]
    pub fn new() -> Option<Self> {
        // RDRAND support indicated by CPUID page 01h, ecx bit 30
        // https://en.wikipedia.org/wiki/RdRand#Overview
        let cpuid = unsafe { core::arch::x86_64::__cpuid(0x1) };
        if cpuid.ecx & (1 << 30) != 0 {
            Some(RdRand(()))
        } else {
            None
        }
    }

    /// Uniformly sampled u64.
    /// May fail in rare circumstances or heavy load.
    #[inline]
    pub fn get_u64(self) -> Option<u64> {
        let mut res: u64 = 0;
        unsafe {
            match core::arch::x86_64::_rdrand64_step(&mut res) {
                1 => Some(res),
                x => {
                    debug_assert_eq!(x, 0, "rdrand64 returned non-binary value");
                    None
                }
            }
        }
    }
    /// Uniformly sampled u32.
    /// May fail in rare circumstances or heavy load.
    #[inline]
    pub fn get_u32(self) -> Option<u32> {
        let mut res: u32 = 0;
        unsafe {
            match core::arch::x86_64::_rdrand32_step(&mut res) {
                1 => Some(res),
                x => {
                    debug_assert_eq!(x, 0, "rdrand32 returned non-binary value");
                    None
                }
            }
        }
    }
    /// Uniformly sampled u16.
    /// May fail in rare circumstances or heavy load.
    #[inline]
    pub fn get_u16(self) -> Option<u16> {
        let mut res: u16 = 0;
        unsafe {
            match core::arch::x86_64::_rdrand16_step(&mut res) {
                1 => Some(res),
                x => {
                    debug_assert_eq!(x, 0, "rdrand16 returned non-binary value");
                    None
                }
            }
        }
    }
}

#[cfg(all(test))]
mod tests {
    use super::*;

    #[test]
    pub fn test_rdrand() {
        let rand = RdRand::new();
        if is_x86_feature_detected!("rdrand") {
            let rand = rand.unwrap();
            assert!(rand.get_u16().is_some());
            assert!(rand.get_u32().is_some());
            assert!(rand.get_u64().is_some());
        } else {
            assert!(rand.is_none());
        }
    }
}
