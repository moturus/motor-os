//! Access to various extended system registers
use bitflags::bitflags;

/// Extended feature enable mask register
#[derive(Debug)]
pub struct XCr0;

bitflags! {
    /// Configuration flags of the XCr0 register.
    ///
    /// For MPX, [`BNDREG`](XCr0Flags::BNDREG) and [`BNDCSR`](XCr0Flags::BNDCSR) must be set/unset simultaneously.
    /// For AVX-512, [`OPMASK`](XCr0Flags::OPMASK), [`ZMM_HI256`](XCr0Flags::ZMM_HI256), and [`HI16_ZMM`](XCr0Flags::HI16_ZMM) must be set/unset simultaneously.
    pub struct XCr0Flags: u64 {
        /// Enables using the x87 FPU state
        /// with `XSAVE`/`XRSTOR`.
        ///
        /// Must be set.
        const X87 = 1;
        /// Enables using MXCSR and the XMM registers
        /// with `XSAVE`/`XRSTOR`.
        ///
        /// Must be set if [`AVX`](XCr0Flags::AVX) is set.
        const SSE = 1 << 1;
        /// Enables AVX instructions and using the upper halves of the AVX registers
        /// with `XSAVE`/`XRSTOR`.
        const AVX = 1 << 2;
        /// Alias for [`AVX`](XCr0Flags::AVX)
        #[deprecated(since = "0.14.5", note = "use `AVX` instead")]
        const YMM = 1<<2;
        /// Enables MPX instructions and using the BND0-BND3 bound registers
        /// with `XSAVE`/`XRSTOR` (Intel Only).
        const BNDREG = 1 << 3;
        /// Enables MPX instructions and using the BNDCFGU and BNDSTATUS registers
        /// with `XSAVE`/`XRSTOR` (Intel Only).
        const BNDCSR = 1 << 4;
        /// Enables AVX-512 instructions and using the K0-K7 mask registers
        /// with `XSAVE`/`XRSTOR` (Intel Only).
        const OPMASK = 1 << 5;
        /// Enables AVX-512 instructions and using the upper halves of the lower ZMM registers
        /// with `XSAVE`/`XRSTOR` (Intel Only).
        const ZMM_HI256 = 1 << 6;
        /// Enables AVX-512 instructions and using the upper ZMM registers
        /// with `XSAVE`/`XRSTOR` (Intel Only).
        const HI16_ZMM = 1 << 7;
        /// Enables using the PKRU register
        /// with `XSAVE`/`XRSTOR`.
        const MPK = 1<<9;
        /// Enables Lightweight Profiling extensions and managing LWP state
        /// with `XSAVE`/`XRSTOR` (AMD Only).
        const LWP = 1<<62;
    }
}

#[cfg(feature = "instructions")]
mod x86_64 {
    use super::*;
    use core::arch::asm;

    impl XCr0 {
        /// Read the current set of XCR0 flags.
        #[inline]
        pub fn read() -> XCr0Flags {
            XCr0Flags::from_bits_truncate(Self::read_raw())
        }

        /// Read the current raw XCR0 value.
        #[inline]
        pub fn read_raw() -> u64 {
            unsafe {
                let (low, high): (u32, u32);
                asm!(
                    "xgetbv",
                    in("ecx") 0,
                    out("rax") low, out("rdx") high,
                    options(nomem, nostack, preserves_flags),
                );
                (high as u64) << 32 | (low as u64)
            }
        }

        /// Write XCR0 flags.
        ///
        /// Preserves the value of reserved fields.
        /// Panics if invalid combinations of [`XCr0Flags`] are set.
        ///
        /// ## Safety
        ///
        /// This function is unsafe because it's possible to
        /// enable features that are not supported by the architecture
        #[inline]
        pub unsafe fn write(flags: XCr0Flags) {
            let old_value = Self::read_raw();
            let reserved = old_value & !(XCr0Flags::all().bits());
            let new_value = reserved | flags.bits();

            assert!(flags.contains(XCr0Flags::X87), "The X87 flag must be set");
            if flags.contains(XCr0Flags::AVX) {
                assert!(
                    flags.contains(XCr0Flags::SSE),
                    "AVX cannot be enabled without enabling SSE"
                );
            }
            let mpx = XCr0Flags::BNDREG | XCr0Flags::BNDCSR;
            if flags.intersects(mpx) {
                assert!(
                    flags.contains(mpx),
                    "MPX flags XCr0.BNDREG and XCr0.BNDCSR must be set and unset together"
                );
            }
            let avx512 = XCr0Flags::OPMASK | XCr0Flags::ZMM_HI256 | XCr0Flags::HI16_ZMM;
            if flags.intersects(avx512) {
                assert!(
                    flags.contains(XCr0Flags::AVX),
                    "AVX-512 cannot be enabled without enabling AVX"
                );
                assert!(
                    flags.contains(avx512),
                    "AVX-512 flags XCR0.opmask, XCR0.ZMM_Hi256, and XCR0.Hi16_ZMM must be set and unset together"
                );
            }

            unsafe {
                Self::write_raw(new_value);
            }
        }

        /// Write raw XCR0 flags.
        ///
        /// Does _not_ preserve any values, including reserved fields.
        ///
        /// ## Safety
        ///
        /// This function is unsafe because it's possible to
        /// enable features that are not supported by the architecture
        #[inline]
        pub unsafe fn write_raw(value: u64) {
            let low = value as u32;
            let high = (value >> 32) as u32;

            unsafe {
                asm!(
                    "xsetbv",
                    in("ecx") 0,
                    in("rax") low, in("rdx") high,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }
    }
}
