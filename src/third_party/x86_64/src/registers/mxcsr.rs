//! Functions to read and write MXCSR register.

#[cfg(feature = "instructions")]
pub use self::x86_64::*;

use bitflags::bitflags;

bitflags! {
    /// MXCSR register.
    #[repr(transparent)]
    pub struct MxCsr: u32 {
        /// Invalid operation
        const INVALID_OPERATION = 1 << 0;
        /// Denormal
        const DENORMAL = 1 << 1;
        /// Divide-by-zero
        const DIVIDE_BY_ZERO = 1 << 2;
        /// Overflow
        const OVERFLOW = 1 << 3;
        /// Underflow
        const UNDERFLOW = 1 << 4;
        /// Precision
        const PRECISION = 1 << 5;
        /// Denormals are zeros
        const DENORMALS_ARE_ZEROS = 1 << 6;
        /// Invalid operation mask
        const INVALID_OPERATION_MASK = 1 << 7;
        /// Denormal mask
        const DENORMAL_MASK = 1 << 8;
        /// Divide-by-zero mask
        const DIVIDE_BY_ZERO_MASK = 1 << 9;
        /// Overflow mask
        const OVERFLOW_MASK = 1 << 10;
        /// Underflow mask
        const UNDERFLOW_MASK = 1 << 11;
        /// Precision mask
        const PRECISION_MASK = 1 << 12;
        /// Toward negative infinity
        const ROUNDING_CONTROL_NEGATIVE = 1 << 13;
        /// Toward positive infinity
        const ROUNDING_CONTROL_POSITIVE = 1 << 14;
        /// Toward zero (positive + negative)
        const ROUNDING_CONTROL_ZERO = 3 << 13;
        /// Flush to zero
        const FLUSH_TO_ZERO = 1 << 15;
    }
}

impl Default for MxCsr {
    /// Return the default MXCSR value at reset, as documented in Intel SDM volume 2A.
    #[inline]
    fn default() -> Self {
        MxCsr::INVALID_OPERATION_MASK
            | MxCsr::DENORMAL_MASK
            | MxCsr::DIVIDE_BY_ZERO_MASK
            | MxCsr::OVERFLOW_MASK
            | MxCsr::UNDERFLOW_MASK
            | MxCsr::PRECISION_MASK
    }
}

#[cfg(feature = "instructions")]
mod x86_64 {
    use super::*;
    use core::arch::asm;

    /// Read the value of MXCSR.
    #[inline]
    pub fn read() -> MxCsr {
        let mut mxcsr: u32 = 0;
        unsafe {
            asm!("stmxcsr [{}]", in(reg) &mut mxcsr, options(nostack, preserves_flags));
        }
        MxCsr::from_bits_truncate(mxcsr)
    }

    /// Write MXCSR.
    #[inline]
    pub fn write(mxcsr: MxCsr) {
        unsafe {
            asm!("ldmxcsr [{}]", in(reg) &mxcsr, options(nostack, readonly));
        }
    }

    #[cfg(test)]
    mod test {
        use crate::registers::mxcsr::*;

        #[test]
        fn mxcsr_default() {
            let mxcsr = read();
            assert_eq!(mxcsr, MxCsr::from_bits_truncate(0x1F80));
        }

        #[test]
        fn mxcsr_read() {
            let mxcsr = read();
            assert_eq!(mxcsr, MxCsr::default());
        }

        #[test]
        fn mxcsr_write() {
            let mxcsr = read();
            write(mxcsr);
            assert_eq!(mxcsr, read());
        }
    }
}
