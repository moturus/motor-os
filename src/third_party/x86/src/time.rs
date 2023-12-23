//! Functions to read time stamp counters on x86.

use crate::arch::{__rdtscp, _rdtsc};

/// Read the time stamp counter.
///
/// The RDTSC instruction is not a serializing instruction.
/// It does not necessarily wait until all previous instructions
/// have been executed before reading the counter. Similarly,
/// subsequent instructions may begin execution before the
/// read operation is performed. If software requires RDTSC to be
/// executed only after all previous instructions have completed locally,
/// it can either use RDTSCP or execute the sequence LFENCE;RDTSC.
///
/// # Safety
/// * Causes a GP fault if the TSD flag in register CR4 is set and the CPL
///   is greater than 0.
pub unsafe fn rdtsc() -> u64 {
    _rdtsc() as u64
}

/// Read the time stamp counter.
///
/// The RDTSCP instruction waits until all previous instructions
/// have been executed before reading the counter.
/// However, subsequent instructions may begin execution
/// before the read operation is performed.
///
/// Volatile is used here because the function may be used to act as
/// an instruction barrier.
///
/// # Safety
/// * Causes a GP fault if the TSD flag in register CR4 is set and the
///   CPL is greater than 0.
pub unsafe fn rdtscp() -> u64 {
    let mut _aux = 0;
    __rdtscp(&mut _aux)
}

#[cfg(all(test, feature = "utest"))]
mod test {
    use super::*;

    #[test]
    fn check_rdtsc() {
        let cpuid = crate::cpuid::CpuId::new();
        let has_tsc = cpuid
            .get_feature_info()
            .map_or(false, |finfo| finfo.has_tsc());

        if has_tsc {
            unsafe {
                assert!(rdtsc() > 0, "rdtsc returned 0, unlikely!");
            }
        }
    }

    #[test]
    fn check_rdtscp() {
        let cpuid = crate::cpuid::CpuId::new();
        let has_rdtscp = cpuid
            .get_extended_processor_and_feature_identifiers()
            .map_or(false, |einfo| einfo.has_rdtscp());

        if has_rdtscp {
            unsafe {
                assert!(rdtscp() > 0, "rdtscp returned 0, unlikely!");
            }
        }
    }
}
