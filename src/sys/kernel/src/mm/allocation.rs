//! Internal allocation failures retain pressure provenance until a syscall or
//! fault handler decides whether to wait. The userspace error-code ABI is unchanged.

pub(crate) use super::phys_blocks::{AllocationClass, RefusalKind, StateSnapshot};
use moto_sys::ErrorCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationFailure {
    /// Validation, per-process limits, or virtual-region exhaustion. These
    /// retain their existing handling even while physical memory is scarce.
    Code(ErrorCode),
    /// Physical allocation refusal, with the count and generation observed
    /// before caller cleanup. Retry decisions must also inspect post-rollback state.
    Pressure {
        class: AllocationClass,
        kind: RefusalKind,
        state: StateSnapshot,
        free_pages: u64,
    },
}

impl AllocationFailure {
    // A huge-page floor refusal can close the gate before its small-page
    // fallback runs. Keep that original shortage: after rollback the syscall
    // must use the physical-failure rule, not repeatedly retry a gate refusal.
    // Keep its original generation even if recovery happened in between;
    // the retry boundary reconciles that history with the post-rollback count.
    pub(crate) fn retain_floor_refusal(self, earlier: Option<Self>) -> Self {
        match (self, earlier) {
            (
                Self::Pressure {
                    class,
                    kind: RefusalKind::Gate,
                    ..
                },
                Some(
                    original @ Self::Pressure {
                        class: old_class,
                        kind: RefusalKind::Floor,
                        ..
                    },
                ),
            ) if class == old_class => original,
            _ => self,
        }
    }
}

impl From<ErrorCode> for AllocationFailure {
    fn from(code: ErrorCode) -> Self {
        Self::Code(code)
    }
}

// Until the waiting consumers land, syscall boundaries retain today's errors.
impl From<AllocationFailure> for ErrorCode {
    fn from(failure: AllocationFailure) -> Self {
        match failure {
            AllocationFailure::Code(code) => code,
            AllocationFailure::Pressure { .. } => moto_rt::E_OUT_OF_MEMORY,
        }
    }
}
