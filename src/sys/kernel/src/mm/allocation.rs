//! Internal allocation failures retain pressure provenance until a syscall or
//! fault handler decides whether to wait. The userspace error-code ABI is unchanged.

pub(crate) use super::phys_blocks::{AllocationClass, RefusalKind, StateSnapshot};
use moto_sys::ErrorCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AllocationFailure {
    /// Validation, per-process limits, or virtual-region exhaustion. These
    /// retain their existing handling even while physical memory is scarce.
    Code(ErrorCode),
    /// A revalidated syscall retry still owes a wait. No allocation was
    /// attempted: recovery must permit a retry, never turn this into OOM.
    Waiting(WaitReason),
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

// Construction paths that cannot suspend (notably process creation) retain
// the existing error ABI. Allocating syscall retries inspect the receipt first.
impl From<AllocationFailure> for ErrorCode {
    fn from(failure: AllocationFailure) -> Self {
        match failure {
            AllocationFailure::Code(code) => code,
            AllocationFailure::Pressure { .. } | AllocationFailure::Waiting(_) => {
                moto_rt::E_OUT_OF_MEMORY
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitReason {
    class: AllocationClass,
    // Gate-only waits have no generation. Shortage waits need this run to end
    // even if System's gate is open, including in an unchanged Latched state.
    generation: Option<u64>,
}

impl WaitReason {
    pub(crate) fn shortage(class: AllocationClass, generation: u64) -> Self {
        Self {
            class,
            generation: Some(generation),
        }
    }
    pub(crate) fn gate(class: AllocationClass) -> Self {
        Self {
            class,
            generation: None,
        }
    }
    pub(crate) fn with_class(self, class: AllocationClass) -> Self {
        Self { class, ..self }
    }
    pub(crate) fn ready(self, snapshot: StateSnapshot) -> bool {
        !snapshot.gate_closed(self.class) && self.generation != Some(snapshot.generation())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RetryDecision {
    Retry,
    Wait(WaitReason),
    Request(AllocationClass),
    Error(ErrorCode),
}

/// `free` is sampled after the failed operation has unwound. Faults have no
/// userspace error return: a valid fault that recovered must be retried.
impl AllocationFailure {
    pub(crate) fn retry_decision(
        self,
        snapshot: StateSnapshot,
        free: u64,
        fault: bool,
    ) -> RetryDecision {
        if let Self::Waiting(reason) = self {
            return if reason.ready(snapshot) {
                RetryDecision::Retry
            } else {
                RetryDecision::Wait(reason)
            };
        }
        let AllocationFailure::Pressure {
            class, kind, state, ..
        } = self
        else {
            return RetryDecision::Error(self.into());
        };
        if !snapshot.armed() {
            return RetryDecision::Error(moto_rt::E_OUT_OF_MEMORY);
        }
        let generation = if kind == RefusalKind::Gate {
            None
        } else {
            if free >= 768 {
                return if fault {
                    RetryDecision::Retry
                } else {
                    RetryDecision::Error(moto_rt::E_OUT_OF_MEMORY)
                };
            }
            if state.run_generation().is_some() && state.generation() != snapshot.generation() {
                // This attempt already saw its run end. Do not retag it with a
                // newer run; only the recipient's current gate can still block it.
                None
            } else if let Some(generation) = snapshot.run_generation() {
                Some(generation)
            } else {
                return RetryDecision::Request(class);
            }
        };
        let reason = WaitReason { class, generation };
        if reason.ready(snapshot) {
            RetryDecision::Retry
        } else {
            RetryDecision::Wait(reason)
        }
    }
}
