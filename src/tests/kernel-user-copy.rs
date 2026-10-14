extern crate self as moto_rt;
extern crate self as moto_sys;

pub type ErrorCode = u16;
pub const E_INVALID_ARGUMENT: ErrorCode = 1;
pub const E_PAGE_ABSENT: ErrorCode = 2;

pub mod syscalls {
    pub struct SyscallResult {
        pub result: u64,
        pub data: [u64; 6],
    }
}

#[path = "../sys/kernel/src/mm/user_copy.rs"]
pub mod user_copy;

mod user {
    use core::cell::Cell;

    pub struct UserAddressSpace {
        pub file_page: u64,
        pub membership_checks: Cell<usize>,
    }

    impl UserAddressSpace {
        pub fn is_file_page(&self, addr: u64) -> bool {
            self.membership_checks.set(self.membership_checks.get() + 1);
            addr >= self.file_page && addr < self.file_page + super::PAGE_SIZE_SMALL
        }
    }
}

const PAGE_SIZE_SMALL: u64 = 4096;

mod xray {
    pub mod stats {
        pub enum MetricType {
            FilePagedSyscallMisses,
        }
        pub struct Stats;
        pub fn kernel_stats_ref() -> Stats {
            Stats
        }
        impl Stats {
            pub fn adjust_metric(&self, _: MetricType, delta: i64) {
                assert_eq!(delta, 1);
            }
        }
    }
}

#[test]
fn absent_page_conversion_only_checks_file_membership() {
    // The address-space substitute exposes membership only: consulting page
    // presence after the original refusal would reintroduce the fill race.
    let caller = user::UserAddressSpace {
        file_page: 4096,
        membership_checks: 0.into(),
    };
    let failure = user_copy::UserCopyError::PageAbsent(4096 + 123);
    let result = failure.into_syscall_result(&caller);
    assert_eq!(result.result, E_PAGE_ABSENT as u64);
    assert_eq!(result.data, [4096, 0, 0, 0, 0, 0]);
    assert_eq!(caller.membership_checks.get(), 1);
}

#[test]
fn zero_is_a_page_address_and_not_an_error_sentinel() {
    let caller = user::UserAddressSpace {
        file_page: 0,
        membership_checks: 0.into(),
    };
    let result = user_copy::UserCopyError::PageAbsent(0).into_syscall_result(&caller);
    assert_eq!(result.result, E_PAGE_ABSENT as u64);
    assert_eq!(result.data, [0; 6]);
}

#[test]
fn ordinary_foreign_and_non_file_failures_are_not_retryable() {
    let caller = user::UserAddressSpace {
        file_page: 4096,
        membership_checks: 0.into(),
    };
    let ordinary = user_copy::UserCopyError::from(E_INVALID_ARGUMENT).into_syscall_result(&caller);
    assert_eq!(ordinary.result, E_INVALID_ARGUMENT as u64);
    assert_eq!(caller.membership_checks.get(), 0);
    let non_file = user_copy::UserCopyError::PageAbsent(8192).into_syscall_result(&caller);
    assert_eq!(non_file.result, E_INVALID_ARGUMENT as u64);
    // Foreign copies use ordinary conversion, even if the numeric address
    // happens to name a file mapping in the caller's space too.
    let foreign: ErrorCode = user_copy::UserCopyError::PageAbsent(4096).into();
    assert_eq!(foreign, E_INVALID_ARGUMENT);
}
