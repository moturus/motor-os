use moto_sys::ErrorCode;

/// Preserve the original refusal even if another CPU fills the page afterward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserCopyError {
    Error(ErrorCode),
    PageAbsent(u64),
}

impl UserCopyError {
    /// Only use for a buffer in the calling process's address space.
    pub fn into_syscall_result(
        self,
        caller: &super::user::UserAddressSpace,
    ) -> moto_sys::syscalls::SyscallResult {
        let mut result = moto_sys::syscalls::SyscallResult {
            result: ErrorCode::from(self) as u64,
            data: [0; 6],
        };
        if let Self::PageAbsent(addr) = self {
            // Test membership, not presence: a concurrent fill must not erase
            // the original refusal. Userspace may safely touch a filled page.
            if caller.is_file_page(addr) {
                result.result = moto_rt::E_PAGE_ABSENT as u64;
                result.data[0] = addr & !(super::PAGE_SIZE_SMALL - 1);
                crate::xray::stats::kernel_stats_ref()
                    .adjust_metric(crate::xray::stats::MetricType::FilePagedSyscallMisses, 1);
            }
        }
        result
    }
}

impl From<ErrorCode> for UserCopyError {
    fn from(err: ErrorCode) -> Self {
        Self::Error(err)
    }
}

// Foreign-space and background copies cannot ask the caller to fault a page.
impl From<UserCopyError> for ErrorCode {
    fn from(err: UserCopyError) -> Self {
        match err {
            UserCopyError::Error(err) => err,
            UserCopyError::PageAbsent(_) => moto_rt::E_INVALID_ARGUMENT,
        }
    }
}
