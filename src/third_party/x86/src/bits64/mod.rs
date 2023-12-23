//! Data structures and functions used by IA-32e but not Protected Mode.

pub mod paging;
#[cfg(target_arch = "x86_64")]
pub mod registers;
pub mod rflags;
pub mod segmentation;
#[cfg(target_arch = "x86_64")]
pub mod sgx;
pub mod syscall;
pub mod task;
#[cfg(target_arch = "x86_64")]
pub mod vmx;
