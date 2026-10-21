//! Miscellaneous utilities.

use moto_rt::time::Instant;
use moto_sys::SysHandle;

/// Sleeps until the deadline, or forever if the deadline isn't specified.
pub(crate) fn sleep_until(deadline: Option<Instant>) {
    let _ = moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, deadline);
}

/// Returns the id of the current thread.
#[inline]
pub fn current_thread_id() -> SysHandle {
    SysHandle::from_u64(moto_sys::UserThreadControlBlock::get().self_handle)
}
