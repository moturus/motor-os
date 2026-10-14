use crate::mm::{admission::Commitment, PAGE_SIZE_SMALL};
use crate::uspace::process::Thread;
use alloc::collections::BTreeSet;
use alloc::sync::Weak;
use alloc::vec::Vec;
use moto_sys::ErrorCode;

pub(super) struct Waiter {
    pub(super) page: u64,
    pub(super) thread: Weak<Thread>,
}

pub(super) struct Mapping {
    pub(super) id: u64,
    /// Admission for every page not yet filled.
    pub(super) reservation: Commitment,
    pub(super) start: u64,
    pub(super) end: u64,
    /// Pages at or after this address are zero-filled without sys-io.
    pub(super) zero_from: u64,
    pub(super) queued: BTreeSet<u64>,
    pub(super) waiters: Vec<Waiter>,
}

impl Mapping {
    /// Validate before changing either collection; a retirement marker is
    /// never a page address. The caller kills the returned waiters unlocked.
    pub(super) fn fail_page(&mut self, page: u64) -> Result<Vec<Waiter>, ErrorCode> {
        let end = page
            .checked_add(PAGE_SIZE_SMALL)
            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
        if !page.is_multiple_of(PAGE_SIZE_SMALL) || page < self.start || end > self.end {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Ok(self.take_waiters(page, end))
    }

    /// Removes waiters and queued pages in the caller-validated range.
    pub(super) fn take_waiters(&mut self, start: u64, end: u64) -> Vec<Waiter> {
        let ready = self
            .waiters
            .extract_if(.., |waiter| (start..end).contains(&waiter.page))
            .collect();
        let pages: Vec<u64> = self.queued.range(start..end).copied().collect();
        for page in pages {
            self.queued.remove(&page);
        }
        ready
    }
}
