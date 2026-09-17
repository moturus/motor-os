use std::{
    io,
    sync::atomic::{AtomicU8, Ordering},
};

const IDLE: u8 = 0;
const CONSUMED: u8 = u8::MAX;
static FAILURE: AtomicU8 = AtomicU8::new(IDLE);

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Failure {
    AfterFirstInstallRemoval = 1,
}

#[must_use]
pub struct ArmedFailure {
    failure: Failure,
}

/// Reserve one injected failure until this value is dropped.
pub fn fail_once(failure: Failure) -> crate::Result<ArmedFailure> {
    FAILURE
        .compare_exchange(IDLE, failure as u8, Ordering::SeqCst, Ordering::SeqCst)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a native test failure is armed",
            )
        })?;
    Ok(ArmedFailure { failure })
}

impl Drop for ArmedFailure {
    fn drop(&mut self) {
        let state = FAILURE.swap(IDLE, Ordering::SeqCst);
        debug_assert!(state == self.failure as u8 || state == CONSUMED);
    }
}

pub(crate) fn checkpoint(failure: Failure) -> crate::Result {
    if FAILURE
        .compare_exchange(failure as u8, CONSUMED, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        return Err(io::Error::other("injected failure after the first install removal").into());
    }
    Ok(())
}
