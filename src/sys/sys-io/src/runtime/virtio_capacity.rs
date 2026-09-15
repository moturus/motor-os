use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::io::{Error, ErrorKind, Result};

pub(crate) const MMIO_PAGE_SIZE: u64 = 4096;
pub(crate) const MMIO_POOL_SIZE: u64 = MMIO_PAGE_SIZE * 512;
pub(crate) const IRQ_START: u8 = 64;
const IRQ_END: u8 = 80;

pub(crate) fn reserve_mmio(cursor: &AtomicU64, size: u64) -> Result<(u64, u64)> {
    if size == 0 {
        return Err(ErrorKind::InvalidInput.into());
    }
    let rounded = size
        .checked_add(MMIO_PAGE_SIZE - 1)
        .ok_or(ErrorKind::InvalidInput)?
        & !(MMIO_PAGE_SIZE - 1);
    // The cursor starts at zero and every successful update advances it by
    // whole pages, preserving alignment without a separate mutable invariant.
    let start = cursor
        .try_update(Ordering::AcqRel, Ordering::Acquire, |start| {
            start
                .checked_add(rounded)
                .filter(|end| *end <= MMIO_POOL_SIZE)
        })
        .map_err(|_| Error::from(ErrorKind::OutOfMemory))?;
    Ok((start, rounded))
}

pub(crate) fn reserve_irq(cursor: &AtomicU8) -> Result<u8> {
    cursor
        .try_update(Ordering::AcqRel, Ordering::Acquire, |irq| {
            (IRQ_START..IRQ_END).contains(&irq).then(|| irq + 1)
        })
        .map_err(|_| ErrorKind::OutOfMemory.into())
}
