use core::sync::atomic::{AtomicU8, Ordering};
use std::io::{ErrorKind, Result};

pub(crate) const IRQ_START: u8 = 64;
const IRQ_END: u8 = 80;

pub(crate) fn reserve_irq(cursor: &AtomicU8) -> Result<u8> {
    cursor
        .try_update(Ordering::AcqRel, Ordering::Acquire, |irq| {
            (IRQ_START..IRQ_END).contains(&irq).then(|| irq + 1)
        })
        .map_err(|_| ErrorKind::OutOfMemory.into())
}
