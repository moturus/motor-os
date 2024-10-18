use crate::RtVdsoVtableV1;
use core::sync::atomic::{AtomicU32, Ordering};

/// An atomic for use as a futex that is at least 8-bits but may be larger.
pub type Futex = AtomicU32;
/// An atomic for use as a futex that is at least 8-bits but may be larger.
pub type SmallFutex = AtomicU32;
/// Must be the underlying type of Futex.
pub type SmallPrimitive = u32;
/// Must be the underlying type of Futex.
pub type Primitive = u32;

/// Returns false on timeout.
pub fn futex_wait(futex: &AtomicU32, expected: u32, timeout: Option<core::time::Duration>) -> bool {
    let vdso_futex_wait: extern "C" fn(*const AtomicU32, u32, u64) -> u32 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().futex_wait.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let timo = if let Some(timo) = timeout {
        let timo_128 = timo.as_nanos();
        if timo_128 > u64::MAX as u128 {
            u64::MAX
        } else {
            timo_128 as u64
        }
    } else {
        u64::MAX
    };

    match vdso_futex_wait(futex, expected, timo) {
        0 => false,
        1 => true,
        _ => panic!(),
    }
}

pub fn futex_wake(futex: &AtomicU32) -> bool {
    let vdso_futex_wake: extern "C" fn(*const AtomicU32) -> u32 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().futex_wake.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    match vdso_futex_wake(futex) {
        0 => false,
        1 => true,
        _ => panic!(),
    }
}

pub fn futex_wake_all(futex: &AtomicU32) {
    let vdso_futex_wake_all: extern "C" fn(*const AtomicU32) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().futex_wake_all.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_futex_wake_all(futex)
}
