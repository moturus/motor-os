//! Miscellaneous utilities.

use core::num::Wrapping;
use core::sync::atomic::*;
use moto_sys::time::Instant;
use moto_sys::SysHandle;

/// Randomly shuffles a slice.
pub(crate) fn shuffle<T>(v: &mut [T]) {
    let len = v.len();
    if len <= 1 {
        return;
    }

    static RNG: AtomicU32 = AtomicU32::new(1_406_868_647);
    let mut rng: Wrapping<u32> = Wrapping(RNG.load(Ordering::Relaxed));

    for i in 1..len {
        // This is the 32-bit variant of Xorshift.
        //
        // Source: https://en.wikipedia.org/wiki/Xorshift
        rng ^= rng << 13;
        rng ^= rng >> 17;
        rng ^= rng << 5;
        RNG.store(rng.0, Ordering::Relaxed);

        let x = rng.0;
        let n = i + 1;

        // This is a fast alternative to `let j = x % n`.
        //
        // Author: Daniel Lemire
        // Source: https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
        let j = ((x as u64).wrapping_mul(n as u64) >> 32) as u32 as usize;

        v.swap(i, j);
    }
}

/// Sleeps until the deadline, or forever if the deadline isn't specified.
pub(crate) fn sleep_until(deadline: Option<Instant>) {
    let _ = moto_sys::syscalls::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, deadline);
}

/// Returns the id of the current thread.
#[inline]
pub fn current_thread_id() -> SysHandle {
    SysHandle::from_u64(moto_sys::UserThreadControlBlock::get().self_handle)
}
