pub mod loader;
pub mod percpu;
pub mod pin_weak;
pub mod spin_lock;
pub mod static_ref;
pub mod unsafe_ref;

use alloc::vec::Vec;

pub use percpu::StaticPerCpu;
pub use pin_weak::sync::PinWeak;
pub use spin_lock::LockGuard;
pub use spin_lock::SpinLock;
pub use static_ref::StaticRef;
pub use unsafe_ref::UnsafeRef;

#[cfg(debug_assertions)]
pub use crate::sched::print_stack_trace_and_die;

#[inline(never)]
pub fn full_fence() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(never)]
pub fn fence(order: core::sync::atomic::Ordering) {
    core::sync::atomic::compiler_fence(order);
    core::sync::atomic::fence(order);
}

pub fn prng(add_entropy: bool) -> u32 {
    use core::ops::DerefMut;

    // https://en.wikipedia.org/wiki/Lehmer_random_number_generator
    static PRNG_BASE: SpinLock<core::num::Wrapping<u64>> = SpinLock::new(core::num::Wrapping(13));

    const MUL: core::num::Wrapping<u64> = core::num::Wrapping(48271);
    const MOD: core::num::Wrapping<u64> = core::num::Wrapping(2_147_483_647);

    let mut lock = PRNG_BASE.lock(line!());
    let val = lock.deref_mut();

    *val *= MUL;

    if add_entropy {
        *val += core::num::Wrapping(crate::arch::time::Instant::now().as_u64());
    }

    *val %= MOD;

    val.0 as u32
}

pub fn decode_arg<F: core::str::FromStr>(args: &Vec<&str>, param: &str) -> Option<F> {
    for arg in args {
        if let Some((prefix, suffix)) = arg.split_once('=') {
            if prefix == param {
                return suffix.parse::<F>().ok();
            }
        }
    }

    None
}
