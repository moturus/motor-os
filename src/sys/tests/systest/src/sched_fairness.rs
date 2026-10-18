//! A thread that spends nearly all its time inside syscalls still gives its
//! CPU up every tick: a timer armed on that CPU fires on time, and the
//! kernel counts the syscall-exit yields that make it so.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A sleep next to a syscall-bound thread may wait for the next tick and for
/// that thread's own re-queue, tens of milliseconds at most; without the
/// yield it waits for a tick to land in the thread's microseconds of user
/// mode, which takes seconds.
const WORST_SLEEP: Duration = Duration::from_millis(150);

pub fn run_all_tests() {
    let num_cpus = moto_sys::num_cpus();
    if num_cpus < 2 {
        println!("sched_fairness::run_all_tests: SKIPPED (one cpu)");
        return;
    }
    // CPU 0 is reserved for the I/O manager's affinity.
    let cpu = num_cpus - 1;
    let yields_before = crate::admission::kernel_metric_at(
        "sched.syscall_exit_yields",
        moto_sys::stats::PID_KERNEL,
    );

    // The syscall-bound thread: each iteration zeroes 16 pages in the kernel
    // and spends a few instructions in user mode.
    let stop = Arc::new(AtomicBool::new(false));
    let spinner = std::thread::spawn({
        let stop = stop.clone();
        move || {
            // Affinity takes effect at the next scheduling; a thread that
            // then never reschedules would stay where it was.
            moto_sys::SysCpu::affine_to_cpu(Some(cpu)).unwrap();
            moto_sys::SysCpu::sched_yield();
            while !stop.load(Ordering::Relaxed) {
                let addr = moto_sys::SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_SMALL, 16).unwrap();
                moto_sys::SysMem::free(addr).unwrap();
            }
        }
    });

    // The sleeper shares the CPU: its timeouts are that CPU's software
    // timers, popped only when that CPU's scheduler loop runs.
    moto_sys::SysCpu::affine_to_cpu(Some(cpu)).unwrap();
    moto_sys::SysCpu::sched_yield();
    let mut worst = Duration::ZERO;
    for _ in 0..50 {
        let started = Instant::now();
        std::thread::sleep(Duration::from_millis(1));
        worst = worst.max(started.elapsed());
        assert!(
            worst < WORST_SLEEP,
            "a 1 ms sleep next to a syscall-bound thread took {worst:?}"
        );
    }
    moto_sys::SysCpu::affine_to_cpu(None).unwrap();
    stop.store(true, Ordering::Relaxed);
    spinner.join().unwrap();

    let yields = crate::admission::kernel_metric_at(
        "sched.syscall_exit_yields",
        moto_sys::stats::PID_KERNEL,
    ) - yields_before;
    assert!(yields > 0, "no syscall gave the CPU up at its exit");
    println!("sched_fairness::run_all_tests PASS: worst sleep {worst:?}, {yields} yields");
}
