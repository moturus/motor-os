use std::sync::{atomic::*, Arc};

use moto_sys::SysHandle;

fn test_thread() {
    use std::sync::atomic::AtomicU64;
    let atomic = AtomicU64::new(0);
    let atomic_ref = unsafe { (&atomic as *const AtomicU64).as_ref::<'static>().unwrap() };

    std::thread::spawn(|| {
        atomic_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    })
    .join()
    .unwrap();

    assert_eq!(1, atomic.load(std::sync::atomic::Ordering::Relaxed));
    println!("-- test_thread PASS");
}

fn test_thread_preemption() {
    // Basically, do some cpu-bound stuff and
    // verify that preemption does not mess up registers.
    const THREADS: usize = 8;

    let shutdown = AtomicBool::new(false);
    let shutdown_ref = unsafe {
        (&shutdown as *const AtomicBool)
            .as_ref::<'static>()
            .unwrap()
    };

    let mut handles = Vec::with_capacity(THREADS);

    for _ in 0..THREADS {
        handles.push(std::thread::spawn(|| {
            let mut counter: u64 = 0;
            while !shutdown_ref.load(std::sync::atomic::Ordering::Relaxed) {
                let mut result: u64;
                unsafe {
                    std::arch::asm!(
                                "
                        mov rcx, rax
                        mov rdx, rax
                        mov rsi, rax
                        mov rdi, rax
                        mov r8, rax
                        mov r9, rax
                        mov r10, rax
                        mov r11, rax
                        mov r12, rax
                        mov r13, rax
                        mov r14, rax
                        mov r15, rax

                        add r15, rax
                        add r15, rcx
                        add r15, rdx
                        add r15, rsi
                        add r15, rdi
                        add r15, r8
                        add r15, r9
                        add r15, r10
                        add r15, r11
                        add r15, r12
                        add r15, r13
                        add r15, r14
                        ",
                        in("rax") counter,
                        out("rcx") _,
                        out("rdx") _,
                        out("rsi") _,
                        out("rdi") _,
                        out("r8") _,
                        out("r9") _,
                        out("r10") _,
                        out("r11") _,
                        out("r12") _,
                        out("r13") _,
                        out("r14") _,
                        out("r15") result,
                        options(nomem, nostack)
                    );
                }

                assert_eq!(result, counter * 13);

                counter += 1;
                if counter > 1_000_000_000 {
                    counter = 0;
                }
            }
        }));
    }

    std::thread::sleep(std::time::Duration::from_secs(1));
    shutdown.store(true, Ordering::Release);

    for _ in 0..THREADS {
        let handle = handles.pop().unwrap();
        handle.join().unwrap();
    }
    println!("-- stress_test_threads PASS");
}

fn test_futex() {
    use moto_rt::futex::*;

    let futex = Arc::new(AtomicU32::new(0));
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    const THREADS: u16 = 20;

    COUNTER.store(0, Ordering::Release);
    let mut threads = vec![];

    for _idx in 0..THREADS {
        let futex_clone = futex.clone();
        threads.push(std::thread::spawn(move || {
            while futex_clone
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                futex_wait(futex_clone.as_ref(), 1, None);
            }

            let prev = COUNTER.fetch_add(1, Ordering::Release);
            futex_clone.store(0, Ordering::Relaxed);

            if (prev & 1) == 0 {
                futex_wake(futex_clone.as_ref());
            } else {
                futex_wake_all(futex_clone.as_ref());
            }
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    assert_eq!(THREADS, COUNTER.load(Ordering::Acquire));
    println!("-- test_futex PASS");
}

fn test_futex_timeout() {
    use moto_rt::futex::*;

    let futex = Arc::new(AtomicU32::new(0));

    assert!(!futex_wait(
        futex.as_ref(),
        0,
        Some(std::time::Duration::from_millis(1)),
    ));
    println!("-- test_futex_timeout PASS");
}

fn test_thread_parking() {
    // This is a modified example from https://doc.rust-lang.org/std/thread/fn.park.html.
    let flag = Arc::new(AtomicI32::new(0));
    let flag2 = Arc::clone(&flag);

    let parked_thread = std::thread::spawn(move || {
        std::thread::park();
        flag2.store(1, Ordering::Release);
    });

    std::thread::sleep(std::time::Duration::from_millis(20));
    assert_eq!(0, flag.load(Ordering::Acquire));
    parked_thread.thread().unpark();

    parked_thread.join().unwrap();
    println!("-- test_thread_parking PASS");
}

/// Stress-test wait/wake.
fn test_wait_wake() {
    const NUM_THREADS: usize = 4;

    #[cfg(debug_assertions)]
    const NUM_ITERS: u32 = 10_000;
    #[cfg(not(debug_assertions))]
    const NUM_ITERS: u32 = 100_000;

    let thread_wait_handles: Arc<[AtomicU64; NUM_THREADS]> = Arc::new(Default::default());
    let thread_futexes: Arc<[AtomicU32; NUM_THREADS]> = Arc::new(Default::default());
    let mut thread_join_handles = vec![];

    // Spawn.
    for idx in 0..NUM_THREADS {
        let threads = thread_wait_handles.clone();
        let futexes = thread_futexes.clone();
        thread_join_handles.push(std::thread::spawn(move || {
            threads[idx].store(moto_sys::current_thread().as_u64(), Ordering::Release);

            let futex = &futexes[idx];
            loop {
                let val = futex.load(Ordering::Relaxed);
                if val == NUM_ITERS {
                    break;
                }
                moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None).unwrap();
            }
        }));
    }

    // Wait for the threads to spawn.
    for thread in &*thread_wait_handles {
        while thread.load(Ordering::Relaxed) == 0 {
            core::hint::spin_loop();
        }
    }

    // Wake them multiple times.
    for _ in 0..NUM_ITERS {
        for idx in 0..NUM_THREADS {
            thread_futexes[idx].fetch_add(1, Ordering::Relaxed);
            let _ = moto_sys::SysCpu::wake(thread_wait_handles[idx].load(Ordering::Relaxed).into());
        }
    }

    // Wake one last time.
    for thread in &*thread_wait_handles {
        let _ = moto_sys::SysCpu::wake(thread.load(Ordering::Relaxed).into());
    }

    for thread in thread_join_handles {
        thread.join().unwrap();
    }

    println!("-- test_wait_wake PASS");
}

/// Stress-test futex wait/wake.
fn test_wait_wake_futex() {
    const NUM_THREADS: usize = 4;
    const NUM_ITERS: u32 = 1_000;

    let thread_futexes: Arc<[AtomicU32; NUM_THREADS]> = Arc::new(Default::default());
    let mut thread_join_handles = vec![];

    // Spawn.
    for idx in 0..NUM_THREADS {
        let futexes = thread_futexes.clone();
        thread_join_handles.push(std::thread::spawn(move || {
            let futex = &futexes[idx];
            loop {
                let val = futex.load(Ordering::Acquire);
                if val == NUM_ITERS {
                    break;
                }
                moto_rt::futex_wait(futex, val, None);
            }
        }));
    }

    // Wake.
    for _ in 0..NUM_ITERS {
        for futex in &*thread_futexes {
            futex.fetch_add(1, Ordering::Relaxed);
            moto_rt::futex_wake(futex);
        }
        std::thread::sleep(std::time::Duration::from_micros(2));
    }

    for thread in thread_join_handles {
        thread.join().unwrap();
    }

    println!("-- test_wait_wake_futex PASS");
}

pub fn run_all_tests() {
    test_thread();
    test_thread_preemption();
    test_thread_parking();
    test_futex();
    test_futex_timeout();
    test_wait_wake();
    test_wait_wake_futex();
    println!("threads: ALL PASS");
}
