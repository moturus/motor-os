use moto_sys::{SysCpu, SysHandle, SysObj};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

fn test_wait_set(size: usize) {
    const ROUNDS: usize = 256;
    let pairs: Vec<_> = (0..size)
        .map(|_| SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap())
        .collect();
    let (idle_peer, idle) = SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();
    let phase = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let workers = size.min(4);
    let threads: Vec<_> = (0..workers)
        .map(|worker| {
            let phase = phase.clone();
            let completed = completed.clone();
            let peers: Vec<_> = pairs
                .iter()
                .skip(worker)
                .step_by(workers)
                .map(|p| p.0)
                .collect();
            std::thread::spawn(move || {
                for generation in 1..=2 * ROUNDS {
                    while phase.load(Ordering::Acquire) < generation {
                        std::hint::spin_loop();
                    }
                    for peer in &peers {
                        SysCpu::wake(*peer).unwrap();
                    }
                    completed.fetch_add(1, Ordering::Release);
                }
            })
        })
        .collect();

    for generation in 1..=2 * ROUNDS {
        let deadline = moto_rt::time::Instant::now() + Duration::from_secs(5);
        let mut pending: Vec<_> = pairs.iter().map(|p| p.1).collect();
        phase.store(generation, Ordering::Release);
        if generation % 2 == 0 {
            // After delivering one generation, leave its late notifications queued
            // while fresh wakes arrive. An unrelated wait must not acknowledge them.
            while completed.load(Ordering::Acquire) < generation * workers {
                assert!(moto_rt::time::Instant::now() < deadline);
                std::hint::spin_loop();
            }
            let mut unrelated = [idle];
            let probe = if generation % 4 == 0 {
                &mut unrelated[..]
            } else {
                &mut []
            };
            let timeout = if generation % 8 < 4 {
                SysCpu::wake(moto_sys::current_thread()).unwrap();
                deadline
            } else {
                moto_rt::time::Instant::nan()
            };
            SysCpu::wait(probe, SysHandle::NONE, SysHandle::NONE, Some(timeout)).unwrap();
            assert!(probe.iter().all(|h| *h == SysHandle::NONE));
        }
        while !pending.is_empty() {
            let mut handles = pending.clone();
            SysCpu::wait(
                &mut handles,
                SysHandle::NONE,
                SysHandle::NONE,
                Some(deadline),
            )
            .unwrap_or_else(|err| {
                panic!(
                    "wait set {size}, generation {generation}: lost wakes {pending:?}, error {err}"
                )
            });
            for handle in handles.into_iter().take_while(|h| *h != SysHandle::NONE) {
                let index = pending
                    .iter()
                    .position(|h| *h == handle)
                    .expect("wait returned an unrequested handle");
                pending.swap_remove(index);
            }
        }
        while completed.load(Ordering::Acquire) < generation * workers {
            assert!(moto_rt::time::Instant::now() < deadline);
            std::hint::spin_loop();
        }
    }

    for thread in threads {
        thread.join().unwrap();
    }
    for (peer, handle) in pairs {
        SysObj::put(peer).unwrap();
        SysObj::put(handle).unwrap();
    }
    SysObj::put(idle_peer).unwrap();
    SysObj::put(idle).unwrap();
    println!("wait set {size} PASS");
}

pub fn run_all_tests() {
    // Register and array ABIs, inline/spilled handle storage, and waker storage.
    for size in [1, 6, 7, 17, 32] {
        test_wait_set(size);
    }
    println!("wait-set tests PASS");
}
