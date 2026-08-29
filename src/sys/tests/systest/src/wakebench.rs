//! Cross-thread wake/wait hop microbenchmark (perf run 2026-08-28). Not a
//! test: `systest wake-bench` prints ns per roundtrip for the kernel's three
//! wake shapes under three CPU placements.
use moto_sys::SysHandle;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Separate, // wake(peer); wait()
    Fold,     // wait(wake_target = peer)
    Swap,     // wait(swap_target = peer)
}

fn wake_then_wait(mode: Mode, peer: SysHandle) {
    match mode {
        Mode::Separate => {
            moto_sys::SysCpu::wake(peer).unwrap();
            moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None).unwrap();
        }
        Mode::Fold => {
            moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, peer, None).unwrap();
        }
        Mode::Swap => {
            moto_sys::SysCpu::wait(&mut [], peer, SysHandle::NONE, None).unwrap();
        }
    }
}

fn ping_pong(name: &str, iters: u32, main_cpu: Option<u32>, peer_cpu: Option<u32>, mode: Mode) {
    let peer_handle: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let token: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
    let main_h = moto_sys::current_thread();
    moto_sys::SysCpu::affine_to_cpu(main_cpu).unwrap();

    let peer = {
        let peer_handle = peer_handle.clone();
        let token = token.clone();
        std::thread::spawn(move || {
            moto_sys::SysCpu::affine_to_cpu(peer_cpu).unwrap();
            peer_handle.store(moto_sys::current_thread().as_u64(), Ordering::Release);
            for i in 0..iters {
                while token.load(Ordering::Acquire) != 2 * i + 1 {
                    moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None)
                        .unwrap();
                }
                token.store(2 * i + 2, Ordering::Release);
                if i + 1 < iters {
                    // The pong: wake main, then park for the next ping.
                    // In Swap/Fold modes the wake rides the next wait.
                    if mode == Mode::Separate {
                        moto_sys::SysCpu::wake(main_h).unwrap();
                    }
                } else {
                    moto_sys::SysCpu::wake(main_h).unwrap();
                }
                if i + 1 < iters && mode != Mode::Separate {
                    // Fold/Swap: the wake of main is folded into this wait.
                    while token.load(Ordering::Acquire) != 2 * i + 3 {
                        match mode {
                            Mode::Fold => {
                                moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, main_h, None)
                                    .unwrap()
                            }
                            _ => moto_sys::SysCpu::wait(&mut [], main_h, SysHandle::NONE, None)
                                .unwrap(),
                        }
                    }
                    // Consumed the next ping already; the outer loop's
                    // while-check passes without waiting.
                }
            }
        })
    };

    while peer_handle.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    let peer_h = SysHandle::from(peer_handle.load(Ordering::Acquire));

    let start = std::time::Instant::now();
    for i in 0..iters {
        token.store(2 * i + 1, Ordering::Release);
        wake_then_wait(mode, peer_h);
        while token.load(Ordering::Acquire) != 2 * i + 2 {
            moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, None).unwrap();
        }
    }
    let elapsed = start.elapsed();
    peer.join().unwrap();
    moto_sys::SysCpu::affine_to_cpu(None).unwrap();
    println!(
        "{name:<28} {:>7} ns/roundtrip  {:>6} ns/hop",
        elapsed.as_nanos() as u64 / iters as u64,
        elapsed.as_nanos() as u64 / (2 * iters as u64)
    );
}

pub fn run(_args: &[String]) {
    const ITERS: u32 = 20_000;
    let ncpus = moto_sys::KernelStaticPage::get().num_cpus;
    println!("wake-bench: {ITERS} roundtrips per row, {ncpus} cpus");
    let placements: &[(&str, Option<u32>, Option<u32>)] = if ncpus >= 3 {
        &[
            ("unaffined", None, None),
            ("same cpu (1,1)", Some(1), Some(1)),
            ("diff cpu (1,2)", Some(1), Some(2)),
        ]
    } else {
        &[("unaffined", None, None)]
    };
    for (pname, mc, pc) in placements {
        for (mname, mode) in [
            ("wake+wait", Mode::Separate),
            ("wait(wake_target)", Mode::Fold),
            ("wait(swap_target)", Mode::Swap),
        ] {
            ping_pong(&format!("{pname} {mname}"), ITERS, *mc, *pc, mode);
        }
    }
    println!("wake-bench done");
}
