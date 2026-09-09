//! Allocator profiler. Not a test: `systest alloc-bench` prints per-workload
//! timings for the process allocator, the same workloads the host harness in
//! docs/plans/frusa.md §3.2 uses, so the vDSO allocator can be compared
//! across builds on Motor itself.
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::time::Instant;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn size(&mut self) -> usize {
        4096 >> (self.next() % 9)
    }
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// A retained population of 64-byte objects: churn on its oldest slot,
/// then free everything in insertion or random order.
fn retained(live: usize, random_free: bool) {
    let layout = Layout::from_size_align(64, 8).unwrap();
    let mut ptrs = Vec::with_capacity(live);
    let t = Instant::now();
    for _ in 0..live {
        let p = unsafe { System.alloc(layout) };
        assert!(!p.is_null());
        unsafe { p.write(1) };
        ptrs.push(p);
    }
    let populate = t.elapsed();
    let t = Instant::now();
    for _ in 0..10_000 {
        unsafe { System.dealloc(ptrs[0], layout) };
        ptrs[0] = unsafe { System.alloc(layout) };
        assert!(!ptrs[0].is_null());
        black_box(&ptrs);
    }
    let churn = t.elapsed();
    if random_free {
        let mut r = Rng(0x9E3779B97F4A7C15);
        for i in (1..ptrs.len()).rev() {
            let j = (r.next() % (i as u64 + 1)) as usize;
            ptrs.swap(i, j);
        }
    }
    let t = Instant::now();
    for p in ptrs {
        unsafe { System.dealloc(p, layout) };
    }
    let free = t.elapsed();
    println!(
        "retained live={live:<6} order={:<6} populate={:>9.3}ms churn10k={:>9.3}ms free_all={:>9.3}ms",
        if random_free { "random" } else { "insert" },
        ms(populate),
        ms(churn),
        ms(free)
    );
}

/// Immediate alloc/free of random sizes up to 4 KiB on `threads` threads.
fn immediate(threads: usize, steps: usize) {
    let t = Instant::now();
    let hs: Vec<_> = (0..threads)
        .map(|i| {
            std::thread::spawn(move || {
                let mut r = Rng(0x1234_5678_9abc_def1 ^ (i as u64 + 1) * 0x9E37);
                for _ in 0..steps {
                    let l = Layout::from_size_align(r.size(), 8).unwrap();
                    let p = unsafe { System.alloc(l) };
                    assert!(!p.is_null());
                    unsafe { p.write(1) };
                    black_box(p);
                    unsafe { System.dealloc(p, l) };
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let ns = t.elapsed().as_nanos() as f64;
    println!(
        "immediate threads={threads} {:>8.1} ns/op per thread, {:>7.2} Mops/s total",
        ns / steps as f64,
        (steps * threads) as f64 * 1e3 / ns
    );
}

/// Each thread keeps `ring` live objects of random sizes and replaces a
/// random one per step.
fn ring(threads: usize, ring: usize, steps: usize) {
    let t = Instant::now();
    let hs: Vec<_> = (0..threads)
        .map(|i| {
            std::thread::spawn(move || {
                let mut r = Rng(0xdead_beef_cafe_f00d ^ (i as u64 + 1) * 0x9E37);
                let mut slots: Vec<(*mut u8, Layout)> = (0..ring)
                    .map(|_| {
                        let l = Layout::from_size_align(r.size(), 8).unwrap();
                        let p = unsafe { System.alloc(l) };
                        assert!(!p.is_null());
                        unsafe { p.write(1) };
                        (p, l)
                    })
                    .collect();
                for _ in 0..steps {
                    let k = (r.next() % ring as u64) as usize;
                    let (p, l) = slots[k];
                    unsafe { System.dealloc(p, l) };
                    let l = Layout::from_size_align(r.size(), 8).unwrap();
                    let p = unsafe { System.alloc(l) };
                    assert!(!p.is_null());
                    unsafe { p.write(1) };
                    slots[k] = (p, l);
                }
                for (p, l) in slots {
                    unsafe { System.dealloc(p, l) };
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    let ns = t.elapsed().as_nanos() as f64;
    println!(
        "ring threads={threads} live/thread={ring} {:>8.1} ns/op per thread, {:>7.2} Mops/s total",
        ns / steps as f64,
        (steps * threads) as f64 * 1e3 / ns
    );
}

/// One thread allocates and hands batches to another that frees them.
fn cross_thread(steps: usize) {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<(usize, Layout)>>(64);
    let t = Instant::now();
    let producer = std::thread::spawn(move || {
        let mut r = Rng(0x0bad_5eed_0bad_5eed);
        let mut batch = Vec::with_capacity(1024);
        for i in 0..steps {
            let l = Layout::from_size_align(r.size(), 8).unwrap();
            let p = unsafe { System.alloc(l) };
            assert!(!p.is_null());
            unsafe { p.write(1) };
            batch.push((p as usize, l));
            if batch.len() == 1024 || i + 1 == steps {
                tx.send(std::mem::replace(&mut batch, Vec::with_capacity(1024)))
                    .unwrap();
            }
        }
    });
    let consumer = std::thread::spawn(move || {
        for batch in rx {
            for (p, l) in batch {
                unsafe { System.dealloc(p as *mut u8, l) };
            }
        }
    });
    producer.join().unwrap();
    consumer.join().unwrap();
    let ns = t.elapsed().as_nanos() as f64;
    println!(
        "cross-thread producer/consumer {:>8.1} ns per alloc+free pair",
        ns / steps as f64
    );
}

pub fn run() {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!("alloc-bench: {cpus} cpus");
    for live in [16_384usize, 65_536] {
        retained(live, false);
    }
    retained(65_536, true);
    for t in [1usize, 2, cpus] {
        immediate(t, 500_000);
    }
    for t in [1usize, cpus] {
        ring(t, 4096, 300_000);
    }
    cross_thread(500_000);
    println!("alloc-bench: done");
}
