//! Regressions for the kernel's mapping accounting and reclamation.

use moto_sys::SysMem;
use moto_sys::sys_mem::{PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};

/// Concurrent system activity (sys-io, sshd, the logger) moves the pool while
/// these tests run; allow it this much slack where an exact figure is not the
/// invariant under test.
pub(crate) const DRIFT_TOLERANCE_PAGES: u64 = 256; // 1M.

/// A kernel metric at a PID scope; the kernel's own per-CPU counters live
/// under `PID_KERNEL`.
pub(crate) fn kernel_metric_at(name: &str, scope: u64) -> u64 {
    use moto_sdk::stats::Collector;

    let kernel = Collector::kernel();
    let descs = Collector::describe(&kernel).unwrap();
    let desc = descs
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("no kernel metric '{name}'"));
    Collector::read(&kernel, desc.id, scope)
        .unwrap_or_else(|err| panic!("kernel metric '{name}' at scope {scope}: {err:?}"))
}

pub(crate) fn used_pages() -> u64 {
    moto_sys::stats::MemoryStats::get().unwrap().used_pages
}

/// Wait for the pool to come back to `expected` pages, within `tolerance`,
/// then verify that filesystem service still works.
pub(crate) fn assert_recovered(expected: u64, tolerance: u64, after_what: &str) {
    const MAX_WAITS: u32 = 300;
    let wait = || std::thread::sleep(std::time::Duration::from_millis(50));

    let mut waits = 0;
    let mut used_after = used_pages();
    while used_after > expected + tolerance && waits < MAX_WAITS {
        wait();
        waits += 1;
        used_after = used_pages();
    }
    assert!(
        used_after <= expected + tolerance,
        "pool did not recover after {after_what}: {used_after} pages used, {expected} + {tolerance} allowed"
    );

    let mut fs_probe = std::fs::metadata("/system/cfg/sys-init.cfg");
    while fs_probe.is_err() && waits < MAX_WAITS {
        wait();
        waits += 1;
        fs_probe = std::fs::metadata("/system/cfg/sys-init.cfg");
    }
    assert!(
        fs_probe
            .expect("sys-io stopped serving FS requests")
            .is_file(),
        "sys-io did not keep serving after {after_what}"
    );
}

/// Map around slab and page-table boundaries, then check reclamation.
fn test_mapping_boundaries() {
    const SIZES: [u64; 16] = [
        1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513,
    ];

    let one_pass = || {
        for size in SIZES {
            let addr = SysMem::alloc(PAGE_SIZE_SMALL, size).unwrap();
            for idx in 0..size {
                unsafe { ((addr + (idx << PAGE_SIZE_SMALL_LOG2)) as *mut u8).write_volatile(1) };
            }
            SysMem::free(addr).unwrap();
        }
    };

    one_pass();
    let used_before = used_pages();
    one_pass();
    let used_after = used_pages();
    assert!(
        used_after <= used_before + DRIFT_TOLERANCE_PAGES,
        "pool drifted across warm boundary mappings: {used_before} -> {used_after} pages used"
    );

    println!("test_mapping_boundaries PASS");
}

pub fn run_all_tests() {
    test_mapping_boundaries();
    test_frame_churn();
}
/// Concurrent alloc/touch/free churn: several threads drive the kernel frame
/// slab across the full<->partial boundary at once. Regression for
/// partial-list membership races (a slab pushed while still listed would
/// link the list into a cycle and hang allocation), and for reservation races
/// at the full boundary (all bitmap slots claimed while the count lagged).
fn test_frame_churn() {
    const THREADS: u64 = 4;
    const ITERS: usize = 512;
    const MAX_PAGES: u64 = 512; // 2M per allocation.
    const MAX_HELD: usize = 4;

    let mut workers = vec![];
    for t in 0..THREADS {
        workers.push(std::thread::spawn(move || {
            let mut seed = (t + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut held = std::collections::VecDeque::new();
            for _ in 0..ITERS {
                // xorshift64: cheap per-thread jitter in allocation sizes.
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let pages = 1 + seed % MAX_PAGES;

                match SysMem::alloc(PAGE_SIZE_SMALL, pages) {
                    Ok(addr) => held.push_back(addr),
                    Err(err) => {
                        assert_eq!(err, moto_rt::E_OUT_OF_MEMORY);
                        while let Some(addr) = held.pop_front() {
                            SysMem::free(addr).unwrap();
                        }
                        continue;
                    }
                }

                // Touch every page so a physical frame is committed even if
                // the mapping is lazy.
                let addr = *held.back().unwrap();
                for page in 0..pages {
                    unsafe {
                        ((addr + page * PAGE_SIZE_SMALL) as *mut u64).write_volatile(page);
                    }
                }

                // Free oldest-first so frees land in older, fuller slabs
                // while allocations fill newer ones.
                if held.len() > MAX_HELD {
                    SysMem::free(held.pop_front().unwrap()).unwrap();
                }
            }
            while let Some(addr) = held.pop_front() {
                SysMem::free(addr).unwrap();
            }
        }));
    }

    for worker in workers {
        worker.join().unwrap();
    }
    println!("test_frame_churn PASS");
}
