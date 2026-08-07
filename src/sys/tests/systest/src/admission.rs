//! Regressions for the kernel's low-memory admission control.

use std::sync::Arc;
use std::sync::Barrier;

use moto_sys::SysMem;
use moto_sys::sys_mem::{PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};

/// Concurrent system activity (sys-io, sshd, the logger) moves the pool while
/// these tests run; allow it this much slack where an exact figure is not the
/// invariant under test.
const DRIFT_TOLERANCE_PAGES: u64 = 256; // 1M.

/// Reads a system-wide kernel metric by name. Metric ids are provider-private,
/// so nothing here is hardcoded to a number.
fn kernel_metric(name: &str) -> u64 {
    use moto_stats::Collector;

    let kernel = Collector::kernel();
    let descs = Collector::describe(&kernel).unwrap();
    let desc = descs
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("no kernel metric '{name}'"));
    Collector::query(&kernel)
        .unwrap()
        .iter()
        .find(|e| e.metric == desc.id && e.scope == moto_stats::SCOPE_GLOBAL)
        .map(|e| e.value)
        .unwrap_or_else(|| panic!("kernel metric '{name}' not reported"))
}

fn used_pages() -> u64 {
    moto_sys::stats::MemoryStats::get().unwrap().used_pages
}

/// An upper bound on free small pages: total RAM counts the mid-page region,
/// which the small-page pool does not own. Used only to size a request that
/// must be refused, never as an assertion.
fn free_pages_upper_bound() -> u64 {
    let stats = moto_sys::stats::MemoryStats::get().unwrap();
    (stats.available >> PAGE_SIZE_SMALL_LOG2) - stats.used_pages
}

/// Every admitted operation releases its reservation when it completes, so an
/// idle system settles at zero. A leaked guard never does.
fn assert_reservations_drain() {
    for _ in 0..100 {
        if kernel_metric("mem.admission_reserved_pages") == 0 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!(
        "admission reservations never drained: {} pages",
        kernel_metric("mem.admission_reserved_pages")
    );
}

/// The guard band held: the pool never came near empty.
fn assert_floors_held() {
    let low_water = kernel_metric("mem.small_pages_low_water");
    let sys_io_floor = kernel_metric("mem.sys_io_floor_pages");
    let user_floor = kernel_metric("mem.user_floor_pages");

    assert!(
        user_floor > sys_io_floor,
        "floors not ordered: user {user_floor}, sys-io {sys_io_floor}"
    );
    assert!(
        low_water >= sys_io_floor,
        "small-page low water {low_water} crossed the sys-io floor {sys_io_floor}"
    );

    // The stronger form: the allocator's true minimum, which unlike the
    // admission-check figure includes allocations made outside admission
    // windows. These tests drain to the *user* floor, so requiring the
    // minimum to stay above the sys-io floor demands that all overlapping
    // unadmitted work fit within the band between the floors -- the exact
    // property the floor sizing rests on.
    let phys_low = kernel_metric("mem.phys_small_pages_low_water");
    assert!(
        phys_low >= sys_io_floor,
        "phys low water {phys_low} crossed the sys-io floor {sys_io_floor}: \
         overlapping kernel work exceeded the floor band"
    );
}

/// The admission-stats query reports the same quantities the kernel's metrics
/// expose, exactly for the pool admission guards -- what sys-io's pressure
/// watermarks are compared against.
fn test_admission_stats_query() {
    let stats = moto_sys::stats::AdmissionStats::get().unwrap();

    assert_eq!(
        stats.user_floor_pages,
        kernel_metric("mem.user_floor_pages")
    );
    assert_eq!(
        stats.sys_io_floor_pages,
        kernel_metric("mem.sys_io_floor_pages")
    );

    // MemoryStats-derived free pages count the mid-page region too, so they
    // bound the small-page pool from above (modulo concurrent activity).
    assert!(
        stats.available_small_pages <= free_pages_upper_bound() + DRIFT_TOLERANCE_PAGES,
        "available_small_pages {} above the MemoryStats bound",
        stats.available_small_pages
    );

    // The pressure watermarks sit strictly between the user floor and total
    // memory, with the hysteresis gap between them.
    assert!(
        stats.pressure_low_pages > stats.user_floor_pages
            && stats.pressure_high_pages > stats.pressure_low_pages,
        "bad pressure watermarks: {stats:?}"
    );

    // A quiescent VM sits far above the floors, with reservations drained
    // and no pressure signaled.
    assert!(
        stats.free_for_admission() > stats.pressure_high_pages,
        "no admission headroom on an idle VM: {stats:?}"
    );
    assert!(!moto_sys::memory_pressure());

    println!("test_admission_stats_query PASS");
}

/// One eager mapping that would cross the user floor is refused with
/// E_OUT_OF_MEMORY, not a kernel panic; refusal has no side effects, and
/// repeating it does not drift the pool downward.
fn test_oversized_mapping_refused() {
    let refused_before = kernel_metric("mem.admission_refused_user");
    let used_before = used_pages();

    for _ in 0..3 {
        assert_eq!(
            SysMem::alloc(PAGE_SIZE_SMALL, free_pages_upper_bound()).err(),
            Some(moto_rt::E_OUT_OF_MEMORY)
        );
    }

    let refusals = kernel_metric("mem.admission_refused_user") - refused_before;
    assert!(refusals >= 3, "only {refusals} refusals counted");

    let used_after = used_pages();
    assert!(
        used_after <= used_before + DRIFT_TOLERANCE_PAGES,
        "pool drifted on refusal: {used_before} -> {used_after} pages used"
    );

    assert_reservations_drain();
    assert_floors_held();
    println!("test_oversized_mapping_refused PASS");
}

/// The same request issued simultaneously on every configured CPU: admission
/// is atomic, so all of them are refused rather than all passing a sampled
/// check and then draining the pool together.
fn test_concurrent_admission() {
    let num_cpus = moto_sys::num_cpus() as usize;
    let barrier = Arc::new(Barrier::new(num_cpus));

    let threads: Vec<_> = (0..num_cpus)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let pages = free_pages_upper_bound();
                barrier.wait();
                SysMem::alloc(PAGE_SIZE_SMALL, pages).err()
            })
        })
        .collect();

    for thread in threads {
        assert_eq!(thread.join().unwrap(), Some(moto_rt::E_OUT_OF_MEMORY));
    }

    assert_reservations_drain();
    assert_floors_held();
    println!("test_concurrent_admission PASS");
}

/// A process that drives the machine to the user floor and then touches a new
/// lazy page: the faulting thread is killed (a fault cannot return an error to
/// the faulting instruction), while the kernel stays alive, sys-io keeps
/// serving, and the pool stays above the floors.
fn test_lazy_fault_at_floor() {
    // While the aggressor pins the pool at the user floor, this process cannot
    // grow its heap either, and a refused global allocation aborts it. So the
    // parent only waits, then releases the child's address space -- a dead
    // process owns it until the last handle is closed -- before asserting
    // anything, because assertions allocate.
    let used_before = used_pages();

    let mut child = crate::subcommand::spawn();
    child.lazy_fault_at_floor();
    let status = child.wait().unwrap();
    drop(child);

    assert!(
        !status.success(),
        "the process survived lazy faults below the user floor"
    );
    assert_floors_held();

    // sys-io kept serving, and the pool is fully back.
    assert!(
        std::fs::metadata("/sys/cfg/sys-init.cfg")
            .unwrap()
            .is_file()
    );
    let used_after = used_pages();
    assert!(
        used_after <= used_before + DRIFT_TOLERANCE_PAGES,
        "pool did not recover after the aggressor died: {used_before} -> {used_after} pages used"
    );
    let addr = SysMem::alloc(PAGE_SIZE_SMALL, 16).unwrap();
    SysMem::free(addr).unwrap();

    println!("test_lazy_fault_at_floor PASS");
}

/// Eager mappings at sizes that straddle metadata-slab and page-table
/// boundaries, where a single extra page can pull in a whole new slab -- the
/// case the flat part of the admission charge covers. The first pass may grow
/// the global slabs permanently (they are never freed), so it only warms them;
/// the second pass must be steady state: no drift, reservations drained,
/// floors held.
fn test_charge_boundaries() {
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

    assert_reservations_drain();
    assert_floors_held();
    println!("test_charge_boundaries PASS");
}

/// Lazy faults on every configured CPU at once, near the user floor:
/// concurrent per-fault admissions race each other and the kernel's unadmitted
/// bookkeeping. The child dies -- a refused fault kills the process -- while
/// the kernel and sys-io stay alive and the pool recovers. Prints the
/// floor-sizing measurements.
fn test_all_cpu_fault_storm() {
    let used_before = used_pages();

    let mut child = crate::subcommand::spawn();
    child.fault_storm();
    let status = child.wait().unwrap();
    drop(child);

    assert!(
        !status.success(),
        "the process survived an all-CPU fault storm below the user floor"
    );
    assert_floors_held();

    // sys-io kept serving, and the pool is fully back.
    assert!(
        std::fs::metadata("/sys/cfg/sys-init.cfg")
            .unwrap()
            .is_file()
    );
    let used_after = used_pages();
    assert!(
        used_after <= used_before + DRIFT_TOLERANCE_PAGES,
        "pool did not recover after the fault storm: {used_before} -> {used_after} pages used"
    );
    assert_reservations_drain();

    // The deepest points reached so far in this run. The overlap -- how far
    // below the user floor unadmitted work pushed actual free pages -- is the
    // measured input to the floor sizing.
    let user_floor = kernel_metric("mem.user_floor_pages");
    let check_low = kernel_metric("mem.small_pages_low_water");
    let phys_low = kernel_metric("mem.phys_small_pages_low_water");
    println!(
        "fault storm measurements: user floor {user_floor}, admission-check low water \
         {check_low}, phys low water {phys_low}, overlap {} pages ({} CPUs)",
        user_floor.saturating_sub(phys_low),
        moto_sys::num_cpus(),
    );

    println!("test_all_cpu_fault_storm PASS");
}

/// The child side of `test_all_cpu_fault_storm`. Threads and lazy regions are
/// created while memory is plentiful; the drain then stops with headroom above
/// the user floor, so the storm sees both outcomes: faults admitted
/// concurrently on every CPU while the headroom lasts, refusals once it is
/// gone. Each region alone exceeds the headroom, so refusal -- and death -- is
/// certain even if one thread outruns the rest. Never returns.
pub fn run_fault_storm_child() -> ! {
    const PAGES_PER_THREAD: u64 = 1024;
    const HEADROOM_PAGES: u64 = 512;
    let num_cpus = moto_sys::num_cpus() as usize;

    let map_lazy = || {
        SysMem::map(
            moto_sys::SysHandle::SELF,
            SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
            u64::MAX,
            u64::MAX,
            PAGE_SIZE_SMALL,
            PAGES_PER_THREAD,
        )
        .unwrap()
    };
    let fault_all = |region: u64| {
        for idx in 0..PAGES_PER_THREAD {
            unsafe { ((region + (idx << PAGE_SIZE_SMALL_LOG2)) as *mut u8).write_volatile(1) };
        }
    };

    let barrier = Arc::new(Barrier::new(num_cpus));
    let mut threads = Vec::new();
    for _ in 1..num_cpus {
        let region = map_lazy();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            fault_all(region);
        }));
    }
    let main_region = map_lazy();

    // Drain to the user floor plus headroom. Nothing below allocates heap:
    // the stats query fills a stack struct, and the mapped pages are leaked
    // deliberately -- this process is about to die anyway.
    let free = || {
        moto_sys::stats::AdmissionStats::get()
            .unwrap()
            .free_for_admission()
    };
    let target = moto_sys::stats::AdmissionStats::get()
        .unwrap()
        .user_floor_pages
        + HEADROOM_PAGES;
    while free() > target + 256 && SysMem::alloc(PAGE_SIZE_SMALL, 256).is_ok() {}
    while free() > target && SysMem::alloc(PAGE_SIZE_SMALL, 8).is_ok() {}

    barrier.wait();
    fault_all(main_region);

    // Unreachable unless every fault on every CPU was admitted, which the
    // sizing above rules out; exit zero so the parent's assertion fires.
    std::process::exit(0);
}

/// The child side of `test_lazy_fault_at_floor`. Never returns: it is either
/// killed on a refused fault, or it exits zero so the parent's assertion fires.
pub fn run_lazy_fault_at_floor_child() -> ! {
    // Reserve lazily while memory is still plentiful: the mapping must exist
    // before the pool is drained.
    const LAZY_PAGES: u64 = 1024;
    let lazy = SysMem::map(
        moto_sys::SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        LAZY_PAGES,
    )
    .unwrap();

    // Drain to the user floor: coarsely first, then one page at a time, so
    // that what is left of the band is smaller than a lazy fault's charge.
    while SysMem::alloc(PAGE_SIZE_SMALL, 256).is_ok() {}
    while SysMem::alloc(PAGE_SIZE_SMALL, 1).is_ok() {}

    // Each fault that is admitted takes one more page, so at most a handful
    // can succeed before the rest are refused and this thread is killed.
    for idx in 0..LAZY_PAGES {
        unsafe { ((lazy + (idx << PAGE_SIZE_SMALL_LOG2)) as *mut u8).write_volatile(1) };
    }

    std::process::exit(0);
}

pub fn run_all_tests() {
    test_admission_stats_query();
    test_oversized_mapping_refused();
    test_charge_boundaries();
    test_concurrent_admission();
    test_lazy_fault_at_floor();
    test_all_cpu_fault_storm();
}
