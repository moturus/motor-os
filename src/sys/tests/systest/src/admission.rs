//! Regressions for the kernel's low-memory admission control.
//! See docs/plans/kernel-oom.md.

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
    test_concurrent_admission();
    test_lazy_fault_at_floor();
}
