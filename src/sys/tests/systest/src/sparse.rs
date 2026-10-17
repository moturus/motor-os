//! Sparse lazy reservations: an untouched `F_LAZY` map costs the same at any
//! size, its pages behave as before once touched, and the admission rules
//! still hold at the floor.

use moto_sys::sys_mem::{PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};
use moto_sys::{SysHandle, SysMem, SysObj};

use crate::admission::{DRIFT_TOLERANCE_PAGES, assert_floors_held, assert_recovered};

const GIB: u64 = 1 << 30;
const TIB: u64 = 1 << 40;

fn map_lazy(bytes: u64) -> Result<u64, moto_rt::ErrorCode> {
    SysMem::map(
        SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        bytes >> PAGE_SIZE_SMALL_LOG2,
    )
}

fn used_pages() -> u64 {
    moto_sys::stats::MemoryStats::get().unwrap().used_pages
}

fn touch(addr: u64) {
    unsafe { (addr as *mut u64).write_volatile(addr) }
}

/// 64 GiB and 1 TiB reserved lazily cost a few pages, not a share of their
/// size; a map above the 1 TiB cap is refused; the ends and the middle of
/// each read as zero, keep what is written, and everything comes back on
/// unmap.
fn test_large_reservations() {
    let used_before = used_pages();
    let started = std::time::Instant::now();
    let big = map_lazy(64 * GIB).unwrap();
    let huge = map_lazy(TIB).unwrap();
    let map_time = started.elapsed();
    assert_eq!(
        map_lazy(TIB + PAGE_SIZE_SMALL),
        Err(moto_rt::E_OUT_OF_MEMORY)
    );
    let grown = used_pages().saturating_sub(used_before);
    assert!(
        grown <= DRIFT_TOLERANCE_PAGES,
        "untouched reservations grew the pool by {grown} pages"
    );

    let pages = [
        big,
        big + 32 * GIB,
        big + 64 * GIB - PAGE_SIZE_SMALL,
        huge,
        huge + TIB / 2,
        huge + TIB - PAGE_SIZE_SMALL,
    ];
    for addr in pages {
        assert_eq!(unsafe { (addr as *const u64).read_volatile() }, 0);
        touch(addr);
    }
    for addr in pages {
        assert_eq!(unsafe { (addr as *const u64).read_volatile() }, addr);
    }
    SysMem::free(big).unwrap();
    SysMem::free(huge).unwrap();
    let used_after = used_pages();
    assert!(
        used_after <= used_before + DRIFT_TOLERANCE_PAGES,
        "pool did not recover after unmap: {used_before} -> {used_after} pages used"
    );
    println!("test_sparse_large_reservations PASS: 64 GiB + 1 TiB mapped in {map_time:?}");
}

/// A lazy segment as a share source: refused while any page of the range is
/// untouched, accepted once every page has a frame.
fn test_lazy_share_source() {
    const PAGES: u64 = 8;
    let target =
        SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=sparse-share").unwrap();
    let source = map_lazy(PAGES * PAGE_SIZE_SMALL).unwrap();
    let dest = moto_sys::CUSTOM_USERSPACE_REGION_START;
    let share = || {
        SysMem::map(
            target,
            SysMem::F_SHARE_SELF | SysMem::F_READABLE,
            source,
            dest,
            PAGE_SIZE_SMALL,
            PAGES,
        )
    };
    for idx in (0..PAGES).step_by(2) {
        touch(source + idx * PAGE_SIZE_SMALL);
    }
    assert_eq!(share(), Err(moto_rt::E_INVALID_ARGUMENT));
    for idx in 0..PAGES {
        touch(source + idx * PAGE_SIZE_SMALL);
    }
    assert_eq!(share(), Ok(dest));
    SysMem::unmap(target, 0, u64::MAX, dest).unwrap();
    SysMem::free(source).unwrap();
    SysObj::put(target).unwrap();
    println!("test_sparse_lazy_share_source PASS");
}

/// A process exits with large reservations still mapped and some pages
/// touched; the pool returns once it is gone.
fn test_exit_with_reservations() {
    let used_before = used_pages();
    let mut child = crate::subcommand::spawn();
    child.sparse_exit();
    let status = child.wait().unwrap();
    drop(child);
    assert!(
        status.success(),
        "the child with reservations failed: {status:?}"
    );
    assert_recovered(
        used_before,
        DRIFT_TOLERANCE_PAGES,
        "a child with live reservations exited",
    );
    println!("test_sparse_exit_with_reservations PASS");
}

/// A process holding a large sparse reservation drives the machine to the
/// user floor and then touches more of it: the faulting thread is killed,
/// the kernel stays alive, and the pool comes back.
fn test_fault_at_floor() {
    let used_before = used_pages();
    let mut child = crate::subcommand::spawn();
    child.sparse_fault_at_floor();
    let status = child.wait().unwrap();
    drop(child);
    assert!(
        !status.success(),
        "the process survived sparse faults below the user floor"
    );
    assert_recovered(
        used_before,
        DRIFT_TOLERANCE_PAGES,
        "the sparse aggressor died",
    );
    assert_floors_held();
    println!("test_sparse_fault_at_floor PASS");
}

/// The child side of `test_exit_with_reservations`.
pub fn run_exit_child() -> ! {
    let big = map_lazy(64 * GIB).unwrap();
    let huge = map_lazy(TIB).unwrap();
    for idx in 0..16 {
        touch(big + idx * (64 * GIB / 16));
        touch(huge + idx * (TIB / 16));
    }
    std::process::exit(0);
}

/// The child side of `test_fault_at_floor`. Never returns: it is killed on a
/// refused fault, or it exits zero so the parent's assertion fires.
pub fn run_fault_at_floor_child() -> ! {
    // The reservation costs nothing until touched; its first pages are
    // faulted in while memory is plentiful.
    let lazy = map_lazy(64 * GIB).unwrap();
    for idx in 0..8 {
        touch(lazy + idx * PAGE_SIZE_SMALL);
    }
    // Drain to the user floor: coarsely first, then one page at a time, so
    // that what is left of the band is smaller than a lazy fault's charge.
    while SysMem::alloc(PAGE_SIZE_SMALL, 256).is_ok() {}
    while SysMem::alloc(PAGE_SIZE_SMALL, 1).is_ok() {}
    // Each admitted fault takes one more page; at most a handful succeed
    // before the rest are refused and this thread is killed.
    for idx in 8..(64 * GIB / PAGE_SIZE_SMALL) {
        touch(lazy + idx * PAGE_SIZE_SMALL);
    }
    std::process::exit(0);
}

/// Run after the admission tests: the first pressure event of a boot grows
/// the pool once, by about a thousand pages, and these tests expect it to be
/// steady afterwards.
pub fn run_all_tests() {
    test_large_reservations();
    test_lazy_share_source();
    test_exit_with_reservations();
    test_fault_at_floor();
}
