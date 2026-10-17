//! Sparse lazy reservations: an untouched `F_LAZY` map costs the same at any
//! size, its pages behave as before once touched, and the admission rules
//! still hold at the floor.

use moto_sys::sys_mem::{PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};
use moto_sys::{SysHandle, SysMem, SysObj};

use moto_sys::stats::PID_KERNEL;

use crate::admission::{
    DRIFT_TOLERANCE_PAGES, assert_floors_held, assert_recovered, kernel_metric_at,
};

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

/// A shared allocation at a fixed address whose second reservation fails is
/// undone under the region lock. A thread that unmaps that address and maps
/// its own segment there, as fast as it can, never loses the mapping to the
/// rollback: once its map succeeds, the mapping is there to unmap. The
/// address is in an address space of this process's own, where nothing
/// else maps; this process's normal region is filled so that the second
/// reservation finds no room, and a gap the runtime frees there in the
/// meantime is kept mapped once found, so the next call fails again.
fn test_shared_alloc_rollback_race() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    const PAGES: u64 = 16;
    const ROUNDS: u32 = 20_000;
    const HOLE: u64 = 1 << 40;
    const MAX_STRAYS: usize = 256;

    let used_before = used_pages();
    let target =
        SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=sparse-race").unwrap();
    // What the mapper shares into the hole: its frames exist from the start.
    let source = SysMem::alloc(PAGE_SIZE_SMALL, PAGES).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Barrier::new(3));
    let go = Arc::new(Barrier::new(3));

    // Both threads are up before the normal region is filled: their stacks
    // need address space, and nothing they do below allocates any.
    let sharer = {
        let (done, ready, go) = (done.clone(), ready.clone(), go.clone());
        std::thread::spawn(move || {
            ready.wait();
            go.wait();
            let (mut strays, mut stray_count) = ([0_u64; MAX_STRAYS], 0_usize);
            let mut refused = 0_u32;
            for _ in 0..ROUNDS {
                // The target side takes the hole, the caller's side finds
                // no room, and the whole call is undone; or the hole is the
                // mapper's for the moment and the call is refused at once.
                match SysMem::map2(
                    target,
                    SysMem::F_SHARE_SELF | SysMem::F_READABLE | SysMem::F_WRITABLE,
                    u64::MAX,
                    HOLE,
                    PAGE_SIZE_SMALL,
                    PAGES,
                ) {
                    Err(moto_rt::E_OUT_OF_MEMORY) => refused += 1,
                    // The caller's side found a gap the runtime freed: keep
                    // it, so the next call fails again. The mapper takes
                    // the hole back, as it does with anything there.
                    Ok((here, there)) => {
                        assert_eq!(here, HOLE);
                        assert!(stray_count < MAX_STRAYS, "too many stray gaps");
                        strays[stray_count] = there;
                        stray_count += 1;
                    }
                    Err(err) => panic!("shared map failed with {err:?}"),
                }
            }
            done.store(true, Ordering::Release);
            (refused, strays, stray_count)
        })
    };
    let mapper = {
        let (done, ready, go) = (done.clone(), ready.clone(), go.clone());
        std::thread::spawn(move || {
            ready.wait();
            go.wait();
            let (mut rounds, mut misses) = (0_u64, 0_u64);
            while !done.load(Ordering::Acquire) {
                // Whatever is at the hole goes, as the scenario demands:
                // nothing, or what the sharer left there.
                let _ = SysMem::unmap(target, 0, u64::MAX, HOLE);
                let mapped = SysMem::map(
                    target,
                    SysMem::F_SHARE_SELF | SysMem::F_READABLE,
                    source,
                    HOLE,
                    PAGE_SIZE_SMALL,
                    PAGES,
                );
                if mapped.is_err() {
                    misses += 1;
                    continue;
                }
                SysMem::unmap(target, 0, u64::MAX, HOLE)
                    .expect("the mapper's mapping was taken by a rollback");
                rounds += 1;
            }
            (rounds, misses)
        })
    };
    ready.wait();

    // Fill the normal region with lazy reservations, cheap now, until
    // nothing of PAGES fits.
    let mut fillers: Vec<u64> = Vec::with_capacity(1024);
    let mut pages = 1_u64 << 28;
    while pages >= PAGES {
        match map_lazy(pages * PAGE_SIZE_SMALL) {
            Ok(addr) => fillers.push(addr),
            Err(_) => pages >>= 1,
        }
    }

    go.wait();
    let (refused, strays, stray_count) = sharer.join().unwrap();
    let (rounds, misses) = mapper.join().unwrap();
    let _ = SysMem::unmap(target, 0, u64::MAX, HOLE);
    for addr in strays.iter().take(stray_count).chain(fillers.iter()) {
        SysMem::free(*addr).unwrap();
    }
    SysMem::free(source).unwrap();
    SysObj::put(target).unwrap();
    assert!(rounds > 0, "the mapper never mapped");
    assert!(refused > 0, "no shared allocation was ever undone");
    assert_recovered(used_before, DRIFT_TOLERANCE_PAGES, "the rollback race");
    println!(
        "test_sparse_shared_alloc_rollback_race PASS: {rounds} maps and {misses} misses \
         against {refused} refused shared allocations, {stray_count} stray gaps"
    );
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
/// the kernel stays alive, and the pool comes back. The child reports each
/// phase on its stdout, so a death before the fault phase, whatever its
/// cause, fails here rather than passing as the kill under test.
fn test_fault_at_floor() {
    use std::io::Read;
    let refused_before = kernel_metric_at("mem.admission_refused_user", PID_KERNEL);
    let used_before = used_pages();
    let mut child = crate::subcommand::spawn();
    child.sparse_fault_at_floor();
    let status = child.wait().unwrap();
    let mut stdout = child.std_child().stdout.take().unwrap();
    drop(child);
    // Nothing allocates until the pool is back; see `assert_recovered`.
    assert_recovered(
        used_before,
        DRIFT_TOLERANCE_PAGES,
        "the sparse aggressor died",
    );

    let mut phases = String::new();
    stdout.read_to_string(&mut phases).unwrap();
    assert_eq!(
        phases, "setup\ndrained\n",
        "the child did not reach the fault phase"
    );
    // A kernel kill, not an exit or an abort of the child's own.
    assert_eq!(
        status.code(),
        Some(-1),
        "not killed by the kernel: {status:?}"
    );
    // Two refusals end the drain loops; the killing fault is at least one more.
    let refusals = kernel_metric_at("mem.admission_refused_user", PID_KERNEL) - refused_before;
    assert!(
        refusals >= 3,
        "{refusals} refusals, expected the drains' two and a fault's"
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
/// refused fault, or it exits zero so the parent's assertion fires. Each
/// phase is reported with a static line; the first one, written while
/// memory is plentiful, is what allocates stdout's buffer.
pub fn run_fault_at_floor_child() -> ! {
    use std::io::Write;
    let mut stdout = std::io::stdout();
    // The reservation costs nothing until touched; its first pages are
    // faulted in while memory is plentiful.
    let lazy = map_lazy(64 * GIB).unwrap();
    for idx in 0..8 {
        touch(lazy + idx * PAGE_SIZE_SMALL);
    }
    stdout.write_all(b"setup\n").unwrap();
    stdout.flush().unwrap();
    // Drain to the user floor: coarsely first, then one page at a time, so
    // that what is left of the band is smaller than a lazy fault's charge.
    while SysMem::alloc(PAGE_SIZE_SMALL, 256).is_ok() {}
    while SysMem::alloc(PAGE_SIZE_SMALL, 1).is_ok() {}
    stdout.write_all(b"drained\n").unwrap();
    stdout.flush().unwrap();
    // Each admitted fault takes one more page; at most a handful succeed
    // before the rest are refused and this thread is killed.
    for idx in 8..(64 * GIB / PAGE_SIZE_SMALL) {
        touch(lazy + idx * PAGE_SIZE_SMALL);
    }
    std::process::exit(0);
}

/// The first pressure event of a boot grows the pool once, by about a
/// thousand pages, and the floor test expects it to be steady afterwards.
/// An OOM child, like `test_oom` in the full suite, absorbs it, cheaply
/// when it has happened already.
fn warm_up_pool() {
    let mut child = crate::subcommand::spawn();
    child.oom();
    assert!(!child.wait().unwrap().success());
}

pub fn run_all_tests() {
    warm_up_pool();
    test_large_reservations();
    test_lazy_share_source();
    test_shared_alloc_rollback_race();
    test_exit_with_reservations();
    test_fault_at_floor();
}
