//! Sparse lazy reservations: an untouched `F_LAZY` map costs the same at any
//! size, its pages behave as before once touched, and the admission rules
//! still hold at the floor.

use moto_sys::sys_mem::{PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};
use moto_sys::syscalls::do_syscall;
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

fn map_guarded(pages: u64, lazy: bool) -> Result<(u64, u64), moto_rt::ErrorCode> {
    let lazy = if lazy { SysMem::F_LAZY } else { 0 };
    SysMem::map2(
        SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_GUARDED | lazy,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        pages,
    )
}

fn used_pages() -> u64 {
    moto_sys::stats::MemoryStats::get().unwrap().used_pages
}

fn touch(addr: u64) {
    unsafe { (addr as *mut u64).write_volatile(addr) }
}

/// Query an unstarted process so the observer's allocations and demand-paged
/// code cannot perturb the exact reserved/resident deltas under test.
fn test_process_memory_stats() {
    let target =
        SysObj::create(SysHandle::NONE, 0, "address_space:debug_name=memory-stats").unwrap();
    let process = SysObj::create(target, 0, "process:entry_point=0").unwrap();
    let pid = moto_sys::SysRay::process_pid(process).unwrap();
    let memory = || ["memory_usage", "memory_resident"].map(|name| kernel_metric_at(name, pid));
    let before = memory();
    assert!(before[1] > 0 && before[1] < before[0]); // Backed stacks, with guards.
    let lazy = SysMem::map(
        target,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        TIB / PAGE_SIZE_SMALL,
    )
    .unwrap();
    assert_eq!(memory(), [before[0] + TIB, before[1]]);
    let eager = SysMem::map(
        target,
        SysMem::F_READABLE | SysMem::F_WRITABLE,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        4,
    )
    .unwrap();
    assert_eq!(
        memory(),
        [
            before[0] + TIB + 4 * PAGE_SIZE_SMALL,
            before[1] + 4 * PAGE_SIZE_SMALL
        ]
    );

    let source = SysMem::alloc(PAGE_SIZE_SMALL, 4).unwrap();
    let alias = SysMem::map(
        target,
        SysMem::F_SHARE_SELF | SysMem::F_READABLE,
        source,
        moto_sys::CUSTOM_USERSPACE_REGION_START,
        PAGE_SIZE_SMALL,
        4,
    )
    .unwrap();
    assert_eq!(
        memory(),
        [
            before[0] + TIB + 8 * PAGE_SIZE_SMALL,
            before[1] + 8 * PAGE_SIZE_SMALL
        ]
    );
    // Guarded: six pages reserved for four, and the guards never resident.
    let guarded = SysMem::map(
        target,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_GUARDED,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        4,
    )
    .unwrap();
    let guarded_lazy = SysMem::map(
        target,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY | SysMem::F_GUARDED,
        u64::MAX,
        u64::MAX,
        PAGE_SIZE_SMALL,
        4,
    )
    .unwrap();
    assert_eq!(
        memory(),
        [
            before[0] + TIB + 20 * PAGE_SIZE_SMALL,
            before[1] + 12 * PAGE_SIZE_SMALL
        ]
    );
    check_ps_memory(pid, memory());
    for addr in [lazy, eager, alias, guarded, guarded_lazy] {
        SysMem::unmap(target, 0, u64::MAX, addr).unwrap();
    }
    assert_eq!(memory(), before);
    SysMem::free(source).unwrap();
    SysObj::put(process).unwrap();
    SysObj::put(target).unwrap();
    println!("test_process_memory_stats PASS");
}

// The unstarted process has stable counters and a mostly untouched 1 TiB
// reservation. Both display modes must agree with the byte metrics exactly.
fn check_ps_memory(pid: u64, expected: [u64; 2]) {
    for tree in [false, true] {
        let mut command = std::process::Command::new("/system/bin/ps");
        if tree {
            command.arg("-H");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "ps: {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout).unwrap();
        let mut lines = output.lines();
        assert_eq!(
            lines.next().unwrap().split_whitespace().collect::<Vec<_>>(),
            [
                "PID*", "PPID", "A_THR", "T_THR", "A_CHLD", "T_CHLD", "V_USER", "V_KERN",
                "VIRT_KB", "RES_KB", "CPU", "ST", "Name"
            ]
        );
        let row = lines
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .find(|fields| {
                fields.first().is_some_and(|value| {
                    value.trim_end_matches(['*', '+', '?']).parse::<u64>() == Ok(pid)
                })
            })
            .unwrap_or_else(|| panic!("pid {pid} absent from ps (tree={tree}): {output}"));
        let value = |column: usize| row[column].parse::<u64>().unwrap();
        assert_eq!(value(8), expected[0] >> 10);
        assert_eq!(value(9), expected[1] >> 10);
        assert_eq!((value(6) + value(7)) * PAGE_SIZE_SMALL, expected[0]);
    }
    println!("test_ps_memory PASS");
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
    shared_alloc_rollback_race(true);
}

/// The race itself; `check_recovery` samples global usage, which only the
/// quiet gate can do.
fn shared_alloc_rollback_race(check_recovery: bool) {
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
    // The hole is taken at the mapper's map only by what a stray success
    // left there, once each. A rollback that reaches the mapper's
    // half-built mapping, as it could when the locks were released in
    // between, fails that map too, and shows as misses beyond that.
    assert!(
        misses <= stray_count as u64,
        "{misses} misses against {stray_count} stray gaps: a rollback took the mapper's mapping"
    );
    if check_recovery {
        assert_recovered(used_before, DRIFT_TOLERANCE_PAGES, "the rollback race");
    }
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

/// `F_GUARDED`, eager or lazy: the segment is the request plus one page at
/// each end, exactly; the guards have no translation, the interior works as
/// usual, and a touch on a guard kills the toucher. Guards come only with
/// a plain heap request.
fn test_guarded_maps() {
    const PAGES: u64 = 257; // A plain heap would round this to 512 pages.
    let present = |addr: u64| SysMem::virt_to_phys(addr).is_ok();
    for (pages, lazy) in [(1, false), (1, true), (PAGES, false), (PAGES, true)] {
        let (start, size) = map_guarded(pages, lazy).unwrap();
        assert_eq!(size, (pages + 2) * PAGE_SIZE_SMALL);
        let (lower, upper) = (start, start + size - PAGE_SIZE_SMALL);
        let ends = [lower + PAGE_SIZE_SMALL, upper - PAGE_SIZE_SMALL];
        let interior = if pages == 1 { &ends[..1] } else { &ends[..] };
        assert!(!present(lower));
        assert!(!present(upper));
        for addr in interior {
            assert_eq!(present(*addr), !lazy, "{pages} pages, lazy {lazy}");
            assert_eq!(unsafe { (*addr as *const u64).read_volatile() }, 0);
            touch(*addr);
            assert_eq!(unsafe { (*addr as *const u64).read_volatile() }, *addr);
            assert!(present(*addr));
        }
        assert!(!present(lower));
        assert!(!present(upper));
        SysMem::free(start).unwrap();
    }

    let rw = SysMem::F_READABLE | SysMem::F_WRITABLE;
    for (flags, virt_addr, pages) in [
        (SysMem::F_GUARDED, u64::MAX, 1),
        (SysMem::F_GUARDED | SysMem::F_READABLE, u64::MAX, 1),
        (SysMem::F_GUARDED | rw | SysMem::F_SHARE_SELF, u64::MAX, 1),
        (
            SysMem::F_GUARDED | rw,
            moto_sys::CUSTOM_USERSPACE_REGION_START,
            1,
        ),
        (SysMem::F_GUARDED | rw, u64::MAX, 0),
        (SysMem::F_GUARDED | rw | SysMem::F_LAZY, u64::MAX, 0),
    ] {
        // The raw syscall: the wrapper asserts a non-zero page count.
        let nr = (u64::from(moto_sys::syscalls::SYS_MEM) << 56)
            | (u64::from(SysMem::OP_MAP) << 48)
            | (u64::from(flags) << 16);
        assert_eq!(
            do_syscall(
                nr,
                SysHandle::SELF.as_u64(),
                u64::MAX,
                virt_addr,
                PAGE_SIZE_SMALL,
                pages,
                0
            )
            .error_code(),
            moto_rt::E_INVALID_ARGUMENT
        );
    }

    // A touch on either guard of either kind is a kernel kill.
    for case in 0..4 {
        let mut child = crate::subcommand::spawn();
        child.guard_touch(case);
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(-1), "guard touch {case}: {status:?}");
    }

    // IPC maps a client's pages into the listener's existing segment, so a
    // guarded listener buffer is refused, and keeps its guards, its bytes
    // and its translation.
    let (start, size) = map_guarded(4, false).unwrap();
    let interior = start + PAGE_SIZE_SMALL;
    touch(interior);
    let phys = SysMem::virt_to_phys(interior).unwrap();
    let source = SysMem::alloc(PAGE_SIZE_SMALL, 6).unwrap();
    let url = |addr: u64| {
        format!(
            "shared:url=guarded-{};address={addr};page_type=small;page_num=6",
            moto_sys::current_pid()
        )
    };
    let listener = SysObj::create(SysHandle::SELF, 0, &url(start)).unwrap();
    assert_eq!(
        SysObj::get(SysHandle::SELF, 0, &url(source)),
        Err(moto_rt::E_INVALID_ARGUMENT)
    );
    assert!(!present(start));
    assert!(!present(start + size - PAGE_SIZE_SMALL));
    assert_eq!(SysMem::virt_to_phys(interior), Ok(phys));
    assert_eq!(
        unsafe { (interior as *const u64).read_volatile() },
        interior
    );
    SysObj::put(listener).unwrap();
    SysMem::free(source).unwrap();
    SysMem::free(start).unwrap();
    println!("test_sparse_guarded_maps PASS");
}

/// The child side of `test_guarded_maps`: touches a guard page and must not
/// survive it. Bit 0 of `case` picks the lazy kind, bit 1 the upper guard.
pub fn run_guard_touch_child(case: u64) -> ! {
    let (start, size) = map_guarded(4, case & 1 != 0).unwrap();
    let guard = if case & 2 != 0 {
        start + size - PAGE_SIZE_SMALL
    } else {
        start
    };
    touch(guard);
    println!("guard_touch {case}: still alive");
    std::process::exit(0);
}

/// The first pressure event of a boot grows the pool once, by about a
/// thousand pages, and the floor test expects it to be steady afterwards.
/// An OOM child, like `test_oom` in the full suite, absorbs it, cheaply
/// when it has happened already; the tests then start once the pressure
/// it caused has cleared.
fn warm_up_pool() {
    let mut child = crate::subcommand::spawn();
    child.oom();
    assert!(!child.wait().unwrap().success());
    drop(child);
    for _ in 0..300 {
        if !moto_sys::memory_pressure() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("memory pressure did not clear after the warm-up child died");
}

/// Bounded resident memory, widely scattered descriptors, and simultaneous
/// faults on the same pages. Each thread owns a distinct word in each page.
fn soak_first_touch() {
    const WORKERS: u64 = 4;
    const REGIONS: u64 = 64;
    let offsets = [0, PAGE_SIZE_SMALL, (2 << 20) - PAGE_SIZE_SMALL];
    for round in 0..4 {
        let base = map_lazy(TIB).unwrap();
        let barrier = std::sync::Barrier::new(WORKERS as usize);
        std::thread::scope(|scope| {
            for worker in 0..WORKERS {
                let barrier = &barrier;
                let offsets = &offsets;
                scope.spawn(move || {
                    barrier.wait();
                    for region in 0..REGIONS {
                        for offset in offsets {
                            let addr = base + region * (TIB / REGIONS) + offset + worker * 8;
                            let expected = addr ^ (round + 1);
                            unsafe {
                                let word = addr as *mut u64;
                                assert_eq!(word.read_volatile(), 0, "fresh sparse word {addr:#x}");
                                word.write_volatile(expected);
                            }
                        }
                    }
                });
            }
        });
        for region in 0..REGIONS {
            for offset in offsets {
                for worker in 0..WORKERS {
                    let addr = base + region * (TIB / REGIONS) + offset + worker * 8;
                    assert_eq!(
                        unsafe { (addr as *const u64).read_volatile() },
                        addr ^ (round + 1)
                    );
                }
            }
        }
        SysMem::free(base).unwrap();
    }
    println!("sparse soak_first_touch PASS");
}

/// Page-table pages emptied by a free go back to the pool only after the
/// TLB flush that ends the free. Readers sweep a region, one page per L1
/// table, until the owner tells them to stop, so their CPUs cache its
/// directory entries; while the owner frees it, each reader builds tables
/// of its own from the pool and checks every word it maps. The owner then
/// maps the region again, at the same address if the runtime gives it
/// back, and the readers check its fresh pages too. A table page reused
/// before the flush would show as a wrong word on either side.
fn soak_table_churn() {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    const READERS: usize = 3;
    const ROUNDS: u64 = 200;
    const PAGES: u64 = 16;
    const STRIDE: u64 = 2 << 20;

    let phase = AtomicU64::new(0);
    let region = AtomicU64::new(0);
    let sweeps = AtomicU64::new(0);
    let joined = AtomicUsize::new(0);
    let acks = AtomicUsize::new(0);
    let read_phase = |round: u64| 2 * round + 1;
    let stop_phase = |round: u64| 2 * round + 2;
    std::thread::scope(|scope| {
        for _ in 0..READERS {
            scope.spawn(|| {
                for round in 0..ROUNDS {
                    while phase.load(Ordering::Acquire) != read_phase(round) {
                        std::hint::spin_loop();
                    }
                    let base = region.load(Ordering::Relaxed);
                    joined.fetch_add(1, Ordering::Release);
                    while phase.load(Ordering::Acquire) == read_phase(round) {
                        for idx in 0..PAGES {
                            let addr = base + idx * STRIDE;
                            let word = unsafe { (addr as *const u64).read_volatile() };
                            assert_eq!(word, addr ^ (round + 1), "swept word {addr:#x}");
                        }
                        sweeps.fetch_add(1, Ordering::Relaxed);
                    }
                    acks.fetch_add(1, Ordering::Release);
                    // Fresh tables while the owner's free is in flight.
                    let own = map_lazy(4 * STRIDE).unwrap();
                    for idx in 0..4 {
                        let addr = own + idx * STRIDE;
                        let word = addr as *mut u64;
                        unsafe {
                            assert_eq!(word.read_volatile(), 0, "fresh reader word {addr:#x}");
                            word.write_volatile(!addr);
                            assert_eq!(word.read_volatile(), !addr, "reader word {addr:#x}");
                        }
                    }
                    SysMem::free(own).unwrap();
                }
            });
        }
        for round in 0..ROUNDS {
            let base = map_lazy(PAGES * STRIDE).unwrap();
            for idx in 0..PAGES {
                let addr = base + idx * STRIDE;
                let word = addr as *mut u64;
                unsafe {
                    assert_eq!(word.read_volatile(), 0, "fresh owner word {addr:#x}");
                    word.write_volatile(addr ^ (round + 1));
                }
            }
            region.store(base, Ordering::Relaxed);
            joined.store(0, Ordering::Relaxed);
            acks.store(0, Ordering::Relaxed);
            let sweeps_before = sweeps.load(Ordering::Relaxed);
            phase.store(read_phase(round), Ordering::Release);
            // Every reader is in this round, and the region has been walked
            // a few times; a reader that joins late must not miss the phase.
            while joined.load(Ordering::Acquire) != READERS
                || sweeps.load(Ordering::Relaxed) < sweeps_before + 4 * READERS as u64
            {
                std::hint::spin_loop();
            }
            phase.store(stop_phase(round), Ordering::Release);
            while acks.load(Ordering::Acquire) != READERS {
                std::hint::spin_loop();
            }
            SysMem::free(base).unwrap();
        }
    });
    println!("sparse soak_table_churn PASS");
}

/// The soak-safe phases: content and lifetime assertions only, no global
/// usage samples, since sibling workloads allocate at any time.
pub fn run_soak_tests() {
    soak_first_touch();
    soak_table_churn();
    shared_alloc_rollback_race(false);
    test_lazy_share_source();
    test_guarded_maps();
    let mut child = crate::subcommand::spawn();
    child.sparse_exit();
    assert!(child.wait().unwrap().success());
    println!("sparse-soak PASS");
}

pub fn run_all_tests() {
    warm_up_pool();
    test_process_memory_stats();
    test_large_reservations();
    test_lazy_share_source();
    test_guarded_maps();
    test_shared_alloc_rollback_race();
    test_exit_with_reservations();
    test_fault_at_floor();
    soak_first_touch();
    soak_table_churn();
}
