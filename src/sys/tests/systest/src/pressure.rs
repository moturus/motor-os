//! Regression for memory pressure mode:
//! the kernel raises the `memory_pressure` flag in `KernelStaticPage` when
//! free-for-admission reaches the low watermark; while it is up, process
//! spawns fail fast in rt.vdso, sys-io refuses new sockets and drops new
//! client connections, and existing connections keep serving. The flag clears
//! on its own -- from the kernel's free path -- once memory returns above the
//! high watermark.

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

use moto_sys::SysMem;
use moto_sys::stats::AdmissionStats;
use moto_sys::sys_mem::PAGE_SIZE_SMALL;

/// Reads a system-wide sys-io metric by name; the sys-io analogue of
/// `admission::kernel_metric`. `None` if the metric does not exist or is not
/// reported.
fn sys_io_metric_opt(name: &str) -> Option<u64> {
    use moto_stats::Collector;

    let provider = Collector::provider_by_name("sys-io").expect("no sys-io stats provider");
    let descs = Collector::describe(&provider).unwrap();
    let desc = descs.iter().find(|d| d.name == name)?;
    Collector::query(&provider)
        .unwrap()
        .iter()
        .find(|e| e.metric == desc.id && e.scope == moto_stats::SCOPE_GLOBAL)
        .map(|e| e.value)
}

fn sys_io_metric(name: &str) -> u64 {
    sys_io_metric_opt(name).unwrap_or_else(|| panic!("no sys-io metric '{name}'"))
}

/// Refusals travel as E_OUT_OF_MEMORY; accept whichever representation the
/// std port surfaces.
fn is_refused(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::OutOfMemory
        || err.raw_os_error() == Some(moto_rt::E_OUT_OF_MEMORY as i32)
}

fn assert_refused(err: &std::io::Error) {
    assert!(
        is_refused(err),
        "refused operation failed with the wrong error: {err:?}"
    );
}

/// Track the deepest free-for-admission sample of a pressure episode.
fn sample_min(min_free: &mut u64) {
    let free = AdmissionStats::get().unwrap().free_for_admission();
    if free < *min_free {
        *min_free = free;
    }
}

/// Poll `cond` for up to `secs` seconds.
fn eventually(secs: u64, what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..secs * 10 {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("not within {secs}s: {what}");
}

/// Drive free-for-admission into the pressure band and hold it there:
/// returns the squeeze child once the kernel has raised the flag. Released
/// with `release_squeeze`.
fn squeeze_to_pressure() -> crate::subcommand::Subcommand {
    let adm = AdmissionStats::get().unwrap();

    // The squeeze must land between the kernel's user floor (or unrelated
    // processes start dying on refused work) and the low watermark (or
    // pressure never trips). Both bounds scale with the watermarks, so the
    // target sits an eighth of the floor-to-watermark gap below the
    // watermark: deep enough that concurrent system activity cannot lift
    // the pool back over it, high enough that the whole gap below stays
    // available to that activity while the squeeze holds.
    let gap = adm.pressure_low_pages - adm.user_floor_pages;
    let target = adm.pressure_low_pages - gap.div_ceil(8);
    assert!(
        target > adm.user_floor_pages + gap / 4,
        "no band to squeeze into: target {target}, user floor {}",
        adm.user_floor_pages
    );

    let mut child = crate::subcommand::spawn();
    let mut child_out = std::io::BufReader::new(child.std_child().stdout.take().unwrap());
    child.pressure_squeeze(target);
    let mut line = String::new();
    child_out.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "squeezed");

    // The child's own admitted allocations crossed the low watermark, so the
    // kernel has already raised the flag.
    assert!(
        moto_sys::memory_pressure(),
        "flag not raised by the squeeze"
    );
    child
}

/// Release the squeeze. A dead process owns its pages until the last handle
/// closes; the kernel's free path then clears the flag with no help from
/// anyone.
fn release_squeeze(mut child: crate::subcommand::Subcommand) {
    child.do_exit(0);
    assert!(child.wait().unwrap().success());
    drop(child);
    eventually(10, "the kernel cleared the pressure flag", || {
        !moto_sys::memory_pressure()
    });
}

/// Probe a fresh io_channel client mid-episode: it dies at one of two racing
/// hands. The channel's own eager mapping (~200 pages) usually fails kernel
/// admission -- the band between the user floor and the low watermark is
/// about one io_channel wide -- so the client dies before the service ever
/// sees it; when the pool happens to sit high enough in the band, the
/// mapping is admitted and the service accepts, then drops, the connection.
/// Both are designed refusals; which fires depends on where in the band the
/// pool sits. `Ok(true)` means the service was the dropping hand; the
/// connect error is returned for the caller to assert on -- immediately or
/// after recovery, per that test's discipline.
fn probe_fresh_client(service: &str) -> Result<bool, moto_rt::Error> {
    match moto_ipc::io_channel::ClientConnection::connect(service) {
        Ok(conn) => {
            eventually(5, "the dropped client's server handle died", || {
                conn.wake_server().is_err()
            });
            drop(conn);
            Ok(true)
        }
        Err(err) => Err(err),
    }
}

fn test_pressure_mode() {
    let adm = AdmissionStats::get().unwrap();
    let low = adm.pressure_low_pages;
    let high = adm.pressure_high_pages;
    assert!(
        low > adm.user_floor_pages && high > low,
        "bad watermarks: low {low}, high {high}, user floor {}",
        adm.user_floor_pages
    );
    assert!(!moto_sys::memory_pressure(), "pressure before the squeeze");

    // sys-io's gauges mirror the kernel policy.
    assert_eq!(low, sys_io_metric("net.pressure_low_pages"));
    assert_eq!(high, sys_io_metric("net.pressure_high_pages"));

    // An established connection from before the squeeze, to show service
    // continuing under pressure.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut serve, _) = listener.accept().unwrap();

    let entries_before = sys_io_metric("net.pressure_entries");
    let refused_before = sys_io_metric("net.pressure_refused");
    let clients_refused_before = sys_io_metric("net.pressure_refused_clients");

    let child = squeeze_to_pressure();

    // Floor-sizing measurement: free-for-admission at
    // episode entry, then the deepest sample while refusals and live traffic
    // run below. The difference is the residual demand -- from every source
    // still allocating, sys-io and this test alike -- that the gap between
    // the low watermark and the user floor must absorb.
    let entry_free = AdmissionStats::get().unwrap().free_for_admission();
    let mut min_free = entry_free;

    // New sockets are refused by sys-io without a syscall...
    assert_refused(&TcpListener::bind("127.0.0.1:0").unwrap_err());
    assert_refused(&TcpStream::connect(addr).unwrap_err());
    assert_refused(&UdpSocket::bind("127.0.0.1:0").unwrap_err());
    sample_min(&mut min_free);

    // ...a process spawn fails fast in rt.vdso, before any work is done...
    let spawn_err = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .spawn()
        .expect_err("spawn succeeded under memory pressure");
    assert_refused(&spawn_err);

    // ...and a fresh client connection to sys-io is refused at one of the
    // two hands in `probe_fresh_client`; this test asserts mid-episode.
    let client_dropped = match probe_fresh_client("sys-io") {
        Ok(dropped) => dropped,
        Err(err) => {
            assert_eq!(err, moto_rt::Error::OutOfMemory);
            false
        }
    };
    sample_min(&mut min_free);

    // The pre-pressure connection keeps serving within its admitted memory;
    // half a second of round trips gives residual demand time to show up in
    // the samples.
    let mut buf = [0u8; 4];
    for _ in 0..10 {
        client.write_all(b"ping").unwrap();
        serve.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        serve.write_all(b"pong").unwrap();
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        sample_min(&mut min_free);
        std::thread::sleep(Duration::from_millis(50));
    }

    release_squeeze(child);

    // The episode's numbers, reported and asserted only now: the metrics
    // RPC and println both allocate, which nothing may do while the episode
    // is live. sys-io noticed the episode and refused the three socket
    // requests; the client counter moved only if the fresh client got far
    // enough for sys-io to be the one to refuse it.
    println!(
        "pressure residual measurements: entry free {entry_free}, min free {min_free}, \
         residual {} pages; client probe: {}",
        entry_free.saturating_sub(min_free),
        if client_dropped {
            "accepted, then dropped by sys-io"
        } else {
            "refused by kernel admission"
        },
    );
    assert!(sys_io_metric("net.pressure_entries") > entries_before);
    assert!(sys_io_metric("net.pressure_refused") >= refused_before + 3);
    if client_dropped {
        assert!(sys_io_metric("net.pressure_refused_clients") > clients_refused_before);
    }

    // With the flag down, everything works again at once.
    let recovered = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = recovered.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut serve, _) = recovered.accept().unwrap();
    client.write_all(b"ok").unwrap();
    let mut buf = [0u8; 2];
    serve.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ok");
    assert_eq!(0, sys_io_metric("net.pressure_active"));

    println!("test_pressure_mode PASS");
}

/// FS-side pressure regression: while the flag is up, every FS command except
/// UNLOCK is refused without growing sys-io, refusals free the channel pages
/// the request donated, the UNLOCK carve-out serves -- including handing a
/// queued waiter its grant -- and service resumes on the same handles after
/// recovery.
///
/// The write hammer alternates the two CMD_WRITE request formats (one donated
/// page, and multi-page) and the stat hammer sends path-carrying stats, each
/// arm far longer than the channel's 64-slot page pool. A refusal that leaked
/// a donated page would exhaust the pool within one arm, leaving the client
/// blocked forever in `alloc_page` (no timeout exists there) and the run to
/// die on the harness timeout with the squeeze still holding -- a silent hang
/// here, not an assert, is what a page leak looks like. That is the coverage
/// for `api_fs::release_donated_pages`.
///
/// The standalone knob `systest test-fs-pressure [lock_spam]` (default
/// 100,000) drives the same body against a build *without* the refusal set,
/// where it is a demonstrator rather than a test. The lever is the lock
/// manager, not the block cache: the cache is capacity-bounded (16 MiB) and
/// boot-time binary loads fill it, after which misses recycle evicted buffers
/// (measured: a 16 MiB write hammer grows sys-io by 0 pages, and 40k opens by
/// 1). Held locks are unbounded at ~22 bytes each -- 100k of them grow sys-io
/// by 546 pages, enough to cross the sys-io floor mid-episode, at which point
/// sys-io dies of the refused allocation and the machine with it. Run that
/// form on a disposable release boot: a debug guest logs several lines per FS
/// request to the serial console, which throttles a 100k-request hammer below
/// any usable timeout.
pub fn test_fs_under_pressure(lock_spam: usize) {
    const PATH: &str = "/sys/tmp/systest-fs-pressure";
    const WAITER_PATH: &str = "/sys/tmp/systest-fs-pressure-waiter";
    // Each hammer arm runs far longer than the channel's 64-slot page pool:
    // refused requests that leaked their donated pages would wedge the
    // channel within one arm.
    const HAMMER_WRITES: usize = 4096;
    const HAMMER_STATS: usize = 128;

    assert!(!moto_sys::memory_pressure(), "pressure before the squeeze");

    // The suite creates /sys/tmp long before this test runs, but the
    // standalone form runs on a fresh image, where it does not exist yet.
    std::fs::create_dir_all("/sys/tmp").unwrap();

    // FS state from before the squeeze: an open file for the write hammer, a
    // held lock to release mid-episode, a second handle to probe acquires,
    // and `lock_spam` handles for the acquire spam -- opened now, because
    // opens are themselves refused once the flag is up.
    let mut file = std::fs::File::create(PATH).unwrap();
    file.write_all(&[0u8; 4096]).unwrap();
    let lock_held = std::fs::File::open(PATH).unwrap();
    lock_held.lock_shared().unwrap();
    let lock_probe = std::fs::File::open(PATH).unwrap();
    let mut spam_handles = Vec::with_capacity(lock_spam);
    for _ in 0..lock_spam {
        spam_handles.push(std::fs::File::open(PATH).unwrap());
    }

    // A queued lock waiter, on its own file so its queue cannot interact
    // with the acquire spam: the mid-episode unlock below must hand this
    // waiter its pre-encoded grant while the flag is up -- the half of the
    // UNLOCK carve-out that a waiter-free unlock never exercises.
    std::fs::File::create(WAITER_PATH).unwrap();
    let waiter_holder = std::fs::File::open(WAITER_PATH).unwrap();
    waiter_holder.lock_shared().unwrap();
    let waiter_handle = std::fs::File::open(WAITER_PATH).unwrap();
    let waiter = std::thread::spawn(move || {
        waiter_handle.lock().unwrap();
        waiter_handle.unlock().unwrap();
    });
    // No client-side signal says "queued"; give the acquire time to reach
    // sys-io's wait queue before squeezing. If this ever races, the waiter
    // panics on a refused acquire and the join below reports it.
    std::thread::sleep(Duration::from_millis(500));

    // Lenient reads: these counters exist only once the refusal set is
    // built, and the pre-refusal demonstrator must reach the hammer rather
    // than die on a missing metric name.
    let refused_before = sys_io_metric_opt("fs.pressure_refused").unwrap_or(0);
    let clients_refused_before = sys_io_metric_opt("fs.pressure_refused_clients").unwrap_or(0);

    let child = squeeze_to_pressure();

    // Nothing below asserts until the episode is over: on a pre-refusal
    // build the early probes succeed, and an assert there would end the run
    // before the arm that actually kills sys-io (the lock hammer) ever runs.
    // Classify, then judge after recovery.
    let buf = [0xA5_u8; 2 * 4096];
    let mut writes_ok = 0_usize;
    let mut writes_refused = 0_usize;
    let mut writes_other = 0_usize;
    for i in 0..HAMMER_WRITES {
        // Alternate the request formats: a 4096-byte write donates one page
        // (`shared_pages[SINGLE_PAGE_SLOT]`), an 8192-byte write takes the
        // multi-page format -- a refusal must free the pages of both.
        let len = if i % 2 == 0 { 4096 } else { buf.len() };
        match file.write_all(&buf[..len]) {
            Ok(()) => writes_ok += 1,
            Err(ref err) if is_refused(err) => writes_refused += 1,
            Err(_) => writes_other += 1,
        }
    }

    // Read-only commands are in the refusal set too, and each metadata call
    // resolves its path afresh, donating a page to CMD_STAT -- this arm pins
    // the single-page release branch for a command other than CMD_WRITE.
    let mut stats_ok = 0_usize;
    let mut stats_refused = 0_usize;
    let mut stats_other = 0_usize;
    for _ in 0..HAMMER_STATS {
        match std::fs::metadata(PATH) {
            Ok(_) => stats_ok += 1,
            Err(ref err) if is_refused(err) => stats_refused += 1,
            Err(_) => stats_other += 1,
        }
    }

    // The lock hammer: unbounded per-lock state in sys-io's lock manager.
    // Pre-refusal this grows sys-io past its floor and the machine dies here.
    let mut locks_ok = 0_usize;
    let mut locks_refused = 0_usize;
    let mut locks_other = 0_usize;
    for handle in &spam_handles {
        match handle.lock_shared() {
            Ok(()) => locks_ok += 1,
            Err(ref err) if is_refused(err) => locks_refused += 1,
            Err(_) => locks_other += 1,
        }
    }

    // UNLOCK is the carve-out, since Drop-based unlock never retries; the
    // waiter-file unlock also hands the queued waiter its grant while the
    // flag is up. A lock acquire stays refused.
    let acquire_result = lock_probe.try_lock();
    let unlock_result = lock_held.unlock();
    let waiter_unlock_result = waiter_holder.unlock();

    // A fresh FS client dies at one of the same two hands as a net client;
    // judged after recovery.
    let fs_client_probe = probe_fresh_client("sys-io-fs");

    release_squeeze(child);

    // The episode's verdict, printed and asserted only now: println and the
    // metrics RPC both allocate, which nothing may do while the flag is up.
    println!(
        "fs under pressure: writes ok/refused/other {writes_ok}/{writes_refused}/{writes_other}, \
         stats {stats_ok}/{stats_refused}/{stats_other}, \
         lock acquires {locks_ok}/{locks_refused}/{locks_other}, \
         acquire refused {}, unlock {unlock_result:?}, waiter unlock {waiter_unlock_result:?}",
        acquire_result.is_err()
    );

    assert_eq!(
        (writes_ok, writes_other, writes_refused),
        (0, 0, HAMMER_WRITES),
        "FS writes not refused under pressure"
    );
    assert_eq!(
        (stats_ok, stats_other, stats_refused),
        (0, 0, HAMMER_STATS),
        "FS metadata not refused under pressure"
    );
    assert_eq!(
        (locks_ok, locks_other, locks_refused),
        (0, 0, lock_spam),
        "FS lock acquires not refused under pressure"
    );
    match acquire_result {
        Err(std::fs::TryLockError::Error(ref err)) => assert_refused(err),
        ref wrong => panic!("lock acquire under pressure: {wrong:?}"),
    }
    unlock_result.expect("UNLOCK refused under pressure");
    waiter_unlock_result.expect("waiter-file UNLOCK refused under pressure");

    // The queued waiter's grant was sent by the mid-episode unlock; on a
    // build that drops grants the thread never wakes, and this reports that
    // instead of hanging in join.
    eventually(10, "the queued lock waiter was granted", || {
        waiter.is_finished()
    });
    waiter.join().unwrap();

    let client_dropped = match fs_client_probe {
        Ok(dropped) => dropped,
        Err(err) => {
            assert_eq!(err, moto_rt::Error::OutOfMemory);
            false
        }
    };

    // Service resumes on the same handles and the same file.
    file.write_all(&buf).unwrap();
    assert!(std::fs::metadata(PATH).unwrap().is_file());
    lock_probe.try_lock().unwrap();
    lock_probe.unlock().unwrap();
    drop(spam_handles);
    drop((file, lock_held, lock_probe, waiter_holder));
    std::fs::remove_file(PATH).unwrap();
    std::fs::remove_file(WAITER_PATH).unwrap();

    // Counters: the three hammers plus the refused acquire probe, and the
    // client counter only if sys-io was the refusing hand.
    let hammered = (HAMMER_WRITES + HAMMER_STATS + lock_spam + 1) as u64;
    assert!(sys_io_metric("fs.pressure_refused") >= refused_before + hammered);
    if client_dropped {
        assert!(sys_io_metric("fs.pressure_refused_clients") > clients_refused_before);
    }

    println!("test_fs_under_pressure PASS");
}

/// The child side of `test_pressure_mode`: drain free memory to
/// `target_pages` and hold it until the parent writes a line to stdin.
pub fn run_pressure_squeeze_child(target_pages: u64) -> ! {
    loop {
        let free = AdmissionStats::get().unwrap().free_for_admission();
        if free <= target_pages || SysMem::alloc(PAGE_SIZE_SMALL, 64).is_err() {
            break;
        }
    }

    // The parent must not probe before the squeeze is complete.
    println!("squeezed");

    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    std::process::exit(0);
}

fn test_large_allocs() {
    let mut allocs = vec![];
    loop {
        match moto_sys::SysMem::alloc(4096, 1024 * 1024 * 1024 / 4096) {
            Ok(addr) => allocs.push(addr),
            Err(err) => {
                assert_eq!(err, moto_rt::E_OUT_OF_MEMORY);
                break;
            }
        }
    }

    let cnt = allocs.len();

    for addr in allocs {
        moto_sys::SysMem::free(addr).unwrap();
    }

    println!("test_large_allocs PASS: {cnt} 1G allocations succeeded");
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

pub fn run_all_tests() {
    test_large_allocs();
    test_frame_churn();
    test_pressure_mode();
    // Suite-sized lock spam: a refused acquire proves the gate at any size,
    // and the standalone knob (`systest test-fs-pressure [n]`) keeps the
    // large-n form for driving a build without the refusal set into OOM.
    test_fs_under_pressure(128);
}
