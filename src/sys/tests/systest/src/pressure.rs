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

    // The squeeze must land between the kernel's user floor (or unrelated
    // processes start dying on refused work) and the low watermark (or
    // pressure never trips). Both bounds scale with the watermarks, so the
    // target sits an eighth of the floor-to-watermark gap below the
    // watermark: deep enough that concurrent system activity cannot lift
    // the pool back over it, high enough that the whole gap below stays
    // available to that activity while the squeeze holds.
    let gap = low - adm.user_floor_pages;
    let target = low - gap.div_ceil(8);
    assert!(
        target > adm.user_floor_pages + gap / 4,
        "no band to squeeze into: target {target}, user floor {}",
        adm.user_floor_pages
    );

    // An established connection from before the squeeze, to show service
    // continuing under pressure.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut serve, _) = listener.accept().unwrap();

    let entries_before = sys_io_metric("net.pressure_entries");
    let refused_before = sys_io_metric("net.pressure_refused");
    let clients_refused_before = sys_io_metric("net.pressure_refused_clients");

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

    // ...and a fresh client connection to sys-io is refused by one of two
    // racing refusers. The channel's own eager mapping (~200 pages) usually
    // fails kernel admission -- the band between the user floor and the low
    // watermark is about one io_channel wide -- so the client dies before
    // sys-io ever sees it; when the pool happens to sit high enough in the
    // band, the mapping is admitted and sys-io accepts, then drops, the
    // fresh connection. Both are designed refusals; which fires depends on
    // where in the band the pool sits, so the test accepts either.
    let client_dropped = match moto_ipc::io_channel::ClientConnection::connect("sys-io") {
        Ok(conn) => {
            eventually(5, "the dropped client's server handle died", || {
                conn.wake_server().is_err()
            });
            drop(conn);
            true
        }
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

    // Release. A dead process owns its pages until the last handle closes;
    // the kernel's free path then clears the flag with no help from anyone.
    child.do_exit(0);
    assert!(child.wait().unwrap().success());
    drop(child);
    eventually(10, "the kernel cleared the pressure flag", || {
        !moto_sys::memory_pressure()
    });

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

/// FS-side pressure regression. Standalone knob:
/// `systest test-fs-pressure [lock_spam]` (default 100,000).
///
/// On a build without the FS refusal set this is a demonstrator, not a test.
/// sys-io's block cache cannot be the lever: it is capacity-bounded (16 MiB)
/// and boot-time binary loads fill it before any test can run, after which
/// misses recycle evicted buffers (measured: a 16 MiB write hammer grows
/// sys-io by 0 pages). The lock manager is unbounded: each held lock costs
/// sys-io ~22 bytes of heap, growing its slabs by ~68-page allocations every
/// ~12k locks (measured: 100k held locks grow sys-io by 546 pages, returned
/// on unlock; 40k opens cost sys-io 1 page, so it is the lock state, not the
/// opens). Mid-episode, kernel admission refuses such a slab growth once
/// free-for-admission sinks within a charge of the sys-io floor, and sys-io
/// dies of the refusal: the machine goes with it. The victim allocation is
/// whichever asks next, so the death has two observed shapes -- an unwrapped
/// null from the block cache (0xbadc0de) or a refused lazy fault killing the
/// faulting thread (0xffffffff). Run it standalone on a disposable boot and
/// read the verdict from the serial log.
///
/// Release only, pre-refusal: a debug guest logs several lines per FS request
/// to the serial console, which throttles a 100k-request hammer below any
/// usable timeout. The suite-sized spam (128) is cheap on both builds.
///
/// With the refusal set built, the same body passes: every FS command except
/// UNLOCK is refused allocation-free while the flag is up, refusals release
/// client-donated channel pages (the write hammer is far longer than the
/// channel's page pool, so a leaked page wedges it), the unlock carve-out
/// works, and service resumes after recovery.
pub fn test_fs_under_pressure(lock_spam: usize) {
    const PATH: &str = "/sys/tmp/systest-fs-pressure";
    // Longer than the channel's 64-slot page pool by a wide margin: refused
    // writes that leaked their donated page would wedge the channel here.
    const HAMMER_WRITES: usize = 4096;

    let adm = AdmissionStats::get().unwrap();
    assert!(!moto_sys::memory_pressure(), "pressure before the squeeze");

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

    // Lenient reads: these counters exist only once the refusal set is
    // built, and the pre-refusal demonstrator must reach the hammer rather
    // than die on a missing metric name.
    let refused_before = sys_io_metric_opt("fs.pressure_refused").unwrap_or(0);
    let clients_refused_before = sys_io_metric_opt("fs.pressure_refused_clients").unwrap_or(0);

    // The squeeze target: see `test_pressure_mode`.
    let gap = adm.pressure_low_pages - adm.user_floor_pages;
    let target = adm.pressure_low_pages - gap.div_ceil(8);
    let mut child = crate::subcommand::spawn();
    let mut child_out = std::io::BufReader::new(child.std_child().stdout.take().unwrap());
    child.pressure_squeeze(target);
    let mut line = String::new();
    child_out.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "squeezed");
    assert!(
        moto_sys::memory_pressure(),
        "flag not raised by the squeeze"
    );

    // Nothing below asserts until the episode is over: on a pre-refusal
    // build the early probes succeed, and an assert there would end the run
    // before the arm that actually kills sys-io (the lock hammer) ever runs.
    // Classify, then judge after recovery.
    let buf = [0xA5_u8; 4096];
    let mut writes_ok = 0_usize;
    let mut writes_refused = 0_usize;
    let mut writes_other = 0_usize;
    for _ in 0..HAMMER_WRITES {
        match file.write_all(&buf) {
            Ok(()) => writes_ok += 1,
            Err(ref err) if is_refused(err) => writes_refused += 1,
            Err(_) => writes_other += 1,
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

    // Read-only commands are in the set too; UNLOCK is the carve-out, since
    // Drop-based unlock never retries.
    let metadata_result = std::fs::metadata(PATH).map(|md| md.is_file());
    let acquire_result = lock_probe.try_lock();
    let unlock_result = lock_held.unlock();

    // A fresh FS client dies at one of the same two hands as a net client;
    // see `test_pressure_mode`.
    let client_dropped = match moto_ipc::io_channel::ClientConnection::connect("sys-io-fs") {
        Ok(conn) => {
            eventually(5, "the dropped fs client's server handle died", || {
                conn.wake_server().is_err()
            });
            drop(conn);
            Ok(true)
        }
        Err(err) => Err(err),
    };

    // Release; the kernel's free path clears the flag on its own.
    child.do_exit(0);
    assert!(child.wait().unwrap().success());
    drop(child);
    eventually(10, "the kernel cleared the pressure flag", || {
        !moto_sys::memory_pressure()
    });

    // The episode's verdict, printed and asserted only now: println and the
    // metrics RPC both allocate, which nothing may do while the flag is up.
    println!(
        "fs under pressure: writes ok/refused/other {writes_ok}/{writes_refused}/{writes_other}, \
         lock acquires {locks_ok}/{locks_refused}/{locks_other}, \
         metadata {metadata_result:?}, acquire refused {}, unlock {unlock_result:?}",
        acquire_result.is_err()
    );

    assert_eq!(
        (writes_ok, writes_other, writes_refused),
        (0, 0, HAMMER_WRITES),
        "FS writes not refused under pressure"
    );
    assert_eq!(
        (locks_ok, locks_other, locks_refused),
        (0, 0, lock_spam),
        "FS lock acquires not refused under pressure"
    );
    assert_refused(&metadata_result.expect_err("metadata served under pressure"));
    match acquire_result {
        Err(std::fs::TryLockError::Error(ref err)) => assert_refused(err),
        ref wrong => panic!("lock acquire under pressure: {wrong:?}"),
    }
    unlock_result.expect("UNLOCK refused under pressure");
    let client_dropped = match client_dropped {
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
    drop((file, lock_held, lock_probe));
    std::fs::remove_file(PATH).unwrap();

    // Counters: the two hammers plus the two refused probes, and the client
    // counter only if sys-io was the refusing hand.
    let hammered = (HAMMER_WRITES + lock_spam) as u64;
    assert!(sys_io_metric("fs.pressure_refused") >= refused_before + hammered + 2);
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

pub fn run_all_tests() {
    test_pressure_mode();
    // test_fs_under_pressure(128) joins here together with the FS refusal
    // set (docs/plans/fs-pressure-refusal.md) -- suite-sized spam, since a
    // refused acquire proves the gate at any size; until then the test OOMs
    // sys-io by design and runs only via `systest test-fs-pressure`.
}
