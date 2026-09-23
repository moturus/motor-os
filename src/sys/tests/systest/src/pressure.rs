//! Regression for memory pressure mode:
//! the kernel raises the `memory_pressure` flag in `KernelStaticPage` when
//! free-for-admission reaches the low watermark; while it is up, process
//! spawns fail fast in rt.vdso, sys-io refuses new sockets and drops new
//! client connections, and existing connections keep serving. The flag clears
//! on its own -- from the kernel's free path -- once memory returns above the
//! high watermark.
//!
//! The flag is the kernel's, not the test's. A squeeze child holds the pool
//! below the low watermark, but under pressure every process's housekeeping
//! returns its allocator slack at its next tick, and one return can lift
//! the pool past the high watermark: the flag clears until the child drains
//! the pool again. The child maintains its target and holds each such dip
//! open for at least `DIP_HOLD` before draining, so a dip that could have
//! influenced a request outlasts that request's reply. Every mid-episode
//! check issues its request while the flag is up and reads the flag right
//! after a served one: down is a dip and the request goes again, up is a
//! real serve and the test fails after recovery.

use std::io::{BufRead, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

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

/// How long the squeeze child keeps a dip open before draining again.
const DIP_HOLD: Duration = Duration::from_millis(50);

/// What one mid-episode request came to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    /// Refused with `E_OUT_OF_MEMORY`, possibly after serves across dips.
    Refused,
    /// Served with the flag up right after: the refusal set lacks it.
    Served,
    /// The flag stayed down, or dips kept coming, for seconds: the squeeze
    /// child lost its hold.
    FlagDown,
    /// Failed with some other error.
    Other,
}

/// Waits for the flag to be up; false if it stays down for a second.
fn flag_up() -> bool {
    let start = Instant::now();
    while !moto_sys::memory_pressure() {
        if start.elapsed() > Duration::from_secs(1) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

/// Issues `op` while the flag is up and classifies the outcome. A serve
/// with the flag observed down right after it was handled across a dip,
/// which the squeeze child holds open long enough to be seen here: `undo`
/// reverses the serve, `dips` counts it, and `op` goes again once the flag
/// is back. Nothing here allocates; the caller judges after recovery.
fn until_refused_undo(
    mut op: impl FnMut() -> std::io::Result<()>,
    mut undo: impl FnMut(),
    dips: &mut usize,
) -> Verdict {
    let start = Instant::now();
    loop {
        if !flag_up() {
            return Verdict::FlagDown;
        }
        match op() {
            Err(ref err) if is_refused(err) => return Verdict::Refused,
            Err(_) => return Verdict::Other,
            Ok(()) => {}
        }
        if moto_sys::memory_pressure() {
            return Verdict::Served;
        }
        undo();
        *dips += 1;
        if start.elapsed() > Duration::from_secs(5) {
            return Verdict::FlagDown;
        }
    }
}

fn until_refused(op: impl FnMut() -> std::io::Result<()>, dips: &mut usize) -> Verdict {
    until_refused_undo(op, || {}, dips)
}

/// Verdict counts for one hammer arm, judged after recovery.
#[derive(Default, Debug)]
struct Tally {
    refused: usize,
    served: usize,
    flag_down: usize,
    other: usize,
}

impl Tally {
    fn count(&mut self, verdict: Verdict) {
        match verdict {
            Verdict::Refused => self.refused += 1,
            Verdict::Served => self.served += 1,
            Verdict::FlagDown => self.flag_down += 1,
            Verdict::Other => self.other += 1,
        }
    }

    fn assert_all_refused(&self, requests: usize, what: &str) {
        assert_eq!(
            (self.refused, self.served, self.flag_down, self.other),
            (requests, 0, 0, 0),
            "{what} not refused under pressure"
        );
    }
}

/// Drive free-for-admission into the pressure band and hold it there:
/// returns the squeeze child once the kernel has raised the flag. Released
/// with `release_squeeze`.
pub(crate) fn squeeze_to_pressure() -> crate::subcommand::Subcommand {
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
    // kernel has already raised the flag -- barring a dip at this instant.
    eventually(
        10,
        "the flag raised by the squeeze",
        moto_sys::memory_pressure,
    );
    child
}

/// Release the squeeze. A dead process owns its pages until the last handle
/// closes; the kernel's free path then clears the flag with no help from
/// anyone.
pub(crate) fn release_squeeze(mut child: crate::subcommand::Subcommand) {
    child.do_exit(0);
    assert!(child.wait().unwrap().success());
    drop(child);
    eventually(10, "the kernel cleared the pressure flag", || {
        !moto_sys::memory_pressure()
    });
}

/// Which hand refused a fresh client.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Hand {
    /// Kernel admission refused the channel's mapping.
    Kernel,
    /// The service accepted, then dropped, the connection.
    Service,
    /// Neither: the service kept the client with the flag up throughout,
    /// or the squeeze lost its hold.
    Neither,
}

impl Hand {
    fn describe(self) -> &'static str {
        match self {
            Hand::Kernel => "refused by kernel admission",
            Hand::Service => "accepted, then dropped by sys-io",
            Hand::Neither => "neither refused nor dropped",
        }
    }
}

/// Probe a fresh io_channel client mid-episode: it dies at one of two racing
/// hands. The channel's own eager mapping (~200 pages) usually fails kernel
/// admission -- the band between the user floor and the low watermark is
/// about one io_channel wide -- so the client dies before the service ever
/// sees it; when the pool happens to sit high enough in the band, the
/// mapping is admitted and the service accepts, then drops, the connection.
/// Both are designed refusals; which fires depends on where in the band the
/// pool sits. The probe connects while the flag is up and watches the flag
/// while it waits for the drop: a client kept through a dip was accepted
/// across it, so `dips` counts the attempt and the probe connects again
/// once the flag is back; a client kept with the flag up throughout is
/// `Neither`. The connect error is returned for the caller to assert on --
/// immediately or after recovery, per that test's discipline.
fn probe_fresh_client(service: &str, dips: &mut usize) -> Result<Hand, moto_rt::Error> {
    let start = Instant::now();
    loop {
        if !flag_up() {
            return Ok(Hand::Neither);
        }
        let conn = moto_ipc::io_channel::ClientConnection::connect(service)?;
        let mut dropped = false;
        let mut dipped = false;
        for _ in 0..500 {
            if conn.wake_server().is_err() {
                dropped = true;
                break;
            }
            dipped |= !moto_sys::memory_pressure();
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(conn);
        if dropped {
            return Ok(Hand::Service);
        }
        if !dipped || start.elapsed() > Duration::from_secs(20) {
            return Ok(Hand::Neither);
        }
        *dips += 1;
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
    let mut dips = 0;

    // New sockets are refused by sys-io without a syscall...
    let mut refusals = Tally::default();
    refusals.count(until_refused(
        || TcpListener::bind("127.0.0.1:0").map(drop),
        &mut dips,
    ));
    refusals.count(until_refused(
        || TcpStream::connect(addr).map(drop),
        &mut dips,
    ));
    refusals.count(until_refused(
        || UdpSocket::bind("127.0.0.1:0").map(drop),
        &mut dips,
    ));
    sample_min(&mut min_free);

    // ...a process spawn fails fast in rt.vdso, before any work is done (one
    // spawned across a dip is reaped)...
    let exe = std::env::args().next().unwrap();
    refusals.count(until_refused(
        || {
            std::process::Command::new(&exe)
                .arg("subcommand")
                .spawn()
                .map(|mut child| {
                    let _ = child.kill();
                    let _ = child.wait();
                })
        },
        &mut dips,
    ));

    // ...and a fresh client connection to sys-io is refused at one of the
    // two hands in `probe_fresh_client`; judged with the rest after
    // recovery.
    let client_hand = match probe_fresh_client("sys-io", &mut dips) {
        Ok(hand) => hand,
        Err(err) => {
            assert_eq!(err, moto_rt::Error::OutOfMemory);
            Hand::Kernel
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
         residual {} pages; client probe: {}; flag dips {dips}",
        entry_free.saturating_sub(min_free),
        client_hand.describe(),
    );
    refusals.assert_all_refused(4, "sockets and spawn");
    assert_ne!(client_hand, Hand::Neither, "fresh sys-io client kept");
    assert!(sys_io_metric("net.pressure_entries") > entries_before);
    assert!(sys_io_metric("net.pressure_refused") >= refused_before + 3);
    if client_hand == Hand::Service {
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
    let path = crate::temp_path("systest-fs-pressure");
    let waiter_path = crate::temp_path("systest-fs-pressure-waiter");
    // Each hammer arm runs far longer than the channel's 64-slot page pool:
    // refused requests that leaked their donated pages would wedge the
    // channel within one arm.
    const HAMMER_WRITES: usize = 4096;
    const HAMMER_STATS: usize = 128;

    assert!(!moto_sys::memory_pressure(), "pressure before the squeeze");

    // The suite creates TMPDIR long before this test runs, but the standalone
    // form can run on a fresh image, where it does not exist yet.
    crate::ensure_temp_dir();

    // FS state from before the squeeze: an open file for the write hammer, a
    // held lock to release mid-episode, a second handle to probe acquires,
    // and `lock_spam` handles for the acquire spam -- opened now, because
    // opens are themselves refused once the flag is up.
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&[0u8; 4096]).unwrap();
    let lock_held = std::fs::File::open(&path).unwrap();
    lock_held.lock_shared().unwrap();
    let lock_probe = std::fs::File::open(&path).unwrap();
    let mut spam_handles = Vec::with_capacity(lock_spam);
    for _ in 0..lock_spam {
        spam_handles.push(std::fs::File::open(&path).unwrap());
    }

    // A queued lock waiter, on its own file so its queue cannot interact
    // with the acquire spam: the mid-episode unlock below must hand this
    // waiter its pre-encoded grant while the flag is up -- the half of the
    // UNLOCK carve-out that a waiter-free unlock never exercises.
    std::fs::File::create(&waiter_path).unwrap();
    let waiter_holder = std::fs::File::open(&waiter_path).unwrap();
    waiter_holder.lock_shared().unwrap();
    let waiter_handle = std::fs::File::open(&waiter_path).unwrap();
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
    let mut dips = 0;

    // Nothing below asserts until the episode is over: on a pre-refusal
    // build the early probes succeed, and an assert there would end the run
    // before the arm that actually kills sys-io (the lock hammer) ever runs.
    // Classify, then judge after recovery.
    let buf = [0xA5_u8; 2 * 4096];
    let mut writes = Tally::default();
    for i in 0..HAMMER_WRITES {
        // Alternate the request formats: a 4096-byte write donates one page
        // (`shared_pages[SINGLE_PAGE_SLOT]`), an 8192-byte write takes the
        // multi-page format -- a refusal must free the pages of both.
        let len = if i % 2 == 0 { 4096 } else { buf.len() };
        writes.count(until_refused(|| file.write_all(&buf[..len]), &mut dips));
    }

    // Read-only commands are in the refusal set too, and each metadata call
    // resolves its path afresh, donating a page to CMD_STAT -- this arm pins
    // the single-page release branch for a command other than CMD_WRITE.
    let mut stats = Tally::default();
    for _ in 0..HAMMER_STATS {
        stats.count(until_refused(
            || std::fs::metadata(&path).map(drop),
            &mut dips,
        ));
    }

    // The lock hammer: unbounded per-lock state in sys-io's lock manager.
    // Pre-refusal this grows sys-io past its floor and the machine dies
    // here, so acquisitions are retained until recovery; only a lock taken
    // across a dip is released before its retry.
    let mut locks = Tally::default();
    for handle in &spam_handles {
        locks.count(until_refused_undo(
            || handle.lock_shared(),
            || handle.unlock().unwrap(),
            &mut dips,
        ));
    }

    // UNLOCK is the carve-out, since Drop-based unlock never retries; the
    // waiter-file unlock also hands the queued waiter its grant while the
    // flag is up. A lock acquire stays refused.
    // The held shared lock makes an exclusive acquire served across a dip
    // report WouldBlock; served either way, it goes again after the dip.
    let acquire_verdict = until_refused(
        || match lock_probe.try_lock() {
            Ok(()) => lock_probe.unlock(),
            Err(std::fs::TryLockError::WouldBlock) => Ok(()),
            Err(std::fs::TryLockError::Error(err)) => Err(err),
        },
        &mut dips,
    );
    let unlock_result = lock_held.unlock();
    let waiter_unlock_result = waiter_holder.unlock();

    // Wait for the grant and the waiter's userspace teardown before
    // reserving a fresh channel mapping. `is_finished` can become true just
    // before the thread's TLS destructors run; `join` is the actual teardown
    // barrier. Running those destructors under the mapping's large temporary
    // admission reservation would violate this test's no-growth discipline.
    let mut waiter_finished = false;
    for _ in 0..10 * 10 {
        if waiter.is_finished() {
            waiter_finished = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let waiter_result = if waiter_finished {
        Some(waiter.join())
    } else {
        None
    };

    // A fresh FS client dies at one of the same two hands as a net client;
    // judged after recovery. Skip it if the waiter missed its bounded grant
    // deadline so the squeeze can still be released before reporting failure.
    let fs_client_probe = waiter_result
        .as_ref()
        .map(|_| probe_fresh_client("sys-io-fs", &mut dips));

    release_squeeze(child);

    // The episode's verdict, printed and asserted only now: println and the
    // metrics RPC both allocate, which nothing may do while the flag is up.
    println!(
        "fs under pressure: writes {writes:?}, stats {stats:?}, lock acquires {locks:?}, \
         acquire {acquire_verdict:?}, unlock {unlock_result:?}, \
         waiter unlock {waiter_unlock_result:?}, flag dips {dips}"
    );

    writes.assert_all_refused(HAMMER_WRITES, "FS writes");
    stats.assert_all_refused(HAMMER_STATS, "FS metadata");
    locks.assert_all_refused(lock_spam, "FS lock acquires");
    assert_eq!(
        acquire_verdict,
        Verdict::Refused,
        "lock acquire under pressure"
    );
    unlock_result.expect("UNLOCK refused under pressure");
    waiter_unlock_result.expect("waiter-file UNLOCK refused under pressure");

    // The queued waiter's grant was sent by the mid-episode unlock; on a
    // build that drops grants the bounded pre-probe wait expires. Report that
    // only after releasing the squeeze rather than hanging in join.
    waiter_result
        .expect("not within 10s: the queued lock waiter was granted")
        .unwrap();

    let client_hand = match fs_client_probe.expect("fresh FS client probe skipped") {
        Ok(hand) => hand,
        Err(err) => {
            assert_eq!(err, moto_rt::Error::OutOfMemory);
            Hand::Kernel
        }
    };
    assert_ne!(client_hand, Hand::Neither, "fresh sys-io-fs client kept");

    // Service resumes on the same handles and the same file.
    file.write_all(&buf).unwrap();
    assert!(std::fs::metadata(&path).unwrap().is_file());
    lock_probe.try_lock().unwrap();
    lock_probe.unlock().unwrap();
    drop(spam_handles);
    drop((file, lock_held, lock_probe, waiter_holder));
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&waiter_path).unwrap();

    // Counters: the three hammers plus the refused acquire probe, and the
    // client counter only if sys-io was the refusing hand.
    let hammered = (HAMMER_WRITES + HAMMER_STATS + lock_spam + 1) as u64;
    assert!(sys_io_metric("fs.pressure_refused") >= refused_before + hammered);
    if client_hand == Hand::Service {
        assert!(sys_io_metric("fs.pressure_refused_clients") > clients_refused_before);
    }

    println!("test_fs_under_pressure PASS");
}

/// The child side of the squeeze: drain free memory to `target_pages` and
/// hold it there until the parent writes a line to stdin. A housekeeping
/// tick in any process can hand back more than the gap to the high
/// watermark; the child drains again after every such return, but only
/// after `DIP_HOLD`, so the parent can see the flag down after a request
/// that the return let through.
pub fn run_pressure_squeeze_child(target_pages: u64) -> ! {
    // The stdin reader ends the squeeze; started before the drain, while its
    // thread charge is still admitted.
    std::thread::spawn(|| {
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        std::process::exit(0);
    });

    let above_target = || AdmissionStats::get().unwrap().free_for_admission() > target_pages;
    let mut squeezed = false;
    loop {
        if above_target() {
            if squeezed {
                std::thread::sleep(DIP_HOLD);
            }
            while above_target() && SysMem::alloc(PAGE_SIZE_SMALL, 64).is_ok() {}
        }
        if !squeezed {
            squeezed = true;
            // The parent must not probe before the squeeze is complete.
            println!("squeezed");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
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
