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
/// `admission::kernel_metric`.
fn sys_io_metric(name: &str) -> u64 {
    use moto_stats::Collector;

    let provider = Collector::provider_by_name("sys-io").expect("no sys-io stats provider");
    let descs = Collector::describe(&provider).unwrap();
    let desc = descs
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("no sys-io metric '{name}'"));
    Collector::query(&provider)
        .unwrap()
        .iter()
        .find(|e| e.metric == desc.id && e.scope == moto_stats::SCOPE_GLOBAL)
        .map(|e| e.value)
        .unwrap_or_else(|| panic!("sys-io metric '{name}' not reported"))
}

/// Refusals travel as E_OUT_OF_MEMORY; accept whichever representation the
/// std port surfaces.
fn assert_refused(err: &std::io::Error) {
    assert!(
        err.kind() == std::io::ErrorKind::OutOfMemory
            || err.raw_os_error() == Some(moto_rt::E_OUT_OF_MEMORY as i32),
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
}
