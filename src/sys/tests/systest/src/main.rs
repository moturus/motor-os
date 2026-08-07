#![feature(addr_parse_ascii)]
#![feature(motor_ext)]
#![feature(random)]

mod admission;
// mod channel_test;
mod command_output;
mod file_locking;
mod fs;
mod icmp;
mod io_channel;
mod logging;
mod moto_async;
mod mpmc;
mod net_driver;
mod poll;
mod pressure;
mod spawn_wait_kill;
mod stats;
mod stdio;
mod stdio_terminal;
mod subcommand;
mod sys_io_self_test;
mod sysbox_find;
mod tcp;
mod threads;
mod tls;
mod udp;
mod xor_server;

use std::{
    io::{Read, Write},
    sync::{Arc, Barrier, atomic::*},
    time::Duration,
};

use moto_sys::SysHandle;

fn test_syscall() {
    const ITERS: usize = 1_000_000;
    let start = std::time::Instant::now();
    for _ in 0..ITERS {
        let res = moto_sys::syscalls::do_syscall(u64::MAX, 0, 0, 0, 0, 0, 0);
        assert!(!res.is_ok());
    }
    let elapsed = start.elapsed();

    let ns_per_syscall = (elapsed.as_nanos() as f64) / (ITERS as f64);

    println!("test_syscall: {ITERS} iterations: {ns_per_syscall:.2} ns/syscall.");
}

// A dup'd handle has its own kernel missed-wake latch: a wake pending on the
// object must be deliverable through each handle independently. This is what
// lets the vdso readiness task wait on a dup of a pollee's handle without
// stealing wakes from blocking reads on the original (EventSourceUnmanaged).
fn test_handle_dup() {
    use moto_sys::SysObj;

    let wait = |handle: SysHandle, timeout_ms: Option<u64>| {
        moto_sys::SysCpu::wait(
            &mut [handle],
            SysHandle::NONE,
            SysHandle::NONE,
            timeout_ms
                .map(|ms| moto_rt::time::Instant::now() + std::time::Duration::from_millis(ms)),
        )
    };

    // Built-in pseudo handles are not in the process handle table.
    assert!(SysObj::dup(SysHandle::NONE).is_err());
    assert!(SysObj::dup(SysHandle::SELF).is_err());

    let (h1, h2) = SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();
    let h2_dup = SysObj::dup(h2).unwrap();
    assert_ne!(h2, h2_dup);

    // Latch a wake on h2's object while nobody waits on it.
    moto_sys::SysCpu::wake(h1).unwrap();

    // The pending wake is delivered through each handle...
    wait(h2_dup, Some(5000)).expect("wake lost on dup'd handle");
    wait(h2, Some(5000)).expect("wake consumed through the dup'd handle");
    // ...exactly once per handle.
    assert_eq!(wait(h2_dup, Some(20)), Err(moto_rt::E_TIMED_OUT));
    assert_eq!(wait(h2, Some(20)), Err(moto_rt::E_TIMED_OUT));

    // A put dup neither invalidates the original nor consumes its wakes.
    SysObj::put(h2_dup).unwrap();
    assert_eq!(wait(h2_dup, Some(20)), Err(moto_rt::E_BAD_HANDLE));
    moto_sys::SysCpu::wake(h1).unwrap();
    wait(h2, Some(5000)).expect("wake lost after dup put");

    SysObj::put(h1).unwrap();
    SysObj::put(h2).unwrap();
    println!("test_handle_dup PASS");
}

fn test_rt_mutex() {
    use moto_rt::mutex::Mutex;

    static COUNTER: Mutex<u64> = Mutex::new(0);
    const THREADS: u16 = 40;

    let mut threads = vec![];
    *COUNTER.lock() = 0;

    for _idx in 0..THREADS {
        threads.push(std::thread::spawn(|| {
            let mut val = COUNTER.lock();
            *val += 1;
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    assert_eq!(THREADS, *COUNTER.lock() as u16);
    println!("test_rt_mutex PASS");
}

fn test_reentrant_mutex() {
    let _lock1 = std::io::stdout().lock();
    let mut lock2 = std::io::stdout().lock();
    lock2
        .write_all(b"test_reentrant_stdout lock PASS\n")
        .unwrap();
}

fn test_cpus() {
    // Spin-loop until all CPUs have been "live".
    let mut cpus: Arc<Vec<AtomicBool>> = Arc::new(vec![]);
    for _i in 0..moto_sys::num_cpus() {
        Arc::get_mut(&mut cpus)
            .unwrap()
            .push(AtomicBool::new(false));
    }

    let num_threads: u16 = moto_sys::num_cpus() as u16;

    let mut threads = vec![];
    for _idx in 0..num_threads {
        let cpus_clone = cpus.clone();
        threads.push(std::thread::spawn(move || {
            loop {
                let cpu = moto_sys::current_cpu() as usize;
                cpus_clone[cpu].store(true, Ordering::Relaxed);

                let mut count = 0;
                for idx in 0..cpus_clone.len() {
                    let cpu = &cpus_clone[idx];
                    if cpu.load(Ordering::Relaxed) {
                        count += 1;
                    }
                }

                if count == moto_sys::num_cpus() {
                    return;
                }
            }
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    println!("test_cpus PASS");
}

// rt.vdso draws eight bytes at a time and copies the tail out of the last draw,
// so what is worth pinning is the arithmetic around that: sizes that are not a
// multiple of eight, the byte past the caller's buffer, and one fresh draw per
// chunk. The retry path itself cannot be reached without a seam over RDRAND and
// is reviewed rather than tested.
fn test_random_bytes() {
    const GUARD: u8 = 0xab;

    for size in 1..=17_usize {
        let mut last = [0_u8; 8];
        for draw in &mut last {
            let mut buf = [GUARD; 24];
            moto_rt::fill_random_bytes(&mut buf[..size]);
            assert!(
                buf[size..].iter().all(|byte| *byte == GUARD),
                "fill_random_bytes({size}) wrote past the buffer"
            );
            *draw = buf[size - 1];
        }
        // Eight draws agreeing on the last byte means it is never written; an
        // honest source repeats itself seven times over with odds of 2^-56.
        assert!(
            last.iter().any(|byte| *byte != last[0]),
            "fill_random_bytes({size}) left its last byte alone"
        );
    }

    let mut empty = [GUARD; 1];
    moto_rt::fill_random_bytes(&mut empty[..0]);
    assert_eq!(empty[0], GUARD);

    // Identical chunks would be one draw hoisted out of the loop, identical
    // calls a source that is not drawing at all.
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    moto_rt::fill_random_bytes(&mut first);
    moto_rt::fill_random_bytes(&mut second);
    assert!(first.chunks(8).any(|chunk| chunk != &first[..8]));
    assert_ne!(first, second);

    println!("test_random_bytes PASS");
}

fn test_ipc() {
    use moto_ipc::sync::*;

    let mut xor_service = subcommand::spawn();
    xor_service.start_xor_service();

    // start_xor_service() only writes a command to the child's stdin; the child
    // must then read it, spawn a thread, and register "xor-service" before this
    // connect can succeed. That whole chain is not bounded by any fixed delay --
    // under load it takes well over the 1ms this used to sleep, and connect then
    // returns NotFound. connect() early-returns without mutating on failure, so
    // the same object can be retried; a service that never appears still fails.
    let mut conn = ClientConnection::new(ChannelSize::Small).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match conn.connect("xor-service") {
            Ok(()) => break,
            Err(err) => {
                assert!(
                    err == moto_rt::E_NOT_FOUND && std::time::Instant::now() < deadline,
                    "connect(xor-service): {err}"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }

    #[cfg(debug_assertions)]
    const STEPS: u64 = 1_000;
    #[cfg(not(debug_assertions))]
    const STEPS: u64 = 100_000;

    // let prev_log_level = moto_sys::syscalls::SysCtl::set_log_level(4).unwrap();
    let start = std::time::Instant::now();
    for idx in 0..STEPS {
        let req = conn.req::<xor_server::XorRequest>();
        req.data = 0xdeadbeef ^ idx;
        assert!(conn.connected());
        conn.do_rpc(None).expect("???");
        let resp = conn.resp::<xor_server::XorResponse>();
        assert_eq!(resp.data ^ (0xdeadbeef ^ idx), u64::MAX);
    }
    let stop = std::time::Instant::now();

    let num_cpus = moto_sys::KernelStaticPage::get().num_cpus;
    let mut cpu_usage = vec![0.0; num_cpus as usize];
    moto_sys::stats::get_cpu_usage(&mut cpu_usage).unwrap();

    conn.disconnect();
    xor_service.do_exit(0);

    let nanos = (stop - start).as_nanos();
    assert!(nanos > 0);
    assert!(nanos < (u64::MAX as u128));
    println!(
        "test_ipc: {} RPC calls (roundtrips) in {} nanoseconds: {} ns per RPC.",
        STEPS,
        nanos,
        (nanos as u64) / STEPS
    );

    for cpu in 0..num_cpus {
        println!("\tCPU {cpu} usage: {:.3}", cpu_usage[cpu as usize]);
    }
}

fn test_lazy_memory_map_read() {
    use moto_sys::*;

    let addr = SysMem::map(
        SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        sys_mem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();

    let buf = unsafe {
        core::slice::from_raw_parts_mut(addr as usize as *mut u8, sys_mem::PAGE_SIZE_SMALL as usize)
    };

    #[allow(clippy::needless_range_loop)]
    for idx in 0..buf.len() {
        assert_eq!(0, buf[idx]);
    }
    std::thread::sleep(std::time::Duration::from_millis(100));

    #[allow(clippy::needless_range_loop)]
    for idx in 0..buf.len() {
        buf[idx] = (idx % (u8::MAX as usize)) as u8;
        assert_eq!(buf[idx], (idx % (u8::MAX as usize)) as u8);
    }

    SysMem::free(addr).unwrap();
    println!("test_lazy_memory_map_read: done");
}

fn test_lazy_memory_map_write() {
    use moto_sys::*;

    let addr = SysMem::map(
        SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        sys_mem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();

    let buf = unsafe {
        core::slice::from_raw_parts_mut(addr as usize as *mut u8, sys_mem::PAGE_SIZE_SMALL as usize)
    };

    #[allow(clippy::needless_range_loop)]
    for idx in 0..buf.len() {
        buf[idx] = (idx % (u8::MAX as usize)) as u8;
    }

    #[allow(clippy::needless_range_loop)]
    for idx in 0..buf.len() {
        assert_eq!(buf[idx], (idx % (u8::MAX as usize)) as u8);
    }

    SysMem::free(addr).unwrap();
    println!("test_lazy_memory_map_write: done");
}

fn test_concurrent_lazy_memory_map_write() {
    use moto_sys::*;

    const NUM_THREADS: usize = 8;
    const NUM_PAGES: usize = 8192;
    const PAGE_SIZE: usize = sys_mem::PAGE_SIZE_SMALL as usize;
    const CHUNK_SIZE: usize = PAGE_SIZE / NUM_THREADS;

    let addr = SysMem::map(
        SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        sys_mem::PAGE_SIZE_SMALL,
        NUM_PAGES as u64,
    )
    .unwrap();

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut threads = Vec::with_capacity(NUM_THREADS);
    for thread_idx in 0..NUM_THREADS {
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            for page_idx in 0..NUM_PAGES {
                barrier.wait();
                let offset = page_idx * PAGE_SIZE + thread_idx * CHUNK_SIZE;
                unsafe {
                    (addr as usize as *mut u8)
                        .add(offset)
                        .write_bytes((thread_idx + 1) as u8, CHUNK_SIZE);
                }
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }

    let pages =
        unsafe { core::slice::from_raw_parts(addr as usize as *const u8, NUM_PAGES * PAGE_SIZE) };
    for page_idx in 0..NUM_PAGES {
        for thread_idx in 0..NUM_THREADS {
            let start = page_idx * PAGE_SIZE + thread_idx * CHUNK_SIZE;
            let expected = (thread_idx + 1) as u8;
            assert!(
                pages[start..start + CHUNK_SIZE]
                    .iter()
                    .all(|byte| *byte == expected),
                "concurrent first touch lost writes on page {page_idx}, chunk {thread_idx}"
            );
        }
    }

    SysMem::free(addr).unwrap();
    println!("test_concurrent_lazy_memory_map_write: done");
}

fn test_invalid_memory_map_options() {
    use moto_sys::*;

    for flags in [
        SysMem::F_SHARE_SELF,
        SysMem::F_SHARE_SELF | SysMem::F_WRITABLE,
        SysMem::F_SHARE_SELF | SysMem::F_EXECUTABLE,
        SysMem::F_SHARE_SELF | SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_EXECUTABLE,
    ] {
        assert_eq!(
            SysMem::map2(
                SysHandle::SELF,
                flags,
                u64::MAX,
                u64::MAX,
                sys_mem::PAGE_SIZE_SMALL,
                1,
            ),
            Err(moto_rt::E_INVALID_ARGUMENT)
        );
    }

    assert_eq!(
        SysMem::map2(
            SysHandle::SELF,
            SysMem::F_SHARE_SELF | SysMem::F_READABLE | SysMem::F_EXECUTABLE,
            u64::MAX,
            u64::MAX,
            sys_mem::PAGE_SIZE_SMALL,
            1,
        ),
        Err(moto_rt::E_NOT_ALLOWED)
    );

    println!("test_invalid_memory_map_options PASS");
}

// First-touch fault throughput: maps a lazy region and writes one u64 per
// page. Each touch takes the full uspace #PF path (preempt machinery, see
// scheduler-work.md S6/S8), so ns/fault tracks kernel #PF-entry costs.
fn bench_page_faults() {
    use moto_sys::*;

    const NUM_PAGES: u64 = 8192; // 32 MiB.
    let addr = SysMem::map(
        SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        sys_mem::PAGE_SIZE_SMALL,
        NUM_PAGES,
    )
    .unwrap();

    let start = std::time::Instant::now();
    for page in 0..NUM_PAGES {
        let ptr = (addr + page * sys_mem::PAGE_SIZE_SMALL) as *mut u64;
        unsafe { ptr.write_volatile(page) };
    }
    let elapsed = start.elapsed();
    SysMem::free(addr).unwrap();

    println!(
        "bench_page_faults: {NUM_PAGES} first-touch faults: {:.0} ns/fault, {:.0} faults/s",
        elapsed.as_nanos() as f64 / NUM_PAGES as f64,
        NUM_PAGES as f64 / elapsed.as_secs_f64()
    );
}

// MXCSR and the x87 control word are callee-saved in the SysV ABI, so they
// must survive a blocking syscall (S10: the kernel's pause/resume path skips
// xsave/xrstor; before the fix another thread's FP env could leak in).
fn test_fp_env_across_blocking_syscall() {
    use core::arch::x86_64::{_mm_getcsr, _mm_setcsr};

    const FTZ_DAZ: u32 = 0x8040; // Flush-to-zero + denormals-are-zero.

    let orig_mxcsr = unsafe { _mm_getcsr() };
    assert_eq!(orig_mxcsr & FTZ_DAZ, 0);
    unsafe { _mm_setcsr(orig_mxcsr | FTZ_DAZ) };

    // Blocks in sys_wait with a timeout => TCB::pause()/resume() round trip.
    std::thread::sleep(std::time::Duration::from_millis(30));

    let mxcsr = unsafe { _mm_getcsr() };
    unsafe { _mm_setcsr(orig_mxcsr) };
    assert_eq!(
        mxcsr & FTZ_DAZ,
        FTZ_DAZ,
        "MXCSR FTZ/DAZ lost across a blocking syscall"
    );

    println!("test_fp_env_across_blocking_syscall PASS");
}

fn test_file_write() {
    const WRITTEN: &str = "Lorem Ipsum";

    let mut path = std::env::temp_dir();
    path.push("temp_file");

    if path.exists() {
        std::fs::remove_file(path.clone()).unwrap();
    }

    // Write.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.clone())
        .unwrap_or_else(|_| panic!("Failed to create {path:?}"));

    file.write_all(WRITTEN.as_bytes()).unwrap();
    std::mem::drop(file); // Close it.

    // Read.
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .open(path.clone())
        .unwrap();
    let mut read_back = String::new();
    file.read_to_string(&mut read_back).unwrap();

    assert_eq!(read_back.as_str(), WRITTEN);
    core::mem::drop(file);
    std::fs::remove_file(path.clone()).unwrap();

    println!("test_file_write() PASS");
}

fn test_oom() {
    let mut child = subcommand::spawn();
    child.oom();
    let status = child.wait().unwrap();
    assert!(!status.success());

    println!("test_oom() PASS");
}

// W^X: executing from heap or stack must kill the process (NX).
fn test_nx() {
    let mut child = subcommand::spawn();
    child.exec_heap();
    let status = child.wait().unwrap();
    assert!(!status.success());

    let mut child = subcommand::spawn();
    child.exec_stack();
    let status = child.wait().unwrap();
    assert!(!status.success());

    println!("test_nx() PASS");
}

fn test_writable_executable_elf_rejected() {
    let mut bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2); // ELFCLASS64
    assert_eq!(bytes[5], 1); // ELFDATA2LSB

    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    let mut modified = false;
    for idx in 0..phnum {
        let offset = phoff + idx * phentsize;
        let kind = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let flags = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        if kind == 1 && flags & 1 != 0 {
            bytes[offset + 4..offset + 8].copy_from_slice(&(flags | 2).to_le_bytes());
            modified = true;
            break;
        }
    }
    assert!(modified, "current executable has no executable PT_LOAD");

    let path = std::env::temp_dir().join("systest-writable-executable-elf");
    std::fs::write(&path, bytes).unwrap();
    let result = std::process::Command::new(&path)
        .arg("test-native-net-cancellation")
        .spawn();
    std::fs::remove_file(path).unwrap();

    if let Ok(mut child) = result {
        let _ = child.kill();
        let status = child.wait().unwrap();
        panic!("loader accepted a writable executable PT_LOAD: {status}");
    }

    println!("test_writable_executable_elf_rejected PASS");
}

fn test_caps() {
    assert_eq!(
        0,
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_SYS
    );

    assert!(
        std::process::Command::new(std::env::args().next().unwrap())
            .arg("subcommand")
            .env(
                moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
                format!("0x{:x}", moto_sys::caps::CAP_SYS),
            )
            .spawn()
            .is_err()
    );

    println!("test_caps() PASS");
}

fn test_thread_names() {
    let handle = std::thread::current();
    assert_eq!(handle.name(), Some("main"));

    let t_data = moto_sys::SysRay::dbg_get_thread_data_v1(
        SysHandle::SELF,
        moto_sys::UserThreadControlBlock::this_thread_tid(),
    )
    .unwrap();
    assert_eq!(t_data.thread_name(), "main");

    let builder = std::thread::Builder::new().name("foo".into());

    builder
        .spawn(|| {
            assert_eq!(std::thread::current().name(), Some("foo"));
            let t_data = moto_sys::SysRay::dbg_get_thread_data_v1(
                SysHandle::SELF,
                moto_sys::UserThreadControlBlock::this_thread_tid(),
            )
            .unwrap();
            assert_eq!(t_data.thread_name(), "foo");
        })
        .unwrap()
        .join()
        .unwrap();

    const LONG_NAME: &str = "foo__0123456789012345678901234567890123456789";
    let builder = std::thread::Builder::new().name(LONG_NAME.into());

    builder
        .spawn(|| {
            assert_eq!(std::thread::current().name(), Some(LONG_NAME));
            let t_data = moto_sys::SysRay::dbg_get_thread_data_v1(
                SysHandle::SELF,
                moto_sys::UserThreadControlBlock::this_thread_tid(),
            )
            .unwrap();
            // Names that are too long are ignored at the OS level.
            assert_eq!(t_data.thread_name(), "");
        })
        .unwrap()
        .join()
        .unwrap();

    println!("test_thread_names() PASS");
}

fn test_liveness() {
    // Spinloop on each CPU; then test that sleep/wake behaves OK.
    let mut cpus: Arc<Vec<crossbeam::utils::CachePadded<AtomicU64>>> = Arc::new(vec![]);
    for _i in 0..moto_sys::num_cpus() {
        Arc::get_mut(&mut cpus)
            .unwrap()
            .push(crossbeam::utils::CachePadded::new(AtomicU64::new(0)));
    }

    let stop = Arc::new(AtomicBool::new(false));

    let num_cpus = moto_sys::num_cpus() as u16;

    // Spawn spinning threads, one for each CPU.
    let mut threads = vec![];
    for _idx in 0..num_cpus {
        let cpus_clone = cpus.clone();
        let stop_clone = stop.clone();
        threads.push(std::thread::spawn(move || {
            loop {
                let cpu = moto_sys::current_cpu() as usize;
                cpus_clone[cpu].fetch_add(1, Ordering::Relaxed);

                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
            }
        }));
    }

    // Wait until all CPUs are used.
    for cpu in 0..num_cpus {
        while cpus[cpu as usize].load(Ordering::Relaxed) < 1000 {}
    }

    // We are running in a VM. Give the host time to use num_cpus.
    std::thread::sleep(std::time::Duration::from_millis(15));

    // Test that this (main) thread is responsive.
    const NUM_ITERS: usize = 100;
    assert_eq!(0, NUM_ITERS % 100);

    let mut results: Vec<u64> = Vec::with_capacity(NUM_ITERS);
    for _ in 0..NUM_ITERS {
        let started_sleeping = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let slept = std::time::Instant::now() - started_sleeping;
        results.push(slept.as_millis().try_into().unwrap());
    }

    results.sort();

    // Sched tick is 10ms or less.
    const P50: u64 = 15;
    const P99: u64 = 25;

    // This measures how promptly a sleeping thread is resumed, which bounds
    // only what the guest controls. Under `--under-load` the harness has told
    // us the host multiplexes our vCPUs onto fewer cores (the stress soak runs
    // 8 vCPUs on 2), so the tail here is host descheduling, not guest
    // scheduling: observed p99 of 27-54ms against this 25ms bound while p50
    // stayed at 3ms. Keep loose bounds there so a real breakdown still fails.
    const P50_LOADED: u64 = 100;
    const P99_LOADED: u64 = 1000;
    let (p50_max, p99_max) = if under_load() {
        (P50_LOADED, P99_LOADED)
    } else {
        (P50, P99)
    };

    let p50 = results[(NUM_ITERS / 2) - 1];

    if p50 > p50_max {
        panic!("test_liveness: p50 {p50}");
    }

    let p99 = results[(NUM_ITERS * 99 / 100) - (NUM_ITERS / 100) - 1];
    if p99 > p99_max {
        panic!("test_liveness: p99 {p99}");
    }

    stop.store(true, Ordering::Release);

    for thread in threads {
        thread.join().unwrap();
    }

    println!(
        "test_liveness() PASS: p50: {p50}, p99: {p99}, max: {}",
        results[NUM_ITERS - 1]
    );
}

fn input_listener() {
    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        if sz == 0 {
            // EOF: stdin is gone; no ^C can ever arrive.
            return;
        }
        for b in &input[0..sz] {
            if *b == 3 {
                println!("Caught ^C: exiting.");
                std::process::exit(1);
            }
        }
    }
}

/// Set by `--under-load`: the harness is running us in a deliberately degraded
/// environment (vCPUs oversubscribed onto fewer host cores), where wall-clock
/// SLOs that depend on host scheduling cannot hold. Correctness checks are
/// unaffected -- only latency bounds consult this.
static UNDER_LOAD: AtomicBool = AtomicBool::new(false);

pub(crate) fn under_load() -> bool {
    UNDER_LOAD.load(Ordering::Relaxed)
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "--under-load" {
        UNDER_LOAD.store(true, Ordering::Relaxed);
        args.truncate(1); // Not a subcommand: run the normal suite.
    }
    if args.len() == 2 && args[1] == "test-native-net-cancellation" {
        tcp::test_native_net_cancellation();
        return;
    }
    if args.len() == 2 && args[1] == "test-native-listener-drop-backpressure" {
        tcp::test_native_listener_drop_backpressure();
        return;
    }
    if args.len() == 2 && args[1] == "test-concurrent-flush-stress" {
        fs::concurrent_flush_stress_test();
        return;
    }
    // The FS pressure regression; the suite runs the same body at spam size
    // 128. The optional argument sizes the mid-episode lock-acquire spam;
    // the large default exists to drive a build *without* the FS refusal set
    // into a sys-io OOM -- a demonstrator, not a test: run that form on a
    // disposable release boot and read the verdict from the serial log.
    if (args.len() == 2 || args.len() == 3) && args[1] == "test-fs-pressure" {
        let lock_spam = args
            .get(2)
            .map(|arg| arg.parse().unwrap())
            .unwrap_or(100_000);
        pressure::test_fs_under_pressure(lock_spam);
        return;
    }
    if args.len() == 2 && args[1] == "test-ipv6-loopback" {
        tcp::test_ipv6();
        return;
    }
    // The suite runs one round of the rebind race; the knob for a soak of just
    // that loop, which is how narrow the race is -- it took tens of thousands
    // of iterations to lose.
    if args.len() == 3 && args[1] == "udp-rebind-soak" {
        for round in 0..args[2].parse::<u32>().unwrap() {
            println!("-- udp-rebind-soak round {round}");
            udp::udp_rebind_after_close_test();
        }
        println!("PASS");
        return;
    }
    if args.len() == 2 && args[1] == "test-shared-listener-restart" {
        spawn_wait_kill::test_shared_listener_restart();
        return;
    }
    if spawn_wait_kill::is_shared_listener_child(&args) {
        spawn_wait_kill::run_shared_listener_child();
    }
    if spawn_wait_kill::is_pid_query_child(&args) {
        spawn_wait_kill::run_pid_query_child();
    }
    if spawn_wait_kill::is_spawn_result_pid_child(&args) {
        spawn_wait_kill::run_spawn_result_pid_child();
    }
    // The suite runs these at a size that fits a full run; this is the knob
    // for a long soak of the same exchange.
    if args.len() == 4 && args[1] == "stdio-poll-stress" {
        if args[2] == "child_stress" {
            stdio::child_poll_stress(args[3].parse().unwrap());
        } else {
            stdio::poll_stress(&args[2], args[3].parse().unwrap());
        }
        println!("PASS");
        return;
    }
    if args.get(1).map(String::as_str) == Some("move-noreplace-child") {
        fs::move_noreplace_child(&args);
        return;
    }
    if command_output::is_child(&args) {
        command_output::run_child(&args);
    }
    // The focused entry the terminal acceptance script (src/tests/test-tui.sh)
    // uses; the full suite runs the same tests via stdio::run_all_tests().
    if args.len() == 2 && args[1] == "stdio-terminal-tests" {
        stdio_terminal::run_all_tests();
        println!("PASS");
        return;
    }
    if stdio_terminal::is_report_child(&args) {
        stdio_terminal::run_report_child();
    }
    if stdio_terminal::is_mask_child(&args) {
        stdio_terminal::run_mask_child();
    }
    if io_channel::is_spawn_read_child(&args) {
        return;
    }
    if args.len() > 1 {
        if args[1] == "file-lock-test" {
            file_locking::run_tests();
            return;
        }
        if args[1] == "file-lock-child" {
            file_locking::child()
        }
        subcommand::run_child(args)
    }

    std::thread::spawn(input_listener);

    println!("Systest starting...");

    assert!(!args.is_empty());
    assert_eq!(
        args[0],
        std::env::current_exe()
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap()
    );

    // Run the logging test first, as it sets the logger for everything.
    logging::run_all_tests();
    test_invalid_memory_map_options();
    test_lazy_memory_map_read();
    test_lazy_memory_map_write();
    test_concurrent_lazy_memory_map_write();
    bench_page_faults();
    test_fp_env_across_blocking_syscall();
    fs::run_tests();
    file_locking::run_tests();
    // return;

    // Test that a userspace interrupt is handled correctly.
    unsafe { core::arch::asm!("int 3") }

    unsafe { std::env::set_var("foo", "bar") };
    assert_eq!(std::env::var("foo").unwrap(), "bar");

    // We should never be allowed to shut down the sytem.
    assert_eq!(
        moto_sys::SysCpu::kill(SysHandle::KERNEL).err().unwrap(),
        moto_rt::E_NOT_ALLOWED
    );

    test_syscall();
    test_handle_dup();
    threads::run_all_tests();
    moto_async::run_all_tests();
    poll::run_all_tests();
    io_channel::run_all_tests();
    test_thread_names();
    test_cpus();
    test_random_bytes();
    tls::test_tls();
    tls::test_tls_join();
    test_caps();
    test_liveness();

    spawn_wait_kill::test_pid_invariants();
    spawn_wait_kill::test_process_pid_query();
    spawn_wait_kill::test_child_id();
    spawn_wait_kill::test_spawn_result_pid();
    spawn_wait_kill::smoke_test();
    spawn_wait_kill::test_pid_kill();
    spawn_wait_kill::test_shared_listener_restart();
    command_output::run_test();
    sysbox_find::run_test();
    test_oom();
    admission::run_all_tests();
    test_nx();
    test_writable_executable_elf_rejected();
    std::thread::sleep(Duration::new(1, 10_000_000));
    test_rt_mutex();
    sys_io_self_test::run_all_tests();
    net_driver::run_all_tests();
    tcp::run_all_tests();
    udp::run_all_tests();
    icmp::run_all_tests();
    pressure::run_all_tests();

    mpmc::test_mpmc();
    mpmc::test_array_queue();
    // channel_test::test_io_channel();
    // channel_test::test_io_latency();
    // channel_test::test_io_throughput();
    test_reentrant_mutex();
    // tcp::test_wget();
    test_file_write();

    test_lazy_memory_map_read();
    test_lazy_memory_map_write();
    test_ipc();
    stats::test_stats_provider();
    stdio::run_all_tests();
    // fs::run_tests();

    println!("PASS");

    std::thread::sleep(Duration::new(0, 10_000_000));
}
