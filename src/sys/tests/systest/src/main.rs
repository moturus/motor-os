#![feature(addr_parse_ascii)]
#![feature(moturus_ext)]

// mod channel_test;
mod fs;
mod mpmc;
mod spawn_wait_kill;
mod stdio;
mod subcommand;
mod tcp;
mod threads;
mod tls;
mod udp;
mod xor_server;

use std::{
    io::{Read, Write},
    sync::{atomic::*, Arc},
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
        threads.push(std::thread::spawn(move || loop {
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
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    println!("test_cpus PASS");
}

fn test_ipc() {
    use moto_ipc::sync::*;

    let mut xor_service = subcommand::spawn();
    xor_service.start_xor_service();

    #[cfg(debug_assertions)]
    std::thread::sleep(std::time::Duration::new(0, 100_000_000));
    #[cfg(not(debug_assertions))]
    std::thread::sleep(std::time::Duration::new(0, 1_000_000));

    let mut conn = ClientConnection::new(ChannelSize::Small).unwrap();
    conn.connect("xor-service").unwrap();

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

fn test_lazy_memory_map() {
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
    // let prev_log_level = moto_sys::syscalls::SysCtl::set_log_level(4).unwrap();
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

    // moto_sys::syscalls::SysCtl::set_log_level(prev_log_level).unwrap();
    SysMem::free(addr).unwrap();
    println!("test_lazy_memory_map: done");
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

fn test_caps() {
    assert_eq!(
        0,
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_SYS
    );

    assert!(std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .env(
            moto_sys::caps::MOTURUS_CAPS_ENV_KEY,
            format!("0x{:x}", moto_sys::caps::CAP_SYS),
        )
        .spawn()
        .is_err());

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
        threads.push(std::thread::spawn(move || loop {
            let cpu = moto_sys::current_cpu() as usize;
            cpus_clone[cpu].fetch_add(1, Ordering::Relaxed);

            if stop_clone.load(Ordering::Relaxed) {
                break;
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

    let p50 = results[(NUM_ITERS / 2) - 1];

    if p50 > P50 {
        panic!("test_liveness: p50 {p50}");
    }

    let p99 = results[(NUM_ITERS * 99 / 100) - (NUM_ITERS / 100) - 1];
    if p99 > P99 {
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
        for b in &input[0..sz] {
            if *b == 3 {
                println!("Caught ^C: exiting.");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        subcommand::run_child(args)
    }

    std::thread::spawn(input_listener);

    println!("Systest starting...");

    // Test that a userspace interrupt is handled correctly.
    unsafe { core::arch::asm!("int 3") }

    std::env::set_var("foo", "bar");
    assert_eq!(std::env::var("foo").unwrap(), "bar");

    test_thread_names();
    test_cpus();
    tls::test_tls();
    tls::test_tls_join();
    test_caps();
    test_liveness();

    spawn_wait_kill::smoke_test();
    spawn_wait_kill::test_pid_kill();
    test_oom();
    std::thread::sleep(Duration::new(1, 10_000_000));
    test_rt_mutex();
    tcp::run_all_tests();
    udp::run_all_tests();

    mpmc::test_mpmc();
    mpmc::test_array_queue();
    // channel_test::test_io_channel();
    // channel_test::test_io_latency();
    // channel_test::test_io_throughput();
    test_reentrant_mutex();
    // tcp::test_wget();
    test_file_write();

    test_lazy_memory_map();
    test_syscall();
    threads::run_all_tests();
    test_ipc();
    stdio::run_all_tests();
    fs::run_tests();

    println!("PASS");

    std::thread::sleep(Duration::new(0, 10_000_000));
}
