mod channel_test;
mod spawn_wait_kill;
mod subcommand;
mod tcp;

use std::{
    io::Read,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering},
        Arc,
    },
};

fn test_syscall() {
    const ITERS: usize = 1_000_000;
    let start = std::time::Instant::now();
    for _ in 0..ITERS {
        let res = moto_sys::syscalls::do_syscall(u64::MAX, 0, 0, 0, 0, 0, 0);
        assert!(!res.is_ok());
    }
    let elapsed = start.elapsed();

    let ns_per_syscall = (elapsed.as_nanos() as f64) / (ITERS as f64);

    println!(
        "test_syscall: {} iterations: {:.2} ns/syscall.",
        ITERS, ns_per_syscall
    );
}

fn test_futex() {
    use moto_runtime::futex::*;

    static FUTEX: AtomicU32 = AtomicU32::new(0);
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    const THREADS: u16 = 20;

    COUNTER.store(0, Ordering::Release);
    let mut threads = vec![];

    for _idx in 0..THREADS {
        threads.push(std::thread::spawn(|| {
            while !FUTEX
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                futex_wait(&FUTEX, 1, None);
            }

            let prev = COUNTER.fetch_add(1, Ordering::Release);
            FUTEX.store(0, Ordering::Relaxed);

            if (prev & 1) == 0 {
                futex_wake(&FUTEX);
            } else {
                futex_wake_all(&FUTEX);
            }
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    assert_eq!(THREADS, COUNTER.load(Ordering::Acquire));
    println!("test_futex PASS");
}

fn test_rt_mutex() {
    use moto_runtime::mutex::Mutex;

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

fn test_cpus() {
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

    let mut conn = ClientConnection::new(ChannelSize::Small).unwrap();
    conn.connect("xor-service").unwrap();

    #[cfg(debug_assertions)]
    const STEPS: u64 = 10_000;
    #[cfg(not(debug_assertions))]
    const STEPS: u64 = 1_000_000;

    // let prev_log_level = moto_sys::syscalls::SysCtl::set_log_level(4).unwrap();
    let start = std::time::Instant::now();
    for idx in 0..STEPS {
        let data_in: &mut u64 =
            unsafe { (conn.data_mut().as_mut_ptr() as *mut u64).as_mut().unwrap() };
        *data_in = 0xdeadbeef ^ idx;
        assert!(conn.connected());
        conn.do_rpc(None).expect("???");
        let data_out: &u64 = unsafe { (conn.data().as_ptr() as *const u64).as_ref().unwrap() };
        assert_eq!(*data_out ^ (0xdeadbeef ^ idx), u64::MAX);
    }
    let stop = std::time::Instant::now();
    // moto_sys::syscalls::SysCtl::set_log_level(prev_log_level).unwrap();

    let mut cpu_usage: [f32; 16] = [0.0; 16];
    moto_sys::stats::get_cpu_usage(&mut cpu_usage).unwrap();

    conn.disconnect();

    let nanos = (stop - start).as_nanos();
    assert!(nanos > 0);
    assert!(nanos < (u64::MAX as u128));
    println!(
        "test_ipc: {} RPC calls (roundtrips) in {} nanoseconds: {} ns per RPC.",
        STEPS,
        nanos,
        (nanos as u64) / STEPS
    );

    println!(
        "cpu usage: {:.3} {:.3} {:.3} {:.3}",
        cpu_usage[0], cpu_usage[1], cpu_usage[2], cpu_usage[3]
    );
}

fn test_pipes() {
    use moto_sys::syscalls::*;
    std::thread::sleep(std::time::Duration::from_millis(1000));

    let (d1, d2) = moto_ipc::sync_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let mut reader = unsafe { moto_ipc::sync_pipe::Reader::new(d1) };
    let mut writer = unsafe { moto_ipc::sync_pipe::Writer::new(d2) };

    let reader_thread = std::thread::spawn(move || {
        let mut step = 1_usize;
        loop {
            let mut buf: Vec<u8> = vec![];
            buf.resize(step % 8176 + 17, 0);

            let read = reader.read(buf.as_mut_slice()).unwrap();
            assert!(read > 0);
            if buf[read - 1] == 0 {
                break;
            }

            step += 1;
        }

        reader.total_read()
    });

    let writer_thread = std::thread::spawn(move || {
        for step in 1_usize..8000_usize {
            let mut buf = vec![];

            for _idx in 0..step {
                buf.push(7_u8);
            }
            assert_eq!(writer.write(buf.as_slice()).unwrap(), step);
        }

        assert_eq!(1, writer.write(&[0_u8; 1]).unwrap());
        writer.total_written()
    });

    let read = reader_thread.join().unwrap();
    let written = writer_thread.join().unwrap();

    assert_eq!(read, written);

    println!("test_pipes PASS");
}

fn test_thread() {
    use std::sync::atomic::AtomicU64;
    let atomic = AtomicU64::new(0);
    let atomic_ref = unsafe { (&atomic as *const AtomicU64).as_ref::<'static>().unwrap() };

    std::thread::spawn(|| {
        atomic_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    })
    .join()
    .unwrap();

    assert_eq!(1, atomic.load(std::sync::atomic::Ordering::Relaxed));
    println!("test_thread PASS");
}

fn test_lazy_memory_map() {
    use moto_sys::syscalls::*;

    let addr = SysMem::map(
        SysHandle::SELF,
        SysMem::F_READABLE | SysMem::F_WRITABLE | SysMem::F_LAZY,
        u64::MAX,
        u64::MAX,
        SysMem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();
    // let prev_log_level = moto_sys::syscalls::SysCtl::set_log_level(4).unwrap();
    let buf = unsafe {
        core::slice::from_raw_parts_mut(addr as usize as *mut u8, SysMem::PAGE_SIZE_SMALL as usize)
    };
    for idx in 0..buf.len() {
        assert_eq!(0, buf[idx]);
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    for idx in 0..buf.len() {
        buf[idx] = (idx % (u8::MAX as usize)) as u8;
        assert_eq!(buf[idx], (idx % (u8::MAX as usize)) as u8);
    }

    // moto_sys::syscalls::SysCtl::set_log_level(prev_log_level).unwrap();
    SysMem::free(addr).unwrap();
    println!("test_lazy_memory_map: done");
}

fn stress_test_threads() {
    // Basically, do some cpu-bound stuff and
    // verify that preemption does not mess up registers.
    println!("stress_test_threads starting...");
    const THREADS: usize = 8;

    let shutdown = AtomicBool::new(false);
    let shutdown_ref = unsafe {
        (&shutdown as *const AtomicBool)
            .as_ref::<'static>()
            .unwrap()
    };

    let mut handles = Vec::with_capacity(THREADS);

    for _ in 0..THREADS {
        handles.push(std::thread::spawn(|| {
            let mut counter: u64 = 0;
            while !shutdown_ref.load(std::sync::atomic::Ordering::Relaxed) {
                #[cfg(feature = "test_sse")]
                {
                    let af64: f64 = f64::from((counter + 1) as u32);
                    let bf64: f64 = f64::from((counter + 2) as u32);
                    let mut res_f64: f64;
                }

                let mut result: u64;
                unsafe {
                    std::arch::asm!(
                                "
                        mov rcx, rax
                        mov rdx, rax
                        mov rsi, rax
                        mov rdi, rax
                        mov r8, rax
                        mov r9, rax
                        mov r10, rax
                        mov r11, rax
                        mov r12, rax
                        mov r13, rax
                        mov r14, rax
                        mov r15, rax

                        add r15, rax
                        add r15, rcx
                        add r15, rdx
                        add r15, rsi
                        add r15, rdi
                        add r15, r8
                        add r15, r9
                        add r15, r10
                        add r15, r11
                        add r15, r12
                        add r15, r13
                        add r15, r14
                        ",
                        in("rax") counter,
                        out("rcx") _,
                        out("rdx") _,
                        out("rsi") _,
                        out("rdi") _,
                        out("r8") _,
                        out("r9") _,
                        out("r10") _,
                        out("r11") _,
                        out("r12") _,
                        out("r13") _,
                        out("r14") _,
                        out("r15") result,
                        options(nomem, nostack)
                    );

                    #[cfg(feature = "test_sse")]
                    {
                        std::arch::asm!(
                            "addsd {0}, {1}",
                            inlateout(xmm_reg) af64 => res_f64,
                            in(xmm_reg) bf64,
                        );
                    }
                }
                #[cfg(feature = "test_sse")]
                {
                    res_f64 *= 13.3;
                    assert!((res_f64 as i64) < (((counter + 1) * 14) as i64));
                }

                assert_eq!(result, counter * 13);

                counter += 1;
                if counter > 1_000_000_000 {
                    counter = 0;
                }
            }
        }));
    }

    std::thread::sleep(std::time::Duration::from_secs(2));
    shutdown.store(true, Ordering::Release);

    for _ in 0..THREADS {
        let handle = handles.pop().unwrap();
        handle.join().unwrap();
    }
    println!("stress_test_threads PASS");
}

fn test_file_write() {
    use std::io::Write;
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
        .unwrap();

    file.write(WRITTEN.as_bytes()).unwrap();
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

#[allow(unused)]
fn test_stdio() {
    fn func(num: i32) {
        for i in 0..5 {
            println!("test_stdio {}: {}", num, i);
        }
    }

    func(0);

    let t1 = std::thread::spawn(|| func(1));
    let t2 = std::thread::spawn(|| func(2));
    let t3 = std::thread::spawn(|| func(3));

    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();

    println!("test_stdio() PASS");
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

    println!("Systest starting...");
    // Test that a userspace interrupt is handled correctly.
    unsafe { core::arch::asm!("int 3") }

    std::thread::spawn(|| input_listener());

    spawn_wait_kill::test();

    // tcp::test_web_server();
    tcp::test_tcp_loopback();
    // tcp::test_wget();
    channel_test::test_io_channel();
    // test_stdio();
    test_file_write();

    test_lazy_memory_map();
    test_syscall();
    stress_test_threads();
    test_thread();
    test_ipc();
    test_pipes();
    test_futex();
    test_rt_mutex();

    test_cpus();
    println!("PASS");
}
