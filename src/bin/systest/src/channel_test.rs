use moto_ipc::io_channel::*;
use moto_runtime::io_executor;
use moto_sys::SysHandle;
use std::{
    sync::{atomic::*, Arc},
    time::Duration,
};

const CHANNEL_TEST_ITERS: u64 = 1000;

fn client_loop(client: &mut Client) {
    use moto_sys::syscalls::SysCpu;
    use moto_sys::ErrorCode;

    let mut values_sent: u64 = 0;
    let mut values_received: u64 = 0;

    let mut process_completions = |client: &mut Client| loop {
        match client.get_cqe() {
            Ok(cqe) => {
                values_received += cqe.id;
                let slice = client.page_bytes(cqe.payload.client_pages()[0]).unwrap();
                for idx in 0..slice.len() {
                    assert_eq!(slice[idx], ((idx & 0xFF) as u8) ^ 0xFF);
                }
                client
                    .free_client_page(cqe.payload.client_pages()[0])
                    .unwrap();
            }
            Err(err) => {
                assert_eq!(err, ErrorCode::NotReady);
                break;
            }
        }
    };

    for iter in 0..CHANNEL_TEST_ITERS {
        let page_idx = loop {
            match client.alloc_page() {
                Ok(buffer) => break buffer,
                Err(err) => {
                    assert_eq!(err, ErrorCode::NotReady);
                    process_completions(client);
                    SysCpu::wait(&mut [], SysHandle::NONE, client.server_handle(), None).unwrap();
                }
            }
        };
        let mut sqe = QueueEntry::new();
        sqe.id = iter;
        sqe.wake_handle = SysHandle::this_thread().into();
        let slice = client.page_bytes(page_idx).unwrap();
        for idx in 0..slice.len() {
            slice[idx] = (idx & 0xFF) as u8;
        }
        sqe.payload.client_pages_mut()[0] = page_idx;
        values_sent += sqe.id;
        loop {
            match client.submit_sqe(sqe) {
                Ok(()) => break,
                Err(err) => {
                    assert_eq!(err, ErrorCode::NotReady);
                    process_completions(client);
                    SysCpu::wait(&mut [], SysHandle::NONE, client.server_handle(), None).unwrap();
                }
            }
        }
    }

    while !client.is_empty() {
        SysCpu::wait(&mut [], SysHandle::NONE, client.server_handle(), None).unwrap();
        process_completions(client);
    }

    assert_eq!(values_sent, values_received);
}

fn server_loop(server: &mut Server) {
    use moto_sys::syscalls::SysCpu;
    use moto_sys::ErrorCode;

    let mut cached_wakee = None;

    'outer: loop {
        match server.get_sqe() {
            Ok(mut sqe) => {
                let client_page_idx = sqe.payload.client_pages()[0];
                let slice = server.client_page_bytes(client_page_idx).unwrap();
                for idx in 0..slice.len() {
                    if slice[idx] != (idx & 0xFF) as u8 {
                        println!(
                            "bad data: idx {} data {} page idx {} iter {}",
                            idx, slice[idx], client_page_idx, sqe.id
                        );
                    }
                    assert_eq!(slice[idx], (idx & 0xFF) as u8);
                    slice[idx] ^= 0xFF;
                }

                sqe.status = ErrorCode::Ok.into();
                cached_wakee = Some((server.wait_handle(), SysHandle::from_u64(sqe.wake_handle)));

                loop {
                    match server.complete_sqe(sqe) {
                        Ok(()) => break,
                        Err(err) => {
                            assert_eq!(err, ErrorCode::NotReady);
                            SysCpu::wake_thread(server.wait_handle(), sqe.wake_handle.into())
                                .unwrap();
                            if SysCpu::wait(
                                &mut [server.wait_handle()],
                                SysHandle::NONE,
                                SysHandle::NONE, // server.wait_handle(),
                                None,
                            )
                            .is_err()
                            {
                                break 'outer;
                            }
                            continue;
                        }
                    }
                }
            }
            Err(err) => {
                assert_eq!(err, ErrorCode::NotReady);
                if let Some((a, b)) = cached_wakee {
                    if SysCpu::wake_thread(a, b).is_err() {
                        break 'outer;
                    }
                }
                if SysCpu::wait(
                    &mut [server.wait_handle()],
                    SysHandle::NONE,
                    SysHandle::NONE, // server.wait_handle(),
                    None,
                )
                .is_err()
                {
                    break 'outer;
                }
            }
        }
    }
}

fn client_thread(server_watcher: Arc<AtomicBool>) {
    // Connect.
    while !server_watcher.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }
    server_watcher.store(false, Ordering::Release);

    let mut client = Client::connect("systest_channel").unwrap();
    client_loop(&mut client);
    core::mem::drop(client);
}

fn server_thread(server_started: Arc<AtomicBool>) {
    use moto_sys::syscalls::SysCpu;

    // Listen.
    let mut server = Server::create("systest_channel").unwrap();
    server_started.store(true, Ordering::Release);

    SysCpu::wait(
        &mut [server.wait_handle()],
        SysHandle::NONE,
        SysHandle::NONE,
        None,
    )
    .unwrap();
    unsafe {
        server.accept().unwrap();
    }
    server_loop(&mut server);
    core::mem::drop(server);
}

pub fn test_io_channel() {
    assert!(Client::connect("systest_channel").is_err());
    if let Err(err) = Server::create("sys-io") {
        assert_eq!(err, moto_sys::ErrorCode::NotAllowed);
    } else {
        panic!("Was able to create a sys-io server.");
    }

    let server_started = Arc::new(AtomicBool::new(false));
    let server_watcher = server_started.clone();

    let server_thread = std::thread::spawn(move || {
        server_thread(server_started);
    });
    let client_thread = std::thread::spawn(move || {
        client_thread(server_watcher);
    });

    server_thread.join().unwrap();
    client_thread.join().unwrap();
    println!("test_io_channel() PASS");
}

async fn throughput_iter(do_4k: bool, batch_size: u64) {
    let mut qe_vec = vec![];

    for step in 0..batch_size {
        let mut sqe = QueueEntry::new();
        sqe.command = CMD_NOOP_OK;
        sqe.wake_handle = SysHandle::this_thread().into();
        sqe.id = step as u64;
        if do_4k {
            let io_page = io_executor::alloc_page().await;
            let buf = io_page.bytes_mut();
            let buf_u64 = unsafe {
                core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u64, buf.len() / 8)
            };
            for idx in 0..buf_u64.len() {
                buf_u64[idx] = idx as u64;
            }
            sqe.payload.client_pages_mut()[0] = io_page.client_idx();
            core::mem::forget(io_page);
        }
        let cqe = io_executor::submit(sqe).await;
        qe_vec.push(cqe);
    }

    while let Some(cqe) = qe_vec.pop() {
        let cqe = cqe.await;
        if do_4k {
            let io_page = io_executor::client_page(cqe.payload.client_pages()[0]);
            let buf = io_page.bytes();
            let buf_u64 =
                unsafe { core::slice::from_raw_parts(buf.as_ptr() as *mut u64, buf.len() / 8) };
            for idx in 0..buf_u64.len() {
                assert_eq!(buf_u64[idx], idx as u64);
            }
        }
    }
}

fn do_test_io_throughput(io_size: usize, batch_size: u64) {
    const DURATION: Duration = Duration::from_millis(1000);

    let mut iterations = 0_u64;
    let start = std::time::Instant::now();
    while start.elapsed() < DURATION {
        iterations += 1;
        io_executor::block_on(throughput_iter(io_size > 0, batch_size));
    }

    let elapsed = start.elapsed();
    let cpu_usage = moto_runtime::util::get_cpu_usage();

    let iops = ((iterations * batch_size) as f64) / elapsed.as_secs_f64();

    println!(
        "test_io_throughput: {: >4} bytes {: >2} batches: {:.3} million IOPS {:.3} usec/IO.",
        io_size,
        batch_size,
        iops / (1000.0 * 1000.0),
        (1000.0 * 1000.0) / iops,
    );
    if io_size > 0 {
        println!(
            "\tI/O throughput: {:.3} MiB/sec",
            iops * (io_size as f64) / (1024.0 * 1024.0)
        );
    }
    print!("\tcpu usage: ");
    for n in &cpu_usage {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();
    std::thread::sleep(Duration::from_millis(10));
}

pub fn test_io_throughput() {
    do_test_io_throughput(0, 1);
    do_test_io_throughput(0, 2);
    do_test_io_throughput(0, 4);
    do_test_io_throughput(0, 8);
    do_test_io_throughput(0, 64);
    do_test_io_throughput(4096, 1);
    do_test_io_throughput(4096, 2);
    do_test_io_throughput(4096, 4);
    do_test_io_throughput(4096, 8);
    do_test_io_throughput(4096, 16);
    do_test_io_throughput(4096, 32);
    do_test_io_throughput(4096, 64);
    // do_test_io_throughput(4096, 8);
    // do_test_io_throughput(4096, 32);
}

static TRACING_1: AtomicU64 = AtomicU64::new(0);
static TRACING_2: AtomicU64 = AtomicU64::new(0);
static TRACING_3: AtomicU64 = AtomicU64::new(0);
static TRACING_4: AtomicU64 = AtomicU64::new(0);

async fn io_latency_iter() {
    let mut skip_tracing = false;

    let ts_0 = moto_sys::time::Instant::now().as_u64();

    // We emulate an async read or write
    let io_page = io_executor::alloc_page().await;

    let ts_1 = moto_sys::time::Instant::now().as_u64();
    let mut sqe = QueueEntry::new();
    sqe.command = CMD_NOOP_OK;
    sqe.flags = FLAG_CMD_NOOP_OK_TIMESTAMP;
    sqe.handle = ts_0;
    sqe.payload.client_pages_mut()[0] = io_page.client_idx();
    let completion = io_executor::submit(sqe).await;
    let cqe = completion.await;
    assert!(cqe.status().is_ok());
    assert_eq!(cqe.command, CMD_NOOP_OK);
    assert_eq!(cqe.payload.client_pages()[0], io_page.client_idx());
    assert_eq!(cqe.handle, sqe.handle);

    let ts_2 = cqe.payload.args_64()[2];
    if ts_2 == 0 {
        skip_tracing = true;
        eprintln!("{}:{} - TODO: fix missing timestamp", file!(), line!());
    }

    let ts_3 = moto_sys::time::Instant::now().as_u64();
    core::mem::drop(io_page);
    let ts_4 = moto_sys::time::Instant::now().as_u64();

    if !skip_tracing {
        TRACING_1.fetch_add(ts_1 - ts_0, Ordering::Relaxed);
        TRACING_2.fetch_add(ts_2 - ts_1, Ordering::Relaxed);
        TRACING_3.fetch_add(ts_3 - ts_2, Ordering::Relaxed);
        TRACING_4.fetch_add(ts_4 - ts_3, Ordering::Relaxed);
    }
}

async fn async_io_iter(batch_size: usize) {
    if batch_size == 1 {
        return io_latency_iter().await;
    }
    let mut futs = vec![];
    for _ in 0..batch_size {
        futs.push(io_latency_iter());
    }

    futures::future::join_all(futs).await;
}

fn io_iter(batch_size: usize) {
    moto_runtime::io_executor::block_on(async_io_iter(batch_size));
}

pub fn do_test_io_latency(batch_size: usize, num_threads: usize) {
    // const ITERS: usize = 50_000;
    const ITERS: usize = 10_000;

    io_iter(batch_size); // Make sure the IO thread is up and running.

    TRACING_1.store(0, Ordering::Release);
    TRACING_2.store(0, Ordering::Release);
    TRACING_3.store(0, Ordering::Release);
    TRACING_4.store(0, Ordering::Release);

    let start = std::time::Instant::now();

    if num_threads == 1 {
        for _ in 0..ITERS {
            io_iter(batch_size);
        }
    } else {
        let mut threads = vec![];
        for _ in 0..num_threads {
            threads.push(std::thread::spawn(move || {
                for _ in 0..ITERS {
                    io_iter(batch_size);
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    let elapsed = start.elapsed();
    // let cpu_usage = moto_runtime::util::get_cpu_usage();
    println!(
        "IO Latency: num_threads: {} batch sz: {: >2} {: >6.3} usec/roundtrip.",
        num_threads,
        batch_size,
        elapsed.as_secs_f64() * 1000.0 * 1000.0 / (ITERS as f64),
    );

    /*
    print!("\tcpu usage: ");
    for n in &cpu_usage {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();

    let tsc_to_nanos = |x: u64| -> Duration {
        let zero = moto_sys::time::Instant::from_u64(0);
        let ts = moto_sys::time::Instant::from_u64(x);
        ts.duration_since(zero)
    };

    println!(
        "\ttracing: alloc: {:?} submit there: {:?} submit back: {:?} dealloc: {:?}",
        tsc_to_nanos(TRACING_1.load(Ordering::Acquire) / (ITERS as u64)),
        tsc_to_nanos(TRACING_2.load(Ordering::Acquire) / (ITERS as u64)),
        tsc_to_nanos(TRACING_3.load(Ordering::Acquire) / (ITERS as u64)),
        tsc_to_nanos(TRACING_4.load(Ordering::Acquire) / (ITERS as u64)),
    );
    */
}

pub fn test_io_latency() {
    do_test_io_latency(1, 1);
    do_test_io_latency(2, 1);
    do_test_io_latency(4, 1);
    do_test_io_latency(8, 1);
    do_test_io_latency(1, 2);
    do_test_io_latency(1, 3);
    do_test_io_latency(2, 2);
    do_test_io_latency(4, 2);
    do_test_io_latency(12, 3);

    // with batch_size > 31, futures::future::join_all() uses a different
    // algorithm that misbehaves (corrupts memory?).
    //
    // do_test_io_latency(32, 1);
}
