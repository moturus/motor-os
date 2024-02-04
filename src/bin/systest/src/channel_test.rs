use moto_ipc::io_channel::*;
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
                let slice = client.buffer_bytes(cqe.payload.buffers()[0]).unwrap();
                let num_blocks = (cqe.id & 0xFFFF) as u8;
                for idx in 0..slice.len() {
                    assert_eq!(slice[idx], num_blocks ^ 0xFF);
                }
                client.free_buffer(cqe.payload.buffers()[0]).unwrap();
            }
            Err(err) => {
                assert_eq!(err, ErrorCode::NotReady);
                break;
            }
        }
    };

    for iter in 0..CHANNEL_TEST_ITERS {
        for num_blocks in 1..11_u16 {
            let buffer = loop {
                match client.alloc_buffer(num_blocks) {
                    Ok(buffer) => break buffer,
                    Err(err) => {
                        assert_eq!(err, ErrorCode::NotReady);
                        process_completions(client);
                        SysCpu::wait(
                            &mut [client.server_handle()],
                            SysHandle::NONE,
                            client.server_handle(),
                            None,
                        )
                        .unwrap();
                    }
                }
            };
            let mut sqe = QueueEntry::new();
            sqe.id = (iter << 32) + (num_blocks as u64);
            let slice = client.buffer_bytes(buffer).unwrap();
            for idx in 0..slice.len() {
                slice[idx] = num_blocks as u8;
            }
            sqe.payload.buffers_mut()[0] = buffer;
            values_sent += sqe.id;
            loop {
                match client.submit_sqe(sqe) {
                    Ok(()) => break,
                    Err(err) => {
                        assert_eq!(err, ErrorCode::NotReady);
                        process_completions(client);
                        SysCpu::wait(
                            &mut [client.server_handle()],
                            SysHandle::NONE,
                            client.server_handle(),
                            None,
                        )
                        .unwrap();
                    }
                }
            }
        }
    }

    loop {
        if client.is_empty() {
            break;
        }
        SysCpu::wait(
            &mut [client.server_handle()],
            SysHandle::NONE,
            client.server_handle(),
            None,
        )
        .unwrap();
        process_completions(client);
    }

    if values_sent != values_received {
        assert_eq!(values_sent, values_received);
    }
}

fn server_loop(server: &mut Server) {
    use moto_sys::syscalls::SysCpu;
    use moto_sys::ErrorCode;

    'outer: loop {
        match server.get_sqe() {
            Ok(mut sqe) => loop {
                let buffer = sqe.payload.buffers()[0];
                let slice = server.buffer_bytes(buffer).unwrap();
                let num_blocks = (sqe.id & 0xFFFF) as u8;
                assert_eq!(slice.len(), num_blocks as usize * 512);
                for idx in 0..slice.len() {
                    assert_eq!(slice[idx], num_blocks);
                    slice[idx] = num_blocks ^ 0xFF;
                }

                sqe.status = ErrorCode::Ok.into();

                match server.complete_sqe(sqe) {
                    Ok(()) => break,
                    Err(err) => {
                        assert_eq!(err, ErrorCode::NotReady);
                        if SysCpu::wait(
                            &mut [server.wait_handle()],
                            SysHandle::NONE,
                            server.wait_handle(),
                            None,
                        )
                        .is_err()
                        {
                            break 'outer;
                        }
                        continue;
                    }
                }
            },
            Err(err) => {
                assert_eq!(err, ErrorCode::NotReady);
                if SysCpu::wait(
                    &mut [server.wait_handle()],
                    SysHandle::NONE,
                    server.wait_handle(),
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

fn do_test_io_throughput(io_size: usize, batch_size: u64) {
    let mut io_client = match Client::connect("sys-io") {
        Ok(client) => client,
        Err(err) => {
            panic!("Failed to connect to sys-io: {:?}", err);
        }
    };

    let num_blocks = io_size / 512;

    const DURATION: Duration = Duration::from_millis(1000);

    moto_sys::syscalls::SysCpu::affine_to_cpu(Some(2)).unwrap();

    let mut iterations = 0_u64;
    let start = std::time::Instant::now();
    while start.elapsed() < DURATION {
        iterations += 1;
        for step in 0..batch_size {
            let mut sqe = QueueEntry::new();
            sqe.command = CMD_NOOP_OK;
            sqe.id = step as u64;
            if num_blocks > 0 {
                let buff = io_client.alloc_buffer(num_blocks as u16).unwrap();
                let buf = io_client.buffer_bytes(buff).unwrap();
                let buf_u64 = unsafe {
                    core::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u64, buf.len() / 8)
                };
                for b in buf_u64 {
                    *b ^= 0x12345678;
                }
                sqe.payload.buffers_mut()[0] = buff;
            }
            io_client.submit_sqe(sqe).unwrap();
        }

        for step in 0..batch_size {
            loop {
                match io_client.get_cqe() {
                    Ok(cqe) => {
                        assert_eq!(cqe.id, step as u64);
                        if num_blocks > 0 {
                            io_client.free_buffer(cqe.payload.buffers()[0]).unwrap();
                        }
                        break;
                    }
                    Err(err) => {
                        assert_eq!(err, moto_sys::ErrorCode::NotReady);
                        moto_sys::syscalls::SysCpu::wait(
                            &mut [io_client.server_handle()],
                            SysHandle::NONE,
                            io_client.server_handle(),
                            None,
                        )
                        .unwrap();
                    }
                }
            }
        }
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
}

pub fn test_io_throughput() {
    do_test_io_throughput(0, 1);
    do_test_io_throughput(0, 32);
    do_test_io_throughput(1024, 32);
    do_test_io_throughput(4096, 8);
}

static TRACING_1: AtomicU64 = AtomicU64::new(0);
static TRACING_2: AtomicU64 = AtomicU64::new(0);
static TRACING_3: AtomicU64 = AtomicU64::new(0);
static TRACING_4: AtomicU64 = AtomicU64::new(0);

async fn single_iter(id: u64, buf_alloc: bool, local_io: bool) {
    use moto_runtime::io_executor;

    let ts_0 = moto_sys::time::Instant::now().as_u64();
    // We emulate an async write
    let io_buffer = if buf_alloc {
        Some(io_executor::get_io_buffer(4).await)
    } else {
        None
    };

    let ts_1 = moto_sys::time::Instant::now().as_u64();
    let mut sqe = QueueEntry::new();
    sqe.id = id;
    sqe.command = if local_io {
        io_executor::CMD_LOCAL_NOOP_OK
    } else {
        CMD_NOOP_OK
    };
    sqe.flags = FLAG_CMD_NOOP_OK_TIMESTAMP;
    let cqe = io_executor::submit(sqe).await;
    if !cqe.status().is_ok() {
        panic!("status: {:?}", cqe.status());
    }
    assert!(cqe.status().is_ok());
    fence(Ordering::Acquire);
    let ts_2 = cqe.payload.args_64()[3];
    assert_ne!(ts_2, 0);

    let ts_3 = moto_sys::time::Instant::now().as_u64();
    if buf_alloc {
        io_executor::put_io_buffer(io_buffer.unwrap()).await;
    }
    let ts_4 = moto_sys::time::Instant::now().as_u64();

    TRACING_1.fetch_add(ts_1 - ts_0, Ordering::Relaxed);
    TRACING_2.fetch_add(ts_2 - ts_1, Ordering::Relaxed);
    TRACING_3.fetch_add(ts_3 - ts_2, Ordering::Relaxed);
    TRACING_4.fetch_add(ts_4 - ts_3, Ordering::Relaxed);
}

async fn async_io_iter(batch_size: u64, buf_alloc: bool, local_io: bool) {
    let mut futs = vec![];
    for id in 0..batch_size {
        futs.push(single_iter(id, buf_alloc, local_io));
    }

    futures::future::join_all(futs).await;
}

fn io_iter(batch_size: u64, buf_alloc: bool, local_io: bool) {
    if batch_size == 32 {
        moto_runtime::io_executor::block_on(futures::future::join(
            async_io_iter(16, buf_alloc, local_io),
            async_io_iter(16, buf_alloc, local_io),
        ));
    }
    moto_runtime::io_executor::block_on(async_io_iter(batch_size, buf_alloc, local_io))
}

pub fn do_test_io_latency(batch_size: u64, buf_alloc: bool, local_io: bool) {
    const DUR: Duration = Duration::from_millis(1000);
    io_iter(batch_size, buf_alloc, local_io); // Make sure the IO thread is up and running.

    TRACING_1.store(0, Ordering::Release);
    TRACING_2.store(0, Ordering::Release);
    TRACING_3.store(0, Ordering::Release);
    TRACING_4.store(0, Ordering::Release);

    let mut iters = 0_u64;
    let start = std::time::Instant::now();
    while start.elapsed() < DUR {
        io_iter(batch_size, buf_alloc, local_io);
        iters += 1;
    }

    let elapsed = start.elapsed();
    let cpu_usage = moto_runtime::util::get_cpu_usage();
    println!(
        "IO Latency: batch sz: {: >2} {: >6.3} usec/IO; {:.3} mIOPS; local: {: >5}; buf alloc: {: >5}.",
        batch_size,
        elapsed.as_secs_f64() * 1000.0 * 1000.0 / ((iters * batch_size) as f64),
        ((batch_size * iters) as f64) / (1000.0 * 1000.0),
        local_io,
        buf_alloc
    );
    print!("\tcpu usage: ");
    for n in &cpu_usage {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();

    println!("\ttracing: t1: {:.3} t2: {:.3} t3: {:.3} t4: {:.3}",
        (TRACING_1.load(Ordering::Acquire) as f64) / (iters as f64),
        (TRACING_2.load(Ordering::Acquire) as f64) / (iters as f64),
        (TRACING_3.load(Ordering::Acquire) as f64) / (iters as f64),
        (TRACING_4.load(Ordering::Acquire) as f64) / (iters as f64),
    );
}

pub fn test_io_latency() {
    do_test_io_latency(1, false, false);
    do_test_io_latency(1, false, true);
    do_test_io_latency(1, true, false);
    do_test_io_latency(1, true, true);

    do_test_io_latency(2, false, false);
    do_test_io_latency(2, false, true);
    do_test_io_latency(2, true, false);
    do_test_io_latency(2, true, true);

    // do_test_io_latency(4, false, true);
    // do_test_io_latency(4, true, true);
    // do_test_io_latency(8, false, true);
    // do_test_io_latency(8, true, true);
    // do_test_io_latency(16, false, true);
    // do_test_io_latency(16, true, true);
    // do_test_io_latency(20, false, true);
    // do_test_io_latency(20, true, true);
    // do_test_io_latency(24, false, true);
    // do_test_io_latency(24, true, true);

    // do_test_io_latency(28, false, true);
    // do_test_io_latency(28, true, true);
    // do_test_io_latency(32, false, true);
    // do_test_io_latency(32, true, true);
}
