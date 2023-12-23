use moto_ipc::io_channel::*;
use std::sync::{atomic::*, Arc};

const CHANNEL_TEST_ITERS: u64 = 1000;

fn client_loop(client: &mut Client) {
    use moto_sys::syscalls::SysCpu;
    use moto_sys::syscalls::SysHandle;
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
    use moto_sys::syscalls::SysHandle;
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
    use moto_sys::syscalls::SysHandle;

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
    println!("channel_test() PASS");
}
