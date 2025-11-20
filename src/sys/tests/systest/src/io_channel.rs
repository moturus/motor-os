use std::sync::atomic::Ordering;

fn basic_test() {
    let server_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = server_started.clone();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_foo");
            server_started.store(true, Ordering::Release);

            let (sender, receiver) = listener.await.unwrap();
            // Receive ping.
            let mut msg = receiver.recv_async().await.unwrap();
            assert_eq!(msg.id, 1);

            // Send pong.
            msg.id = 2;
            sender.send_async(msg).await.unwrap();
        }); // block_on
    }); // thread::spawn

    while !waiter.load(Ordering::Relaxed) {
        core::hint::spin_loop();
    }

    let client_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, receiver) = moto_ipc::io_channel::connect("systest_foo").unwrap();

            // Send ping.
            let mut msg = moto_ipc::io_channel::Msg::new();
            msg.id = 1;
            sender.send_async(msg).await.unwrap();

            // Receive pong.
            msg = receiver.recv_async().await.unwrap();
            assert_eq!(msg.id, 2);
        }); // block_on
    }); // thread::spawn

    let _ = server_thread.join();
    let _ = client_thread.join();

    println!("----- io_channel::basic_test PASS");
}

fn test_ping_pong() {
    const ITERS: u64 = 20000;

    let server_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = server_started.clone();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_foo");
            server_started.store(true, Ordering::Release);

            let (sender, receiver) = listener.await.unwrap();

            for idx in 0..ITERS {
                // Receive ping.
                let mut msg = receiver.recv_async().await.unwrap();
                assert_eq!(msg.id, idx * 2);

                // Send pong.
                msg.id = idx * 2 + 1;
                sender.send_async(msg).await.unwrap();
            }
        }); // block_on
    }); // thread::spawn

    while !waiter.load(Ordering::Relaxed) {
        core::hint::spin_loop();
    }

    let client_thread = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, receiver) = moto_ipc::io_channel::connect("systest_foo").unwrap();

            for idx in 0..ITERS {
                // Send ping.
                let mut msg = moto_ipc::io_channel::Msg::new();
                msg.id = idx * 2;
                sender.send_async(msg).await.unwrap();

                // Receive pong.
                msg = receiver.recv_async().await.unwrap();
                assert_eq!(msg.id, idx * 2 + 1);
            }
        }); // block_on

        let elapsed_nanos = start.elapsed().as_nanos();
        println!(
            "      io_channel::test_ping_pong: {ITERS} roundtrips; {} nanos/roudtrip.",
            elapsed_nanos / (ITERS as u128)
        );
    }); // thread::spawn

    let _ = server_thread.join();
    let _ = client_thread.join();

    println!("----- io_channel::test_ping_pong PASS");
}

/*
fn test_page_alloc() {
    const ITERS: u64 = 20000;

    let mut server = ServerConnection::create("systest_foo").unwrap();
    let mut client = ClientConnection::connect("systest_foo").unwrap();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            server.wait_handle().as_future().await.unwrap();
            server.accept().unwrap();

            for idx in 0..ITERS {
                // Receive ping.
                let mut msg = server.recv_async().await.unwrap();
                assert_eq!(msg.id, idx * 2);

                // Send pong.
                msg.id = idx * 2 + 1;
                server.send_async(msg).await.unwrap();
            }
        }); // block_on
    }); // thread::spawn

    let client_thread = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        moto_async::LocalRuntime::new().block_on(async move {
            println!("starting ping-pong");
            for idx in 0..ITERS {
                // Send ping.
                let mut msg = moto_ipc::io_channel::Msg::new();
                msg.id = idx * 2;
                client.send_async(msg).await.unwrap();

                // Receive pong.
                msg = client.recv_async().await.unwrap();
                assert_eq!(msg.id, idx * 2 + 1);
            }
        }); // block_on

        let elapsed_nanos = start.elapsed().as_nanos();
        println!(
            "      io_channel::test_ping_pong: {ITERS} roundtrips; {} nanos/roudtrip.",
            elapsed_nanos / (ITERS as u128)
        );
    }); // thread::spawn

    let _ = server_thread.join();
    let _ = client_thread.join();

    println!("----- io_channel::test_page_alloc PASS");
}
*/

/*
fn test_two_tasks() {
    let mut server = ServerConnection::create("systest_foo").unwrap();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            server.wait_handle().as_future().await.unwrap();
            server.accept().unwrap();

            let sender = server.clone();
            let receiver = server;

            // Receive ping.
            let mut msg = server.recv_async().await.unwrap();
            assert_eq!(msg.id, 1);

            // Send pong.
            msg.id = 2;
            server.send_async(msg).await.unwrap();

            // Final poke...
            server.wake_client().unwrap();
        }); // block_on
    }); // thread::spawn

    std::thread::sleep(Duration::from_millis(500));
    let client_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let mut client = ClientConnection::connect("systest_foo").unwrap();

            // Send ping.
            let mut msg = moto_ipc::io_channel::Msg::new();
            msg.id = 1;
            client.send_async(msg).await.unwrap();

            // Receive pong.
            msg = client.recv_async().await.unwrap();
            assert_eq!(msg.id, 2);

            // Receive wake.
            // Ignore errors as the server might be gone.
            let _ = client.server_handle().as_future().await;
        }); // block_on
    }); // thread::spawn

    let _ = server_thread.join();
    let _ = client_thread.join();

    println!("----- io_channel::test_two_tasks PASS");
}
*/

pub fn run_all_tests() {
    basic_test();
    test_ping_pong();
    // test_two_tasks();
    // test_page_alloc();

    println!("io_channel: ALL PASS");
}
