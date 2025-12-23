use std::sync::atomic::Ordering;

fn basic_test() {
    let server_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = server_started.clone();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_foo");
            server_started.store(true, Ordering::Release);

            let (sender, mut receiver) = listener.await.unwrap();
            // Receive ping.
            let mut msg = receiver.recv().await.unwrap();
            assert_eq!(msg.id, 1);

            // Send pong.
            msg.id = 2;
            sender.send(msg).await.unwrap();
        }); // block_on
    }); // thread::spawn

    while !waiter.load(Ordering::Relaxed) {
        core::hint::spin_loop();
    }

    let client_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, mut receiver) = moto_ipc::io_channel::connect("systest_foo").unwrap();

            // Send ping.
            let mut msg = moto_ipc::io_channel::Msg::new();
            msg.id = 1;
            sender.send(msg).await.unwrap();

            // Receive pong.
            msg = receiver.recv().await.unwrap();
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

            let (sender, mut receiver) = listener.await.unwrap();

            for idx in 0..ITERS {
                // Receive ping.
                let mut msg = receiver.recv().await.unwrap();
                assert_eq!(msg.id, idx * 2);

                // Send pong.
                msg.id = idx * 2 + 1;
                sender.send(msg).await.unwrap();
            }
        }); // block_on
    }); // thread::spawn

    while !waiter.load(Ordering::Relaxed) {
        core::hint::spin_loop();
    }

    let client_thread = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, mut receiver) = moto_ipc::io_channel::connect("systest_foo").unwrap();

            for idx in 0..ITERS {
                // Send ping.
                let mut msg = moto_ipc::io_channel::Msg::new();
                msg.id = idx * 2;
                sender.send(msg).await.unwrap();

                // Receive pong.
                msg = receiver.recv().await.unwrap();
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

fn test_page_alloc() {
    // We test that a waiter to allocate a page is properly woken when a page becomes available.
    let server_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = server_started.clone();

    let step_synchronizer_receiver = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let step_synchronizer_sender = step_synchronizer_receiver.clone();
    let step_synchronizer_allocator = step_synchronizer_receiver.clone();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_foo");
            server_started.store(true, Ordering::Release);

            let (sender, mut receiver) = listener.await.unwrap();
            // Receive ping.
            let mut msg = receiver.recv().await.unwrap();
            assert_eq!(msg.id, 1);

            // This is the page that will be deallocated.
            let page = receiver.get_page(msg.payload.shared_pages()[0]).unwrap();

            assert_eq!(1, step_synchronizer_receiver.fetch_add(1, Ordering::AcqRel));
            assert_eq!(page.bytes()[0], 42);

            // Send pong.
            msg.id = 2;
            sender.send(msg).await.unwrap();
        }); // block_on
    }); // thread::spawn

    while !waiter.load(Ordering::Relaxed) {
        core::hint::spin_loop();
    }

    let client_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            use futures::FutureExt;

            let (sender, mut receiver) = moto_ipc::io_channel::connect("systest_foo").unwrap();

            let mut pages = vec![];

            // Can allocate 3 pages (7 means pages # 0, 1, and 2)
            for _ in 0..3 {
                let page = sender.alloc_page(7).await.unwrap();
                pages.push(page);
            }

            let sender_allocator = sender.clone();
            let join_handle = moto_async::LocalRuntime::spawn(async move {
                // Can't allocate another page now.
                let allocated = futures::select! {
                    _ = sender_allocator.alloc_page(7).fuse() => true,
                    _ = moto_async::sleep(std::time::Duration::from_millis(20)).fuse() => false,
                };
                assert!(!allocated);

                // Raise flag so that one of the pre-allocated pages is sent to the receiver.
                assert_eq!(
                    0,
                    step_synchronizer_allocator.fetch_add(1, Ordering::AcqRel)
                );

                // Now should be able to allocate (after some time).
                let page = sender_allocator.alloc_page(7).await.unwrap();
                assert_eq!(2, step_synchronizer_allocator.load(Ordering::Acquire));
                core::mem::drop(page);
            });

            // Wait for the send flag.
            while step_synchronizer_sender.load(Ordering::Relaxed) != 1 {
                moto_async::sleep(std::time::Duration::from_millis(1)).await;
            }

            // Send a page.
            let mut msg = moto_ipc::io_channel::Msg::new();
            msg.id = 1;
            let page = pages.pop().unwrap();
            page.bytes_mut()[0] = 42;
            msg.payload.shared_pages_mut()[0] = moto_ipc::io_channel::IoPage::into_u16(page);
            sender.send(msg).await.unwrap();

            // Receive pong.
            msg = receiver.recv().await.unwrap();
            assert_eq!(msg.id, 2);

            join_handle.await;
        }); // block_on
    }); // thread::spawn

    let _ = server_thread.join();
    let _ = client_thread.join();

    println!("----- io_channel::test_page_alloc PASS");
}

pub fn run_all_tests() {
    basic_test();
    test_ping_pong();
    test_page_alloc();

    println!("io_channel: ALL PASS");
}
