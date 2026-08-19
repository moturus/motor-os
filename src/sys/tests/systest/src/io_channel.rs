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

fn test_pipelined_queue_wakeups() {
    const ROUNDS: u64 = 250;
    const BATCH: u64 = moto_ipc::io_channel::QUEUE_SIZE * 2;
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

    let server_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = server_started.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let server_done = done_tx.clone();

    let server = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_pipelined_wakeups");
            server_started.store(true, Ordering::Release);
            let (sender, mut receiver) = listener.await.unwrap();

            for request_id in (0..ROUNDS * BATCH).map(|id| id * 2) {
                let mut msg = receiver.recv().await.unwrap();
                assert_eq!(msg.id, request_id);
                msg.id += 1;
                sender.send(msg).await.unwrap();
            }
        });
        server_done.send(()).unwrap();
    });

    while !waiter.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let client_done = done_tx;
    let client = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, mut receiver) =
                moto_ipc::io_channel::connect("systest_pipelined_wakeups").unwrap();

            for round in 0..ROUNDS {
                for index in 0..BATCH {
                    let mut msg = moto_ipc::io_channel::Msg::new();
                    msg.id = (round * BATCH + index) * 2;
                    sender.send(msg).await.unwrap();
                }
                for index in 0..BATCH {
                    let msg = receiver.recv().await.unwrap();
                    assert_eq!(msg.id, (round * BATCH + index) * 2 + 1);
                }
            }
        });
        client_done.send(()).unwrap();
    });

    done_rx
        .recv_timeout(DEADLINE)
        .expect("pipelined io_channel endpoint stopped making progress");
    done_rx
        .recv_timeout(DEADLINE)
        .expect("pipelined io_channel endpoint stopped making progress");
    client.join().unwrap();
    server.join().unwrap();

    println!("----- io_channel::test_pipelined_queue_wakeups PASS");
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

fn test_local_page_free_wakes_waiter() {
    use std::future::Future;
    use std::task::Poll;
    use std::time::Duration;

    let server_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = server_started.clone();
    let server = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_local_page_free");
            server_started.store(true, Ordering::Release);
            let (_sender, mut receiver) = listener.await.unwrap();
            receiver.recv().await.unwrap();
        });
    });
    while !waiter.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let client = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, _receiver) =
                moto_ipc::io_channel::connect("systest_local_page_free").unwrap();
            let mut pages = sender.alloc_pages(3, 7).await.unwrap();
            let (pending_tx, pending_rx) = std::sync::mpsc::sync_channel(0);
            let (allocated_tx, allocated_rx) = std::sync::mpsc::channel();
            let allocator_sender = sender.clone();
            let allocator = std::thread::spawn(move || {
                moto_async::LocalRuntime::new().block_on(async move {
                    let mut allocation = Box::pin(allocator_sender.alloc_pages(2, 7));
                    futures::future::poll_fn(|cx| match allocation.as_mut().poll(cx) {
                        Poll::Pending => {
                            pending_tx.send(()).unwrap();
                            Poll::Ready(())
                        }
                        Poll::Ready(_) => panic!("page allocation unexpectedly completed"),
                    })
                    .await;
                    allocated_tx.send(allocation.await.unwrap()).unwrap();
                });
            });

            pending_rx.recv().unwrap();
            pages.truncate(1);
            let allocated = allocated_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("locally freed pages did not wake the allocator");
            drop(allocated);
            allocator.join().unwrap();

            let mut done = moto_ipc::io_channel::Msg::new();
            done.id = 1;
            sender.send(done).await.unwrap();
        });
    });

    client.join().unwrap();
    server.join().unwrap();
    println!("----- io_channel::test_local_page_free_wakes_waiter PASS");
}

fn test_remote_page_free_preserves_other_waiters() {
    use std::future::Future;
    use std::task::Poll;
    use std::time::Duration;

    const PAGE_MASK: u64 = 7;
    let server_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waiter = server_started.clone();
    let stage = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let server_stage = stage.clone();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let server_done = done_tx.clone();

    let server = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_remote_page_free");
            server_started.store(true, Ordering::Release);
            let (_sender, mut receiver) = listener.await.unwrap();
            let msg = receiver.recv().await.unwrap();
            let mut pages = (0..3)
                .map(|idx| receiver.get_page(msg.payload.shared_pages()[idx]).unwrap())
                .collect::<Vec<_>>();
            server_stage.store(1, Ordering::Release);

            while server_stage.load(Ordering::Acquire) < 2 {
                moto_async::sleep(Duration::from_millis(1)).await;
            }
            drop(pages.pop());
            server_stage.store(3, Ordering::Release);

            while server_stage.load(Ordering::Acquire) < 4 {
                moto_async::sleep(Duration::from_millis(1)).await;
            }
            drop(pages);
            server_stage.store(5, Ordering::Release);

            while server_stage.load(Ordering::Acquire) < 6 {
                moto_async::sleep(Duration::from_millis(1)).await;
            }
        });
        server_done.send(()).unwrap();
    });

    while !waiter.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let client_stage = stage;
    let client = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, _receiver) =
                moto_ipc::io_channel::connect("systest_remote_page_free").unwrap();
            let pages = sender.alloc_pages(3, PAGE_MASK).await.unwrap();
            let mut msg = moto_ipc::io_channel::Msg::new();
            for (idx, page) in pages.into_iter().enumerate() {
                msg.payload.shared_pages_mut()[idx] = moto_ipc::io_channel::IoPage::into_u16(page);
            }
            sender.send(msg).await.unwrap();

            while client_stage.load(Ordering::Acquire) < 1 {
                moto_async::sleep(Duration::from_millis(1)).await;
            }

            let poll_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
            let allocator_poll_count = poll_count.clone();
            let allocator_sender = sender.clone();
            let (pending_tx, pending_rx) = moto_async::oneshot();
            let allocator = moto_async::LocalRuntime::spawn(async move {
                let mut allocation = Box::pin(allocator_sender.alloc_pages(2, PAGE_MASK));
                let mut pending_tx = Some(pending_tx);
                core::future::poll_fn(move |cx| {
                    allocator_poll_count.fetch_add(1, Ordering::Release);
                    match allocation.as_mut().poll(cx) {
                        Poll::Pending => {
                            if let Some(pending_tx) = pending_tx.take() {
                                pending_tx.send(()).unwrap();
                            }
                            Poll::Pending
                        }
                        Poll::Ready(result) => Poll::Ready(result),
                    }
                })
                .await
                .unwrap()
            });
            pending_rx.await.unwrap();

            client_stage.store(2, Ordering::Release);
            while client_stage.load(Ordering::Acquire) < 3 || poll_count.load(Ordering::Acquire) < 2
            {
                moto_async::sleep(Duration::from_millis(1)).await;
            }

            // This succeeds from the one free page. It must not clear the
            // overlapping remote wait registration owned by `allocator`.
            let single_page = sender.alloc_page(PAGE_MASK).await.unwrap();
            client_stage.store(4, Ordering::Release);
            while client_stage.load(Ordering::Acquire) < 5 {
                moto_async::sleep(Duration::from_millis(1)).await;
            }

            let allocated = allocator.await;
            drop(allocated);
            drop(single_page);
            client_stage.store(6, Ordering::Release);
        });
        done_tx.send(()).unwrap();
    });

    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("remote page allocator stopped making progress");
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("remote page allocator stopped making progress");
    client.join().unwrap();
    server.join().unwrap();
    println!("----- io_channel::test_remote_page_free_preserves_other_waiters PASS");
}

// Verifies the io_channel error handler (set_error_handler) fires -- instead of
// a panic -- when a page is double-freed. This is the mechanism sys-io will use
// to drop a client that names an already-recovered page in two TX messages. We
// reproduce the double free locally by building two IoPages over one allocated
// page (as the server does recovering a client-named page twice) and dropping
// both: the second free reports the page as not-in-use, which must reach the
// handler rather than crash the process.
fn test_error_handler_on_double_free() {
    use std::sync::atomic::{AtomicBool, AtomicU64};

    static CALLED: AtomicBool = AtomicBool::new(false);
    static REMOTE: AtomicU64 = AtomicU64::new(0);

    fn on_error(remote: moto_sys::SysHandle, error: moto_ipc::io_channel::ChannelError) {
        assert!(matches!(
            error,
            moto_ipc::io_channel::ChannelError::FreeingUnusedPage { .. }
        ));
        REMOTE.store(u64::from(remote), Ordering::SeqCst);
        CALLED.store(true, Ordering::SeqCst);
    }
    moto_ipc::io_channel::set_error_handler(on_error);

    // A server that accepts and holds the connection, so the client's recovered
    // pages carry a live remote handle (the client the handler would drop).
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
    let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel(0);
    let server = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let listener = moto_ipc::io_channel::listen("systest_err_handler");
            started_tx.send(()).unwrap();
            let (_sender, mut receiver) = listener.await.unwrap();
            accepted_tx.send(()).unwrap();
            let _ = receiver.recv().await; // Hold until the client signals done.
        });
    });
    started_rx.recv().unwrap();

    let client = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (sender, _receiver) = moto_ipc::io_channel::connect("systest_err_handler").unwrap();
            accepted_rx.recv().unwrap();

            // into_u16 disarms this owner's Drop and leaves the shared in-use
            // bit set, so both get_page handles free the same page on drop.
            let page = sender.alloc_page(u64::MAX).await.unwrap();
            let idx = moto_ipc::io_channel::IoPage::into_u16(page);
            let p1 = sender.get_page(idx).unwrap();
            let p2 = sender.get_page(idx).unwrap();

            drop(p1); // First free: the page was in use -> cleared, no error.
            drop(p2); // Second free: not in use -> the handler fires (no panic).

            let mut done = moto_ipc::io_channel::Msg::new();
            done.id = 1;
            let _ = sender.send(done).await; // Release the server.
        });
    });

    let _ = client.join();
    let _ = server.join();

    assert!(
        CALLED.load(Ordering::SeqCst),
        "error handler was not called"
    );
    assert_ne!(
        0,
        REMOTE.load(Ordering::SeqCst),
        "handler got no remote handle"
    );
    println!("----- io_channel::test_error_handler_on_double_free PASS");
}

const SPAWN_READ_CHILD: &str = "io-channel-spawn-read-child";

pub fn is_spawn_read_child(args: &[String]) -> bool {
    args.len() == 2 && args[1] == SPAWN_READ_CHILD
}

fn test_concurrent_spawn_reads() {
    let exe = std::env::current_exe().unwrap();
    const CONCURRENT_SPAWNS: usize = 8;
    for _ in 0..2 {
        let barrier = std::sync::Barrier::new(CONCURRENT_SPAWNS);
        std::thread::scope(|scope| {
            for _ in 0..CONCURRENT_SPAWNS {
                scope.spawn(|| {
                    barrier.wait();
                    assert!(
                        std::process::Command::new(&exe)
                            .arg(SPAWN_READ_CHILD)
                            .status()
                            .unwrap()
                            .success()
                    );
                });
            }
        });
    }
    println!("----- io_channel::test_concurrent_spawn_reads PASS");
}

pub fn run_all_tests() {
    basic_test();
    test_ping_pong();
    test_pipelined_queue_wakeups();
    test_page_alloc();
    test_local_page_free_wakes_waiter();
    test_remote_page_free_preserves_other_waiters();
    test_error_handler_on_double_free();
    test_concurrent_spawn_reads();

    println!("io_channel: ALL PASS");
}
