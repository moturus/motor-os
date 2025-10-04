use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use moto_async::AsFuture;
use moto_ipc::io_channel::{ClientConnection, ServerConnection};

fn test_accept_fail() {
    // Test that a correct error is returned.
    let mut server = ServerConnection::create("systest_foo").unwrap();
    assert_eq!(moto_rt::E_NOT_CONNECTED, server.accept().err().unwrap());

    println!("----- io_channel_test::test_accept_fail PASS");
}

fn _basic_test() {
    let checker_server = Arc::new(AtomicU64::new(0));
    let checker_client = checker_server.clone();
    let mut server = ServerConnection::create("systest_foo").unwrap();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            assert_eq!(0, checker_server.fetch_add(1, Ordering::AcqRel));
            server.wait_handle().as_future().await.unwrap();
            assert_eq!(2, checker_server.fetch_add(1, Ordering::AcqRel));

            server.accept().unwrap();
            moto_async::sleep(Duration::from_millis(2)).await;
            assert_eq!(server.recv().err().unwrap(), moto_rt::E_NOT_READY);

            // Receive ping.
            let mut msg = server.recv_async().await.unwrap();
            assert_eq!(msg.id, 1);
            assert_eq!(4, checker_server.fetch_add(1, Ordering::AcqRel));

            // Send pong.
            msg.id = 2;
            server.send(msg).unwrap();

            // Final poke...
            moto_async::sleep(Duration::from_millis(50)).await;
            assert_eq!(6, checker_server.fetch_add(1, Ordering::AcqRel));
            server.wake_client().unwrap();

            // And wait.
            server.wait_handle().as_future().await.unwrap();
            assert_eq!(8, checker_server.fetch_add(1, Ordering::AcqRel));
        }); // block_on
    }); // thread::spawn

    std::thread::sleep(Duration::from_millis(100));
    let client_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            assert_eq!(1, checker_client.fetch_add(1, Ordering::AcqRel));
            let client = ClientConnection::connect("systest_foo").unwrap();
            client.wake_server().unwrap();
            moto_async::sleep(Duration::from_millis(50)).await;
            assert_eq!(3, checker_client.fetch_add(1, Ordering::AcqRel));

            // Send ping.
            let mut msg = moto_ipc::io_channel::Msg::new();
            msg.id = 1;
            client.send_async(msg).await.unwrap();

            // Receive pong.
            msg = client.recv_async().await.unwrap();
            assert_eq!(msg.id, 2);
            assert_eq!(5, checker_client.fetch_add(1, Ordering::AcqRel));

            // Receive wake.
            client.server_handle().as_future().await.unwrap();
            assert_eq!(7, checker_client.fetch_add(1, Ordering::AcqRel));

            // Post wake.
            client.wake_server().unwrap();
        }); // block_on
    }); // thread::spawn

    let _ = server_thread.join();
    let _ = client_thread.join();

    println!("----- io_channel_test::basic_test PASS");
}

pub fn run_all_tests() {
    test_accept_fail();
    std::thread::sleep(Duration::from_millis(10));
    // basic_test();

    println!("io_channel_test: ALL PASS");
}
