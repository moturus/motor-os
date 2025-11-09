use moto_async::AsFuture;
use moto_ipc::io_channel::{ClientConnection, ServerConnection};
use std::time::Duration;

fn test_accept_fail() {
    // Test that a correct error is returned.
    let mut server = ServerConnection::create("systest_foo").unwrap();
    assert_eq!(moto_rt::E_NOT_CONNECTED, server.accept().err().unwrap());

    println!("----- io_channel::test_accept_fail PASS");
}

fn basic_test() {
    let mut server = ServerConnection::create("systest_foo").unwrap();

    let server_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            server.wait_handle().as_future().await.unwrap();
            server.accept().unwrap();

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

    println!("----- io_channel::basic_test PASS");
}

pub fn run_all_tests() {
    test_accept_fail();
    std::thread::sleep(Duration::from_millis(10));
    basic_test();

    println!("io_channel: ALL PASS");
}
