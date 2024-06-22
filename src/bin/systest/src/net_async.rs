use std::{net::SocketAddr, time::Duration};

use moto_runtime::net::TcpListener;
use moto_sys::ErrorCode;
// use moto_runtime::net::TcpStream;

fn test_listener_accept() {
    let addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        3333,
    );
    let listener = TcpListener::bind(&addr).unwrap();
    let listener_clone = listener.duplicate().unwrap();

    let thread = std::thread::spawn(move || {
        let res = listener_clone.accept();

        // Because we mark listener as non-blocking, existing accepts should return.
        assert_eq!(res.err().unwrap(), ErrorCode::NotReady);
    });

    std::thread::sleep(Duration::from_millis(10));
    listener.set_nonblocking(true).unwrap();
    thread.join().unwrap();
}

pub fn test() {
    test_listener_accept();
    println!("moto_async::test() PASS");
    std::thread::sleep(Duration::from_secs(2));
}
