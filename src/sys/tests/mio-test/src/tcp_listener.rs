use mio_moturus as mio;
use mio::net::TcpListener;
use mio::{Interest, Token};
use std::io::{self, Read};
use std::net::{self, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use crate::util::{
    any_local_address, any_local_ipv6_address, assert_send, assert_socket_close_on_exec,
    assert_socket_non_blocking, assert_sync, assert_would_block, expect_events, expect_no_events,
    init, init_with_poll, ExpectEvent,
};

const ID1: Token = Token(0);
const ID2: Token = Token(1);

fn test_is_send_and_sync() {
    assert_send::<TcpListener>();
    assert_sync::<TcpListener>();
}

fn test_tcp_listener() {
    smoke_test_tcp_listener(any_local_address(), TcpListener::bind);
    println!("tcp_listener::test_tcp_listener PASS");
}

fn test_tcp_listener_ipv6() {
    smoke_test_tcp_listener(any_local_ipv6_address(), TcpListener::bind);
    println!("tcp_listener::test_tcp_listener_ipv6 PASS");
}

fn test_tcp_listener_std() {
    smoke_test_tcp_listener(any_local_address(), |addr| {
        let listener = net::TcpListener::bind(addr).unwrap();
        // `std::net::TcpListener`s are blocking by default, so make sure it is in
        // non-blocking mode before wrapping in a Mio equivalent.
        listener.set_nonblocking(true).unwrap();
        Ok(TcpListener::from_std(listener))
    });
    println!("tcp_listener::test_tcp_listener_std PASS");
}

fn smoke_test_tcp_listener<F>(addr: SocketAddr, make_listener: F)
where
    F: FnOnce(SocketAddr) -> io::Result<TcpListener>,
{
    let (mut poll, mut events) = init_with_poll();

    let mut listener = make_listener(addr).unwrap();
    let address = listener.local_addr().unwrap();

    assert_socket_non_blocking(&listener);
    assert_socket_close_on_exec(&listener);

    poll.registry()
        .register(&mut listener, ID1, Interest::READABLE)
        .expect("unable to register TCP listener");

    let barrier = Arc::new(Barrier::new(2));
    let thread_handle = start_connections(address, 1, barrier.clone());

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    // Expect a single connection.
    let (mut stream, peer_address) = listener.accept().expect("unable to accept connection");
    assert!(peer_address.ip().is_loopback());
    assert_eq!(stream.peer_addr().unwrap(), peer_address);
    assert_eq!(stream.local_addr().unwrap(), address);

    // Expect the stream to be non-blocking.
    let mut buf = [0; 20];
    assert_would_block(stream.read(&mut buf));

    // Expect no more connections.
    assert_would_block(listener.accept());

    assert!(listener.take_error().unwrap().is_none());

    barrier.wait();
    thread_handle.join().expect("unable to join thread");
}

fn test_set_get_ttl() {
    init();

    let listener = TcpListener::bind(any_local_address()).unwrap();

    // set TTL, get TTL, make sure it has the expected value
    const TTL: u32 = 10;
    listener.set_ttl(TTL).unwrap();
    assert_eq!(listener.ttl().unwrap(), TTL);
    assert!(listener.take_error().unwrap().is_none());
    println!("tcp_listener::test_set_get_ttl PASS");
}

fn test_get_ttl_without_previous_set() {
    init();

    let listener = TcpListener::bind(any_local_address()).unwrap();

    // expect a get TTL to work w/o any previous set_ttl
    listener.ttl().expect("unable to get TTL for TCP listener");
    assert!(listener.take_error().unwrap().is_none());
    println!("tcp_listener::test_get_ttl_without_previous_set PASS");
}

fn test_raw_fd() {
    init();

    let listener = TcpListener::bind(any_local_address()).unwrap();
    let address = listener.local_addr().unwrap();

    let raw_fd1 = listener.as_raw_fd();
    let raw_fd2 = listener.into_raw_fd();
    assert_eq!(raw_fd1, raw_fd2);

    let listener = unsafe { TcpListener::from_raw_fd(raw_fd2) };
    assert_eq!(listener.as_raw_fd(), raw_fd1);
    assert_eq!(listener.local_addr().unwrap(), address);
    println!("tcp_listener::test_raw_fd PASS");
}

fn test_registering() {
    let (mut poll, mut events) = init_with_poll();

    let mut stream = TcpListener::bind(any_local_address()).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::READABLE)
        .expect("unable to register TCP listener");

    expect_no_events(&mut poll, &mut events);

    // NOTE: more tests are done in the smoke tests above.
    println!("tcp_listener::test_registering PASS");
}

fn test_reregister() {
    let (mut poll, mut events) = init_with_poll();

    let mut listener = TcpListener::bind(any_local_address()).unwrap();
    let address = listener.local_addr().unwrap();

    poll.registry()
        .register(&mut listener, ID1, Interest::READABLE)
        .unwrap();
    poll.registry()
        .reregister(&mut listener, ID2, Interest::READABLE)
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let thread_handle = start_connections(address, 1, barrier.clone());

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID2, Interest::READABLE)],
    );

    let (stream, peer_address) = listener.accept().expect("unable to accept connection");
    assert!(peer_address.ip().is_loopback());
    assert_eq!(stream.peer_addr().unwrap(), peer_address);
    assert_eq!(stream.local_addr().unwrap(), address);

    assert_would_block(listener.accept());

    assert!(listener.take_error().unwrap().is_none());

    barrier.wait();
    thread_handle.join().expect("unable to join thread");
    println!("tcp_listener::test_reregister PASS");
}

fn test_no_events_after_deregister() {
    let (mut poll, mut events) = init_with_poll();

    let mut listener = TcpListener::bind(any_local_address()).unwrap();
    let address = listener.local_addr().unwrap();

    poll.registry()
        .register(&mut listener, ID1, Interest::READABLE)
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let thread_handle = start_connections(address, 1, barrier.clone());

    poll.registry().deregister(&mut listener).unwrap();

    expect_no_events(&mut poll, &mut events);

    // Should still be able to accept the connection.
    let (stream, peer_address) = listener.accept().expect("unable to accept connection");
    assert!(peer_address.ip().is_loopback());
    assert_eq!(stream.peer_addr().unwrap(), peer_address);
    assert_eq!(stream.local_addr().unwrap(), address);

    assert_would_block(listener.accept());

    assert!(listener.take_error().unwrap().is_none());

    barrier.wait();
    thread_handle.join().expect("unable to join thread");
    println!("tcp_listener::test_no_events_after_deregister PASS");
}

/// This tests reregister on successful accept works
fn test_tcp_listener_two_streams() {
    let (mut poll1, mut events) = init_with_poll();

    let mut listener = TcpListener::bind(any_local_address()).unwrap();
    let address = listener.local_addr().unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let thread_handle1 = start_connections(address, 1, barrier.clone());

    poll1
        .registry()
        .register(&mut listener, ID1, Interest::READABLE)
        .unwrap();

    expect_events(
        &mut poll1,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    {
        let (stream, peer_address) = listener.accept().expect("unable to accept connection");
        assert!(peer_address.ip().is_loopback());
        assert_eq!(stream.peer_addr().unwrap(), peer_address);
        assert_eq!(stream.local_addr().unwrap(), address);
    }

    assert_would_block(listener.accept());

    let thread_handle2 = start_connections(address, 1, barrier.clone());

    expect_events(
        &mut poll1,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    {
        let (stream, peer_address) = listener.accept().expect("unable to accept connection");
        assert!(peer_address.ip().is_loopback());
        assert_eq!(stream.peer_addr().unwrap(), peer_address);
        assert_eq!(stream.local_addr().unwrap(), address);
    }

    expect_no_events(&mut poll1, &mut events);

    barrier.wait();
    thread_handle1.join().expect("unable to join thread");
    thread_handle2.join().expect("unable to join thread");
    println!("tcp_listener::test_tcp_listener_two_streams PASS");
}

/// Start `n_connections` connections to `address`. If a `barrier` is provided
/// it will wait on it after each connection is made before it is dropped.
fn start_connections(
    address: SocketAddr,
    n_connections: usize,
    barrier: Arc<Barrier>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for _ in 0..n_connections {
            let conn = net::TcpStream::connect(address).unwrap();
            barrier.wait();
            drop(conn);
        }
    })
}

pub fn run_all_tests() {
    test_is_send_and_sync();
    test_tcp_listener();
    test_tcp_listener_ipv6();
    test_tcp_listener_std();
    test_set_get_ttl();
    test_get_ttl_without_previous_set();
    test_raw_fd();
    test_registering();
    test_reregister();
    test_no_events_after_deregister();
    test_tcp_listener_two_streams();

    std::thread::sleep(Duration::from_millis(1000));
    println!("tcp_listener ALL PASS");
    std::thread::sleep(Duration::from_millis(100));
}
