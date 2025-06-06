use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::{self, Shutdown, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::sync::{mpsc::channel, Arc, Barrier};
use std::thread;
use std::time::Duration;

use mio::net::TcpStream;
use mio::{Interest, Token};

use crate::util::init;
use crate::util::{
    any_local_address, any_local_ipv6_address, assert_send, assert_socket_close_on_exec,
    assert_socket_non_blocking, assert_sync, assert_would_block, expect_events, expect_no_events,
    init_with_poll, set_linger_zero, ExpectEvent, Readiness,
};

use crate::util::checked_write;
use crate::util::expect_read;

const DATA1: &[u8] = b"Hello world!";
const DATA2: &[u8] = b"Hello mars!";
// TODO: replace with `DATA1.len()` once `const_slice_len` is stable.
const DATA1_LEN: usize = 12;
const DATA2_LEN: usize = 11;

const ID1: Token = Token(0);
const ID2: Token = Token(1);

fn test_is_send_and_sync() {
    assert_send::<TcpStream>();
    assert_sync::<TcpStream>();
}

fn test_tcp_stream_ipv4() {
    smoke_test_tcp_stream(any_local_address(), TcpStream::connect);
    println!("tcp_stream::test_tcp_stream_ipv4 PASS");
}

fn test_tcp_stream_ipv6() {
    smoke_test_tcp_stream(any_local_ipv6_address(), TcpStream::connect);
    println!("tcp_stream::test_tcp_stream_ipv6 PASS");
}

fn test_tcp_stream_std() {
    smoke_test_tcp_stream(any_local_address(), |addr| {
        let stream = net::TcpStream::connect(addr).unwrap();
        // `std::net::TcpStream`s are blocking by default, so make sure it is
        // in non-blocking mode before wrapping in a Mio equivalent.
        stream.set_nonblocking(true).unwrap();
        Ok(TcpStream::from_std(stream))
    });
    println!("tcp_stream::test_tcp_stream_std PASS");
}

fn smoke_test_tcp_stream<F>(addr: SocketAddr, make_stream: F)
where
    F: FnOnce(SocketAddr) -> io::Result<TcpStream>,
{
    let (mut poll, mut events) = init_with_poll();

    let (handle, addr) = echo_listener(addr, 1);
    let mut stream = make_stream(addr).unwrap();

    assert_socket_non_blocking(&stream);
    assert_socket_close_on_exec(&stream);

    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE.add(Interest::READABLE))
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    let mut buf = [0; 16];
    assert_would_block(stream.peek(&mut buf));
    assert_would_block(stream.read(&mut buf));

    // NOTE: the call to `peer_addr` must happen after we received a writable
    // event as the stream might not yet be connected.
    assert_eq!(stream.peer_addr().unwrap(), addr);
    assert!(stream.local_addr().unwrap().ip().is_loopback());

    checked_write!(stream.write(DATA1));

    stream.flush().unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    expect_read!(stream.peek(&mut buf), DATA1);
    expect_read!(stream.read(&mut buf), DATA1);

    assert!(stream.take_error().unwrap().is_none());

    assert_would_block(stream.read(&mut buf));

    let bufs = [IoSlice::new(DATA1), IoSlice::new(DATA2)];
    let n = stream
        .write_vectored(&bufs)
        .expect("unable to write vectored to stream");
    assert_eq!(n, DATA1.len() + DATA2.len());

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    let mut buf1 = [1; DATA1_LEN];
    let mut buf2 = [2; DATA2_LEN + 1];
    let mut bufs = [IoSliceMut::new(&mut buf1), IoSliceMut::new(&mut buf2)];
    let n = stream
        .read_vectored(&mut bufs)
        .expect("unable to read vectored from stream");
    assert_eq!(n, DATA1.len() + DATA2.len());
    assert_eq!(&buf1, DATA1);
    assert_eq!(&buf2[..DATA2.len()], DATA2);
    assert_eq!(buf2[DATA2.len()], 2); // Last byte should be unchanged.

    // Close the connection to allow the listener to shutdown.
    drop(stream);
    handle.join().expect("unable to join thread");
}

fn test_set_get_ttl() {
    let (mut poll, mut events) = init_with_poll();

    let barrier = Arc::new(Barrier::new(2));
    let (thread_handle, address) = start_listener(1, Some(barrier.clone()), false);

    let mut stream = TcpStream::connect(address).unwrap();

    // on Windows: the stream must be connected before setting the ttl, otherwise
    // it is unspecified behavior, register and expect a WRITABLE here to make sure
    // the stream is connected
    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE)
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    // set TTL, get TTL, make sure it has the expected value
    const TTL: u32 = 10;
    stream.set_ttl(TTL).unwrap();
    assert_eq!(stream.ttl().unwrap(), TTL);
    assert!(stream.take_error().unwrap().is_none());

    barrier.wait();
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_set_get_ttl PASS");
}

fn test_get_ttl_without_previous_set() {
    let (mut poll, mut events) = init_with_poll();

    let barrier = Arc::new(Barrier::new(2));
    let (thread_handle, address) = start_listener(1, Some(barrier.clone()), false);

    let mut stream = TcpStream::connect(address).unwrap();

    // on Windows: the stream must be connected before getting the ttl, otherwise
    // it is unspecified behavior, register and expect a WRITABLE here to make sure
    // the stream is connected
    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE)
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    // expect a get TTL to work w/o any previous set_ttl
    stream.ttl().expect("unable to get TTL for TCP stream");
    assert!(stream.take_error().unwrap().is_none());

    barrier.wait();
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_get_ttl_without_previous_set PASS");
}

fn test_set_get_nodelay() {
    let (mut poll, mut events) = init_with_poll();

    let barrier = Arc::new(Barrier::new(2));
    let (thread_handle, address) = start_listener(1, Some(barrier.clone()), false);

    let mut stream = TcpStream::connect(address).unwrap();

    // on Windows: the stream must be connected before setting the nodelay, otherwise
    // it is unspecified behavior, register and expect a WRITABLE here to make sure
    // the stream is connected
    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE)
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    // set nodelay, get nodelay, make sure it has the expected value
    const NO_DELAY: bool = true;
    stream.set_nodelay(NO_DELAY).unwrap();
    assert_eq!(stream.nodelay().unwrap(), NO_DELAY);
    assert!(stream.take_error().unwrap().is_none());

    barrier.wait();
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_set_get_nodelay PASS");
}

fn test_get_nodelay_without_previous_set() {
    let (mut poll, mut events) = init_with_poll();

    let barrier = Arc::new(Barrier::new(2));
    let (thread_handle, address) = start_listener(1, Some(barrier.clone()), false);

    let mut stream = TcpStream::connect(address).unwrap();

    // on Windows: the stream must be connected before setting the nodelay, otherwise
    // it is unspecified behavior, register and expect a WRITABLE here to make sure
    // the stream is connected
    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE)
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    // expect a get nodelay to work w/o any previous set nodelay
    stream
        .nodelay()
        .expect("Unable to get nodelay for TCP stream");
    assert!(stream.take_error().unwrap().is_none());

    barrier.wait();
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_get_nodelay_without_previous_set PASS");
}

fn test_shutdown_read() {
    let (mut poll, mut events) = init_with_poll();

    let (thread_handle, address) = echo_listener(any_local_address(), 1);

    let mut stream = TcpStream::connect(address).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE.add(Interest::READABLE))
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    checked_write!(stream.write(DATA2));

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    stream.shutdown(Shutdown::Read).unwrap();

    // Shutting down the reading side is different on each platform. For example
    // on Linux based systems we can still read.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    {
        let mut buf = [0; 20];
        expect_read!(stream.read(&mut buf), &[]);
    }

    drop(stream);
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_shutdown_read PASS");
}

// #[ignore = "This test is flaky, it doesn't always receive an event after shutting down the write side"]
fn test_shutdown_write() {
    let (mut poll, mut events) = init_with_poll();

    let (thread_handle, address) = echo_listener(any_local_address(), 1);

    let mut stream = TcpStream::connect(address).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE.add(Interest::READABLE))
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    checked_write!(stream.write(DATA1));

    stream.shutdown(Shutdown::Write).unwrap();

    let err = stream.write(DATA2).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotConnected);

    // FIXME: we don't always receive the following event.
    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    // Read should be ok.
    let mut buf = [0; 20];
    expect_read!(stream.read(&mut buf), DATA1);

    drop(stream);
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_shutdown_write PASS");
}

fn test_shutdown_both() {
    let (mut poll, mut events) = init_with_poll();

    let (thread_handle, address) = echo_listener(any_local_address(), 1);

    let mut stream = TcpStream::connect(address).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE.add(Interest::READABLE))
        .expect("unable to register TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    checked_write!(stream.write(DATA1));

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    stream.shutdown(Shutdown::Both).unwrap();

    // Shutting down the reading side is different on each platform. For example
    // on Linux based systems we can still read.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    {
        let mut buf = [0; 20];
        expect_read!(stream.read(&mut buf), &[]);
    }

    let err = stream.write(DATA2).unwrap_err();
    #[cfg(unix)]
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    #[cfg(windows)]
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    #[cfg(target_os = "moturus")]
    assert_eq!(err.kind(), io::ErrorKind::NotConnected);

    drop(stream);
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_shutdown_both PASS");
}

fn test_raw_fd() {
    init();

    let (thread_handle, address) = start_listener(1, None, false);

    let stream = TcpStream::connect(address).unwrap();
    // Motor OS: local addr unavailable until connect completes.
    // let address = stream.local_addr().unwrap();

    let raw_fd1 = stream.as_raw_fd();
    let raw_fd2 = stream.into_raw_fd();
    assert_eq!(raw_fd1, raw_fd2);

    let stream = unsafe { TcpStream::from_raw_fd(raw_fd2) };
    assert_eq!(stream.as_raw_fd(), raw_fd1);
    // Motor OS: local addr unavailable until connect completes.
    // assert_eq!(stream.local_addr().unwrap(), address);

    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_raw_fd PASS");
}

fn test_registering() {
    let (mut poll, mut events) = init_with_poll();

    let (thread_handle, address) = echo_listener(any_local_address(), 1);

    let mut stream = TcpStream::connect(address).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::READABLE)
        .expect("unable to register TCP stream");

    expect_no_events(&mut poll, &mut events);

    // NOTE: more tests are done in the smoke tests above.

    drop(stream);
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_registering PASS");
}

fn test_reregistering() {
    let (mut poll, mut events) = init_with_poll();

    let (thread_handle, address) = echo_listener(any_local_address(), 1);

    let mut stream = TcpStream::connect(address).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::READABLE)
        .expect("unable to register TCP stream");

    poll.registry()
        .reregister(&mut stream, ID2, Interest::WRITABLE)
        .expect("unable to reregister TCP stream");

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID2, Interest::WRITABLE)],
    );

    assert_eq!(stream.peer_addr().unwrap(), address);

    drop(stream);
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_reregistering PASS");
}

fn test_no_events_after_deregister() {
    let (mut poll, mut events) = init_with_poll();

    let (thread_handle, address) = echo_listener(any_local_address(), 1);

    let mut stream = TcpStream::connect(address).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::WRITABLE.add(Interest::READABLE))
        .expect("unable to register TCP stream");

    poll.registry()
        .deregister(&mut stream)
        .expect("unable to deregister TCP stream");

    expect_no_events(&mut poll, &mut events);

    // We do expect to be connected.
    assert_eq!(stream.peer_addr().unwrap(), address);

    // Also, write should work
    let mut buf = [0; 16];
    assert_would_block(stream.peek(&mut buf));
    assert_would_block(stream.read(&mut buf));

    checked_write!(stream.write(DATA1));
    stream.flush().unwrap();

    expect_no_events(&mut poll, &mut events);

    drop(stream);
    thread_handle.join().expect("unable to join thread");
    println!("tcp_stream::test_no_events_after_deregister PASS");
}

fn test_tcp_shutdown_client_read_close_event() {
    let (mut poll, mut events) = init_with_poll();
    let barrier = Arc::new(Barrier::new(2));

    let (handle, sockaddr) = start_listener(1, Some(barrier.clone()), false);
    let mut stream = TcpStream::connect(sockaddr).unwrap();

    let interests = Interest::READABLE | Interest::WRITABLE;

    poll.registry()
        .register(&mut stream, ID1, interests)
        .unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    stream.shutdown(Shutdown::Read).unwrap();
    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Readiness::READ_CLOSED)],
    );

    barrier.wait();
    handle.join().expect("failed to join thread");
    println!("tcp_stream::test_tcp_shutdown_client_read_close_event PASS");
}

fn test_tcp_shutdown_client_write_close_event() {
    let (mut poll, mut events) = init_with_poll();
    let barrier = Arc::new(Barrier::new(2));

    let (handle, sockaddr) = start_listener(1, Some(barrier.clone()), false);
    let mut stream = TcpStream::connect(sockaddr).unwrap();

    let interests = Interest::READABLE | Interest::WRITABLE;

    poll.registry()
        .register(&mut stream, ID1, interests)
        .unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    stream.shutdown(Shutdown::Write).unwrap();
    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Readiness::WRITE_CLOSED)],
    );

    barrier.wait();
    handle.join().expect("failed to join thread");
    println!("tcp_stream::test_tcp_shutdown_client_write_close_event PASS");
}

fn test_tcp_shutdown_server_write_close_event() {
    let (mut poll, mut events) = init_with_poll();
    let barrier = Arc::new(Barrier::new(2));

    let (handle, sockaddr) = start_listener(1, Some(barrier.clone()), true);
    let mut stream = TcpStream::connect(sockaddr).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::READABLE.add(Interest::WRITABLE))
        .unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    barrier.wait();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Readiness::READ_CLOSED)],
    );

    barrier.wait();
    handle.join().expect("failed to join thread");
    println!("tcp_stream::test_tcp_shutdown_server_write_close_event PASS");
}

fn test_tcp_reset_close_event() {
    let (mut poll, mut events) = init_with_poll();

    let listener = net::TcpListener::bind(any_local_address()).unwrap();
    let sockaddr = listener.local_addr().unwrap();
    let mut stream = TcpStream::connect(sockaddr).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::READABLE.add(Interest::WRITABLE))
        .unwrap();

    let server_stream = listener.accept().unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );
    checked_write!(stream.write(DATA1));

    // Try to read something.
    assert_would_block(stream.read(&mut [0]));

    // Server goes away.
    drop(server_stream);

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Readiness::READ_CLOSED)],
    );

    // Make sure we quiesce. `expect_no_events` seems to flake sometimes on mac/freebsd.
    loop {
        poll.poll(&mut events, Some(Duration::from_millis(100)))
            .expect("poll failed");
        if events.iter().count() == 0 {
            break;
        }
    }
    println!("tcp_stream::test_tcp_reset_close_event PASS");
}

fn tcp_shutdown_client_both_close_event() {
    let (mut poll, mut events) = init_with_poll();
    let barrier = Arc::new(Barrier::new(2));

    let (handle, sockaddr) = start_listener(1, Some(barrier.clone()), false);
    let mut stream = TcpStream::connect(sockaddr).unwrap();

    poll.registry()
        .register(&mut stream, ID1, Interest::READABLE.add(Interest::WRITABLE))
        .unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::WRITABLE)],
    );

    stream.shutdown(Shutdown::Both).unwrap();
    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Readiness::WRITE_CLOSED)],
    );

    barrier.wait();
    handle.join().expect("failed to join thread");
    println!("tcp_stream::tcp_shutdown_client_both_close_event PASS");
}

/// Start a listener that accepts `n_connections` connections on the returned
/// address. It echos back any data it reads from the connection before
/// accepting another one.
fn echo_listener(addr: SocketAddr, n_connections: usize) -> (thread::JoinHandle<()>, SocketAddr) {
    let (sender, receiver) = channel();
    let thread_handle = thread::spawn(move || {
        let listener = net::TcpListener::bind(addr).unwrap();
        let local_address = listener.local_addr().unwrap();
        sender.send(local_address).unwrap();

        let mut buf = [0; 128];
        for _ in 0..n_connections {
            let (mut stream, _) = listener.accept().unwrap();

            loop {
                let n = stream
                    .read(&mut buf)
                    // On Linux based system it will cause a connection reset
                    // error when the reading side of the peer connection is
                    // shutdown, we don't consider it an actual here.
                    .or_else(|err| match err {
                        ref err if err.kind() == io::ErrorKind::ConnectionReset => Ok(0),
                        err => Err(err),
                    })
                    .expect("error reading");
                if n == 0 {
                    break;
                }
                crate::util::checked_write!(stream.write(&buf[..n]));
            }
        }
    });
    (thread_handle, receiver.recv().unwrap())
}

/// Start a listener that accepts `n_connections` connections on the returned
/// address. If a barrier is provided it will wait on it before closing the
/// connection.
fn start_listener(
    n_connections: usize,
    barrier: Option<Arc<Barrier>>,
    shutdown_write: bool,
) -> (thread::JoinHandle<()>, SocketAddr) {
    let (sender, receiver) = channel();
    let thread_handle = thread::spawn(move || {
        let listener = net::TcpListener::bind(any_local_address()).unwrap();
        let local_address = listener.local_addr().unwrap();
        sender.send(local_address).unwrap();

        for _ in 0..n_connections {
            let (stream, _) = listener.accept().unwrap();
            if let Some(ref barrier) = barrier {
                barrier.wait();

                if shutdown_write {
                    stream.shutdown(Shutdown::Write).unwrap();
                    barrier.wait();
                }
            }
            drop(stream);
        }
    });
    (thread_handle, receiver.recv().unwrap())
}

fn test_hup_event_on_disconnect() {
    use mio::net::TcpListener;

    let (mut poll, mut events) = init_with_poll();
    let addr = "127.0.0.1:0".parse().unwrap();

    let mut listener = TcpListener::bind(addr).unwrap();
    let addr = listener.local_addr().unwrap();
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .unwrap();

    let mut stream = TcpStream::connect(addr).unwrap();
    poll.registry()
        .register(
            &mut stream,
            Token(1),
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![
            ExpectEvent::new(Token(0), Interest::READABLE),
            ExpectEvent::new(Token(1), Interest::WRITABLE),
        ],
    );

    let (sock, _) = listener.accept().unwrap();
    // Prevent the OS from performing a graceful shutdown
    set_linger_zero(&sock);
    drop(sock);

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(Token(1), Interest::READABLE)],
    );
    println!("tcp_stream::test_hup_event_on_disconnect PASS");
}

pub fn run_all_tests() {
    test_is_send_and_sync();
    test_tcp_stream_ipv4();
    test_tcp_stream_ipv6();
    test_tcp_stream_std();
    test_set_get_ttl();
    test_get_ttl_without_previous_set();
    test_set_get_nodelay();
    test_get_nodelay_without_previous_set();
    test_shutdown_read();
    test_shutdown_write();
    test_shutdown_both();
    test_raw_fd();
    test_registering();
    test_reregistering();
    test_no_events_after_deregister();
    test_tcp_shutdown_client_read_close_event();
    test_tcp_shutdown_client_write_close_event();
    test_tcp_shutdown_server_write_close_event();
    test_tcp_reset_close_event();
    tcp_shutdown_client_both_close_event();
    test_hup_event_on_disconnect();

    std::thread::sleep(Duration::from_millis(100));
    println!("tcp_stream ALL PASS");
    std::thread::sleep(Duration::from_millis(100));
}
