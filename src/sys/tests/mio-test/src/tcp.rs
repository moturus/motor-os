use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use std::io::{self, Read, Write};
use std::net::{self, Shutdown};
use std::sync::mpsc::channel;
use std::thread::{self, sleep};
use std::time::Duration;

use crate::util::{
    any_local_address, assert_send, assert_sync, expect_events, expect_no_events, init,
    init_with_poll, set_linger_zero, ExpectEvent,
};

const LISTEN: Token = Token(0);
const CLIENT: Token = Token(1);
const SERVER: Token = Token(2);

#[cfg(not(debug_assertions))]
fn test_assert_size() {
    use mio::net::*;
    use std::mem::size_of;

    // Without debug assertions enabled `TcpListener`, `TcpStream` and
    // `UdpSocket` should have the same size as the system specific socket, i.e.
    // just a file descriptor on Unix platforms.
    assert_eq!(size_of::<TcpListener>(), size_of::<std::net::TcpListener>());
    assert_eq!(size_of::<TcpStream>(), size_of::<std::net::TcpStream>());
}

fn test_is_send_and_sync() {
    assert_send::<TcpListener>();
    assert_sync::<TcpListener>();

    assert_send::<TcpStream>();
    assert_sync::<TcpStream>();
}

fn test_accept() {
    init();

    struct Data {
        hit: bool,
        listener: TcpListener,
        shutdown: bool,
    }

    let mut listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        net::TcpStream::connect(addr).unwrap();
    });

    let mut poll = Poll::new().unwrap();

    poll.registry()
        .register(&mut listener, Token(1), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(128);

    let mut data = Data {
        hit: false,
        listener,
        shutdown: false,
    };
    while !data.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            data.hit = true;
            assert_eq!(event.token(), Token(1));
            assert!(event.is_readable());
            assert!(data.listener.accept().is_ok());
            data.shutdown = true;
        }
    }
    assert!(data.hit);
    assert!(data.listener.accept().unwrap_err().kind() == io::ErrorKind::WouldBlock);
    handle.join().unwrap();
    println!("tcp::test_accept PASS");
}

fn test_connect() {
    init();

    struct Data {
        hit: u32,
        shutdown: bool,
    }

    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = channel();
    let (tx2, rx2) = channel();
    let handle = thread::spawn(move || {
        let stream = listener.accept().unwrap();
        rx.recv().unwrap();
        drop(stream);
        tx2.send(()).unwrap();
    });

    let mut poll = Poll::new().unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();

    poll.registry()
        .register(
            &mut stream,
            Token(1),
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap();

    let mut events = Events::with_capacity(128);

    let mut data = Data {
        hit: 0,
        shutdown: false,
    };
    while !data.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            assert_eq!(event.token(), Token(1));
            match data.hit {
                0 => assert!(event.is_writable()),
                1 => assert!(event.is_readable()),
                _ => panic!(),
            }
            data.hit += 1;
            data.shutdown = true;
        }
    }
    assert_eq!(data.hit, 1);
    tx.send(()).unwrap();
    rx2.recv().unwrap();
    data.shutdown = false;
    while !data.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            assert_eq!(event.token(), Token(1));
            match data.hit {
                0 => assert!(event.is_writable()),
                1 => assert!(event.is_readable()),
                _ => panic!(),
            }
            data.hit += 1;
            data.shutdown = true;
        }
    }
    assert_eq!(data.hit, 2);
    handle.join().unwrap();
    println!("tcp::test_connect PASS");
}

fn test_read() {
    init();

    const N: usize = 16 * 1024 * 1024;
    struct Data {
        amt: usize,
        socket: TcpStream,
        shutdown: bool,
    }

    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        let buf = [0; 1024];
        let mut amt = 0;
        while amt < N {
            amt += stream.write(&buf).unwrap();
        }
    });

    let mut poll = Poll::new().unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();

    poll.registry()
        .register(&mut stream, Token(1), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(128);

    let mut data = Data {
        amt: 0,
        socket: stream,
        shutdown: false,
    };
    while !data.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            assert_eq!(event.token(), Token(1));
            let mut buf = [0; 1024];
            #[allow(clippy::while_let_loop)]
            loop {
                if let Ok(amt) = data.socket.read(&mut buf) {
                    assert_ne!(amt, 0);
                    data.amt += amt;
                } else {
                    break;
                }
                if data.amt >= N {
                    data.shutdown = true;
                    break;
                }
            }
        }
    }
    handle.join().unwrap();
    println!("tcp::test_read PASS");
}

fn test_peek() {
    init();

    const N: usize = 16 * 1024 * 1024;
    struct Data {
        amt: usize,
        socket: TcpStream,
        shutdown: bool,
    }

    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        let buf = [0; 1024];
        let mut amt = 0;
        while amt < N {
            amt += stream.write(&buf).unwrap();
        }
    });

    let mut poll = Poll::new().unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();

    poll.registry()
        .register(&mut stream, Token(1), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(128);

    let mut data = Data {
        amt: 0,
        socket: stream,
        shutdown: false,
    };
    while !data.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            assert_eq!(event.token(), Token(1));
            let mut buf = [0; 1024];
            match data.socket.peek(&mut buf) {
                Ok(_) => (),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => panic!("unexpected error: {err}"),
            }

            #[allow(clippy::while_let_loop)]
            loop {
                if let Ok(amt) = data.socket.read(&mut buf) {
                    assert_ne!(amt, 0);
                    data.amt += amt;
                } else {
                    break;
                }
                if data.amt >= N {
                    data.shutdown = true;
                    break;
                }
            }
        }
    }
    handle.join().unwrap();
    println!("tcp::test_peek PASS");
}

fn test_write() {
    init();

    const N: usize = 16 * 1024 * 1024;
    struct Data {
        amt: usize,
        socket: TcpStream,
        shutdown: bool,
    }

    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        let mut buf = [0; 1024];
        let mut amt = 0;
        while amt < N {
            amt += stream.read(&mut buf).unwrap();
        }
    });

    let mut poll = Poll::new().unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();

    poll.registry()
        .register(&mut stream, Token(1), Interest::WRITABLE)
        .unwrap();

    let mut events = Events::with_capacity(128);

    let mut data = Data {
        amt: 0,
        socket: stream,
        shutdown: false,
    };

    while !data.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            assert_eq!(event.token(), Token(1));
            let buf = [0; 1024];
            #[allow(clippy::while_let_loop)]
            loop {
                if let Ok(amt) = data.socket.write(&buf) {
                    data.amt += amt;
                } else {
                    break;
                }
                if data.amt >= N {
                    data.shutdown = true;
                    break;
                }
            }
        }
    }
    println!("tcp::test_write - writes done");
    handle.join().unwrap();
    println!("tcp::test_write PASS");
}

fn test_connect_then_close() {
    init();

    struct Data {
        listener: TcpListener,
        shutdown: bool,
    }

    let mut poll = Poll::new().unwrap();
    let mut listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut s = TcpStream::connect(listener.local_addr().unwrap()).unwrap();

    poll.registry()
        .register(&mut listener, Token(1), Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(&mut s, Token(2), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(128);

    let mut data = Data {
        listener,
        shutdown: false,
    };
    while !data.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            if event.token() == Token(1) {
                let mut s = data.listener.accept().unwrap().0;
                poll.registry()
                    .register(&mut s, Token(3), Interest::READABLE | Interest::WRITABLE)
                    .unwrap();
                drop(s);
            } else if event.token() == Token(2) {
                data.shutdown = true;
            }
        }
    }
    println!("tcp::test_connect_then_close PASS");
}

fn test_listen_then_close() {
    init();

    let mut poll = Poll::new().unwrap();
    let mut listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();

    poll.registry()
        .register(&mut listener, Token(1), Interest::READABLE)
        .unwrap();
    drop(listener);

    let mut events = Events::with_capacity(128);

    poll.poll(&mut events, Some(Duration::from_millis(100)))
        .unwrap();

    for event in &events {
        if event.token() == Token(1) {
            panic!("received ready() on a closed TcpListener")
        }
    }
    println!("tcp::test_listen_then_close PASS");
}

fn test_bind_twice_bad() {
    init();

    let l1 = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = l1.local_addr().unwrap();
    assert!(TcpListener::bind(addr).is_err());
    println!("tcp::test_bind_twice_bad PASS");
}

fn test_multiple_writes_immediate_success() {
    init();

    const N: usize = 4;
    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        let mut s = listener.accept().unwrap().0;
        let mut b = [0; 1024];
        let mut amt = 0;
        while amt < 1024 * N {
            for byte in b.iter_mut() {
                *byte = 0;
            }
            let n = s.read(&mut b).unwrap();
            amt += n;
            for byte in b[..n].iter() {
                assert_eq!(*byte, 1);
            }
        }
    });

    let mut poll = Poll::new().unwrap();
    let mut s = TcpStream::connect(addr).unwrap();
    poll.registry()
        .register(&mut s, Token(1), Interest::WRITABLE)
        .unwrap();
    let mut events = Events::with_capacity(16);

    // Wait for our TCP stream to connect
    'outer: loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            if event.token() == Token(1) && event.is_writable() {
                break 'outer;
            }
        }
    }

    for _ in 0..N {
        s.write_all(&[1; 1024]).unwrap();
    }

    handle.join().unwrap();
    println!("tcp::test_multiple_writes_immediate_success PASS");
}

fn test_connection_reset_by_peer() {
    init();

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(16);
    let mut buf = [0u8; 16];

    // Create listener
    let mut listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();

    // Connect client
    let mut client = TcpStream::connect(addr).unwrap();
    set_linger_zero(&client);

    // Register server
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .unwrap();

    // Register interest in the client
    poll.registry()
        .register(
            &mut client,
            Token(1),
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap();

    // Wait for listener to be ready
    let mut server;
    'outer: loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            if event.token() == Token(0) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        server = sock;
                        break 'outer;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("unexpected error {e:?}"),
                }
            }
        }
    }

    // Close the connection
    drop(client);

    // Wait a moment
    sleep(Duration::from_millis(100));

    // Register interest in the server socket
    poll.registry()
        .register(&mut server, Token(3), Interest::READABLE)
        .unwrap();

    loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            if event.token() == Token(3) {
                assert!(event.is_readable());

                match server.read(&mut buf) {
                    Ok(0) | Err(_) => {}

                    Ok(x) => panic!("expected empty buffer but read {x} bytes"),
                }
                println!("tcp::test_connection_reset_by_peer PASS");
                return;
            }
        }
    }
}

fn test_connect_error() {
    let (mut poll, mut events) = init_with_poll();

    // Pick a "random" port that shouldn't be in use.
    let mut stream = match TcpStream::connect("127.0.0.1:58381".parse().unwrap()) {
        Ok(l) => l,
        Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            // Connection failed synchronously.  This is not a bug, but it
            // unfortunately doesn't get us the code coverage we want.
            return;
        }
        Err(e) => panic!("TcpStream::connect unexpected error {e:?}"),
    };

    poll.registry()
        .register(&mut stream, Token(0), Interest::WRITABLE)
        .unwrap();

    'outer: loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            if event.token() == Token(0) {
                // With fastopen we would be able to write
                // Without fastopen we would be getting the connection error
                assert!(event.is_writable() || event.is_error());
                // Solaris poll(2) says POLLHUP and POLLOUT are mutually exclusive.
                #[cfg(not(target_os = "solaris"))]
                assert!(event.is_write_closed());
                break 'outer;
            }
        }
    }

    assert!(stream.take_error().unwrap().is_some());
    println!("tcp::test_connect_error PASS");
}

fn test_write_error() {
    init();

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(16);
    let (tx, rx) = channel();

    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (conn, _addr) = listener.accept().unwrap();
        rx.recv().unwrap();
        drop(conn);
    });

    let mut s = TcpStream::connect(addr).unwrap();
    poll.registry()
        .register(&mut s, Token(0), Interest::READABLE | Interest::WRITABLE)
        .unwrap();

    let mut wait_writable = || 'outer: loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            if event.token() == Token(0) && event.is_writable() {
                break 'outer;
            }
        }
    };

    wait_writable();

    tx.send(()).unwrap();
    handle.join().unwrap();

    let buf = [0; 1024];
    loop {
        match s.write(&buf) {
            Ok(0) => panic!("unexpected end"),
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => wait_writable(),
            Err(e) => {
                println!("good error: {e}");
                break;
            }
        }
    }
    println!("tcp::test_write_error PASS");
}

macro_rules! wait {
    ($poll:ident, $ready:ident, $expect_read_closed: expr) => {{
        use std::time::Instant;

        let now = Instant::now();
        let mut events = Events::with_capacity(16);
        let mut found = false;

        while !found {
            if now.elapsed() > Duration::from_secs(5) {
                panic!("not ready");
            }

            $poll
                .poll(&mut events, Some(Duration::from_secs(1)))
                .unwrap();

            for event in &events {
                std::thread::sleep(Duration::from_millis(100));
                if $expect_read_closed {
                    assert!(event.is_read_closed());
                } else {
                    assert!(!event.is_read_closed() && !event.is_write_closed());
                }

                if event.token() == Token(0) && event.$ready() {
                    found = true;
                    break;
                }
            }
        }
    }};
}

fn test_write_shutdown() {
    init();

    let mut poll = Poll::new().unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client = TcpStream::connect(addr).unwrap();
    poll.registry()
        .register(
            &mut client,
            Token(0),
            Interest::READABLE.add(Interest::WRITABLE),
        )
        .unwrap();

    let (socket, _) = listener.accept().unwrap();

    wait!(poll, is_writable, false);

    let mut events = Events::with_capacity(16);

    // Polling should not have any events
    poll.poll(&mut events, Some(Duration::from_millis(100)))
        .unwrap();

    let next = events.iter().next();
    assert!(next.is_none());

    println!("SHUTTING DOWN");
    // Now, shutdown the write half of the socket.
    socket.shutdown(Shutdown::Write).unwrap();

    // POLLRDHUP isn't supported on Solaris,
    if cfg!(any(
        target_os = "hurd",
        target_os = "solaris",
        target_os = "nto"
    )) {
        wait!(poll, is_readable, false);
    } else {
        wait!(poll, is_readable, true);
    }
    println!("tcp::test_write_shutdown PASS");
}

struct MyHandler {
    listener: TcpListener,
    connected: TcpStream,
    accepted: Option<TcpStream>,
    shutdown: bool,
}

fn test_local_addr_ready() {
    init();

    let addr = "127.0.0.1:0".parse().unwrap();
    let mut server = TcpListener::bind(addr).unwrap();
    let addr = server.local_addr().unwrap();

    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut server, LISTEN, Interest::READABLE)
        .unwrap();

    let mut sock = TcpStream::connect(addr).unwrap();
    poll.registry()
        .register(&mut sock, CLIENT, Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(1024);

    let mut handler = MyHandler {
        listener: server,
        connected: sock,
        accepted: None,
        shutdown: false,
    };

    while !handler.shutdown {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            // println!("event: {:?}", event);
            // std::thread::sleep(Duration::from_millis(100));
            match event.token() {
                LISTEN => {
                    let mut sock = handler.listener.accept().unwrap().0;
                    poll.registry()
                        .register(&mut sock, SERVER, Interest::WRITABLE)
                        .unwrap();
                    handler.accepted = Some(sock);
                }
                SERVER => {
                    handler.accepted.as_ref().unwrap().peer_addr().unwrap();
                    handler.accepted.as_ref().unwrap().local_addr().unwrap();
                    let n = handler
                        .accepted
                        .as_mut()
                        .unwrap()
                        .write(&[1, 2, 3])
                        .unwrap();
                    assert_eq!(n, 3);
                    handler.accepted = None; // TODO: this line triggers close/disconnect,
                                             // which makes client closed,
                                             // which returns error on peer_addr() below.
                }
                CLIENT => {
                    handler.connected.peer_addr().unwrap();
                    handler.connected.local_addr().unwrap();
                    handler.shutdown = true;
                }
                _ => panic!("unexpected token"),
            }
        }
    }
    println!("tcp::test_local_addr_ready PASS");
}

fn test_write_then_drop() {
    init();

    let mut a = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = a.local_addr().unwrap();
    let mut s = TcpStream::connect(addr).unwrap();

    let mut poll = Poll::new().unwrap();

    poll.registry()
        .register(&mut a, Token(1), Interest::READABLE)
        .unwrap();

    poll.registry()
        .register(&mut s, Token(3), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(1024);
    while events.is_empty() {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.iter().count(), 1);
    assert_eq!(events.iter().next().unwrap().token(), Token(1));

    let mut s2 = a.accept().unwrap().0;

    poll.registry()
        .register(&mut s2, Token(2), Interest::WRITABLE)
        .unwrap();

    let mut events = Events::with_capacity(1024);
    while events.is_empty() {
        poll.poll(&mut events, None).unwrap();
    }
    if events.iter().count() != 1 {
        for event in &events {
            println!("bad events: {event:?}");
        }
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(events.iter().count(), 1);
    assert_eq!(events.iter().next().unwrap().token(), Token(2));

    s2.write_all(&[1, 2, 3, 4]).unwrap();
    drop(s2);

    poll.registry()
        .reregister(&mut s, Token(3), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(1024);
    while events.is_empty() {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.iter().count(), 1);
    assert_eq!(events.iter().next().unwrap().token(), Token(3));

    let mut buf = [0; 10];
    crate::util::expect_read!(s.read(&mut buf), &[1, 2, 3, 4]);
    println!("tcp::test_write_then_drop PASS");
}

fn test_write_then_deregister() {
    init();

    let mut a = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = a.local_addr().unwrap();
    let mut s = TcpStream::connect(addr).unwrap();

    let mut poll = Poll::new().unwrap();

    poll.registry()
        .register(&mut a, Token(1), Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(&mut s, Token(3), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(1024);
    while events.is_empty() {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.iter().count(), 1);
    assert_eq!(events.iter().next().unwrap().token(), Token(1));

    let mut s2 = a.accept().unwrap().0;

    poll.registry()
        .register(&mut s2, Token(2), Interest::WRITABLE)
        .unwrap();

    let mut events = Events::with_capacity(1024);
    while events.is_empty() {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.iter().count(), 1);
    assert_eq!(events.iter().next().unwrap().token(), Token(2));

    s2.write_all(&[1, 2, 3, 4]).unwrap();
    poll.registry().deregister(&mut s2).unwrap();

    poll.registry()
        .reregister(&mut s, Token(3), Interest::READABLE)
        .unwrap();

    let mut events = Events::with_capacity(1024);
    while events.is_empty() {
        poll.poll(&mut events, None).unwrap();
    }
    assert_eq!(events.iter().count(), 1);
    assert_eq!(events.iter().next().unwrap().token(), Token(3));

    let mut buf = [0; 10];
    crate::util::expect_read!(s.read(&mut buf), &[1, 2, 3, 4]);
    println!("tcp::test_write_then_deregister PASS");
}

const ID1: Token = Token(1);
const ID2: Token = Token(2);
const ID3: Token = Token(3);

fn test_tcp_no_events_after_deregister() {
    let (mut poll, mut events) = init_with_poll();

    let mut listener = TcpListener::bind(any_local_address()).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();

    poll.registry()
        .register(&mut listener, ID1, Interest::READABLE)
        .unwrap();
    poll.registry()
        .register(&mut stream, ID3, Interest::READABLE)
        .unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID1, Interest::READABLE)],
    );

    let (mut stream2, peer_address) = listener.accept().expect("unable to accept connection");
    assert!(peer_address.ip().is_loopback());
    assert_eq!(stream2.peer_addr().unwrap(), peer_address);
    assert_eq!(stream2.local_addr().unwrap(), addr);

    poll.registry()
        .register(&mut stream2, ID2, Interest::WRITABLE)
        .unwrap();
    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID2, Interest::WRITABLE)],
    );

    stream2.write_all(&[1, 2, 3, 4]).unwrap();

    expect_events(
        &mut poll,
        &mut events,
        vec![ExpectEvent::new(ID3, Interest::READABLE)],
    );

    poll.registry().deregister(&mut listener).unwrap();
    poll.registry().deregister(&mut stream).unwrap();
    poll.registry().deregister(&mut stream2).unwrap();

    expect_no_events(&mut poll, &mut events);

    let mut buf = [0; 10];
    crate::util::expect_read!(stream.read(&mut buf), &[1, 2, 3, 4]);

    crate::util::checked_write!(stream2.write(&[1, 2, 3, 4]));
    expect_no_events(&mut poll, &mut events);

    sleep(Duration::from_millis(200));
    crate::util::expect_read!(stream.read(&mut buf), &[1, 2, 3, 4]);

    expect_no_events(&mut poll, &mut events);
    println!("tcp::test_tcp_no_events_after_deregister PASS");
}

pub fn run_all_tests() {
    #[cfg(not(debug_assertions))]
    test_assert_size();

    test_is_send_and_sync();
    test_accept();
    test_connect();
    test_read();
    test_peek();
    test_write();
    test_connect_then_close();
    test_listen_then_close();
    test_bind_twice_bad();
    test_multiple_writes_immediate_success();
    test_connection_reset_by_peer();
    test_connect_error();
    test_write_error();
    test_write_shutdown();
    test_local_addr_ready();
    test_write_then_drop();
    test_write_then_deregister();
    test_tcp_no_events_after_deregister();

    std::thread::sleep(Duration::from_millis(100));
    println!("tcp ALL PASS");
    std::thread::sleep(Duration::from_millis(100));
}
