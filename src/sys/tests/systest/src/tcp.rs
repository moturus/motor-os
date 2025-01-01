#![allow(unused)]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{atomic::*, Arc};
use std::time::Duration;

fn handle_client(mut stream: std::net::TcpStream, stop: Arc<AtomicBool>) {
    stream.set_read_timeout(Some(Duration::from_millis(1000)));
    let mut data = [0_u8; 17];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match stream.read(&mut data) {
            Ok(size) => {
                if size == 0 {
                    break;
                }
                for byte in &mut data {
                    *byte = 255 - *byte;
                }
                stream.write_all(&data[0..size]).unwrap();
            }
            Err(_) => {
                break;
            }
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn server_thread(start: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:3333").unwrap();
    assert!(std::net::TcpListener::bind("127.0.0.1:3333").is_err());
    start.store(true, Ordering::Release);

    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let stop_clone = stop.clone();
                std::thread::spawn(move || handle_client(stream, stop_clone));
            }
            Err(e) => {
                std::thread::sleep(std::time::Duration::from_secs(1));
                println!("Error: ----------- {} ----------------", e);
                panic!("{}", e)
                /* connection failed */
            }
        }
    }
}

fn client_iter() {
    let addrs: Vec<_> = "localhost:3333".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let mut stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(1000)).unwrap();
    let tx: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    stream.write_all(&tx).unwrap();

    let mut rx = [0_u8; 8];
    match stream.read_exact(&mut rx) {
        Ok(_) => {
            assert_eq!(rx, [254, 253, 252, 251, 250, 249, 248, 247]);
        }
        Err(e) => {
            println!("Failed to receive data: {}", e);
            panic!("{:?}", e)
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

fn test_io_latency() {
    let addrs: Vec<_> = "localhost:3333".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(1000)).unwrap();

    // set_nodelay() is a good way to measure local I/O latency, as for the loopback
    // device it is a NOOP.
    let mut iters = 0_u64;
    const DUR: Duration = Duration::from_millis(500);
    let start = std::time::Instant::now();
    while start.elapsed() < DUR {
        stream.set_nodelay(true).unwrap();
        iters += 1;
    }

    let elapsed = start.elapsed();
    let _ = stream.shutdown(std::net::Shutdown::Both);
    println!(
        "IO latency of TcpStream::set_nodelay(): {:.3} usec/IO",
        elapsed.as_secs_f64() * 1000.0 * 1000.0 / (iters as f64)
    );
}

fn test_read_timeout() {
    let started_listener = Arc::new(AtomicBool::new(false));
    let started_sender = started_listener.clone();
    let stop_sender = Arc::new(AtomicBool::new(false));
    let stop_listener = stop_sender.clone();
    let server = std::thread::spawn(move || {
        let listener = std::net::TcpListener::bind("127.0.0.1:3334").unwrap();
        assert!(std::net::TcpListener::bind("127.0.0.1:3334").is_err());
        started_sender.store(true, Ordering::Release);

        let mut stream = listener.incoming().next().unwrap().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        // Read, don't write.
        let mut data = [0_u8; 64];
        while !stop_listener.load(Ordering::Relaxed) {
            let _ = stream.read(&mut data);
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });

    while !started_listener.load(Ordering::Relaxed) {
        core::hint::spin_loop()
    }

    let addrs: Vec<_> = "localhost:3334".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let mut stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(1000)).unwrap();
    let tx: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    stream.write_all(&tx).unwrap();

    assert!(stream.read_timeout().unwrap().is_none());
    stream
        .set_read_timeout(Some(Duration::from_millis(600)))
        .unwrap();

    let mut rx = [0_u8; 8];
    let start = std::time::Instant::now();
    match stream.read(&mut rx) {
        Ok(_) => {
            panic!("test_read_timeout: did read something")
        }
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        }
    }
    let timo = std::time::Instant::now() - start;
    assert!(timo.as_millis() >= 600);

    assert_eq!(stream.read_timeout().unwrap().unwrap().as_millis(), 600);
    stream.set_read_timeout(None).unwrap();
    assert!(stream.read_timeout().unwrap().is_none());

    assert!(stream.write_timeout().unwrap().is_none());
    stream
        .set_write_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    assert_eq!(stream.write_timeout().unwrap().unwrap().as_millis(), 2);
    stream.set_write_timeout(None).unwrap();
    assert!(stream.write_timeout().unwrap().is_none());

    // Test nodelay get/set.
    stream.set_nodelay(true).unwrap();
    assert!(stream.nodelay().unwrap());
    stream.set_nodelay(false).unwrap();
    assert!(!stream.nodelay().unwrap());

    stream.set_ttl(43).unwrap();
    assert_eq!(43, stream.ttl().unwrap());

    let _ = stream.shutdown(std::net::Shutdown::Both);
    stop_sender.store(true, Ordering::Relaxed);

    // TODO: server.join() below sometimes (rarely) hangs, indicating that stream.shutdown()
    //       above and in the server thread don't fully mesh together.
    //       This is a bug that needs fixing.
    // server.join();
}

fn test_tcp_loopback() {
    assert!(std::net::TcpStream::connect("localhost:3333").is_err());
    let start = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let start_server = start.clone();
    let stop_server = stop.clone();
    let server = std::thread::spawn(|| server_thread(start_server, stop_server));

    while !start.load(Ordering::Acquire) {
        core::hint::spin_loop()
    }

    client_iter();
    client_iter();
    client_iter();
    std::thread::sleep(Duration::from_millis(100));
    println!("will test latency");
    std::thread::sleep(Duration::from_millis(100));
    test_io_latency();

    stop.store(true, Ordering::Release);
    // Kick the listener.
    // TODO: is there a better way?
    while !server.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let socket_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            3333,
        );
        let stream = std::net::TcpStream::connect_timeout(&socket_addr, Duration::from_millis(100));
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Ok(stream) = stream {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
    server.join().unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));
    test_read_timeout();
    // TODO: how can we test write timeout?

    // Wrap the output in sleeps to avoid debug console output mangling.
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_tcp_loopback() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

pub fn test_zero_port_listen() {
    static HELLO: &[u8] = b"hello";
    static BYE: &[u8] = b"see you later";

    let port = Arc::new(AtomicU16::new(0));
    let response_received = AtomicBool::new(false);

    std::thread::scope(|scope| {
        // server/listener
        scope.spawn(|| {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let listener = std::net::TcpListener::bind(addr).unwrap();
            port.store(listener.local_addr().unwrap().port(), Ordering::Release);

            let (mut conn, _) = listener.accept().unwrap();

            let mut buf = [0_u8; HELLO.len()];
            conn.read_exact(&mut buf).unwrap();
            assert_eq!(buf, HELLO);
            conn.write_all(BYE).unwrap();
            // If the server is dropped now, the write above may not be delivered.
            while !response_received.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        });

        // Client: wait for the listener to start.
        while port.load(Ordering::Relaxed) == 0 {
            core::hint::spin_loop();
        }

        let addr: SocketAddr = format!("127.0.0.1:{}", port.load(Ordering::Relaxed))
            .parse()
            .unwrap();
        let mut conn = std::net::TcpStream::connect(addr).unwrap();
        conn.write_all(HELLO).unwrap();
        let mut buf = [0_u8; BYE.len()];
        conn.read_exact(&mut buf).unwrap();
        assert_eq!(buf, BYE);
        response_received.store(true, Ordering::Relaxed);
    });
}

fn test_peek() {
    const N: usize = 1024 * 1024 * 3 + 1001;

    let listener = std::net::TcpListener::bind("127.0.0.1:333").unwrap();
    let server_thread = std::thread::spawn(move || {
        let (mut server, _) = listener.accept().unwrap();

        let mut buf = [0_u8; 1024];
        #[allow(clippy::needless_range_loop)]
        for pos in 0..buf.len() {
            buf[pos] = (pos & 255) as u8;
        }

        let mut total_written = 0;
        while total_written < N {
            total_written += server.write(&buf).unwrap();
        }
    });

    let mut client = std::net::TcpStream::connect("127.0.0.1:333").unwrap();
    let mut buf = [0_u8; 1024];
    let mut total_received = 0;
    let mut peek = false;
    while total_received < N {
        if peek {
            let sz = client.peek(&mut buf).unwrap();
            assert!(sz > 0);
            #[allow(clippy::needless_range_loop)]
            for pos in 0..sz {
                assert_eq!(buf[pos], ((total_received + pos) & 255) as u8);
            }
        }
        let sz = client.read(&mut buf).unwrap();
        assert!(sz > 0);
        #[allow(clippy::needless_range_loop)]
        for pos in 0..sz {
            assert_eq!(buf[pos], ((total_received + pos) & 255) as u8);
        }
        total_received += sz;
    }

    server_thread.join().unwrap();

    // Wrap the output in sleeps to avoid debug console output mangling.
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_peek() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

fn test_ipv6() {
    const N: usize = 1024 * 1024 * 3 + 1001;

    let listener = std::net::TcpListener::bind("[::1]:333").unwrap();
    let server_thread = std::thread::spawn(move || {
        let (mut server, _) = listener.accept().unwrap();

        let mut buf = [0_u8; 1024];
        #[allow(clippy::needless_range_loop)]
        for pos in 0..buf.len() {
            buf[pos] = (pos & 255) as u8;
        }

        let mut total_written = 0;
        while total_written < N {
            server.write_all(&buf).unwrap();
            total_written += buf.len();
        }
    });

    let mut client = std::net::TcpStream::connect("[::1]:333").unwrap();
    let mut buf = [0_u8; 1024];
    let mut total_received = 0;
    while total_received < N {
        let sz = client.read(&mut buf).unwrap();
        assert!(sz > 0);
        #[allow(clippy::needless_range_loop)]
        for pos in 0..sz {
            assert_eq!(buf[pos], ((total_received + pos) & 255) as u8);
        }
        total_received += sz;
    }

    server_thread.join().unwrap();

    // Wrap the output in sleeps to avoid debug console output mangling.
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_ipv6() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

pub fn run_tests() {
    test_ipv6();
    test_zero_port_listen();
    test_tcp_loopback();
    test_peek();
}

// pub fn test_wget() {
//     // let url = "1.1.1.1:80";
//     // let url = "10.0.2.10:10023";
//     let mut stream = std::net::TcpStream::connect(url).unwrap();
//     let request = "GET /\nHost: 1.1.1.1\nUser-Agent: *\nAccept: */*\n\n";
//     stream.write(request.as_bytes()).unwrap();

//     let mut rx = [0 as u8; 8];
//     match stream.read(&mut rx) {
//         Ok(_) => {
//             println!("test_wget(): got a response from {}", url);
//         }
//         Err(e) => {
//             println!("Failed to receive data: {}", e);
//             panic!()
//         }
//     }
// }
