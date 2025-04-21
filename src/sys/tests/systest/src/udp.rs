#![allow(clippy::slow_vector_initialization)]

fn test_udp_basic() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();

    assert_eq!(a1, s1.local_addr().unwrap());
    assert_eq!(a2, s2.local_addr().unwrap());

    let buf1 = [7; 10];
    assert_eq!(buf1.len(), s1.send_to(&buf1, a2).unwrap());

    let mut buf2 = [0; 100];

    let (amt, src) = s2.peek_from(&mut buf2).unwrap();
    assert_eq!(amt, buf1.len());
    assert_eq!(src, a1);
    assert_eq!(&buf1, &buf2[0..amt]);

    let (amt, src) = s2.recv_from(&mut buf2).unwrap();

    assert_eq!(amt, buf1.len());
    assert_eq!(src, a1);
    assert_eq!(&buf1, &buf2[0..amt]);

    println!("-- test_udp_basic() PASS");
}

fn test_udp_large_packets() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();

    let mut buf1 = vec![];
    buf1.resize(moto_rt::net::MAX_UDP_PAYLOAD, 0); // 65493

    let mut buf2 = vec![];
    buf2.resize(moto_rt::net::MAX_UDP_PAYLOAD, 0);

    #[cfg(debug_assertions)]
    const NUM_PACKETS: i32 = 10;
    #[cfg(not(debug_assertions))]
    const NUM_PACKETS: i32 = 100;

    for idx in 0..NUM_PACKETS {
        buf1[4097] = (idx % 255) as u8;
        assert_eq!(buf1.len(), s1.send_to(&buf1, a2).unwrap());
        let (amt, src) = s2.recv_from(&mut buf2).unwrap();

        assert_eq!(amt, buf1.len());
        assert_eq!(src, a1);
        assert_eq!(buf2[4097], (idx % 255) as u8);
    }

    println!("-- test_udp_large_packets() PASS");
}

fn test_udp_double_bind() {
    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let sock = std::net::UdpSocket::bind(addr).unwrap();
    assert!(std::net::UdpSocket::bind(addr).is_err()); // Can't bind again to the same address.
    drop(sock);
    let _ = std::net::UdpSocket::bind(addr).unwrap(); // Can bind now that `sock` is dropped.
    println!("-- test_udp_double_bind() PASS");
}

fn test_udp_connect() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10000").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10001").unwrap();
    let a3 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:10002").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();
    let s3 = std::net::UdpSocket::bind(a3).unwrap();

    s1.connect(a2).unwrap();
    assert_eq!(s1.local_addr().unwrap(), a1);
    assert_eq!(s1.peer_addr().unwrap(), a2);
    assert_eq!(
        s2.peer_addr().err().unwrap().kind(),
        std::io::ErrorKind::NotConnected
    );

    s2.connect(a1).unwrap();
    assert_eq!(s2.local_addr().unwrap(), a2);
    assert_eq!(s2.peer_addr().unwrap(), a1);

    let buf1 = [7; 10];
    // s3 -> s2 packet is dropped, but s1 -> s2 is received.
    assert_eq!(buf1.len(), s3.send_to(&buf1, a2).unwrap());
    assert_eq!(buf1.len(), s1.send(&buf1).unwrap());

    let mut buf2 = [0; 100];

    // s1 -> s2 send works.
    let (amt, src) = s2.peek_from(&mut buf2).unwrap();
    assert_eq!(amt, buf1.len());
    assert_eq!(src, a1);
    assert_eq!(&buf1, &buf2[0..amt]);

    let amt = s2.peek(&mut buf2).unwrap();
    assert_eq!(amt, buf1.len());
    assert_eq!(&buf1, &buf2[0..amt]);

    let amt = s2.recv(&mut buf2).unwrap();

    assert_eq!(amt, buf1.len());
    assert_eq!(&buf1, &buf2[0..amt]);

    println!("-- test_udp_connect() PASS");
}

fn test_udp_timeouts() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();

    // No timeouts by default.
    assert!(s1.write_timeout().unwrap().is_none());
    assert!(s1.read_timeout().unwrap().is_none());

    // Set timeouts.
    let timo = std::time::Duration::from_millis(1);
    s1.set_write_timeout(Some(timo)).unwrap();
    s1.set_read_timeout(Some(timo)).unwrap();

    assert_eq!(timo, s1.write_timeout().unwrap().unwrap());
    assert_eq!(timo, s1.read_timeout().unwrap().unwrap());

    #[allow(unused)]
    let mut buf = &mut [0; 64];
    assert_eq!(
        s1.peek_from(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(
        s1.recv_from(buf).err().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );

    // Clear timeouts.
    s1.set_write_timeout(None).unwrap();
    s1.set_read_timeout(None).unwrap();

    assert!(s1.write_timeout().unwrap().is_none());
    assert!(s1.read_timeout().unwrap().is_none());

    // Disallow zero timeouts: see
    // https://doc.rust-lang.org/std/net/struct.UdpSocket.html#method.set_write_timeout
    let zero = std::time::Duration::new(0, 0);
    assert_eq!(
        s1.set_write_timeout(Some(zero)).err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        s1.set_read_timeout(Some(zero)).err().unwrap().kind(),
        std::io::ErrorKind::InvalidInput
    );

    println!("-- test_udp_timeouts() PASS");
}

pub fn run_all_tests() {
    test_udp_basic();
    test_udp_large_packets();
    test_udp_double_bind();
    test_udp_connect();
    test_udp_timeouts();
    println!("UDP tests PASS");
}
