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

    println!("test_udp_basic() PASS");
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

    println!("test_udp_large_packets() PASS");
}

fn test_udp_double_bind() {
    let addr = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let sock = std::net::UdpSocket::bind(addr).unwrap();
    assert!(std::net::UdpSocket::bind(addr).is_err()); // Can't bind again to the same address.
    drop(sock);
    let _ = std::net::UdpSocket::bind(addr).unwrap(); // Can bind now that `sock` is dropped.
    println!("test_udp_double_bind() PASS");
}

pub fn run_all_tests() {
    test_udp_basic();
    test_udp_large_packets();
    test_udp_double_bind();
}
