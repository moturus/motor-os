fn test_udp_basic() {
    let a1 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:1234").unwrap();
    let a2 = std::net::SocketAddr::parse_ascii(b"127.0.0.1:5678").unwrap();
    let s1 = std::net::UdpSocket::bind(a1).unwrap();
    let s2 = std::net::UdpSocket::bind(a2).unwrap();

    let buf1 = [7; 10];
    assert_eq!(buf1.len(), s1.send_to(&buf1, a2).unwrap());

    let mut buf2 = [0; 100];
    let (amt, src) = s2.recv_from(&mut buf2).unwrap();

    assert_eq!(amt, buf1.len());
    assert_eq!(src, a1);
    assert_eq!(&buf1, &buf2[0..amt]);

    println!("test_udp_basic() PASS");
}

pub fn run_all_tests() {
    test_udp_basic();
}
