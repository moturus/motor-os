use std::{
    io::Write,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    thread,
    time::Duration,
};

const PAYLOAD_LEN: usize = 4096;

fn expected_byte(offset: usize) -> u8 {
    (offset.wrapping_mul(37).wrapping_add(11) & 0xff) as u8
}

fn echo_one(socket: UdpSocket) {
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut payload = vec![0_u8; PAYLOAD_LEN + 1];
    let (len, peer) = socket.recv_from(&mut payload).unwrap();
    assert_eq!(len, PAYLOAD_LEN);
    assert!(
        payload[..len]
            .iter()
            .enumerate()
            .all(|(offset, byte)| *byte == expected_byte(offset))
    );
    assert_eq!(socket.send_to(&payload[..len], peer).unwrap(), len);
}

fn main() {
    let ipv4 = UdpSocket::bind((Ipv4Addr::new(192, 168, 4, 1), 0)).unwrap();
    let port = ipv4.local_addr().unwrap().port();
    let ipv6 = UdpSocket::bind((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), port)).unwrap();

    println!("{port}");
    std::io::stdout().flush().unwrap();

    let ipv4_thread = thread::spawn(move || echo_one(ipv4));
    let ipv6_thread = thread::spawn(move || echo_one(ipv6));
    ipv4_thread.join().unwrap();
    ipv6_thread.join().unwrap();
}
