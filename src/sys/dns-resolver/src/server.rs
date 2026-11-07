//! Loopback DNS transport for clients using the DNS wire protocol, including mlibc.
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use moto_dns::AddressFamily;

const WORKERS: usize = 2;
const MAX_QUERY: usize = 4096;
const UDP_LIMIT: usize = 512;

pub(super) fn start() -> io::Result<()> {
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:53")?);
    let tcp = Arc::new(TcpListener::bind("127.0.0.1:53")?);
    for index in 0..WORKERS {
        let socket = udp.clone();
        std::thread::Builder::new()
            .name(format!("dns-udp:{index}"))
            .spawn(move || {
                if let Err(error) = serve_udp(&socket) {
                    log::error!("DNS UDP listener failed: {error}");
                    std::process::exit(1);
                }
            })?;
        let listener = tcp.clone();
        std::thread::Builder::new()
            .name(format!("dns-tcp:{index}"))
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else {
                        log::error!("DNS TCP listener failed");
                        std::process::exit(1);
                    };
                    // Each worker serves one bounded connection. Slow or
                    // disconnected clients cannot grow the worker pool.
                    let _ = serve_tcp(stream);
                }
            })?;
    }
    Ok(())
}

fn serve_udp(socket: &UdpSocket) -> io::Result<()> {
    let mut packet = [0; MAX_QUERY + 1];
    loop {
        let (length, peer) = socket.recv_from(&mut packet)?;
        if !peer.ip().is_loopback() || length < 12 || packet[2] & 0x80 != 0 {
            continue;
        }
        let response = limit_udp(answer(&packet[..length]));
        // A client may close its socket while the upstream request runs.
        if let Err(error) = socket.send_to(&response, peer) {
            log::debug!("DNS UDP response failed: {error}");
        }
    }
}

fn limit_udp(response: Vec<u8>) -> Vec<u8> {
    if response.len() <= UDP_LIMIT {
        return response;
    }
    // Keep the question so clients can validate the transaction before TCP
    // fallback. Re-encode it without pointers into the discarded records.
    let (name, end) = super::dns::read_name(&response, 12).unwrap();
    let qtype = u16::from_be_bytes([response[end], response[end + 1]]);
    let id = u16::from_be_bytes([response[0], response[1]]);
    let mut truncated = super::dns::build_query(&name, qtype, id).unwrap();
    truncated[2] = response[2] | 0x02;
    truncated[3] = response[3];
    truncated
}

fn serve_tcp(mut stream: TcpStream) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    // One question per connection keeps idle clients from holding a worker.
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let mut size = [0; 2];
        read_before(&mut stream, &mut size, deadline)?;
        let length = u16::from_be_bytes(size) as usize;
        if !(12..=MAX_QUERY).contains(&length) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut packet = vec![0; length];
        read_before(&mut stream, &mut packet, deadline)?;
        let response = answer(&packet);
        stream.write_all(&(response.len() as u16).to_be_bytes())?;
        stream.write_all(&response)?;
    }
    Ok(())
}

fn read_before(
    stream: &mut TcpStream,
    mut bytes: &mut [u8],
    deadline: std::time::Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or(io::ErrorKind::TimedOut)?;
        stream.set_read_timeout(Some(remaining))?;
        let count = stream.read(bytes)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn error(packet: &[u8], code: u8) -> Vec<u8> {
    let mut response = vec![0; 12];
    response[..2].copy_from_slice(&packet[..2]);
    response[2] = 0x80 | (packet[2] & 1);
    response[3] = 0x80 | code;
    response
}

fn question(packet: &[u8]) -> Option<(Vec<u8>, u16)> {
    if packet.len() > MAX_QUERY
        || packet.len() < 12
        || packet[2] & 0xf8 != 0
        || u16::from_be_bytes([packet[4], packet[5]]) != 1
        || packet[6..10] != [0; 4]
    {
        return None;
    }
    let (name, end) = super::dns::read_name(packet, 12).ok()?;
    let tail = packet.get(end..end + 4)?;
    if !name.is_ascii() || tail[2..] != [0, 1] {
        return None;
    }
    let mut offset = end + 4;
    // Accept one EDNS OPT record, but use ordinary DNS upstream. No advertised
    // UDP size can make the loopback response exceed the fixed 512-byte bound.
    let additional = u16::from_be_bytes([packet[10], packet[11]]);
    if additional > 1 {
        return None;
    }
    if additional == 1 {
        let (owner, next) = super::dns::read_name(packet, offset).ok()?;
        let record = packet.get(next..next + 10)?;
        if !owner.is_empty() || record[..2] != [0, 41] {
            return None;
        }
        offset = next + 10 + u16::from_be_bytes([record[8], record[9]]) as usize;
    }
    if offset != packet.len() {
        return None;
    }
    Some((name, u16::from_be_bytes([tail[0], tail[1]])))
}

fn answer(packet: &[u8]) -> Vec<u8> {
    let Some((name, qtype)) = question(packet) else {
        return error(packet, 1);
    };
    // Zone transfers require a streaming server, not a bounded stub query.
    if matches!(qtype, 251 | 252) {
        return error(packet, 4);
    }
    let family = match qtype {
        1 => Some(AddressFamily::V4),
        28 => Some(AddressFamily::V6),
        _ => None,
    };
    if let Some(addresses) = family.and_then(|family| super::bridge::local_addresses(&name, family))
    {
        let id = u16::from_be_bytes([packet[0], packet[1]]);
        let mut response = super::dns::build_query(&name, qtype, id).unwrap();
        response[2..4].copy_from_slice(&[0x80 | (packet[2] & 1), 0x80]);
        let record_size = if qtype == 1 { 16 } else { 28 };
        let count = addresses
            .len()
            .min((u16::MAX as usize - response.len()) / record_size);
        if count < addresses.len() {
            response[2] |= 0x02;
        }
        response[6..8].copy_from_slice(&(count as u16).to_be_bytes());
        for address in addresses.into_iter().take(count) {
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&qtype.to_be_bytes());
            response.extend_from_slice(&[0, 1, 0, 0, 0, 0]); // IN, no cache
            match address {
                std::net::IpAddr::V4(address) => {
                    response.extend_from_slice(&4u16.to_be_bytes());
                    response.extend_from_slice(&address.octets());
                }
                std::net::IpAddr::V6(address) => {
                    response.extend_from_slice(&16u16.to_be_bytes());
                    response.extend_from_slice(&address.octets());
                }
            }
        }
        return response;
    }
    let Ok(servers) = super::config::nameservers() else {
        return error(packet, 2);
    };
    match super::dns::forward(&name, qtype, &servers) {
        Ok(mut response) => {
            response[..2].copy_from_slice(&packet[..2]);
            response[2] = (response[2] & !1) | (packet[2] & 1);
            response
        }
        Err(_) => error(packet, 2),
    }
}

pub(super) fn self_test() {
    let query = super::dns::build_query(b"motor-dns-test", 1, 123).unwrap();
    assert_eq!(question(&query), Some((b"motor-dns-test".to_vec(), 1)));
    let root_query = super::dns::build_query(b"", 2, 1).unwrap();
    assert_eq!(question(&root_query), Some((vec![], 2)));
    let mut large = query.clone();
    large[2..4].copy_from_slice(&[0x81, 0x80]);
    large[6..8].copy_from_slice(&32u16.to_be_bytes());
    for _ in 0..32 {
        large.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1]);
    }
    let truncated = limit_udp(large);
    assert_eq!(
        &truncated[..12],
        &[0, 123, 0x83, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(&truncated[12..], &query[12..]);
    for change in [4, 6, 8, 10] {
        let mut bad = query.clone();
        bad[change + 1] = 2;
        assert!(question(&bad).is_none());
        assert_eq!(answer(&bad)[3] & 15, 1);
    }
    let mut cyclic = query[..12].to_vec();
    cyclic.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    assert!(question(&cyclic).is_none());
    for length in 0..query.len() {
        assert!(question(&query[..length]).is_none());
    }
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    udp.connect("127.0.0.1:53").unwrap();
    udp.send(&query).unwrap();
    let mut packet = [0; UDP_LIMIT];
    let length = udp.recv(&mut packet).unwrap();
    assert_eq!(&packet[..4], &[0, 123, 0x81, 0x80]);
    assert_eq!(&packet[length - 4..length], &[127, 0, 0, 53]);

    let query = super::dns::build_query(b"motor-dns-test", 28, 124).unwrap();
    let mut tcp =
        TcpStream::connect_timeout(&"127.0.0.1:53".parse().unwrap(), Duration::from_secs(1))
            .unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    tcp.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
    tcp.write_all(&query).unwrap();
    let mut size = [0; 2];
    tcp.read_exact(&mut size).unwrap();
    let mut response = vec![0; u16::from_be_bytes(size) as usize];
    tcp.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], &[0, 124, 0x81, 0x80]);
    assert_eq!(
        &response[response.len() - 16..],
        &std::net::Ipv6Addr::LOCALHOST.octets()
    );
    println!("dns-resolver loopback UDP/TCP test PASS");
}
