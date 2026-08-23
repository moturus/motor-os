use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use moto_dns::Status;

const DNS_PORT: u16 = 53;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const ATTEMPTS: usize = 2;
const UDP_RESPONSE_MAX: usize = 512;

enum ParsedResponse {
    Ignore,
    Truncated,
    Answer(Vec<IpAddr>),
    Error(Status),
}

pub(super) fn lookup(name: &[u8], qtype: u16, servers: &[IpAddr]) -> Result<Vec<IpAddr>, Status> {
    let mut last_error = Status::TemporaryFailure;
    for _ in 0..ATTEMPTS {
        for server in servers {
            match udp_attempt(name, qtype, *server) {
                Ok(addresses) => return Ok(addresses),
                Err(Status::NotFound) => return Err(Status::NotFound),
                Err(error) => last_error = error,
            }
        }
    }
    Err(last_error)
}

fn udp_attempt(name: &[u8], qtype: u16, server: IpAddr) -> Result<Vec<IpAddr>, Status> {
    let id = random_id();
    let query = build_query(name, qtype, id)?;
    let bind_ip = match server {
        IpAddr::V4(address) if address.is_loopback() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(address) if address.is_loopback() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).map_err(map_io_error)?;
    socket
        .connect(SocketAddr::new(server, DNS_PORT))
        .map_err(map_io_error)?;
    socket.send(&query).map_err(map_io_error)?;

    let deadline = Instant::now() + ATTEMPT_TIMEOUT;
    let mut packet = [0u8; UDP_RESPONSE_MAX];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Status::TimedOut)?;
        socket
            .set_read_timeout(Some(remaining))
            .map_err(map_io_error)?;
        let len = socket.recv(&mut packet).map_err(map_io_error)?;
        match parse_response(&packet[..len], id, name, qtype) {
            ParsedResponse::Ignore => continue,
            ParsedResponse::Truncated => return tcp_attempt(&query, id, name, qtype, server),
            ParsedResponse::Answer(addresses) => return Ok(addresses),
            ParsedResponse::Error(error) => return Err(error),
        }
    }
}

fn tcp_attempt(
    query: &[u8],
    id: u16,
    name: &[u8],
    qtype: u16,
    server: IpAddr,
) -> Result<Vec<IpAddr>, Status> {
    let mut stream =
        TcpStream::connect_timeout(&SocketAddr::new(server, DNS_PORT), ATTEMPT_TIMEOUT)
            .map_err(map_io_error)?;
    stream
        .set_read_timeout(Some(ATTEMPT_TIMEOUT))
        .map_err(map_io_error)?;
    stream
        .set_write_timeout(Some(ATTEMPT_TIMEOUT))
        .map_err(map_io_error)?;
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .and_then(|_| stream.write_all(query))
        .map_err(map_io_error)?;

    let mut len = [0u8; 2];
    stream.read_exact(&mut len).map_err(map_io_error)?;
    let mut packet = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut packet).map_err(map_io_error)?;
    match parse_response(&packet, id, name, qtype) {
        ParsedResponse::Answer(addresses) => Ok(addresses),
        ParsedResponse::Error(error) => Err(error),
        ParsedResponse::Ignore | ParsedResponse::Truncated => Err(Status::ResolverFailure),
    }
}

fn random_id() -> u16 {
    let mut bytes = [0u8; 2];
    moto_rt::fill_random_bytes(&mut bytes);
    u16::from_ne_bytes(bytes)
}

fn build_query(name: &[u8], qtype: u16, id: u16) -> Result<Vec<u8>, Status> {
    let mut query = Vec::with_capacity(name.len() + 18);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    for label in name.split(|byte| *byte == b'.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Status::InvalidRequest);
        }
        query.push(label.len() as u8);
        query.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn parse_response(packet: &[u8], id: u16, name: &[u8], qtype: u16) -> ParsedResponse {
    if packet.len() < 12 || read_u16(packet, 0) != Some(id) {
        return ParsedResponse::Ignore;
    }
    let Some(flags) = read_u16(packet, 2) else {
        return ParsedResponse::Ignore;
    };
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || read_u16(packet, 4) != Some(1) {
        return ParsedResponse::Error(Status::ResolverFailure);
    }
    let Ok((question, mut offset)) = read_name(packet, 12) else {
        return ParsedResponse::Error(Status::ResolverFailure);
    };
    if !question.eq_ignore_ascii_case(name)
        || read_u16(packet, offset) != Some(qtype)
        || read_u16(packet, offset + 2) != Some(1)
    {
        return ParsedResponse::Error(Status::ResolverFailure);
    }
    offset += 4;
    match flags & 0x000f {
        0 => {}
        2 => return ParsedResponse::Error(Status::TemporaryFailure),
        3 => return ParsedResponse::Error(Status::NotFound),
        _ => return ParsedResponse::Error(Status::ResolverFailure),
    }
    if flags & 0x0200 != 0 {
        return ParsedResponse::Truncated;
    }

    let answers = read_u16(packet, 6).unwrap_or(0);
    let mut accepted_names = vec![name.to_vec()];
    let mut addresses = Vec::new();
    for _ in 0..answers {
        let Ok((owner, next)) = read_name(packet, offset) else {
            return ParsedResponse::Error(Status::ResolverFailure);
        };
        offset = next;
        let (Some(record_type), Some(class), Some(data_len)) = (
            read_u16(packet, offset),
            read_u16(packet, offset + 2),
            read_u16(packet, offset + 8),
        ) else {
            return ParsedResponse::Error(Status::ResolverFailure);
        };
        offset += 10;
        let end = match offset.checked_add(data_len as usize) {
            Some(end) if end <= packet.len() => end,
            _ => return ParsedResponse::Error(Status::ResolverFailure),
        };
        let accepted = accepted_names
            .iter()
            .any(|name| owner.eq_ignore_ascii_case(name));
        if accepted && record_type == 5 && class == 1 {
            let Ok((target, target_end)) = read_name(packet, offset) else {
                return ParsedResponse::Error(Status::ResolverFailure);
            };
            if target_end != end {
                return ParsedResponse::Error(Status::ResolverFailure);
            }
            if !accepted_names.contains(&target) {
                accepted_names.push(target);
            }
        } else if accepted {
            let address = match (record_type, class, &packet[offset..end]) {
                (1, 1, bytes) if qtype == 1 && bytes.len() == 4 => {
                    Some(IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap()))
                }
                (28, 1, bytes) if qtype == 28 && bytes.len() == 16 => {
                    Some(IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap()))
                }
                _ => None,
            };
            if let Some(address) = address {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        offset = end;
    }
    if addresses.is_empty() {
        ParsedResponse::Error(Status::NotFound)
    } else {
        ParsedResponse::Answer(addresses)
    }
}

fn read_name(packet: &[u8], start: usize) -> Result<(Vec<u8>, usize), ()> {
    let mut name = Vec::new();
    let mut cursor = start;
    let mut next = None;
    let mut jumps = 0;
    loop {
        let len = *packet.get(cursor).ok_or(())?;
        if len & 0xc0 == 0xc0 {
            let low = *packet.get(cursor + 1).ok_or(())?;
            next.get_or_insert(cursor + 2);
            cursor = (((len & 0x3f) as usize) << 8) | low as usize;
            jumps += 1;
            if jumps > 16 {
                return Err(());
            }
            continue;
        }
        if len & 0xc0 != 0 || len > 63 {
            return Err(());
        }
        cursor += 1;
        if len == 0 {
            return Ok((name, next.unwrap_or(cursor)));
        }
        let end = cursor.checked_add(len as usize).ok_or(())?;
        let label = packet.get(cursor..end).ok_or(())?;
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend(label.iter().map(u8::to_ascii_lowercase));
        if name.len() > 253 {
            return Err(());
        }
        cursor = end;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        packet.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn map_io_error(error: std::io::Error) -> Status {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Status::TimedOut,
        _ => Status::TemporaryFailure,
    }
}

pub(super) fn self_test() {
    let name = b"example.test";
    let query = build_query(name, 1, 0x1234).unwrap();
    let mut response = Vec::from(&query[..]);
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1]);
    match parse_response(&response, 0x1234, name, 1) {
        ParsedResponse::Answer(addresses) => {
            assert_eq!(addresses, ["192.0.2.1".parse::<IpAddr>().unwrap()]);
        }
        _ => panic!("valid DNS response was rejected"),
    }
    assert!(matches!(
        parse_response(&response, 0x4321, name, 1),
        ParsedResponse::Ignore
    ));
    response[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
    assert!(matches!(
        parse_response(&response, 0x1234, name, 1),
        ParsedResponse::Truncated
    ));

    transport_self_test();
}

fn transport_self_test() {
    let udp = UdpSocket::bind(("127.0.0.1", DNS_PORT)).unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let tcp = TcpListener::bind(("127.0.0.1", DNS_PORT)).unwrap();
    let server = std::thread::spawn(move || {
        let mut packet = [0u8; UDP_RESPONSE_MAX];
        let _ = udp.recv_from(&mut packet).unwrap();
        let (len, peer) = udp.recv_from(&mut packet).unwrap();
        let mut truncated = Vec::from(&packet[..len]);
        truncated[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
        udp.send_to(&truncated, peer).unwrap();

        let (mut stream, _) = tcp.accept().unwrap();
        let mut query_len = [0u8; 2];
        stream.read_exact(&mut query_len).unwrap();
        let mut query = vec![0u8; u16::from_be_bytes(query_len) as usize];
        stream.read_exact(&mut query).unwrap();
        let mut response = query;
        response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 9]);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .and_then(|_| stream.write_all(&response))
            .unwrap();
    });

    assert_eq!(
        lookup(
            b"example.test",
            1,
            &["127.0.0.1".parse::<IpAddr>().unwrap()]
        )
        .unwrap(),
        ["192.0.2.9".parse::<IpAddr>().unwrap()]
    );
    server.join().unwrap();
}
