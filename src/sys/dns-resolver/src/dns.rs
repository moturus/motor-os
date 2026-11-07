use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::FromRawFd;
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
    lookup_on_port(name, qtype, servers, DNS_PORT)
}

fn lookup_on_port(
    name: &[u8],
    qtype: u16,
    servers: &[IpAddr],
    port: u16,
) -> Result<Vec<IpAddr>, Status> {
    let mut last_error = Status::TemporaryFailure;
    for _ in 0..ATTEMPTS {
        for server in servers {
            match udp_attempt(name, qtype, *server, port) {
                Ok(addresses) => return Ok(addresses),
                Err(Status::NotFound) => return Err(Status::NotFound),
                Err(error) => last_error = error,
            }
        }
    }
    Err(last_error)
}

fn udp_attempt(name: &[u8], qtype: u16, server: IpAddr, port: u16) -> Result<Vec<IpAddr>, Status> {
    let packet = udp_response(name, qtype, server, port)?;
    let id = read_u16(&packet, 0).ok_or(Status::ResolverFailure)?;
    match parse_response(&packet, id, name, qtype) {
        ParsedResponse::Answer(addresses) => Ok(addresses),
        ParsedResponse::Error(error) => Err(error),
        _ => Err(Status::ResolverFailure),
    }
}

/// Keep the full DNS response, including PTR/CNAME data, TTLs and negative
/// answers. The loopback frontend only changes its transaction ID.
pub(super) fn forward(name: &[u8], qtype: u16, servers: &[IpAddr]) -> Result<Vec<u8>, Status> {
    let mut error = Status::TemporaryFailure;
    for _ in 0..ATTEMPTS {
        for server in servers {
            match udp_response(name, qtype, *server, DNS_PORT) {
                Ok(packet) if packet[3] & 15 != 2 => return Ok(packet),
                Ok(_) => error = Status::TemporaryFailure,
                Err(failure) => error = failure,
            }
        }
    }
    Err(error)
}

fn udp_response(name: &[u8], qtype: u16, server: IpAddr, port: u16) -> Result<Vec<u8>, Status> {
    let id = random_id();
    let query = build_query(name, qtype, id)?;
    let remote = SocketAddr::new(server, port);
    let fd =
        moto_rt::net::udp_bind_for_remote(&remote.into()).map_err(|_| Status::TemporaryFailure)?;
    // The successful bind returns a new descriptor owned by this query.
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    socket.connect(remote).map_err(map_io_error)?;
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
        match validate_packet(&packet[..len], id, name, qtype)? {
            None => continue,
            Some(true) => return tcp_response(&query, id, name, qtype, remote),
            Some(false) => return Ok(packet[..len].to_vec()),
        }
    }
}

fn tcp_response(
    query: &[u8],
    id: u16,
    name: &[u8],
    qtype: u16,
    remote: SocketAddr,
) -> Result<Vec<u8>, Status> {
    let mut stream = TcpStream::connect_timeout(&remote, ATTEMPT_TIMEOUT).map_err(map_io_error)?;
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
    match validate_packet(&packet, id, name, qtype)? {
        Some(false) => Ok(packet),
        _ => Err(Status::ResolverFailure),
    }
}

// None is an unrelated transaction; true requests TCP; false is a complete
// response. Validate all section boundaries before forwarding opaque RDATA.
fn validate_packet(
    packet: &[u8],
    id: u16,
    name: &[u8],
    qtype: u16,
) -> Result<Option<bool>, Status> {
    if packet.len() < 12 || read_u16(packet, 0) != Some(id) {
        return Ok(None);
    }
    let flags = read_u16(packet, 2).unwrap();
    if flags & 0xf800 != 0x8000 || read_u16(packet, 4) != Some(1) {
        return Err(Status::ResolverFailure);
    }
    let (question, mut offset) = read_name(packet, 12).map_err(|_| Status::ResolverFailure)?;
    if !question.eq_ignore_ascii_case(name)
        || read_u16(packet, offset) != Some(qtype)
        || read_u16(packet, offset + 2) != Some(1)
    {
        return Err(Status::ResolverFailure);
    }
    if flags & 0x0200 != 0 {
        return Ok(Some(true));
    }
    offset += 4;
    let count = [6, 8, 10]
        .iter()
        .map(|&offset| read_u16(packet, offset).unwrap() as usize)
        .sum::<usize>();
    for _ in 0..count {
        offset = read_name(packet, offset)
            .map_err(|_| Status::ResolverFailure)?
            .1;
        let kind = read_u16(packet, offset).ok_or(Status::ResolverFailure)?;
        let length = read_u16(packet, offset + 8).ok_or(Status::ResolverFailure)? as usize;
        offset += 10;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= packet.len())
            .ok_or(Status::ResolverFailure)?;
        if matches!(kind, 2 | 5 | 12)
            && read_name(packet, offset)
                .map_err(|_| Status::ResolverFailure)?
                .1
                != end
        {
            return Err(Status::ResolverFailure);
        }
        offset = end;
    }
    if offset != packet.len() {
        return Err(Status::ResolverFailure);
    }
    Ok(Some(false))
}

fn random_id() -> u16 {
    let mut bytes = [0u8; 2];
    moto_rt::fill_random_bytes(&mut bytes);
    u16::from_ne_bytes(bytes)
}

pub(super) fn build_query(name: &[u8], qtype: u16, id: u16) -> Result<Vec<u8>, Status> {
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

pub(super) fn read_name(packet: &[u8], start: usize) -> Result<(Vec<u8>, usize), ()> {
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
    assert_eq!(
        forward(b"example.test", 1, &[]),
        Err(Status::TemporaryFailure)
    );
    forwarding_self_test();
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
    packet_device_self_test();
}

fn forwarding_self_test() {
    let name = b"1.0.0.127.in-addr.arpa";
    let mut packet = build_query(name, 12, 73).unwrap();
    packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    packet[6..8].copy_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 30, 0, 11]);
    let data_offset = packet.len();
    packet.extend_from_slice(b"\x09localhost\0");
    assert_eq!(validate_packet(&packet, 73, name, 12), Ok(Some(false)));
    assert_eq!(validate_packet(&packet, 74, name, 12), Ok(None));
    assert!(validate_packet(&packet, 73, b"other.test", 12).is_err());
    assert!(validate_packet(&packet[..packet.len() - 1], 73, name, 12).is_err());
    let mut cyclic = packet[..data_offset].to_vec();
    cyclic[data_offset - 2..].copy_from_slice(&2u16.to_be_bytes());
    cyclic.extend_from_slice(&[0xc0, data_offset as u8]);
    assert!(validate_packet(&cyclic, 73, name, 12).is_err());

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(ATTEMPT_TIMEOUT)).unwrap();
    let port = socket.local_addr().unwrap().port();
    let expected = packet.clone();
    let fixture = std::thread::spawn(move || {
        let mut request = [0; 512];
        let (_, peer) = socket.recv_from(&mut request).unwrap();
        packet[..2].copy_from_slice(&request[..2]);
        socket.send_to(&packet, peer).unwrap();
    });
    let response = udp_response(name, 12, "127.0.0.1".parse().unwrap(), port).unwrap();
    assert_eq!(&response[2..], &expected[2..]);
    fixture.join().unwrap();
}

fn packet_device_self_test() {
    use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};
    use std::future::Future;
    use std::task::Poll;

    let (ready, started) = std::sync::mpsc::channel();
    let (stop, mut stopped) = moto_sdk::async_runtime::oneshot();
    let provider = std::thread::spawn(move || {
        moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
            let addresses = vec![
                Cidr {
                    address: "10.243.12.1".parse().unwrap(),
                    prefix_len: 24,
                },
                Cidr {
                    address: "fd43:12::1".parse().unwrap(),
                    prefix_len: 64,
                },
            ];
            let config = Registration {
                name: "dns_test_wg".into(),
                mtu: 1420,
                routes: addresses
                    .iter()
                    .map(|cidr| cidr.network().unwrap())
                    .collect(),
                addresses,
            };
            let mut device = moto_sdk::io::ip_device::IpDevice::register(&config)
                .await
                .unwrap();
            ready.send(()).unwrap();
            {
                let (sender, mut receiver) = device.split();
                let mut bytes = [0; 1420];
                loop {
                    let length = std::future::poll_fn(|cx| {
                        if std::pin::Pin::new(&mut stopped).poll(cx).is_ready() {
                            return Poll::Ready(None);
                        }
                        receiver.poll_receive(cx, &mut bytes).map(Some)
                    })
                    .await;
                    let Some(length) = length else {
                        break;
                    };
                    let length = length.unwrap();
                    let (start, size) = match bytes[0] >> 4 {
                        4 => (12, 4),
                        6 => (8, 16),
                        _ => unreachable!(),
                    };
                    // Reflection preserves checksums while making the remote
                    // DNS server and the query socket distinct IP endpoints.
                    for index in 0..size {
                        bytes.swap(start + index, start + size + index);
                    }
                    sender.send(&bytes[..length]).await.unwrap();
                }
            }
            device.unregister().await.unwrap();
        });
    });
    started.recv_timeout(Duration::from_secs(3)).unwrap();
    for (local, remote) in [("10.243.12.1", "10.243.12.2"), ("fd43:12::1", "fd43:12::2")] {
        let remote: IpAddr = remote.parse().unwrap();
        let server = UdpSocket::bind(SocketAddr::new(local.parse().unwrap(), DNS_PORT)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let server = std::thread::spawn(move || {
            let mut packet = [0; UDP_RESPONSE_MAX];
            let (length, peer) = server.recv_from(&mut packet).unwrap();
            assert_eq!(peer.ip(), remote);
            let mut response = packet[..length].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 9]);
            server.send_to(&response, peer).unwrap();
            // Keep the queued reply alive until the lookup finishes and joins.
            server
        });
        assert_eq!(
            lookup(b"tunnel.test", 1, &[remote]).unwrap(),
            ["192.0.2.9".parse::<IpAddr>().unwrap()]
        );
        server.join().unwrap();
    }
    stop.send(()).unwrap();
    provider.join().unwrap();
}

fn transport_self_test() {
    let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let port = udp.local_addr().unwrap().port();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let tcp = TcpListener::bind(("127.0.0.1", port)).unwrap();
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
        lookup_on_port(
            b"example.test",
            1,
            &["127.0.0.1".parse::<IpAddr>().unwrap()],
            port,
        )
        .unwrap(),
        ["192.0.2.9".parse::<IpAddr>().unwrap()]
    );
    server.join().unwrap();
}
