//! Bounded CONNECT handshakes. Keep the buffered socket for the following relay
//! so bytes pipelined after a request are preserved. No handshake timer is added.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::forward_args::TargetAddress;

#[derive(Clone, Copy)]
enum Version {
    Four,
    Five,
}

pub struct Request {
    pub target: TargetAddress,
    version: Version,
}

impl Request {
    pub async fn respond<S: AsyncWrite + Unpin>(
        &self,
        socket: &mut S,
        error: Option<&russh::Error>,
    ) -> io::Result<()> {
        use russh::{ChannelOpenFailure as Failure, Error};
        let code = match error {
            None => 0,
            Some(Error::ChannelOpenFailure(Failure::AdministrativelyProhibited)) => 2,
            Some(Error::ChannelOpenFailure(Failure::ConnectFailed)) => 5,
            Some(Error::ChannelOpenFailure(Failure::UnknownChannelType)) => 7,
            Some(_) => 1,
        };
        reply(socket, self.version, code).await
    }
}

pub async fn negotiate<S: AsyncBufRead + AsyncWrite + Unpin>(
    socket: &mut S,
) -> io::Result<Request> {
    match socket.read_u8().await? {
        4 => socks4(socket).await,
        5 => socks5(socket).await,
        _ => Err(invalid("unsupported SOCKS version")),
    }
}

async fn socks4<S: AsyncBufRead + AsyncWrite + Unpin>(socket: &mut S) -> io::Result<Request> {
    let mut header = [0; 7];
    socket.read_exact(&mut header).await?;
    if header[0] != 1 {
        return reject(socket, Version::Four, 1, "unsupported SOCKS4 command").await;
    }
    // USERID is ignored, as in OpenSSH, but an unterminated ID cannot grow a buffer.
    let mut terminated = false;
    for _ in 0..=1024 {
        if socket.read_u8().await? == 0 {
            terminated = true;
            break;
        }
    }
    if !terminated {
        return reject(
            socket,
            Version::Four,
            1,
            "SOCKS4 user ID exceeds 1024 bytes",
        )
        .await;
    }
    let address = [header[3], header[4], header[5], header[6]];
    let host = if address[..3] == [0, 0, 0] && address[3] != 0 {
        let mut name = Vec::with_capacity(255);
        loop {
            let byte = socket.read_u8().await?;
            if byte == 0 {
                break;
            }
            if name.len() == 255 || !(byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)) {
                return reject(socket, Version::Four, 1, "invalid SOCKS4a hostname").await;
            }
            name.push(byte);
        }
        String::from_utf8(name).unwrap()
    } else {
        Ipv4Addr::from(address).to_string()
    };
    let port = u16::from_be_bytes([header[1], header[2]]);
    if crate::forward::validate_target(&host, u32::from(port)).is_err() {
        return reject(socket, Version::Four, 1, "invalid SOCKS target").await;
    }
    Ok(Request {
        target: TargetAddress { host, port },
        version: Version::Four,
    })
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn socks5<S: AsyncBufRead + AsyncWrite + Unpin>(socket: &mut S) -> io::Result<Request> {
    let count = usize::from(socket.read_u8().await?);
    let mut methods = [0; 255];
    socket.read_exact(&mut methods[..count]).await?;
    if !methods[..count].contains(&0) {
        socket.write_all(&[5, 0xff]).await?;
        return Err(invalid("SOCKS5 requires no-authentication support"));
    }
    socket.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        return reject(socket, Version::Five, 1, "invalid SOCKS5 request header").await;
    }
    if header[1] != 1 {
        return reject(socket, Version::Five, 7, "unsupported SOCKS5 command").await;
    }
    let host = match header[3] {
        1 => {
            let mut address = [0; 4];
            socket.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let count = usize::from(socket.read_u8().await?);
            if count == 0 {
                return reject(socket, Version::Five, 1, "empty SOCKS5 hostname").await;
            }
            let mut name = [0; 255];
            socket.read_exact(&mut name[..count]).await?;
            match std::str::from_utf8(&name[..count]) {
                Ok(name) => name.to_owned(),
                Err(_) => return reject(socket, Version::Five, 1, "invalid SOCKS5 hostname").await,
            }
        }
        4 => {
            let mut address = [0; 16];
            socket.read_exact(&mut address).await?;
            Ipv6Addr::from(address).to_string()
        }
        _ => return reject(socket, Version::Five, 8, "unsupported SOCKS5 address type").await,
    };
    let port = socket.read_u16().await?;
    if crate::forward::validate_target(&host, u32::from(port)).is_err() {
        return reject(socket, Version::Five, 1, "invalid SOCKS target").await;
    }
    Ok(Request {
        target: TargetAddress { host, port },
        version: Version::Five,
    })
}

async fn reply<S: AsyncWrite + Unpin>(
    socket: &mut S,
    version: Version,
    code: u8,
) -> io::Result<()> {
    match version {
        Version::Four => {
            socket
                .write_all(&[0, if code == 0 { 90 } else { 91 }, 0, 0, 0, 0, 0, 0])
                .await
        }
        Version::Five => socket.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await,
    }
}

async fn reject<S: AsyncWrite + Unpin>(
    socket: &mut S,
    version: Version,
    code: u8,
    message: &str,
) -> io::Result<Request> {
    reply(socket, version, code).await?;
    Err(invalid(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn socks4_and_4a_preserve_names_and_pipelined_payload() {
        for (address, name, expected) in [
            ([127, 0, 0, 1], None, "127.0.0.1"),
            (
                [0, 0, 0, 1],
                Some("Mixed-Case.invalid."),
                "Mixed-Case.invalid.",
            ),
        ] {
            let (mut application, stream) = tokio::io::duplex(4096);
            let mut stream = BufReader::with_capacity(64, stream);
            let mut wire = vec![4, 1, 0x1f, 0x90];
            wire.extend(address);
            wire.extend(b"ignored-user\0");
            if let Some(name) = name {
                wire.extend(name.bytes());
                wire.push(0);
            }
            wire.extend(b"payload");
            application.write_all(&wire).await.unwrap();
            let request = negotiate(&mut stream).await.unwrap();
            assert_eq!(request.target.host, expected);
            assert_eq!(request.target.port, 8080);
            let mut payload = [0; 7];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload");
            request.respond(&mut stream, None).await.unwrap();
            let mut response = [0; 8];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0, 90, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[tokio::test]
    async fn socks4_rejects_bad_commands_targets_and_unbounded_strings() {
        let mut oversized_user = vec![4, 1, 0, 80, 127, 0, 0, 1];
        oversized_user.extend(vec![b'x'; 1025]);
        let mut oversized_name = vec![4, 1, 0, 80, 0, 0, 0, 1, 0];
        oversized_name.extend(vec![b'x'; 256]);
        for wire in [
            vec![4, 2, 0, 80, 127, 0, 0, 1],
            vec![4, 1, 0, 0, 127, 0, 0, 1, 0],
            vec![4, 1, 0, 80, 0, 0, 0, 1, 0, 0],
            vec![4, 1, 0, 80, 0, 0, 0, 1, 0, 0xff],
            oversized_user,
            oversized_name,
        ] {
            let (mut application, stream) = tokio::io::duplex(4096);
            let mut stream = BufReader::with_capacity(64, stream);
            application.write_all(&wire).await.unwrap();
            assert_eq!(
                negotiate(&mut stream).await.err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
            let mut response = [0; 8];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0, 91, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[tokio::test]
    async fn socks4_accepts_limits_and_propagates_truncation_without_a_timer() {
        let (mut application, stream) = tokio::io::duplex(4096);
        let mut stream = BufReader::with_capacity(64, stream);
        let mut wire = vec![4, 1, 0, 80, 0, 0, 0, 1];
        wire.extend(vec![b'u'; 1024]);
        wire.push(0);
        wire.extend(vec![b'h'; 255]);
        wire.push(0);
        application.write_all(&wire).await.unwrap();
        assert_eq!(negotiate(&mut stream).await.unwrap().target.host.len(), 255);
        for truncated in [b"".as_slice(), &[4], &[4, 1, 0, 80, 127, 0, 0, 1]] {
            let (mut application, stream) = tokio::io::duplex(64);
            let mut stream = BufReader::new(stream);
            application.write_all(truncated).await.unwrap();
            application.shutdown().await.unwrap();
            assert_eq!(
                negotiate(&mut stream).await.err().unwrap().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn socks5_negotiates_ipv4_ipv6_and_unresolved_names_without_losing_payload() {
        let mut ipv6 = vec![5, 1, 0, 4];
        ipv6.extend(Ipv6Addr::LOCALHOST.octets());
        ipv6.extend([0, 80]);
        let mut cases = vec![
            (
                vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 80],
                "127.0.0.1".to_owned(),
            ),
            (ipv6, "::1".to_owned()),
        ];
        for name in ["Mixed-Case.invalid.".to_owned(), "h".repeat(255)] {
            let mut request = vec![5, 1, 0, 3, name.len() as u8];
            request.extend(name.bytes());
            request.extend([0, 80]);
            cases.push((request, name));
        }
        for (request, expected) in cases {
            let (mut application, stream) = tokio::io::duplex(4096);
            let mut stream = BufReader::with_capacity(64, stream);
            let mut wire = vec![5, 255];
            wire.extend(vec![2; 254]);
            wire.push(0);
            wire.extend(request);
            wire.extend(b"payload");
            application.write_all(&wire).await.unwrap();
            let request = negotiate(&mut stream).await.unwrap();
            assert_eq!(
                request.target,
                TargetAddress {
                    host: expected,
                    port: 80
                }
            );
            let mut payload = [0; 7];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload");
            let mut method = [0; 2];
            application.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            request.respond(&mut stream, None).await.unwrap();
            let mut response = [0; 10];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[tokio::test]
    async fn socks5_rejects_unsupported_auth_commands_and_addresses() {
        for wire in [vec![5, 0], vec![5, 2, 1, 2]] {
            let (mut application, stream) = tokio::io::duplex(64);
            let mut stream = BufReader::new(stream);
            application.write_all(&wire).await.unwrap();
            assert!(negotiate(&mut stream).await.is_err());
            let mut response = [0; 2];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0xff]);
        }
        for (request, code) in [
            (vec![4, 1, 0, 1], 1),
            (vec![5, 1, 1, 1], 1),
            (vec![5, 2, 0, 1], 7),
            (vec![5, 3, 0, 1], 7),
            (vec![5, 1, 0, 2], 8),
            (vec![5, 1, 0, 3, 0], 1),
            (vec![5, 1, 0, 3, 1, 0xff, 0, 80], 1),
            (vec![5, 1, 0, 3, 1, b' ', 0, 80], 1),
            (vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 0], 1),
        ] {
            let (mut application, stream) = tokio::io::duplex(64);
            let mut stream = BufReader::new(stream);
            application.write_all(&[5, 1, 0]).await.unwrap();
            application.write_all(&request).await.unwrap();
            assert_eq!(
                negotiate(&mut stream).await.err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
            let mut response = [0; 12];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0, 5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }

    #[tokio::test]
    async fn socks5_every_truncated_prefix_ends_at_eof_and_unknown_versions_are_rejected() {
        let wire = [5, 2, 2, 0, 5, 1, 0, 3, 3, b'a', b'b', b'c', 0, 80];
        for len in 0..wire.len() {
            let (mut application, stream) = tokio::io::duplex(64);
            let mut stream = BufReader::new(stream);
            application.write_all(&wire[..len]).await.unwrap();
            application.shutdown().await.unwrap();
            assert_eq!(
                negotiate(&mut stream).await.err().unwrap().kind(),
                io::ErrorKind::UnexpectedEof,
                "prefix {len}"
            );
        }
        for version in [0, 3, 6, 0xff] {
            let (mut application, stream) = tokio::io::duplex(64);
            let mut stream = BufReader::new(stream);
            application.write_u8(version).await.unwrap();
            assert_eq!(
                negotiate(&mut stream).await.err().unwrap().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn ssh_open_results_map_to_version_specific_replies() {
        use russh::{ChannelOpenFailure as Failure, Error};
        for (error, code) in [
            (None, 0),
            (
                Some(Error::ChannelOpenFailure(
                    Failure::AdministrativelyProhibited,
                )),
                2,
            ),
            (Some(Error::ChannelOpenFailure(Failure::ConnectFailed)), 5),
            (
                Some(Error::ChannelOpenFailure(Failure::UnknownChannelType)),
                7,
            ),
            (
                Some(Error::ChannelOpenFailure(Failure::ResourceShortage)),
                1,
            ),
            (Some(Error::Disconnect), 1),
        ] {
            let (mut application, mut stream) = tokio::io::duplex(64);
            let mut request = Request {
                target: TargetAddress {
                    host: "unused.invalid".into(),
                    port: 80,
                },
                version: Version::Five,
            };
            request.respond(&mut stream, error.as_ref()).await.unwrap();
            let mut response = [0; 10];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
            request.version = Version::Four;
            request.respond(&mut stream, error.as_ref()).await.unwrap();
            let mut response = [0; 8];
            application.read_exact(&mut response).await.unwrap();
            assert_eq!(
                response,
                [0, if error.is_some() { 91 } else { 90 }, 0, 0, 0, 0, 0, 0]
            );
        }
    }
}
