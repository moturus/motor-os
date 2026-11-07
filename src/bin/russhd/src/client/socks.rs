//! Bounded CONNECT handshakes. Keep the buffered socket for the following relay
//! so bytes pipelined after a request are preserved. No handshake timer is added.

use std::io;
use std::net::Ipv4Addr;

use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::forward_args::TargetAddress;

#[derive(Clone, Copy)]
enum Version {
    Four,
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
        reply(socket, self.version, u8::from(error.is_some())).await
    }
}

pub async fn negotiate<S: AsyncBufRead + AsyncWrite + Unpin>(
    socket: &mut S,
) -> io::Result<Request> {
    match socket.read_u8().await? {
        4 => socks4(socket).await,
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
}
