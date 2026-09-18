use crate::common::Server;
use std::io::{Read, Write};

trait Io: Read + Write {}
impl<T: Read + Write> Io for T {}

fn connect(server: &Server, tls: bool) -> Box<dyn Io> {
    let mut io: Box<dyn Io> = if tls {
        let connection = rustls::ClientConnection::new(
            crate::tls_config(b"h2"),
            "localhost".try_into().unwrap(),
        )
        .unwrap();
        Box::new(rustls::StreamOwned::new(connection, server.connect()))
    } else {
        Box::new(server.connect())
    };
    io.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    write_frame(&mut io, 4, 0, 0, &[]);
    io
}

pub fn check() {
    for tls in [false, true] {
        let args = [
            "--http2",
            "--max-active-connections",
            "1",
            "--max-header-deadline-sec",
            "1",
        ];
        for responsive in [false, true] {
            let server = if tls {
                Server::start_tls(None, &args)
            } else {
                Server::start(None, &args)
            };
            let mut io = connect(&server, tls);
            get(&mut io, tls, 1);
            crate::assert_closed(&mut server.connect());
            if responsive {
                // Stay reusable beyond both the interval and ACK timeout.
                // A raw peer lets this test explicitly withhold later ACKs.
                for _ in 0..3 {
                    let ping = read_ping(&mut io);
                    write_frame(&mut io, 6, 1, 0, &ping);
                }
                get(&mut io, tls, 3);
            }
            let mut control = Vec::new();
            if let Err(error) = io.read_to_end(&mut control) {
                assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                    ),
                    "HTTP/2 peer stayed open without PING acknowledgements: {error}"
                );
            }
            // The timed-out connection must release the sole admission permit.
            let mut replacement = connect(&server, tls);
            get(&mut replacement, tls, 1);
            server.stop();
        }
    }
    println!("httpd-axum HTTP/2 keep-alive and admission recovery tests passed");
}

fn get(io: &mut impl Io, tls: bool, stream: u32) {
    // HPACK static indices: GET, http/https, /; literal :authority localhost.
    let mut headers = vec![0x82, if tls { 0x87 } else { 0x86 }, 0x84, 0x01, 9];
    headers.extend_from_slice(b"localhost");
    write_frame(io, 1, 5, stream, &headers); // END_STREAM | END_HEADERS.
    let mut body = Vec::new();
    loop {
        let (header, payload) = read_frame(io);
        if header[3] == 4 && header[4] == 0 {
            write_frame(io, 4, 1, 0, &[]); // Acknowledge server SETTINGS.
        }
        let response_stream = u32::from_be_bytes(header[5..].try_into().unwrap());
        if response_stream == stream && matches!(header[3], 0 | 1) {
            if header[3] == 0 {
                body.extend_from_slice(&payload);
            }
            if header[4] & 1 != 0 {
                break;
            }
        }
    }
    assert_eq!(body, b"test content\n");
}

fn read_ping(io: &mut impl Io) -> Vec<u8> {
    loop {
        let (header, payload) = read_frame(io);
        if header[3] == 6 && header[4] == 0 {
            assert_eq!(&header[5..], &[0; 4]);
            assert_eq!(payload.len(), 8);
            return payload;
        }
    }
}

fn read_frame(io: &mut impl Read) -> ([u8; 9], Vec<u8>) {
    let mut header = [0; 9];
    io.read_exact(&mut header).unwrap();
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    assert!(length <= 16384, "unexpected HTTP/2 frame length: {length}");
    let mut payload = vec![0; length];
    io.read_exact(&mut payload).unwrap();
    (header, payload)
}

fn write_frame(io: &mut impl Write, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let mut header = [0; 9];
    header[..3].copy_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    header[3] = kind;
    header[4] = flags;
    header[5..].copy_from_slice(&stream.to_be_bytes());
    io.write_all(&header).unwrap();
    io.write_all(payload).unwrap();
    io.flush().unwrap();
}
