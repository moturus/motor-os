use crate::common::{request, Server};
use std::io::{BufReader, Read, Write};

pub fn check() {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let settings = [0, 0, 0, 4, 0, 0, 0, 0, 0];
    let ping = [0, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // HEADERS promises three payload bytes but supplies only one.
    let partial_head = [0, 0, 3, 1, 1, 0, 0, 0, 1, 0x82];
    for tls in [false, true] {
        let args = [
            "--http2",
            "--max-active-connections",
            "1",
            "--max-header-deadline-sec",
            "1",
        ];
        let server = if tls {
            Server::start_tls(None, &args)
        } else {
            Server::start(None, &args)
        };
        for suffix in [
            vec![],
            [settings.as_slice(), &ping].concat(),
            [settings.as_slice(), &partial_head].concat(),
        ] {
            let bytes = [preface.as_slice(), &suffix].concat();
            if tls {
                let connection = rustls::ClientConnection::new(
                    crate::tls_config(b"h2"),
                    "localhost".try_into().unwrap(),
                )
                .unwrap();
                stalled(
                    &mut rustls::StreamOwned::new(connection, server.connect()),
                    &bytes,
                );
            } else {
                stalled(&mut server.connect(), &bytes);
            }
            // Closure must release admission, including on the TLS path.
            if tls {
                let connection = rustls::ClientConnection::new(
                    crate::tls_config(b"http/1.1"),
                    "localhost".try_into().unwrap(),
                )
                .unwrap();
                let mut io = BufReader::new(rustls::StreamOwned::new(connection, server.connect()));
                assert_eq!(
                    request(&mut io, "GET", "/", "Connection: close\r\n").status,
                    200
                );
                crate::assert_closed(&mut io);
            } else {
                let mut io = BufReader::new(server.connect());
                assert_eq!(
                    request(&mut io, "GET", "/", "Connection: close\r\n").status,
                    200
                );
                crate::assert_closed(&mut io);
            }
        }
        server.stop();
    }
}

fn stalled(io: &mut (impl Read + Write), bytes: &[u8]) {
    io.write_all(bytes).unwrap();
    io.flush().unwrap();
    // HTTP/2 may send SETTINGS before timing out. A client-side read timeout
    // is a failure, not evidence that the server closed the connection.
    let mut response = Vec::new();
    if let Err(error) = io.read_to_end(&mut response) {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ),
            "{error}"
        );
    }
}
