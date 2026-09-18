use crate::common::{request, Server};
use std::io::{BufReader, Read, Write};
use std::sync::Arc;

pub fn check() {
    let server = Server::start(None, &["--max-active-connections", "1"]);
    reject(&mut server.connect());
    assert_eq!(
        request(&mut BufReader::new(server.connect()), "GET", "/", "").status,
        200
    );
    server.stop();

    let server = Server::start_tls(None, &[]);
    // Offer HTTP/2 first, as browsers do, and require HTTP/1.1 negotiation.
    let mut config = crate::tls_config(b"h2");
    Arc::make_mut(&mut config)
        .alpn_protocols
        .push(b"http/1.1".to_vec());
    let connection =
        rustls::ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
    let mut io = BufReader::new(rustls::StreamOwned::new(connection, server.connect()));
    for _ in 0..2 {
        assert_eq!(request(&mut io, "GET", "/", "").body, b"test content\n");
    }
    assert_eq!(io.get_ref().conn.alpn_protocol(), Some(&b"http/1.1"[..]));

    let mut connection =
        rustls::ClientConnection::new(crate::tls_config(b"h2"), "localhost".try_into().unwrap())
            .unwrap();
    let error = connection.complete_io(&mut server.connect()).unwrap_err();
    assert!(
        matches!(
            error
                .get_ref()
                .and_then(|err| err.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::NoApplicationProtocol
            ))
        ),
        "unexpected TLS error: {error:?}"
    );
    server.stop();

    // ALPN alone cannot enforce the default: also reject raw HTTP/2 over
    // TLS with no ALPN, or after the client negotiated HTTP/1.1.
    let server = Server::start_tls(None, &["--max-active-connections", "1"]);
    for alpn in [false, true] {
        let mut config = crate::tls_config(b"http/1.1");
        if !alpn {
            Arc::make_mut(&mut config).alpn_protocols.clear();
        }
        let connection =
            rustls::ClientConnection::new(config, "localhost".try_into().unwrap()).unwrap();
        reject(&mut rustls::StreamOwned::new(connection, server.connect()));
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
    }
    server.stop();
    println!("httpd-axum HTTP/2 disabled-by-default tests passed");
}

pub fn reject(io: &mut (impl Read + Write)) {
    for byte in b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        io.write_all(&[*byte]).unwrap();
        io.flush().unwrap();
    }
    let mut response = Vec::new();
    if let Err(error) = io.read_to_end(&mut response) {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ),
            "HTTP/2 preface was not rejected: {error}"
        );
    }
    assert!(
        response.is_empty(),
        "unexpected protocol response: {response:?}"
    );
}
