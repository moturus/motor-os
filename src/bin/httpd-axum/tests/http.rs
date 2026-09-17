mod cache;
mod common;
mod http2;
mod redirect_live;

use common::{request, Server};
use std::io::{BufReader, Read, Write};
use std::sync::Arc;

#[cfg(target_os = "motor")]
fn motor_getrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_rt::fill_random_bytes(dest);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

fn main() {
    let deadlines = Server::start(None, &["--max-header-deadline-sec", "1"]);
    for prefix in [
        b"".as_slice(),
        b"GET / HTTP/1.1\r\nHost:",
        b"PRI * HTTP/2.0\r\n",
    ] {
        let mut stream = deadlines.connect();
        stream.write_all(prefix).unwrap();
        assert_header_deadline(&mut stream);
    }
    let mut persistent = BufReader::new(deadlines.connect());
    assert_eq!(request(&mut persistent, "GET", "/", "").status, 200);
    persistent
        .get_mut()
        .write_all(b"GET / HTTP/1.1\r\nHost:")
        .unwrap();
    assert_header_deadline(&mut persistent);
    let mut idle = BufReader::new(deadlines.connect());
    assert_eq!(request(&mut idle, "GET", "/", "").status, 200);
    assert_header_deadline(&mut idle);
    deadlines.stop();
    let limited = Server::start(None, &["--max-active-connections", "1"]);
    let mut admitted = BufReader::new(limited.connect());
    assert_eq!(request(&mut admitted, "GET", "/", "").status, 200);
    assert_closed(&mut limited.connect());
    assert_eq!(
        request(&mut admitted, "GET", "/", "Connection: close\r\n").status,
        200
    );
    assert_closed(&mut admitted);
    assert_eq!(
        request(&mut BufReader::new(limited.connect()), "GET", "/", "").status,
        200
    );
    let logs = limited.stop();
    assert!(logs.contains("active connection limit reached"), "{logs}");
    assert!(logs.contains("listener=\"content\""), "{logs}");
    assert!(logs.contains("refused=1"), "{logs}");
    let server = Server::start(None, &["--cache=off"]);
    let mut io = BufReader::new(server.connect());
    let response = request(&mut io, "GET", "/", "");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"test content\n");
    let modified = response
        .headers
        .lines()
        .find_map(|line| line.strip_prefix("last-modified: "))
        .unwrap();
    let response = request(
        &mut io,
        "GET",
        "/index.html",
        &format!("If-Modified-Since: {modified}\r\n"),
    );
    assert_eq!(response.status, 304);
    assert!(response.body.is_empty());
    let response = request(&mut io, "HEAD", "/index.html", "");
    assert_eq!(response.status, 200);
    assert!(response.headers.contains("content-length: 13\r\n"));
    assert!(response.body.is_empty());
    let response = request(&mut io, "GET", "/index.html", "Range: bytes=1-3\r\n");
    assert_eq!(response.status, 206);
    assert_eq!(response.body, b"est");
    for path in ["/missing", "/%2e%2e/outside"] {
        assert_eq!(request(&mut io, "GET", path, "").status, 404);
    }
    std::fs::write(server.directory.join("index.html"), b"edited\n").unwrap();
    assert_eq!(request(&mut io, "GET", "/", "").body, b"edited\n");
    drop(io);
    assert!(server.stop().contains("response prepared"));
    let server = Server::start(None, &["--no-request-log"]);
    assert_eq!(
        request(&mut BufReader::new(server.connect()), "GET", "/", "").status,
        200
    );
    assert!(!server.stop().contains("response prepared"));
    cache::check();

    let server = Server::start(Some("httpd_axum=debug"), &[]);
    let response = request(&mut BufReader::new(server.connect()), "GET", "/", "");
    assert_eq!(response.status, 200);
    let logs = server.stop();
    assert!(logs.contains("response prepared"), "{logs}");
    assert!(logs.contains("prepare_us="), "{logs}");

    let server = Server::start_tls(None, &["--max-active-connections", "1"]);
    let connection =
        rustls::ClientConnection::new(tls_config(b"http/1.1"), "localhost".try_into().unwrap())
            .unwrap();
    let mut io = BufReader::new(rustls::StreamOwned::new(connection, server.connect()));
    for _ in 0..2 {
        let response = request(&mut io, "GET", "/index.html", "");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"test content\n");
    }
    assert_eq!(io.get_ref().conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_closed(&mut server.connect());
    request(&mut io, "GET", "/", "Connection: close\r\n");
    assert_closed(&mut io);
    assert!(server.stop().contains("response prepared"));

    let server = Server::start_tls(None, &["--max-header-deadline-sec", "1"]);
    let connection =
        rustls::ClientConnection::new(tls_config(b"http/1.1"), "localhost".try_into().unwrap())
            .unwrap();
    let mut io = BufReader::new(rustls::StreamOwned::new(connection, server.connect()));
    io.get_mut().write_all(b"GET / HTTP/1.1\r\nHost:").unwrap();
    io.get_mut().flush().unwrap();
    assert_header_deadline(&mut io);
    drop(io);
    assert!(!server.stop().contains("response prepared"));
    http2::check();
    // Motor permits standard service ports. Host runs can opt in when ports
    // 80/443 are available and the test process has permission to bind them.
    if cfg!(target_os = "motor") || std::env::var_os("HTTPD_AXUM_REDIRECT_TESTS").is_some() {
        redirect_live::check();
    }
    println!("httpd-axum HTTP/1, HTTP/2, TLS, and logging tests passed");
}

fn tls_config(protocol: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            include_bytes!("fixtures/cert.der").to_vec(),
        ))
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![protocol.to_vec()];
    Arc::new(config)
}

fn assert_header_deadline(io: &mut impl Read) {
    let mut bytes = Vec::new();
    if let Err(error) = io.read_to_end(&mut bytes) {
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
            ),
            "{error}"
        );
    }
    assert!(
        bytes.is_empty() || bytes.starts_with(b"HTTP/1.1 408"),
        "{bytes:?}"
    );
}

fn assert_closed(io: &mut impl Read) {
    match io.read(&mut [0; 1]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        result => panic!("expected closed connection, got {result:?}"),
    }
}
