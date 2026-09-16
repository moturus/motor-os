mod common;

use common::{request, Server};
use std::io::BufReader;
use std::sync::Arc;

#[cfg(target_os = "motor")]
fn motor_getrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_rt::fill_random_bytes(dest);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

fn main() {
    let server = Server::start(None, &[]);
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
    assert_eq!(request(&mut io, "GET", "/index.html", "").body, b"edited\n");
    drop(io);
    assert!(!server.stop().contains("response prepared"));

    let server = Server::start(Some("httpd_axum=debug"), &[]);
    let response = request(&mut BufReader::new(server.connect()), "GET", "/", "");
    assert_eq!(response.status, 200);
    let logs = server.stop();
    assert!(logs.contains("response prepared"), "{logs}");
    assert!(logs.contains("prepare_us="), "{logs}");

    let server = Server::start_tls(None, &[]);
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
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connection =
        rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut io = BufReader::new(rustls::StreamOwned::new(connection, server.connect()));
    for _ in 0..2 {
        let response = request(&mut io, "GET", "/index.html", "");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"test content\n");
    }
    assert_eq!(io.get_ref().conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    drop(io);
    assert!(!server.stop().contains("response prepared"));
    println!("httpd-axum HTTP, TLS, and logging tests passed");
}
