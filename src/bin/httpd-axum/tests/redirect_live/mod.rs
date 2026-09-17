use crate::common::{certificates, connect, request, request_with_host, Fixture, Server};
use crate::{assert_closed, assert_header_deadline, tls_config};
use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;

const HTTPS: &str = "127.0.0.1:443";
const HTTP: &str = "127.0.0.1:80";
const DESTINATION: &str = "https://localhost/landing?q=%2f#section";

fn connect_http() -> TcpStream {
    connect(HTTP)
}

fn connect_https(
    server: &Server,
) -> BufReader<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let connection =
        rustls::ClientConnection::new(tls_config(b"http/1.1"), "localhost".try_into().unwrap())
            .unwrap();
    BufReader::new(rustls::StreamOwned::new(connection, server.connect()))
}

pub fn check() {
    // A TLS-only server must leave port 80 available. Conversely, enabling the
    // redirect must fail before readiness if another service owns that port.
    let server = Server::start_tls_at(None, &[], HTTPS);
    let occupied = TcpListener::bind(HTTP).unwrap();
    assert_eq!(
        request(&mut connect_https(&server), "GET", "/", "").body,
        b"test content\n"
    );
    server.stop();
    let fixtures = Fixture::new("redirect");
    let (cert, key) = certificates(&fixtures.0);
    let binary = std::env::var_os("HTTPD_AXUM_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_httpd-axum").into());
    let output = Command::new(binary)
        .args(["-a", HTTPS, "-d"])
        .arg(&fixtures.0)
        .arg("--ssl-cert")
        .arg(cert)
        .arg("--ssl-key")
        .arg(key)
        .args(["--http-redirect-url", DESTINATION])
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("listening on"));
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("cannot bind HTTP redirect listener at 127.0.0.1:80"),
        "{error}"
    );
    drop(TcpListener::bind(HTTPS).unwrap());
    drop(fixtures);
    drop(occupied);

    let mut server = Server::start_tls_at(
        None,
        &[
            "--http-redirect-url",
            DESTINATION,
            "--max-active-connections",
            "1",
        ],
        HTTPS,
    );
    assert!(server.next_log().contains("HTTP redirect on 127.0.0.1:80"));
    let mut plain = BufReader::new(connect_http());
    for method in ["GET", "HEAD", "POST", "OPTIONS"] {
        for path in ["/", "/index.html?ignored=yes", "//attacker.example/%2f?q=1"] {
            let response = request_with_host(&mut plain, method, path, "attacker.example:1234",
                "Forwarded: host=attacker.example;proto=http\r\nX-Forwarded-Host: attacker.example\r\n");
            assert_eq!(response.status, 308);
            assert!(
                response
                    .headers
                    .contains(&format!("location: {DESTINATION}\r\n")),
                "{}",
                response.headers
            );
            assert!(response.body.is_empty());
        }
    }
    // Each listener rejects excess connections without starving the other.
    assert_closed(&mut connect_http());
    let mut secure = connect_https(&server);
    let response = request(&mut secure, "GET", "/", "");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"test content\n");
    assert_closed(&mut server.connect());
    request(&mut plain, "GET", "/", "Connection: close\r\n");
    assert_closed(&mut plain);
    let mut replacement = BufReader::new(connect_http());
    assert_eq!(
        request(&mut replacement, "GET", "/", "Connection: close\r\n").status,
        308
    );
    assert_closed(&mut replacement);
    request(&mut secure, "GET", "/", "Connection: close\r\n");
    assert_closed(&mut secure);
    server.stop();

    // Deliberately short deadlines are confined to stalled-client scenarios.
    let mut server = Server::start_tls_at(
        None,
        &[
            "--http-redirect-url",
            DESTINATION,
            "--max-active-connections",
            "1",
            "--max-header-deadline-sec",
            "1",
        ],
        HTTPS,
    );
    assert!(server.next_log().contains("HTTP redirect on 127.0.0.1:80"));
    let mut plain = BufReader::new(connect_http());
    plain
        .get_mut()
        .write_all(b"GET / HTTP/1.1\r\nHost:")
        .unwrap();
    assert_header_deadline(&mut plain);
    drop(plain);
    let mut secure = connect_https(&server);
    let response = request(&mut secure, "GET", "/", "");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"test content\n");
    secure
        .get_mut()
        .write_all(b"GET / HTTP/1.1\r\nHost:")
        .unwrap();
    secure.get_mut().flush().unwrap();
    assert_header_deadline(&mut secure);
    drop(secure);
    assert_header_deadline(&mut connect_http());
    let response = request(
        &mut BufReader::new(connect_http()),
        "GET",
        "/",
        "Connection: close\r\n",
    );
    assert_eq!(response.status, 308);
    assert!(response
        .headers
        .contains(&format!("location: {DESTINATION}\r\n")));
    server.stop();
    println!("httpd-axum live port-80 redirect and port-443 TLS tests passed");
}
