mod common;

use common::{request, Server};
use std::io::BufReader;

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
    println!("httpd-axum HTTP and logging tests passed");
}
