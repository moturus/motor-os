use crate::common::{request, Server};
use std::io::BufReader;
use std::time::Duration;

pub fn check() {
    let server = Server::start(None, &[]);
    let mut io = BufReader::new(server.connect());
    assert_eq!(request(&mut io, "GET", "/", "").body, b"test content\n");
    std::fs::write(server.directory.join("index.html"), b"new\n").unwrap();
    assert_eq!(
        request(&mut io, "GET", "/?query=1", "").body,
        b"test content\n"
    );
    assert_eq!(
        request(&mut io, "HEAD", "/", "")
            .headers
            .lines()
            .find(|line| line.starts_with("content-length:"))
            .unwrap(),
        "content-length: 13"
    );
    assert_eq!(
        request(&mut io, "GET", "/", "Range: bytes=1-3\r\n").body,
        b"est"
    );
    std::fs::remove_file(server.directory.join("index.html")).unwrap();
    assert_eq!(request(&mut io, "GET", "/", "").body, b"test content\n");
    drop(io);
    server.stop();

    let server = Server::start(None, &["--cache-timeout-sec", "1", "--cache-size-mb", "1"]);
    let mut io = BufReader::new(server.connect());
    assert_eq!(request(&mut io, "GET", "/", "").body, b"test content\n");
    std::fs::write(server.directory.join("index.html"), b"new\n").unwrap();
    assert_eq!(request(&mut io, "GET", "/", "").body, b"test content\n");
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(request(&mut io, "GET", "/", "").body, b"new\n");
    assert_eq!(request(&mut io, "GET", "/created", "").status, 404);
    std::fs::write(server.directory.join("created"), b"created").unwrap();
    assert_eq!(request(&mut io, "GET", "/created", "").body, b"created");
    let large = server.directory.join("large");
    std::fs::write(&large, vec![b'a'; 256 * 1024 + 1]).unwrap();
    assert_eq!(
        request(&mut io, "GET", "/large", "").body,
        vec![b'a'; 256 * 1024 + 1]
    );
    std::fs::write(&large, vec![b'b'; 256 * 1024 + 1]).unwrap();
    assert_eq!(
        request(&mut io, "GET", "/large", "").body,
        vec![b'b'; 256 * 1024 + 1]
    );
    drop(io);
    server.stop();
    println!("httpd-axum cache freshness and streaming tests passed");
}
