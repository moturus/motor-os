use crate::common::{request, Server};
use std::io::BufReader;
use std::time::Duration;
mod bench;

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
    pressure();
    if std::env::var_os("HTTPD_AXUM_BENCH").is_some() {
        bench::run();
    }
}

fn pressure() {
    let server = Server::start(None, &["--cache-size-mb", "1"]);
    let mut io = BufReader::new(server.connect());
    let content = vec![b'x'; 256 * 1024];
    for i in 0..4 {
        std::fs::write(server.directory.join(i.to_string()), &content).unwrap();
        assert_eq!(request(&mut io, "GET", &format!("/{i}"), "").body, content);
    }
    std::fs::write(server.directory.join("0"), b"evicted").unwrap();
    std::fs::write(server.directory.join("3"), b"still cached").unwrap();
    assert_eq!(request(&mut io, "GET", "/0", "").body, b"evicted");
    assert_eq!(request(&mut io, "GET", "/3", "").body, content);
    std::fs::write(server.directory.join("parallel"), b"concurrent fill").unwrap();
    let jobs: Vec<_> = (0..16)
        .map(|_| {
            let stream = server.connect();
            std::thread::spawn(move || {
                let response = request(&mut BufReader::new(stream), "GET", "/parallel", "");
                assert_eq!(response.status, 200);
                assert_eq!(response.body, b"concurrent fill");
            })
        })
        .collect();
    for job in jobs {
        job.join().unwrap();
    }
    drop(io);
    server.stop();
    println!("httpd-axum cache pressure and concurrent fill tests passed");
}
