use crate::common::{request, Server};
use std::io::BufReader;

pub fn check() {
    let server = Server::start(None, &[]);
    let mut io = BufReader::new(server.connect());
    request(&mut io, "GET", "/", "");
    std::fs::write(server.directory.join("index.html"), b"fresh").unwrap();
    for (index, headers) in [
        "Cache-Control: no-cache\r\n",
        "Cache-Control: no-store\r\n",
        "Cache-Control: max-age=0\r\n",
        "Cache-Control: max-age=\"0\"\r\n",
        "Cache-Control: public, No-Cache\r\n",
        "Cache-Control: public\r\nCache-Control: NO-STORE\r\n",
        "Pragma: public\r\nPragma: No-Cache\r\n",
    ]
    .iter()
    .enumerate()
    {
        let response = request(&mut io, "GET", "/", headers);
        assert_eq!(response.body, b"fresh");
        assert!(!response.headers.contains("age:"));
        // A bypass on a miss must not populate the cache either.
        let name = format!("cold{index}");
        let path = format!("/{name}");
        std::fs::write(server.directory.join(&name), b"before").unwrap();
        assert_eq!(request(&mut io, "GET", &path, headers).body, b"before");
        std::fs::write(server.directory.join(name), b"after").unwrap();
        assert_eq!(request(&mut io, "GET", &path, "").body, b"after");
    }
    let response = request(&mut io, "HEAD", "/", "Cache-Control: no-cache\r\n");
    assert!(response.headers.contains("content-length: 5\r\n"));
    assert_eq!(
        request(
            &mut io,
            "GET",
            "/",
            "Range: bytes=0-1\r\nCache-Control: no-cache\r\n"
        )
        .body,
        b"fr"
    );
    for headers in ["", "Cache-Control: x-no-cache, max-age=10\r\n"] {
        let response = request(&mut io, "GET", "/", headers);
        assert_eq!(response.body, b"test content\n");
        assert!(response
            .headers
            .lines()
            .any(|line| line.starts_with("age: ")));
    }
    std::fs::remove_file(server.directory.join("index.html")).unwrap();
    assert_eq!(
        request(&mut io, "GET", "/", "Cache-Control: no-cache\r\n").status,
        404
    );
    assert_eq!(request(&mut io, "GET", "/", "").body, b"test content\n");
    server.stop();
    println!("httpd-axum cache bypass tests passed");
}
