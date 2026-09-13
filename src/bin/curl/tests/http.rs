use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

use curl::{CurlError, Options, Protocols};

fn serve(response: &'static [u8]) -> (String, std::thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 65536);
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let length = String::from_utf8_lossy(&head)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let start = head.len();
        head.resize(start + length, 0);
        stream.read_exact(&mut head[start..]).unwrap();
        stream.write_all(response).unwrap();
        head
    });
    (format!("http://{addr}/v1/chat/completions"), server)
}

fn options(url: String) -> Options {
    Options {
        protocols: Protocols::Http,
        url,
        max_time: Duration::from_secs(3),
        // An explicit HTTP transfer must not attempt to load this file.
        ca_cert: Some("/nonexistent/gears-http-ca.pem".into()),
        ..Options::default()
    }
}

#[test]
fn get_reports_body_and_redirect_without_following_it() {
    let (url, server) =
        serve(b"HTTP/1.1 302 Found\r\nContent-Length: 5\r\nLocation: /next\r\n\r\nhello");
    let mut body = Vec::new();
    let info = curl::transfer(&options(url.clone()), None, &mut body).unwrap();
    let request = server.join().unwrap();
    assert!(request.starts_with(b"GET /v1/chat/completions HTTP/1.1\r\n"));
    assert_eq!(body, b"hello");
    assert_eq!(info.response_code, 302);
    assert_eq!(info.url_effective, url);
    assert_eq!(
        info.redirect_url,
        url.replace("/v1/chat/completions", "/next")
    );
}

#[test]
fn binary_posts_and_decodes_chunked_sse() {
    let (url, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\ne\r\ndata: [DONE]\n\n\r\n0\r\n\r\n");
    let output = Command::new(env!("CARGO_BIN_EXE_curl"))
        .args([
            "--proto",
            "=http",
            "--data-binary",
            r#"{"model":"local"}"#,
            "--url",
            &url,
        ])
        .output()
        .unwrap();
    let request = server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(request.starts_with(b"POST /v1/chat/completions HTTP/1.1\r\n"));
    assert!(request.ends_with(br#"{"model":"local"}"#));
    assert_eq!(output.stdout, b"data: one\n\ndata: [DONE]\n\n");
}

#[test]
fn refuses_disallowed_protocols_before_connecting_or_loading_ca() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for (scheme, protocols) in [("http", Protocols::Https), ("https", Protocols::Http)] {
        let mut opts = options(format!("{scheme}://{}/", listener.local_addr().unwrap()));
        opts.protocols = protocols;
        let error = curl::transfer(&opts, None, &mut Vec::new()).unwrap_err();
        assert_eq!(error.code(), CurlError::UNSUPPORTED_PROTOCOL);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn refuses_truncated_plaintext_responses() {
    for response in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc".as_slice(),
    ] {
        let (url, server) = serve(response);
        let error = curl::transfer(&options(url), None, &mut Vec::new()).unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code(), CurlError::RECEIVE);
    }
}
