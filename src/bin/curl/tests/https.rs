use std::io::{BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use curl::{CurlError, Options};
use rustls::version::{TLS12, TLS13};
use rustls::{ServerConfig, ServerConnection, Stream};

const CERTIFICATE: &[u8] = include_bytes!("server-cert.pem");
const PRIVATE_KEY: &[u8] = include_bytes!("server-key.pem");
const HOSTNAME_CERTIFICATE: &[u8] = include_bytes!("hostname-server-cert.pem");
const HOSTNAME_PRIVATE_KEY: &[u8] = include_bytes!("hostname-server-key.pem");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(name)
}

fn server_config(certificate: &[u8], private_key: &[u8]) -> Arc<ServerConfig> {
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(private_key))
        .unwrap()
        .unwrap();
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn serve(response: &'static [u8]) -> (String, JoinHandle<()>) {
    serve_after(response, Duration::ZERO)
}

fn serve_after(response: &'static [u8], delay: Duration) -> (String, JoinHandle<()>) {
    serve_with_identity(response, delay, CERTIFICATE, PRIVATE_KEY)
}

fn serve_with_identity(
    response: &'static [u8],
    delay: Duration,
    certificate: &'static [u8],
    private_key: &'static [u8],
) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle =
        std::thread::spawn(move || serve_one(listener, response, delay, certificate, private_key));
    (format!("https://{address}/object"), handle)
}

fn serve_one(
    listener: TcpListener,
    response: &[u8],
    delay: Duration,
    certificate: &'static [u8],
    private_key: &'static [u8],
) {
    let (mut socket, _) = listener.accept().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut connection = ServerConnection::new(server_config(certificate, private_key)).unwrap();
    let mut stream = Stream::new(&mut connection, &mut socket);
    let mut request = Vec::new();
    let mut byte = [0];
    while request.len() < 64 * 1024 {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            std::thread::sleep(delay);
            if stream.write_all(response).is_ok() {
                stream.conn.send_close_notify();
                let _ = stream.flush();
            }
            return;
        }
    }
}

#[test]
fn tls_server_child() {
    let Ok(scenario) = std::env::var("LORRY_TEST_TLS_SERVER_SCENARIO") else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    println!("\nLORRY_TLS_PORT={}", listener.local_addr().unwrap().port());
    std::io::stdout().flush().unwrap();
    if scenario == "tls-failure" {
        let (mut socket, _) = listener.accept().unwrap();
        socket.write_all(b"not TLS").unwrap();
        return;
    }
    if scenario == "large" {
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n".to_vec();
        response.resize(response.len() + 1024 * 1024, b'x');
        serve_one(
            listener,
            &response,
            Duration::ZERO,
            CERTIFICATE,
            PRIVATE_KEY,
        );
        return;
    }
    let (response, delay) = match scenario.as_str() {
        "success" => (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
            Duration::ZERO,
        ),
        "redirect" => (
            b"HTTP/1.1 302 Found\r\nContent-Length: 4\r\n\
              Location: /next\r\n\r\nbody"
                .as_slice(),
            Duration::ZERO,
        ),
        "chunked" => (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nabc\r\n2;test=yes\r\nde\r\n0\r\nTrailer: yes\r\n\r\n"
                .as_slice(),
            Duration::ZERO,
        ),
        "close" => (
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil close".as_slice(),
            Duration::ZERO,
        ),
        "stall" => (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
            Duration::from_secs(2),
        ),
        "hostname" => (
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
            Duration::ZERO,
        ),
        "truncated" => (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".as_slice(),
            Duration::ZERO,
        ),
        "malformed" => (b"NOT HTTP\r\n\r\n".as_slice(), Duration::ZERO),
        _ => panic!("unknown TLS server scenario `{scenario}`"),
    };
    let (certificate, private_key) = if scenario == "hostname" {
        (HOSTNAME_CERTIFICATE, HOSTNAME_PRIVATE_KEY)
    } else {
        (CERTIFICATE, PRIVATE_KEY)
    };
    serve_one(listener, response, delay, certificate, private_key);
}

fn options(url: String) -> Options {
    Options {
        ca_cert: Some(fixture_path("test-ca.pem")),
        url,
        connect_timeout: Duration::from_secs(2),
        max_time: Duration::from_secs(3),
        speed_time: Duration::from_secs(2),
        ..Options::default()
    }
}

#[test]
fn transfers_a_verified_https_response() {
    let (url, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let mut body = Vec::new();
    let info = curl::transfer(&options(url.clone()), &mut body).unwrap();
    server.join().unwrap();
    assert_eq!(body, b"hello");
    assert_eq!(info.response_code, 200);
    assert_eq!(info.url_effective, url);
    assert_eq!(info.size_download, 5);
}

#[test]
fn binary_separates_body_and_write_out_trailer() {
    let (url, server) = serve(
        b"HTTP/1.1 302 Found\r\nContent-Length: 4\r\n\
          Location: /next\r\n\r\nbody",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_curl"))
        .args([
            "--silent",
            "--show-error",
            "--cacert",
            fixture_path("test-ca.pem").to_str().unwrap(),
            "--write-out",
            "%{stderr}\\nstatus=%{response_code}\\nurl=%{url_effective}\\nredirect=%{redirect_url}\\nsize=%{size_download}\\n",
            "--url",
            &url,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"body");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "\nstatus=302\nurl={url}\nredirect=https://{}/next\nsize=4\n",
            url.strip_prefix("https://")
                .unwrap()
                .split('/')
                .next()
                .unwrap()
        )
    );
}

#[test]
fn rejects_an_untrusted_server_certificate() {
    let (url, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let mut options = options(url);
    options.ca_cert = Some(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../img_files/motor-os/sys/cfg/ssl/ssl-cert.pem"),
    );
    let error = curl::transfer(&options, &mut Vec::new()).unwrap_err();
    server.join().unwrap();
    assert_eq!(error.code(), CurlError::CERTIFICATE);
}

#[test]
fn rejects_a_server_certificate_for_another_host() {
    let (url, server) = serve_with_identity(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        Duration::ZERO,
        HOSTNAME_CERTIFICATE,
        HOSTNAME_PRIVATE_KEY,
    );
    let mut options = options(url);
    options.ca_cert = Some(fixture_path("hostname-ca.pem"));
    let error = curl::transfer(&options, &mut Vec::new()).unwrap_err();
    server.join().unwrap();
    assert_eq!(error.code(), CurlError::CERTIFICATE);
}

#[test]
fn transfers_chunked_and_close_delimited_responses() {
    for (response, expected) in [
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
                .as_slice(),
            b"abcde".as_slice(),
        ),
        (
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil close".as_slice(),
            b"until close".as_slice(),
        ),
    ] {
        let (url, server) = serve(response);
        let mut body = Vec::new();
        let info = curl::transfer(&options(url), &mut body).unwrap();
        server.join().unwrap();
        assert_eq!(body, expected);
        assert_eq!(info.size_download, expected.len() as u64);
    }
}

#[test]
fn rejects_malformed_and_truncated_https_responses() {
    for response in [
        b"NOT HTTP\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".as_slice(),
    ] {
        let (url, server) = serve(response);
        let error = curl::transfer(&options(url), &mut Vec::new()).unwrap_err();
        server.join().unwrap();
        assert_eq!(error.code(), CurlError::RECEIVE);
    }
}

#[test]
fn enforces_the_total_transfer_timeout() {
    let (url, server) = serve_after(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        Duration::from_secs(2),
    );
    let mut options = options(url);
    options.max_time = Duration::from_secs(1);
    let error = curl::transfer(&options, &mut Vec::new()).unwrap_err();
    server.join().unwrap();
    assert_eq!(error.code(), CurlError::TIMEOUT);
}

#[cfg(target_os = "linux")]
#[test]
fn matches_upstream_curl_for_supported_success_output() {
    fn run(program: &str, url: &str) -> std::process::Output {
        Command::new(program)
            .args([
                "--disable",
                "--silent",
                "--show-error",
                "--http1.1",
                "--cacert",
                fixture_path("test-ca.pem").to_str().unwrap(),
                "--output",
                "-",
                "--write-out",
                "\\n%{response_code}|%{redirect_url}|%{size_download}",
                "--url",
                url,
            ])
            .output()
            .unwrap()
    }

    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    let (upstream_url, upstream_server) = serve(response);
    let upstream = run("curl", &upstream_url);
    upstream_server.join().unwrap();

    let (motor_url, motor_server) = serve(response);
    let motor = run(env!("CARGO_BIN_EXE_curl"), &motor_url);
    motor_server.join().unwrap();

    assert!(upstream.status.success(), "{upstream:?}");
    assert!(motor.status.success(), "{motor:?}");
    assert_eq!(motor.stdout, upstream.stdout);
    assert_eq!(motor.stderr, upstream.stderr);
}
