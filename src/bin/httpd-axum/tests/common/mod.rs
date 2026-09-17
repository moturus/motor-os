use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
mod fixture;
pub use fixture::Fixture;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Server {
    child: Child,
    output: Receiver<std::io::Result<String>>,
    reader: Option<JoinHandle<()>>,
    pub address: SocketAddr,
    pub directory: PathBuf,
    _fixture: Fixture,
}

impl Server {
    pub fn start(logging: Option<&str>, extra: &[&str]) -> Self {
        Self::start_with_tls(logging, extra, false, "127.0.0.1:0")
    }

    pub fn start_tls(logging: Option<&str>, extra: &[&str]) -> Self {
        Self::start_tls_at(logging, extra, "127.0.0.1:0")
    }

    pub fn start_tls_at(logging: Option<&str>, extra: &[&str], address: &str) -> Self {
        Self::start_with_tls(logging, extra, true, address)
    }

    fn start_with_tls(logging: Option<&str>, extra: &[&str], tls: bool, address: &str) -> Self {
        let fixture = Fixture::new("http");
        let directory = fixture.0.clone();
        std::fs::write(directory.join("index.html"), b"test content\n").unwrap();
        let binary = std::env::var_os("HTTPD_AXUM_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_httpd-axum").into());
        let mut command = Command::new(binary);
        if tls {
            let (cert, key) = certificates(&directory);
            command
                .arg("--ssl-cert")
                .arg(cert)
                .arg("--ssl-key")
                .arg(key);
        }
        command
            .args(["-a", address, "-d"])
            .arg(&directory)
            .args(extra)
            .env("NO_COLOR", "1")
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped());
        if let Some(logging) = logging {
            command.env("RUST_LOG", logging);
        }
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        // Drain stdout during requests, including at the default access-log
        // level. A full pipe must not block the server under test.
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut server = Self {
            child,
            output,
            reader: Some(reader),
            address: address.parse().unwrap(),
            directory,
            _fixture: fixture,
        };
        // The bound-address event is readiness; no sleeps or connection retries.
        let line = server.next_log();
        server.address = line
            .split_once("listening on ")
            .expect(&line)
            .1
            .trim()
            .parse()
            .unwrap();
        server
    }

    pub fn connect(&self) -> TcpStream {
        connect(self.address)
    }

    pub fn stop(mut self) -> String {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        self.reader.take().unwrap().join().unwrap();
        self.output
            .try_iter()
            .map(|line| line.unwrap() + "\n")
            .collect()
    }

    pub fn next_log(&mut self) -> String {
        self.output.recv().expect("server closed stdout").unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

pub fn certificates(directory: &Path) -> (PathBuf, PathBuf) {
    let cert = directory.join("cert.pem");
    let key = directory.join("key.pem");
    std::fs::write(&cert, include_bytes!("../fixtures/cert.pem")).unwrap();
    std::fs::write(&key, include_bytes!("../fixtures/key.pem")).unwrap();
    (cert, key)
}

pub fn connect(address: impl std::net::ToSocketAddrs) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.set_nodelay(true).unwrap();
    stream
}

pub struct Response {
    pub status: u16,
    pub headers: String,
    pub body: Vec<u8>,
}

pub fn request<S: Read + Write>(
    io: &mut BufReader<S>,
    method: &str,
    path: &str,
    headers: &str,
) -> Response {
    request_with_host(io, method, path, "localhost", headers)
}

pub fn request_with_host<S: Read + Write>(
    io: &mut BufReader<S>,
    method: &str,
    path: &str,
    host: &str,
    headers: &str,
) -> Response {
    write!(
        io.get_mut(),
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n"
    )
    .unwrap();
    io.get_mut().flush().unwrap();
    let mut line = String::new();
    assert_ne!(
        io.read_line(&mut line).unwrap(),
        0,
        "server closed the connection before responding to {method} {path}"
    );
    let status = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("invalid status line for {method} {path}: {line:?}"))
        .parse()
        .unwrap();
    let mut headers = String::new();
    let mut length = 0;
    loop {
        line.clear();
        assert_ne!(io.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        let name = name.to_ascii_lowercase();
        if name == "content-length" {
            length = value.trim().parse().unwrap();
        }
        headers.push_str(&name);
        headers.push(':');
        headers.push_str(value);
    }
    assert!(length < 1024 * 1024, "unexpected response length {length}");
    let mut body = vec![
        0;
        if method == "HEAD" || status == 304 {
            0
        } else {
            length
        }
    ];
    io.read_exact(&mut body).unwrap();
    Response {
        status,
        headers,
        body,
    }
}
