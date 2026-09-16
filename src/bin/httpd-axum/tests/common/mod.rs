use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Server {
    child: Child,
    output: BufReader<ChildStdout>,
    pub address: SocketAddr,
    pub directory: PathBuf,
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
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("httpd-http-{nonce}"));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("index.html"), b"test content\n").unwrap();
        let binary = std::env::var_os("HTTPD_AXUM_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_httpd-axum").into());
        let mut command = Command::new(binary);
        if tls {
            let cert = directory.join("cert.pem");
            let key = directory.join("key.pem");
            std::fs::write(&cert, include_bytes!("../fixtures/cert.pem")).unwrap();
            std::fs::write(&key, include_bytes!("../fixtures/key.pem")).unwrap();
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
        let mut output = BufReader::new(child.stdout.take().unwrap());
        // Startup reports the actual bound port. No sleeps or connection retries
        // are needed, and an early startup failure closes stdout and fails here.
        let mut line = String::new();
        assert_ne!(output.read_line(&mut line).unwrap(), 0);
        let address = line
            .split_once("listening on ")
            .expect(&line)
            .1
            .trim()
            .parse()
            .unwrap();
        Self {
            child,
            output,
            address,
            directory,
        }
    }

    pub fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }

    pub fn stop(mut self) -> String {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        let mut logs = String::new();
        self.output.read_to_string(&mut logs).unwrap();
        logs
    }

    pub fn next_log(&mut self) -> String {
        let mut line = String::new();
        assert_ne!(self.output.read_line(&mut line).unwrap(), 0);
        line
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
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
    io.read_line(&mut line).unwrap();
    let status = line
        .split_whitespace()
        .nth(1)
        .expect(&line)
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
