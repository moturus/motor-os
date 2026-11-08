#[cfg(target_os = "motor")]
fn main() {}

#[cfg(not(target_os = "motor"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    host::run()
}

#[cfg(not(target_os = "motor"))]
mod host {
    use std::{
        fs::{self, File},
        io::{self, BufReader, Read, Write},
        net::{IpAddr, Ipv4Addr, TcpListener},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::Arc,
        time::Duration,
    };

    use rustls::{ServerConfig, ServerConnection, StreamOwned};

    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    pub(super) fn run() -> Result {
        let mut args = std::env::args_os().skip(1);
        let repository = fs::canonicalize(args.next().ok_or("repository required")?)?;
        let push_repository = fs::canonicalize(args.next().ok_or("push repository required")?)?;
        let work = PathBuf::from(args.next().ok_or("scratch directory required")?);
        let bind: IpAddr = args
            .next()
            .ok_or("bind address required")?
            .to_str()
            .ok_or("address must be UTF-8")?
            .parse()?;
        if bind != IpAddr::V4(Ipv4Addr::LOCALHOST)
            && bind != IpAddr::V4(Ipv4Addr::new(192, 168, 4, 1))
        {
            return Err("fixture binds only loopback or the Motor test bridge".into());
        }
        if args.next().is_some() {
            return Err("unexpected fixture argument".into());
        }

        fs::create_dir(&work)?;
        for name in ["home", "xdg", "template"] {
            fs::create_dir(work.join(name))?;
        }
        let certificates = rustls_pemfile::certs(&mut BufReader::new(
            include_bytes!("https-server-cert.pem").as_slice(),
        ))
        .collect::<io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(
            include_bytes!("https-server-key.pem").as_slice(),
        ))?
        .ok_or("fixture private key missing")?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
                .with_no_client_auth()
                .with_single_cert(certificates, key)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);

        let listener = TcpListener::bind((bind, 0))?;
        println!("HTTPS_READY={}", listener.local_addr()?.port());
        io::stdout().flush()?;
        for (number, socket) in listener.incoming().enumerate() {
            let socket = socket?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            let mut stream = StreamOwned::new(ServerConnection::new(config.clone())?, socket);
            let request = read_request(&mut stream)?;
            let (case, path) = [
                "redirect",
                "reject-status",
                "reject-type",
                "reject-origin",
                "bad-protocol",
                "stall",
                "fast-forward-only",
                "auth",
            ]
            .into_iter()
            .find_map(|case| {
                request
                    .path
                    .strip_prefix(&format!("/{case}"))
                    .map(|path| (case, path))
            })
            .unwrap_or(("good", &request.path));
            let (service, advertisement) = match (request.method.as_str(), path) {
                ("GET", "/repo.git/info/refs?service=git-upload-pack") => ("upload-pack", true),
                ("POST", "/repo.git/git-upload-pack") => ("upload-pack", false),
                ("GET", "/push.git/info/refs?service=git-receive-pack") => ("receive-pack", true),
                ("POST", "/push.git/git-receive-pack") => ("receive-pack", false),
                _ => {
                    return Err(format!(
                        "unexpected fixture request: {} {}",
                        request.method, request.path
                    )
                    .into());
                }
            };
            let (repository, config) = match service {
                "upload-pack" => (&repository, None),
                _ if case == "fast-forward-only" => {
                    (&push_repository, Some("receive.denyNonFastForwards=true"))
                }
                _ => (&push_repository, None),
            };

            if case == "stall" {
                stream
                    .sock
                    .set_read_timeout(Some(Duration::from_secs(20)))?;
                println!("STALL_READY");
                io::stdout().flush()?;
                match stream.read(&mut [0]) {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                        ) => {}
                    result => {
                        return Err(format!("stalled connection did not close: {result:?}").into());
                    }
                }
                println!("STALL_CLOSED");
                io::stdout().flush()?;
                continue;
            }

            // Basic credentials for fixture-user with the password fixture-token.
            let credentials = match request.authorization.as_deref() {
                None => "anonymous",
                Some("Basic Zml4dHVyZS11c2VyOmZpeHR1cmUtdG9rZW4=") => "good-credentials",
                Some(_) => "bad-credentials",
            };
            let mut status = 200;
            let mut location = None;
            let mut challenge = false;
            let mut kind = format!(
                "application/x-git-{service}-{}",
                if advertisement {
                    "advertisement"
                } else {
                    "result"
                }
            );
            let output = match case {
                "redirect" if advertisement => {
                    status = 302;
                    location = Some("/repo.git/info/refs?service=git-upload-pack".to_owned());
                    Vec::new()
                }
                "reject-origin" => {
                    status = 302;
                    location = Some(format!(
                        "https://127.0.0.2:{}/repo.git/info/refs?service=git-upload-pack",
                        listener.local_addr()?.port()
                    ));
                    Vec::new()
                }
                "reject-status" => {
                    status = 401;
                    b"fixture denied".to_vec()
                }
                "auth" if credentials != "good-credentials" => {
                    status = 401;
                    challenge = true;
                    b"fixture requires credentials".to_vec()
                }
                "reject-type" => {
                    kind = "text/plain".to_owned();
                    b"wrong Git media type".to_vec()
                }
                "bad-protocol" if !advertisement => vec![b'z'; 128 * 1024],
                _ => git_service(
                    repository,
                    &work,
                    number,
                    (service, config),
                    advertisement,
                    &request,
                )?,
            };
            write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n",
                output.len()
            )?;
            if let Some(location) = location {
                write!(stream, "Location: {location}\r\n")?;
            }
            if challenge {
                write!(stream, "WWW-Authenticate: Basic realm=\"gix fixture\"\r\n")?;
            }
            stream.write_all(b"\r\n")?;
            stream.write_all(&output)?;
            stream.conn.send_close_notify();
            stream.flush()?;
            println!(
                "{} {} -> {status} {credentials}: {} -> {} bytes",
                request.method,
                request.path,
                request.body.len(),
                output.len()
            );
            io::stdout().flush()?;
        }
        Ok(())
    }

    struct Request {
        method: String,
        path: String,
        protocol_v2: bool,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    fn read_request(stream: &mut impl Read) -> Result<Request> {
        let mut head = Vec::with_capacity(1024);
        loop {
            if head.len() == 64 * 1024 {
                return Err("request header limit exceeded".into());
            }
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&head)?;
        let mut lines = text.split("\r\n");
        let first = lines
            .next()
            .ok_or("request line missing")?
            .split(' ')
            .collect::<Vec<_>>();
        if first.len() != 3 || first[2] != "HTTP/1.1" {
            return Err("invalid request line".into());
        }

        let mut length = None;
        let mut protocol_v2 = false;
        let mut authorization = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or("invalid header")?;
            if name.eq_ignore_ascii_case("Content-Length") {
                if length.replace(value.trim().parse::<usize>()?).is_some() {
                    return Err("duplicate content length".into());
                }
            } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
                return Err("fixture requires content length".into());
            } else if name.eq_ignore_ascii_case("Git-Protocol") {
                if protocol_v2 || value.trim() != "version=2" {
                    return Err("unexpected Git protocol header".into());
                }
                protocol_v2 = true;
            } else if name.eq_ignore_ascii_case("Authorization")
                && authorization.replace(value.trim().to_owned()).is_some()
            {
                return Err("duplicate authorization header".into());
            }
        }
        let length = match (first[0], length) {
            ("GET", None | Some(0)) => 0,
            ("POST", Some(length)) => length,
            _ => return Err("invalid fixture body length".into()),
        };
        if length > 8 * 1024 * 1024 {
            return Err("request body limit exceeded".into());
        }
        let mut body = vec![0; length];
        stream.read_exact(&mut body)?;
        Ok(Request {
            method: first[0].to_owned(),
            path: first[1].to_owned(),
            protocol_v2,
            authorization,
            body,
        })
    }

    /// Run host `git upload-pack` or `git receive-pack` for one stateless request.
    fn git_service(
        repository: &Path,
        work: &Path,
        number: usize,
        (service, config): (&str, Option<&str>),
        advertisement: bool,
        request: &Request,
    ) -> Result<Vec<u8>> {
        let input = work.join(format!("request-{number}"));
        fs::write(&input, &request.body)?;
        let mut git = Command::new("/usr/bin/git");
        git.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", work.join("home"))
            .env("XDG_CONFIG_HOME", work.join("xdg"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TEMPLATE_DIR", work.join("template"))
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .args(["-c", "core.hooksPath=/dev/null"]);
        if let Some(config) = config {
            git.args(["-c", config]);
        }
        git.args([service, "--stateless-rpc"]);
        if request.protocol_v2 {
            git.env("GIT_PROTOCOL", "version=2");
        }
        if advertisement {
            git.arg("--advertise-refs");
        }
        git.arg(repository)
            .stdin(File::open(&input)?)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = git.output();
        drop(git);
        let cleanup = fs::remove_file(input);
        let output = output?;
        cleanup?;
        if !output.status.success() {
            return Err(format!(
                "{service} {}: {}",
                output.status,
                output.stderr.escape_ascii()
            )
            .into());
        }
        let mut response = Vec::new();
        if advertisement && !request.protocol_v2 {
            let announcement = format!("# service=git-{service}\n");
            write!(response, "{:04x}{announcement}0000", announcement.len() + 4)?;
        }
        response.extend_from_slice(&output.stdout);
        Ok(response)
    }
}
