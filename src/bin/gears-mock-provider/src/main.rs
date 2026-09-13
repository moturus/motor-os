//! A deterministic TLS provider for Motor's development image, with explicit
//! plain-HTTP and non-loopback modes for the guest-to-host gate.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use gears::mock::{
    PROVIDER_SCENARIOS, Piece, provider_scenario, request_context_bytes, validate_provider_request,
};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 1024 * 1024;

#[cfg(target_os = "motor")]
fn motor_getrandom(destination: &mut [u8]) -> Result<(), getrandom::Error> {
    moto_rt::fill_random_bytes(destination);
    Ok(())
}

#[cfg(target_os = "motor")]
getrandom::register_custom_getrandom!(motor_getrandom);

#[derive(Debug, PartialEq, Eq)]
struct Args {
    addr: SocketAddr,
    scenario: String,
    expect_model: Option<String>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    plain: bool,
    allow_non_loopback: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("gears-mock-provider: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args(std::env::args()).map_err(invalid)?;
    let scripts = provider_scenario(&args.scenario).ok_or_else(|| {
        invalid(format!(
            "unknown scenario {:?}; expected one of: {}",
            args.scenario,
            PROVIDER_SCENARIOS.join(", ")
        ))
    })?;
    let listener = TcpListener::bind(args.addr)?;
    let config = if args.plain {
        None
    } else {
        Some(tls_config(
            args.cert.as_deref().expect("validated cert"),
            args.key.as_deref().expect("validated key"),
        )?)
    };
    let addr = listener.local_addr()?;
    let scheme = if args.plain { "http" } else { "https" };
    println!(
        "GEARS_MOCK_READY base_url={scheme}://{addr}/v1 scenario={}",
        args.scenario
    );
    std::io::stdout().flush()?;
    serve(listener, scripts, config, &args)?;
    println!("GEARS_MOCK_DONE requests_complete");
    Ok(())
}

fn parse_args<I, S>(arguments: I) -> Result<Args, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    let _program = arguments.next();
    let mut addr = None;
    let mut scenario = None;
    let mut expect_model = None;
    let mut cert = None;
    let mut key = None;
    let mut plain = false;
    let mut allow_non_loopback = false;
    while let Some(option) = arguments.next() {
        let flag = match option.as_str() {
            "--plain" => Some(&mut plain),
            "--allow-non-loopback" => Some(&mut allow_non_loopback),
            _ => None,
        };
        if let Some(flag) = flag {
            if std::mem::replace(flag, true) {
                return Err(format!("{option} was given more than once"));
            }
            continue;
        }
        let value = arguments
            .next()
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--addr" => set_once(&mut addr, value.parse().map_err(|_| "bad --addr")?, &option)?,
            "--scenario" => set_once(&mut scenario, value, &option)?,
            "--expect-model" => set_once(&mut expect_model, value, &option)?,
            "--cert" => set_once(&mut cert, PathBuf::from(value), &option)?,
            "--key" => set_once(&mut key, PathBuf::from(value), &option)?,
            _ => return Err(format!("unknown option {option}")),
        }
    }
    if plain {
        if cert.is_some() || key.is_some() {
            return Err("--plain cannot be combined with --cert or --key".into());
        }
    } else if cert.is_none() || key.is_none() {
        return Err("TLS requires both --cert and --key; use --plain for HTTP".into());
    }
    let args = Args {
        addr: addr.ok_or("missing --addr")?,
        scenario: scenario.ok_or("missing --scenario")?,
        expect_model,
        cert,
        key,
        plain,
        allow_non_loopback,
    };
    check_address(args.addr, "bind address", args.allow_non_loopback)
        .map_err(|error| error.to_string())?;
    Ok(args)
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        Err(format!("{option} was given more than once"))
    } else {
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn tls_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key)?))?
        .ok_or_else(|| invalid("private-key file contains no supported key"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

fn serve(
    listener: TcpListener,
    scripts: Vec<gears::mock::Script>,
    config: Option<Arc<ServerConfig>>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    for (index, script) in scripts.into_iter().enumerate() {
        let (mut tcp, peer) = listener.accept()?;
        let destination = tcp.local_addr()?;
        check_address(destination, "destination", args.allow_non_loopback)?;
        check_address(peer, "client", args.allow_non_loopback)?;
        tcp.set_nodelay(true)?;
        let exchange = Exchange {
            args,
            index,
            destination,
            started,
        };
        // A script that ends in `Close` drops the connection without a clean
        // shutdown, which is what that piece simulates.
        if let Some(config) = &config {
            let connection = ServerConnection::new(Arc::clone(config))?;
            let mut stream = StreamOwned::new(connection, tcp);
            if exchange.respond(&mut stream, script)? {
                stream.conn.send_close_notify();
                stream.flush()?;
                stream.sock.shutdown(std::net::Shutdown::Write)?;
            }
        } else if exchange.respond(&mut tcp, script)? {
            tcp.shutdown(std::net::Shutdown::Write)?;
        }
    }
    Ok(())
}

fn check_address(address: SocketAddr, kind: &str, allow_non_loopback: bool) -> std::io::Result<()> {
    if address.ip().is_loopback() || allow_non_loopback {
        Ok(())
    } else {
        Err(invalid(format!(
            "refusing non-loopback {kind} {address}; use --allow-non-loopback"
        )))
    }
}

struct Exchange<'a> {
    args: &'a Args,
    index: usize,
    destination: SocketAddr,
    started: Instant,
}

impl Exchange<'_> {
    /// Reads and checks one request, then plays the script. Returns whether
    /// the script ran to its end rather than to a `Close` piece.
    fn respond(
        &self,
        stream: &mut (impl Read + Write),
        script: gears::mock::Script,
    ) -> std::io::Result<bool> {
        let body = read_provider_request(stream)?;
        validate_provider_request(
            &self.args.scenario,
            &body,
            self.args.expect_model.as_deref(),
        )
        .map_err(invalid)?;
        let body_bytes = body.len();
        let context_bytes = request_context_bytes(&body).map_err(invalid)?;
        println!(
            "GEARS_MOCK_REQUEST index={} destination={} body_bytes={body_bytes} \
             context_bytes={context_bytes} elapsed_us={}",
            self.index + 1,
            self.destination,
            self.started.elapsed().as_micros()
        );
        std::io::stdout().flush()?;
        play(stream, script)
    }
}

fn read_provider_request(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() == MAX_HEAD {
            return Err(invalid("request head exceeds 64 KiB"));
        }
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let text = std::str::from_utf8(&head).map_err(|_| invalid("request head is not UTF-8"))?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    if lines.next() != Some("POST /v1/chat/completions HTTP/1.1") {
        return Err(invalid("expected POST /v1/chat/completions over HTTP/1.1"));
    }
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed request header"))?;
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(invalid("duplicate Content-Length"));
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| invalid("bad Content-Length"))?,
            );
        }
    }
    let body_bytes = content_length.ok_or_else(|| invalid("missing Content-Length"))?;
    if body_bytes > MAX_BODY {
        return Err(invalid("request body exceeds 1 MiB"));
    }
    let mut body = vec![0_u8; body_bytes];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn play(stream: &mut impl Write, script: gears::mock::Script) -> std::io::Result<bool> {
    for piece in script.into_pieces() {
        match piece {
            Piece::Write(bytes) => {
                stream.write_all(&bytes)?;
                stream.flush()?;
            }
            Piece::Pause(delay) => std::thread::sleep(delay),
            Piece::Close => return Ok(false),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::process::Command;

    fn plain_args(scenario: &str) -> Args {
        parse_args([
            "mock",
            "--addr",
            "127.0.0.1:0",
            "--scenario",
            scenario,
            "--plain",
        ])
        .unwrap()
    }

    fn curl_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../curl/tests")
            .join(name)
    }

    #[test]
    fn arguments_are_explicit_and_unambiguous() {
        let args = parse_args([
            "mock",
            "--addr",
            "127.0.0.1:9443",
            "--scenario",
            "tool-round",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
        ])
        .unwrap();
        assert_eq!(args.addr, "127.0.0.1:9443".parse().unwrap());
        assert_eq!(args.scenario, "tool-round");
        assert!(parse_args(["mock", "--addr", "127.0.0.1:1"]).is_err());
        assert!(parse_args(["mock", "--wat", "value"]).is_err());
    }

    #[test]
    fn plaintext_and_non_loopback_require_separate_flags() {
        for (flags, allowed) in [
            (vec![], false),
            (vec!["--plain"], false),
            (vec!["--allow-non-loopback"], false),
            (vec!["--plain", "--allow-non-loopback"], true),
            (
                vec!["--plain", "--allow-non-loopback", "--cert", "cert.pem"],
                false,
            ),
            (vec!["--plain", "--plain", "--allow-non-loopback"], false),
            (vec!["--cert", "cert.pem", "--key", "key.pem"], false),
            (
                vec![
                    "--cert",
                    "cert.pem",
                    "--key",
                    "key.pem",
                    "--allow-non-loopback",
                ],
                true,
            ),
        ] {
            let mut args = vec![
                "mock",
                "--addr",
                "192.168.4.1:8080",
                "--scenario",
                "streamed-text",
            ];
            args.extend(flags);
            assert_eq!(parse_args(args.clone()).is_ok(), allowed, "{args:?}");
        }
        let args = parse_args([
            "mock",
            "--addr",
            "127.0.0.1:0",
            "--scenario",
            "streamed-text",
            "--plain",
            "--expect-model",
            "test/model",
        ])
        .unwrap();
        assert_eq!(args.expect_model.as_deref(), Some("test/model"));
        assert!(plain_args("streamed-text").expect_model.is_none());
    }

    #[test]
    fn bind_destination_and_client_checks_keep_the_loopback_default() {
        for kind in ["bind address", "destination", "client"] {
            for address in [
                "192.168.4.1:8080",
                "192.168.4.2:40000",
                "[2001:db8::1]:8080",
            ] {
                let address = address.parse().unwrap();
                let error = check_address(address, kind, false).unwrap_err();
                assert!(error.to_string().contains(kind));
                assert!(check_address(address, kind, true).is_ok());
            }
            assert!(check_address("127.0.0.1:8080".parse().unwrap(), kind, false).is_ok());
            assert!(check_address("[::1]:8080".parse().unwrap(), kind, false).is_ok());
        }
    }

    #[test]
    fn fragmented_sse_crosses_a_plain_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let args = plain_args("fragmented-sse");
        let server = std::thread::spawn(move || {
            serve(
                listener,
                provider_scenario("fragmented-sse").unwrap(),
                None,
                &args,
            )
            .unwrap();
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let body = br#"{"messages":[]}"#;
        write!(
            stream,
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        server.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("fragmented"));
        assert!(response.contains("[DONE]"));
    }

    #[test]
    fn fragmented_sse_crosses_a_real_tls_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = tls_config(
            &curl_fixture("server-cert.pem"),
            &curl_fixture("server-key.pem"),
        )
        .unwrap();
        let scripts = provider_scenario("fragmented-sse").unwrap();
        let args = plain_args("fragmented-sse");
        let server =
            std::thread::spawn(move || serve(listener, scripts, Some(config), &args).unwrap());

        let output = Command::new("curl")
            .args(["--silent", "--show-error", "--http1.1", "--noproxy", "*"])
            .arg("--cacert")
            .arg(curl_fixture("test-ca.pem"))
            .args(["--data-binary", r#"{"messages":[]}"#, "--url"])
            .arg(format!("https://{addr}/v1/chat/completions"))
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let body = String::from_utf8(output.stdout).unwrap();
        assert!(body.contains("fragmented"), "{body}");
        assert!(body.contains("[DONE]"), "{body}");
    }
}
