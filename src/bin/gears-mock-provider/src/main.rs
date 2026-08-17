//! A deterministic TLS provider that exists only in Motor's development image.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
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
    cert: PathBuf,
    key: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("gears-mock-provider: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args(std::env::args()).map_err(invalid)?;
    if !args.addr.ip().is_loopback() {
        return Err(invalid("--addr must be a literal loopback address").into());
    }
    let scripts = provider_scenario(&args.scenario).ok_or_else(|| {
        invalid(format!(
            "unknown scenario {:?}; expected one of: {}",
            args.scenario,
            PROVIDER_SCENARIOS.join(", ")
        ))
    })?;
    let listener = TcpListener::bind(args.addr)?;
    let config = tls_config(&args.cert, &args.key)?;
    let addr = listener.local_addr()?;
    println!(
        "GEARS_MOCK_READY base_url=https://{addr}/v1 scenario={}",
        args.scenario
    );
    std::io::stdout().flush()?;
    serve(listener, scripts, config, &args.scenario)?;
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
    let mut cert = None;
    let mut key = None;
    while let Some(option) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{option} requires a value"))?;
        match option.as_str() {
            "--addr" => set_once(&mut addr, value.parse().map_err(|_| "bad --addr")?, &option)?,
            "--scenario" => set_once(&mut scenario, value, &option)?,
            "--cert" => set_once(&mut cert, PathBuf::from(value), &option)?,
            "--key" => set_once(&mut key, PathBuf::from(value), &option)?,
            _ => return Err(format!("unknown option {option}")),
        }
    }
    Ok(Args {
        addr: addr.ok_or("missing --addr")?,
        scenario: scenario.ok_or("missing --scenario")?,
        cert: cert.ok_or("missing --cert")?,
        key: key.ok_or("missing --key")?,
    })
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
    config: Arc<ServerConfig>,
    scenario: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    for (index, script) in scripts.into_iter().enumerate() {
        let (tcp, peer) = listener.accept()?;
        let destination = observed_loopback_destination(&tcp)?;
        if !peer.ip().is_loopback() {
            return Err(invalid(format!("refusing non-loopback client {peer}")).into());
        }
        tcp.set_nodelay(true)?;
        let connection = ServerConnection::new(Arc::clone(&config))?;
        let mut stream = StreamOwned::new(connection, tcp);
        let body = read_provider_request(&mut stream)?;
        validate_provider_request(scenario, &body).map_err(invalid)?;
        let body_bytes = body.len();
        let context_bytes = request_context_bytes(&body).map_err(invalid)?;
        println!(
            "GEARS_MOCK_REQUEST index={} destination={destination} body_bytes={body_bytes} \
             context_bytes={context_bytes} elapsed_us={}",
            index + 1,
            started.elapsed().as_micros()
        );
        std::io::stdout().flush()?;
        play(&mut stream, script)?;
    }
    Ok(())
}

fn observed_loopback_destination(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    let destination = stream.local_addr()?;
    if destination.ip().is_loopback() {
        Ok(destination)
    } else {
        Err(invalid(format!(
            "request targeted non-loopback destination {destination}"
        )))
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

fn play(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    script: gears::mock::Script,
) -> std::io::Result<()> {
    for piece in script.into_pieces() {
        match piece {
            Piece::Write(bytes) => {
                stream.write_all(&bytes)?;
                stream.flush()?;
            }
            Piece::Pause(delay) => std::thread::sleep(delay),
            Piece::Close => return Ok(()),
        }
    }
    stream.conn.send_close_notify();
    stream.flush()?;
    stream.sock.shutdown(std::net::Shutdown::Write)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

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
    fn fragmented_sse_crosses_a_real_tls_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = tls_config(
            &curl_fixture("server-cert.pem"),
            &curl_fixture("server-key.pem"),
        )
        .unwrap();
        let scripts = provider_scenario("fragmented-sse").unwrap();
        let server =
            std::thread::spawn(move || serve(listener, scripts, config, "fragmented-sse").unwrap());

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
