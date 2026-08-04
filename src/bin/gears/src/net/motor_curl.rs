//! The Motor OS backend of the HTTP seam: an `HttpClient` driving the
//! in-tree `/bin/curl` through the shared [`CurlTransport`] engine — the
//! same way lorry drives it for vendor downloads, and the same way the host
//! backend drives upstream curl(1).
//!
//! A subprocess, deliberately, not the curl crate as a library: linking it
//! would pull rustls and the Motor-patched `ring` into gears' dependency
//! graph, and with them the lorry staging pipeline into every gears build —
//! host test runs, in-tree cross-compiles, Motor clippy, and the self-update
//! flow would all inherit it. The Motor curl implements exactly the long
//! options [`super::curl::build_argv`] emits (its own test suite proves the
//! argv against both binaries), so process isolation costs one spawn per
//! request and buys gears a dependency list that is still just serde.
//!
//! Compiled on every platform so the host suite can hold it to the seam's
//! contract with a stand-in program.

use super::curl::CurlTransport;
use super::{EgressPolicy, HttpClient, HttpRequest, HttpSink, NetError, ResponseHead};

/// Where the image installs curl. An absolute path on purpose: Motor OS
/// spawns take the name as given, with no PATH search to lean on.
pub const MOTOR_CURL: &str = "/bin/curl";

pub struct MotorCurl {
    transport: CurlTransport,
}

impl MotorCurl {
    /// `Result` to mirror the host constructor, so `main` builds either
    /// backend with the same calls. There is no version probe here: the
    /// binary ships in the same image as gears, so the two cannot drift
    /// apart, and a missing `/bin/curl` reports itself on first use.
    pub fn new(policy: EgressPolicy) -> Result<MotorCurl, NetError> {
        Ok(MotorCurl::with_program(MOTOR_CURL, policy))
    }

    /// A different curl binary, for tests that need a stand-in.
    pub fn with_program(program: &str, policy: EgressPolicy) -> MotorCurl {
        MotorCurl {
            transport: CurlTransport::new(program, policy),
        }
    }

    /// Supply the value for a secret header's environment variable. The
    /// value is registered for redaction, so it cannot appear in the trace.
    pub fn with_secret(mut self, env: &str, value: &str) -> MotorCurl {
        self.transport.add_secret(env, value);
        self
    }

    pub fn with_verbosity(mut self, level: u8) -> MotorCurl {
        self.transport.set_verbosity(level, true);
        self
    }
}

impl HttpClient for MotorCurl {
    fn execute(
        &self,
        req: &HttpRequest,
        sink: &mut dyn HttpSink,
    ) -> Result<ResponseHead, NetError> {
        self.transport.execute(req, sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{CollectSink, HeaderValue, Method, Url};

    fn policy() -> EgressPolicy {
        EgressPolicy::new(&["openrouter.ai".to_string()])
    }

    /// Egress is checked before any process is spawned: a blocked host is
    /// blocked, and an allowed one fails on the missing binary — in that
    /// order.
    #[test]
    fn egress_answers_before_the_program_is_even_looked_for() {
        let client = MotorCurl::with_program("gears-no-such-curl", policy());
        let mut sink = CollectSink::default();

        let req = HttpRequest::get(Url::parse("https://evil.test/x").unwrap());
        assert!(matches!(
            client.execute(&req, &mut sink),
            Err(NetError::Forbidden(_))
        ));

        let req = HttpRequest::get(Url::parse("https://openrouter.ai/api").unwrap());
        let err = client.execute(&req, &mut sink).unwrap_err();
        assert!(matches!(err, NetError::Transport(_)), "{err}");
        assert!(err.to_string().contains("cannot run"), "{err}");
        assert!(sink.head.is_none(), "nothing must reach the sink");
    }

    /// The whole Motor transport against a real curl(1): the argv gears
    /// builds is the one both curls implement, so on the host the system
    /// curl stands in for `/bin/curl`. One POST exercises the body pipe, the
    /// secret's environment-only path, the head-first split, and the sink.
    #[cfg(unix)]
    #[test]
    fn drives_a_real_curl_end_to_end() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") && socket.read_exact(&mut byte).is_ok() {
                request.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&request).to_string();
            let length: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            socket.read_exact(&mut body).unwrap();
            request.extend_from_slice(&body);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 11\r\n\r\n{\"ok\":true}",
                )
                .unwrap();
            request
        });

        let policy =
            EgressPolicy::new(&["127.0.0.1".to_string()]).allow_loopback_http_for_tests();
        let client =
            MotorCurl::with_program("curl", policy).with_secret("GEARS_MC_TEST_KEY", "sk-mc-42");
        let url = Url::parse(&format!("http://127.0.0.1:{port}/v1/chat")).unwrap();
        let req = HttpRequest {
            method: Method::Post,
            url,
            headers: vec![
                (
                    "Content-Type".to_string(),
                    HeaderValue::Literal("application/json".to_string()),
                ),
                (
                    "Authorization".to_string(),
                    HeaderValue::Secret {
                        prefix: "Bearer ".to_string(),
                        env: "GEARS_MC_TEST_KEY".to_string(),
                    },
                ),
            ],
            body: b"{\"q\":1}".to_vec(),
            timeouts: Default::default(),
        };

        let mut sink = CollectSink::default();
        let head = client.execute(&req, &mut sink).unwrap();
        let request = String::from_utf8(server.join().unwrap()).unwrap();

        assert_eq!(head.status, 200);
        assert_eq!(head.header("content-type"), Some("application/json"));
        assert_eq!(sink.body, b"{\"ok\":true}");
        assert!(request.starts_with("POST /v1/chat HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains("\r\nAuthorization: Bearer sk-mc-42\r\n"),
            "the secret must arrive as a header: {request}"
        );
        assert!(request.ends_with("{\"q\":1}"), "{request}");
    }
}
