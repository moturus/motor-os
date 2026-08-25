//! The transport engine both HTTP backends share: spawn a curl, feed it the
//! body, split its stdout into head and chunks, map its exit code to a
//! cause. The host backend points it at upstream curl(1); the Motor backend
//! points it at the in-tree `/system/bin/curl`, which implements exactly the
//! options [`build_argv`] emits — that compatibility is what lets one
//! audited command line, and this one engine, serve both platforms.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use super::{
    EgressPolicy, HeaderValue, HttpRequest, HttpSink, Method, NetError, ResponseHead, check_request,
};

/// Refuse a head larger than this rather than buffer whatever arrives.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// How much of curl's stderr is kept for error messages.
const MAX_STDERR_BYTES: usize = 8 * 1024;

pub(crate) struct CurlTransport {
    program: String,
    policy: EgressPolicy,
    verbosity: u8,
    verbose_child: bool,
    /// Values for [`HeaderValue::Secret`] environment variables, passed to
    /// the curl child only. gears deliberately does not hold the API key in
    /// its *own* environment: every other child it spawns — the toolchain,
    /// and whatever the model asks `run` to execute — would inherit it
    /// there.
    secrets: Vec<(String, String)>,
    ca_cert: Option<String>,
}

impl CurlTransport {
    pub fn new(program: &str, policy: EgressPolicy) -> CurlTransport {
        CurlTransport {
            program: program.to_string(),
            policy,
            verbosity: 0,
            verbose_child: false,
            secrets: Vec::new(),
            ca_cert: None,
        }
    }

    pub fn set_verbosity(&mut self, level: u8, verbose_child: bool) {
        self.verbosity = level.min(3);
        self.verbose_child = verbose_child;
    }

    /// Supply the value for a secret header's environment variable. The
    /// value is registered for redaction, so it cannot appear in the trace.
    pub fn add_secret(&mut self, env: &str, value: &str) {
        crate::trace::redact(value);
        self.secrets.push((env.to_string(), value.to_string()));
    }

    pub fn set_ca_cert(&mut self, path: &str) {
        self.ca_cert = Some(path.to_string());
    }

    fn secret(&self, env: &str) -> Option<&str> {
        self.secrets
            .iter()
            .find(|(name, _)| name == env)
            .map(|(_, value)| value.as_str())
    }

    /// Spawn curl with the request's argv and environment.
    fn spawn(&self, req: &HttpRequest) -> Result<Child, NetError> {
        let mut cmd = Command::new(&self.program);
        // The transport helper must not become Gears' foreground terminal child.
        #[cfg(not(unix))]
        cmd.env(moto_rt::process::STDIO_NO_TERMINAL_ENV_KEY, "true");
        if self.verbose_child
            && let Some(flag) = verbosity_flag(self.verbosity)
        {
            cmd.arg(flag);
            // Curl's stdout carries the HTTP response consumed below. Route
            // its diagnostics separately, then relay them to gears' stdout.
            cmd.env("MOTOR_CURL_VERBOSE_STDERR", "1");
        }
        cmd.args(build_argv(req, self.ca_cert.as_deref()))
            .stdin(if req.body.is_empty() {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (_, value) in &req.headers {
            let HeaderValue::Secret { env, .. } = value else {
                continue;
            };
            match self.secret(env) {
                Some(secret) => {
                    cmd.env(env, secret);
                }
                // Already in this process's environment, so the child
                // inherits it; curl reads it via --variable.
                None if std::env::var_os(env).is_some() => {}
                None => {
                    return Err(NetError::BadRequest(format!(
                        "environment variable {env} is not set"
                    )));
                }
            }
        }

        cmd.spawn()
            .map_err(|e| NetError::Transport(format!("cannot run {}: {e}", self.program)))
    }

    pub fn execute(
        &self,
        req: &HttpRequest,
        sink: &mut dyn HttpSink,
    ) -> Result<ResponseHead, NetError> {
        check_request(req)?;
        self.policy.check(&req.url)?;

        verbose(
            self.verbosity,
            1,
            &format!(
                "spawning {} for a {}-byte request body",
                self.program,
                req.body.len()
            ),
        );

        let mut child = self.spawn(req)?;

        verbose(
            self.verbosity,
            2,
            &format!("curl child {} started", child.id()),
        );

        // The body goes out on its own thread: curl buffers stdin before it
        // sends, and a large request would otherwise deadlock against a full
        // pipe while this thread waits to read the response.
        if !req.body.is_empty() {
            let mut stdin = child.stdin.take().expect("stdin is piped");
            let body = req.body.clone();
            let verbosity = self.verbosity;
            std::thread::spawn(move || {
                verbose(
                    verbosity,
                    2,
                    &format!("writing {} request-body bytes to curl", body.len()),
                );
                // An early exit by curl closes the pipe; that shows up as the
                // real error on the response side.
                let result = stdin.write_all(&body);
                verbose(
                    verbosity,
                    2,
                    match &result {
                        Ok(()) => "request body written; closing curl stdin",
                        Err(_) => "request-body write failed; closing curl stdin",
                    },
                );
            });
        }

        let mut stderr = child.stderr.take().expect("stderr is piped");
        let mirror = self.verbose_child && self.verbosity != 0;
        let stderr_thread = std::thread::spawn(move || {
            let mut text = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let count = match stderr.read(&mut buf) {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                if mirror {
                    mirror_curl_stderr(&buf[..count]);
                }
                let kept = (MAX_STDERR_BYTES - text.len()).min(count);
                text.extend_from_slice(&buf[..kept]);
            }
            String::from_utf8_lossy(&text).trim().to_string()
        });

        verbose(self.verbosity, 1, "waiting for curl's response stream");
        let outcome = self.pump(&mut child, sink);
        verbose(
            self.verbosity,
            2,
            "curl stdout closed; waiting for the child",
        );
        let status = child.wait();
        let stderr = stderr_thread.join().unwrap_or_default();

        let head = outcome?;
        let status = status.map_err(|e| NetError::Transport(format!("waiting for curl: {e}")))?;
        match status.code() {
            Some(0) => head.ok_or_else(|| {
                NetError::BadResponse("curl exited without a response head".to_string())
            }),
            Some(code) => Err(map_exit_code(code, &stderr)),
            // Killed by a signal: not ours (an abort returns above), so the
            // transport itself died.
            None => Err(NetError::Transport(format!("curl was killed: {stderr}"))),
        }
    }

    /// Read curl's stdout, splitting off the head and pushing the rest to
    /// the sink. Any failure kills the child so it cannot outlive the call.
    fn pump(
        &self,
        child: &mut Child,
        sink: &mut dyn HttpSink,
    ) -> Result<Option<ResponseHead>, NetError> {
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let mut parser = HeadParser::new();
        let mut head: Option<ResponseHead> = None;
        let mut buf = [0u8; 16 * 1024];
        let mut read_number = 0usize;

        loop {
            read_number += 1;
            verbose(
                self.verbosity,
                3,
                &format!("waiting for curl stdout read {read_number}"),
            );
            let read = match stdout.read(&mut buf) {
                Ok(0) => {
                    verbose(self.verbosity, 2, "curl stdout reached EOF");
                    return Ok(head);
                }
                Ok(n) => n,
                Err(e) => {
                    let _ = child.kill();
                    return Err(NetError::Transport(format!("reading from curl: {e}")));
                }
            };
            verbose(self.verbosity, 3, &format!("curl stdout read {read} bytes"));
            let chunk = &buf[..read];

            let body = match &head {
                Some(_) => chunk,
                None => match parser.feed(chunk) {
                    Ok(None) => continue,
                    Err(e) => {
                        let _ = child.kill();
                        return Err(e);
                    }
                    Ok(Some((parsed, consumed))) => {
                        verbose(
                            self.verbosity,
                            1,
                            &format!("received HTTP response head: status {}", parsed.status),
                        );
                        if let Err(e) = sink.on_head(&parsed) {
                            let _ = child.kill();
                            return Err(NetError::Aborted(e.to_string()));
                        }
                        head = Some(parsed);
                        &chunk[consumed..]
                    }
                },
            };
            if !body.is_empty() {
                verbose(
                    self.verbosity,
                    3,
                    &format!("delivering {} response-body bytes", body.len()),
                );
            }
            if !body.is_empty()
                && let Err(e) = sink.on_chunk(body)
            {
                let _ = child.kill();
                return Err(NetError::Aborted(e.to_string()));
            }
        }
    }
}

fn verbosity_flag(level: u8) -> Option<&'static str> {
    match level {
        1 => Some("-v"),
        2 => Some("-vv"),
        3 => Some("-vvv"),
        _ => None,
    }
}

fn verbose(active: u8, level: u8, message: &str) {
    if active < level {
        return;
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "gears-v{level}: {message}");
    let _ = stdout.flush();
}

fn mirror_curl_stderr(bytes: &[u8]) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(bytes);
    let _ = stdout.flush();
}

/// The command line for `req`. Pure, so the shape below is unit-tested
/// rather than inferred from behavior. Long-form options throughout: they
/// are the ones the Motor curl implements, and upstream curl reads them
/// identically.
pub(crate) fn build_argv(req: &HttpRequest, ca_cert: Option<&str>) -> Vec<String> {
    let seconds = |d: std::time::Duration| d.as_secs().max(1).to_string();
    let mut argv: Vec<String> = Vec::new();
    let mut push = |arg: &str| argv.push(arg.to_string());

    // --disable must come first: it is what makes upstream curl ignore
    // ~/.curlrc, and a config file could otherwise change every option after
    // it. (Motor curl has no config files and takes it as a no-op.)
    push("--disable");
    push("--silent");
    push("--show-error"); // No progress meter, but do report errors.
    push("--no-buffer"); // Stream as bytes arrive.
    push("--include"); // The response head first, then the body.
    push("--http1.1"); // Pin the head format; the Motor curl is 1.1-only.
    push("--noproxy");
    push("*");
    push("--header");
    push("Expect:"); // No 100-continue interim head.
    push("--header");
    push("Accept-Encoding: identity"); // Match the Motor curl: no decompression.
    push("--connect-timeout");
    push(&seconds(req.timeouts.connect));
    push("--max-time");
    push(&seconds(req.timeouts.total));
    // Stall detection: below one byte per second for this long is a hang.
    push("--speed-limit");
    push("1");
    push("--speed-time");
    push(&seconds(req.timeouts.stall));
    if let Some(path) = ca_cert {
        push("--cacert");
        push(path);
    }

    for (name, value) in &req.headers {
        match value {
            HeaderValue::Literal(text) => {
                push("--header");
                push(&format!("{name}: {text}"));
            }
            // The secret reaches curl through the environment: argv holds
            // only the variable's name.
            HeaderValue::Secret { prefix, env } => {
                push("--variable");
                push(&format!("%{env}"));
                push("--expand-header");
                push(&format!("{name}: {prefix}{{{{{env}}}}}"));
            }
        }
    }

    if req.method == Method::Post {
        // Implies POST, and streams the body in from stdin.
        push("--data-binary");
        push("@-");
    }
    // Safe as the last argument: `Url::parse` guarantees an http(s) scheme,
    // so this can never be read as an option.
    push(req.url.as_str());
    argv
}

/// Map curl's exit code to the cause the agent layer reacts to. Codes are
/// from curl(1), and the Motor curl uses the same ones; anything
/// unrecognized stays a transport error rather than being guessed at.
pub(crate) fn map_exit_code(code: i32, stderr: &str) -> NetError {
    let detail = if stderr.is_empty() {
        format!("curl exited {code}")
    } else {
        stderr.to_string()
    };
    match code {
        3 => NetError::BadUrl(detail),
        6 => NetError::Dns(detail),
        7 => NetError::Connect(detail),
        28 => NetError::Timeout(detail),
        18 | 52 | 55 | 56 => NetError::Disconnected(detail),
        35 | 58 | 59 | 60 | 77 | 91 => NetError::Connect(detail),
        _ => NetError::Transport(detail),
    }
}

/// Parses HTTP/1.1 response heads out of a byte stream that arrives in
/// arbitrary pieces — `--include` writes the head to stdout ahead of the
/// body, and unbuffered the split points are wherever the network put them.
#[derive(Default)]
pub struct HeadParser {
    buf: Vec<u8>,
}

impl HeadParser {
    pub fn new() -> HeadParser {
        HeadParser::default()
    }

    /// Feed the next piece of stdout. `Ok(Some((head, consumed)))` means the
    /// head is complete and `chunk[consumed..]` is the first of the body;
    /// `Ok(None)` means more input is needed.
    ///
    /// Interim (1xx) responses are dropped and parsing continues with the
    /// head that follows, which is what makes an unsolicited `103 Early
    /// Hints` harmless.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Option<(ResponseHead, usize)>, NetError> {
        let already = self.buf.len();
        self.buf.extend_from_slice(chunk);
        loop {
            let Some(end) = find_head_end(&self.buf) else {
                if self.buf.len() > MAX_HEAD_BYTES {
                    return Err(NetError::BadResponse(format!(
                        "response head exceeds {MAX_HEAD_BYTES} bytes"
                    )));
                }
                return Ok(None);
            };
            let head = parse_head(&self.buf[..end.head_len])?;
            let consumed = end.total_len;
            self.buf.drain(..consumed);
            if (100..200).contains(&head.status) {
                continue; // Interim response: the real one is next.
            }
            // `consumed` counts bytes from earlier chunks too; the caller
            // only knows about this one.
            return Ok(Some((head, consumed - already.min(consumed))));
        }
    }
}

struct HeadEnd {
    /// Bytes of head text, excluding the blank line that terminates it.
    head_len: usize,
    /// Bytes to drop, including that blank line.
    total_len: usize,
}

/// Find the blank line ending the head. Both CRLF and bare LF terminators are
/// accepted: the parser has to survive whatever a server actually sends.
fn find_head_end(buf: &[u8]) -> Option<HeadEnd> {
    for (i, window) in buf.windows(2).enumerate() {
        if window == b"\n\n" {
            return Some(HeadEnd {
                head_len: i,
                total_len: i + 2,
            });
        }
        if window == b"\r\n" && buf[i + 2..].starts_with(b"\r\n") {
            return Some(HeadEnd {
                head_len: i,
                total_len: i + 4,
            });
        }
    }
    None
}

fn parse_head(bytes: &[u8]) -> Result<ResponseHead, NetError> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));

    let status_line = lines
        .next()
        .ok_or_else(|| NetError::BadResponse("empty response head".to_string()))?;
    let (version, rest) = status_line
        .split_once(' ')
        .ok_or_else(|| NetError::BadResponse(format!("bad status line {status_line:?}")))?;
    if !version.starts_with("HTTP/") {
        return Err(NetError::BadResponse(format!(
            "bad status line {status_line:?}"
        )));
    }
    let (code, reason) = match rest.split_once(' ') {
        Some((code, reason)) => (code, reason),
        None => (rest, ""),
    };
    let status: u16 = code
        .parse()
        .ok()
        .filter(|s| (100..600).contains(s))
        .ok_or_else(|| NetError::BadResponse(format!("bad status code {code:?}")))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        // Obsolete line folding is not generated by anything gears talks to,
        // and accepting it is a request-smuggling foothold.
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(NetError::BadResponse(
                "folded header lines are not accepted".to_string(),
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| NetError::BadResponse(format!("bad header line {line:?}")))?;
        if name.is_empty() || !name.bytes().all(super::is_token_byte) {
            return Err(NetError::BadResponse(format!("bad header name {name:?}")));
        }
        headers.push((
            name.to_string(),
            value.trim_matches([' ', '\t']).to_string(),
        ));
    }

    Ok(ResponseHead {
        status,
        reason: reason.trim().to_string(),
        headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(pieces: &[&[u8]]) -> Result<Option<(ResponseHead, Vec<u8>)>, NetError> {
        let mut parser = HeadParser::new();
        for (i, piece) in pieces.iter().enumerate() {
            if let Some((head, consumed)) = parser.feed(piece)? {
                let mut body = piece[consumed..].to_vec();
                for rest in &pieces[i + 1..] {
                    body.extend_from_slice(rest);
                }
                return Ok(Some((head, body)));
            }
        }
        Ok(None)
    }

    #[test]
    fn parses_a_whole_head_at_once() {
        let (head, body) = feed_all(&[
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nX-Id: 7\r\n\r\ndata: hi\n\n",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.reason, "OK");
        assert_eq!(head.header("content-type"), Some("text/event-stream"));
        assert_eq!(head.header("x-id"), Some("7"));
        assert_eq!(body, b"data: hi\n\n");
    }

    #[test]
    fn parses_a_head_split_anywhere() {
        let raw: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\n\r\n{\"error\":1}";
        for split in 1..raw.len() {
            let (head, body) = feed_all(&[&raw[..split], &raw[split..]])
                .unwrap()
                .unwrap_or_else(|| panic!("no head when split at {split}"));
            assert_eq!(head.status, 429, "split at {split}");
            assert_eq!(head.reason, "Too Many Requests", "split at {split}");
            assert_eq!(head.header("retry-after"), Some("3"), "split at {split}");
            assert_eq!(body, b"{\"error\":1}", "split at {split}");
        }
    }

    #[test]
    fn accepts_bare_lf_and_a_missing_reason() {
        let (head, body) = feed_all(&[b"HTTP/1.1 204\nX-A: 1\n\nrest"])
            .unwrap()
            .unwrap();
        assert_eq!(head.status, 204);
        assert_eq!(head.reason, "");
        assert_eq!(head.header("x-a"), Some("1"));
        assert_eq!(body, b"rest");
    }

    #[test]
    fn skips_interim_responses() {
        let (head, body) = feed_all(&[
            b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-B: 2\r\n\r\nbody",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.header("x-b"), Some("2"));
        assert_eq!(head.header("link"), None);
        assert_eq!(body, b"body");
    }

    #[test]
    fn waits_for_a_complete_head() {
        assert!(
            feed_all(&[b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn refuses_malformed_heads() {
        for bad in [
            &b"200 OK\r\n\r\n"[..],
            b"HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 99 Nope\r\n\r\n",
            b"HTTP/1.1 xyz OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nNo-Colon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: 1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\tfolded\r\n\r\n",
        ] {
            assert!(
                matches!(feed_all(&[bad]), Err(NetError::BadResponse(_))),
                "accepted {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    fn request(url: &str) -> HttpRequest {
        HttpRequest::get(super::super::Url::parse(url).unwrap())
    }

    #[test]
    fn argv_has_the_fixed_shape() {
        let argv = build_argv(&request("https://openrouter.ai/api/v1"), None);
        assert_eq!(
            argv[0], "--disable",
            "--disable must come first to ignore ~/.curlrc"
        );
        for expected in [
            "--silent",
            "--show-error",
            "--no-buffer",
            "--include",
            "--http1.1",
        ] {
            assert!(argv.contains(&expected.to_string()), "{argv:?}");
        }
        assert!(argv.windows(2).any(|w| w == ["--noproxy", "*"]), "{argv:?}");
        assert!(
            argv.windows(2).any(|w| w == ["--header", "Expect:"]),
            "{argv:?}"
        );
        assert!(
            argv.windows(2)
                .any(|w| w == ["--header", "Accept-Encoding: identity"]),
            "{argv:?}"
        );
        assert!(
            argv.windows(2).any(|w| w == ["--speed-limit", "1"]),
            "{argv:?}"
        );
        assert!(argv.windows(2).any(|w| w == ["--speed-time", "90"]));
        assert!(argv.windows(2).any(|w| w == ["--connect-timeout", "30"]));
        assert!(argv.windows(2).any(|w| w == ["--max-time", "900"]));
        assert_eq!(argv.last().unwrap(), "https://openrouter.ai/api/v1");
        assert!(!argv.contains(&"--data-binary".to_string()));
        // No --fail: a 4xx body is the provider's error detail, and the
        // caller needs to read it. And no short options: the Motor curl
        // implements exactly the long forms this builder emits.
        assert!(!argv.iter().any(|a| a == "--fail" || a == "-f"));
        assert!(
            argv.iter()
                .all(|a| !a.starts_with('-') || a.starts_with("--")),
            "{argv:?}"
        );
    }

    #[test]
    fn a_provider_ca_is_passed_without_changing_the_url() {
        let argv = build_argv(
            &request("https://127.0.0.1:9443/v1/chat/completions"),
            Some("/devtools/tests/gears/TEST_ONLY_CA.pem"),
        );
        assert!(
            argv.windows(2)
                .any(|w| w == ["--cacert", "/devtools/tests/gears/TEST_ONLY_CA.pem"]),
            "{argv:?}"
        );
        assert_eq!(
            argv.last().unwrap(),
            "https://127.0.0.1:9443/v1/chat/completions"
        );
    }

    #[test]
    fn a_post_streams_its_body_from_stdin() {
        let url = super::super::Url::parse("https://openrouter.ai/api").unwrap();
        let argv = build_argv(&HttpRequest::post(url, b"{}".to_vec()), None);
        assert!(
            argv.windows(2).any(|w| w == ["--data-binary", "@-"]),
            "{argv:?}"
        );
    }

    #[test]
    fn a_secret_header_never_reaches_the_command_line() {
        let argv = build_argv(
            &request("https://openrouter.ai/api")
                .header("Content-Type", "application/json")
                .secret_header("Authorization", "Bearer ", "OPENROUTER_API_KEY"),
            None,
        );
        assert!(
            argv.windows(2)
                .any(|w| w == ["--header", "Content-Type: application/json"]),
            "{argv:?}"
        );
        assert!(
            argv.windows(2)
                .any(|w| w == ["--variable", "%OPENROUTER_API_KEY"]),
            "{argv:?}"
        );
        assert!(
            argv.windows(2).any(|w| w
                == [
                    "--expand-header",
                    "Authorization: Bearer {{OPENROUTER_API_KEY}}"
                ]),
            "{argv:?}"
        );
    }

    #[test]
    fn exit_codes_map_to_causes() {
        assert!(matches!(
            map_exit_code(6, "could not resolve"),
            NetError::Dns(_)
        ));
        assert!(matches!(map_exit_code(7, ""), NetError::Connect(_)));
        assert!(matches!(map_exit_code(60, ""), NetError::Connect(_)));
        assert!(matches!(map_exit_code(28, ""), NetError::Timeout(_)));
        assert!(matches!(map_exit_code(18, ""), NetError::Disconnected(_)));
        assert!(matches!(map_exit_code(52, ""), NetError::Disconnected(_)));
        assert!(matches!(map_exit_code(55, ""), NetError::Disconnected(_)));
        assert!(matches!(map_exit_code(56, ""), NetError::Disconnected(_)));
        assert!(matches!(map_exit_code(3, ""), NetError::BadUrl(_)));
        assert!(matches!(map_exit_code(2, ""), NetError::Transport(_)));
        // curl's own words are kept when it said anything.
        assert_eq!(
            map_exit_code(7, "curl: (7) Failed to connect").to_string(),
            "connection failed: curl: (7) Failed to connect"
        );
        assert_eq!(
            map_exit_code(28, "").to_string(),
            "timed out: curl exited 28"
        );
    }

    #[test]
    fn refuses_an_unbounded_head() {
        let mut parser = HeadParser::new();
        let mut result = parser.feed(b"HTTP/1.1 200 OK\r\n");
        let filler = vec![b'x'; 8 * 1024];
        while result == Ok(None) {
            result = parser.feed(&filler);
            if parser.buf.len() > 2 * MAX_HEAD_BYTES {
                break; // The cap should have fired long before here.
            }
        }
        assert!(
            matches!(result, Err(NetError::BadResponse(_))),
            "{result:?}"
        );
    }
}
