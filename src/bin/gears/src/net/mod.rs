//! The HTTP seam. Everything gears sends or receives over the network goes
//! through one `HttpClient`, which has two backends: the host `curl` binary
//! (Linux development) and Motor OS's in-tree curl crate (step 10 of the
//! plan). The seam is *push*-shaped — head first, then body chunks into a
//! sink — because the Motor crate is architecturally push; a pull-shaped
//! trait would force inverting its control flow at port time.
//!
//! Egress is enforced here and nowhere else: every request passes
//! [`EgressPolicy`] before a byte leaves the process.

#[cfg(unix)]
pub mod host_curl;
pub mod motor_curl;
pub mod sse;

// ---- errors ----------------------------------------------------------------

/// Why a request failed. The variants are what the agent layer reacts to, so
/// they name causes rather than repeating the transport's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The URL is malformed or uses an unsupported scheme.
    BadUrl(String),
    /// Egress policy refused: not on the allowlist, or plain HTTP.
    Forbidden(String),
    /// The request itself is malformed (header injection, bad secret ref).
    BadRequest(String),
    /// The host name did not resolve.
    Dns(String),
    /// The connection or TLS handshake failed.
    Connect(String),
    /// Connect, total or stall timeout.
    Timeout(String),
    /// The transfer ended before the body did.
    Disconnected(String),
    /// The response head was not valid HTTP.
    BadResponse(String),
    /// The sink asked to stop: a cancelled turn, not a failure.
    Aborted(String),
    /// The transport could not be run at all.
    Transport(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (what, detail) = match self {
            NetError::BadUrl(d) => ("bad url", d),
            NetError::Forbidden(d) => ("blocked by egress policy", d),
            NetError::BadRequest(d) => ("bad request", d),
            NetError::Dns(d) => ("dns lookup failed", d),
            NetError::Connect(d) => ("connection failed", d),
            NetError::Timeout(d) => ("timed out", d),
            NetError::Disconnected(d) => ("connection lost", d),
            NetError::BadResponse(d) => ("bad response", d),
            NetError::Aborted(d) => ("aborted", d),
            NetError::Transport(d) => ("transport error", d),
        };
        write!(f, "{what}: {detail}")
    }
}

impl std::error::Error for NetError {}

// ---- URLs ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

/// A validated absolute HTTP(S) URL. Parsing is deliberately strict: gears
/// hands these to a subprocess and to an egress check, and anything exotic
/// (userinfo, fragments, control characters) is refused rather than
/// interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    scheme: Scheme,
    host: String, // lowercase; IPv6 without brackets
    port: Option<u16>,
    path: String, // includes the query; always starts with '/'
    text: String, // as given, which is what a backend sends
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, NetError> {
        let bad = |why: &str| NetError::BadUrl(format!("{text}: {why}"));
        if text.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(bad("contains whitespace or control characters"));
        }
        if text.contains('#') {
            return Err(bad("fragments are not supported"));
        }
        let (scheme_text, rest) = text.split_once("://").ok_or_else(|| bad("no scheme"))?;
        let scheme = match scheme_text.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(bad("scheme must be http or https")),
        };
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(split);
        // `https://allowed.host@evil.example/` has host `evil.example`. Rather
        // than get that subtle check right, refuse userinfo outright.
        if authority.contains('@') {
            return Err(bad("userinfo is not supported"));
        }
        let (host, port) = split_host_port(authority).ok_or_else(|| bad("bad host or port"))?;
        Ok(Url {
            scheme,
            host,
            port,
            path: if path.is_empty() {
                "/".to_string()
            } else {
                path.to_string()
            },
            text: text.to_string(),
        })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// Split an authority into a lowercase host and an optional port, validating
/// both. `None` means the authority is malformed.
fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    let (host, port_text) = match authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:8080`.
        Some(rest) => {
            let (inside, after) = rest.split_once(']')?;
            if !inside
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
            {
                return None;
            }
            (inside.to_string(), after.strip_prefix(':'))
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host.to_ascii_lowercase(), Some(port)),
            None => (authority.to_ascii_lowercase(), None),
        },
    };
    if host.is_empty() {
        return None;
    }
    if !authority.starts_with('[')
        && !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    let port = match port_text {
        None => None,
        Some(text) => Some(text.parse::<u16>().ok().filter(|p| *p != 0)?),
    };
    Some((host, port))
}

// ---- egress policy ---------------------------------------------------------

/// The hosts gears may talk to. Matching is exact — `openrouter.ai` does not
/// cover its subdomains — so widening reach is always a visible config edit.
///
/// A clone shares the runtime grants (see [`EgressPolicy::grant`]) with the
/// policy it came from, because a client and the tool holding it must agree
/// about what the user has said yes to.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allowlist: Vec<String>,
    allow_loopback_http: bool,
    granted: std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
}

impl EgressPolicy {
    pub fn new(allowlist: &[String]) -> EgressPolicy {
        EgressPolicy {
            allowlist: allowlist.iter().map(|h| h.to_ascii_lowercase()).collect(),
            allow_loopback_http: false,
            granted: Default::default(),
        }
    }

    /// Whether the *config* allows this host — the question `fetch` asks to
    /// decide whether the user has to be put to the trouble at all. Runtime
    /// grants deliberately do not count: one "yes" is not a policy change.
    pub fn allowlisted(&self, host: &str) -> bool {
        self.allowlist.contains(&host.to_ascii_lowercase())
    }

    /// Let this host through for the rest of the run. Only `fetch` calls it,
    /// and only once the permission gate has said yes: egress stays enforced
    /// in [`EgressPolicy::check`] and nowhere else, so what the user agreed to
    /// has to be recorded here rather than worked around at the call site.
    pub fn grant(&self, host: &str) {
        self.granted
            .lock()
            .unwrap()
            .insert(host.to_ascii_lowercase());
    }

    /// Also accept plain HTTP to a loopback address, which the in-process
    /// mock server speaks. **Tests only**: production egress is HTTPS, and on
    /// Motor OS the curl crate refuses plain HTTP outright, so nothing built
    /// on this can quietly become the shipping path.
    pub fn allow_loopback_http_for_tests(mut self) -> EgressPolicy {
        self.allow_loopback_http = true;
        self
    }

    /// The one gate: a URL passes only if the scheme is permitted *and* the
    /// host is on the allowlist.
    pub fn check(&self, url: &Url) -> Result<(), NetError> {
        if url.scheme() == Scheme::Http && !(self.allow_loopback_http && is_loopback(url.host())) {
            return Err(NetError::Forbidden(format!(
                "{url}: plain HTTP is not allowed"
            )));
        }
        if !self.allowlisted(url.host()) && !self.granted.lock().unwrap().contains(url.host()) {
            return Err(NetError::Forbidden(format!(
                "{} is not on the egress allowlist",
                url.host()
            )));
        }
        Ok(())
    }
}

fn is_loopback(host: &str) -> bool {
    // Literal addresses only: `localhost` is a name, and a name resolves to
    // whatever the resolver says.
    host == "127.0.0.1" || host == "::1"
}

// ---- requests --------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderValue {
    Literal(String),
    /// `prefix` followed by the value of environment variable `env`. A
    /// backend must expand this itself, so the secret never reaches an
    /// argument vector, a file, or this process's own memory beyond the
    /// environment it was given.
    Secret {
        prefix: String,
        env: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub connect: std::time::Duration,
    /// Cap on the whole transfer, streamed responses included.
    pub total: std::time::Duration,
    /// Give up if the transfer makes no progress for this long. Long model
    /// thinks stay under it because providers send comment keep-alives.
    pub stall: std::time::Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: std::time::Duration::from_secs(30),
            total: std::time::Duration::from_secs(900),
            stall: std::time::Duration::from_secs(90),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: Vec<(String, HeaderValue)>,
    pub body: Vec<u8>,
    pub timeouts: Timeouts,
}

impl HttpRequest {
    pub fn get(url: Url) -> HttpRequest {
        HttpRequest {
            method: Method::Get,
            url,
            headers: Vec::new(),
            body: Vec::new(),
            timeouts: Timeouts::default(),
        }
    }

    pub fn post(url: Url, body: Vec<u8>) -> HttpRequest {
        HttpRequest {
            method: Method::Post,
            body,
            ..HttpRequest::get(url)
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> HttpRequest {
        self.headers
            .push((name.to_string(), HeaderValue::Literal(value.to_string())));
        self
    }

    /// Add a header whose value ends in a secret read from the environment;
    /// see [`HeaderValue::Secret`].
    pub fn secret_header(mut self, name: &str, prefix: &str, env: &str) -> HttpRequest {
        self.headers.push((
            name.to_string(),
            HeaderValue::Secret {
                prefix: prefix.to_string(),
                env: env.to_string(),
            },
        ));
        self
    }
}

/// Validate a request before any backend acts on it. Header injection — a
/// CR or LF smuggled into a name or value — is the attack this closes, and
/// it is checked once here rather than in each backend.
pub fn check_request(req: &HttpRequest) -> Result<(), NetError> {
    let bad = |why: String| Err(NetError::BadRequest(why));
    for (name, value) in &req.headers {
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return bad(format!("bad header name {name:?}"));
        }
        match value {
            HeaderValue::Literal(text) => {
                if !text.bytes().all(is_field_byte) {
                    return bad(format!("bad value for header {name}"));
                }
            }
            HeaderValue::Secret { prefix, env } => {
                // `{{` would be re-expanded by curl's --expand-header.
                if !prefix.bytes().all(is_field_byte) || prefix.contains("{{") {
                    return bad(format!("bad secret prefix for header {name}"));
                }
                if env.is_empty()
                    || !env
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                {
                    return bad(format!("bad environment variable name {env:?}"));
                }
            }
        }
    }
    if req.method == Method::Get && !req.body.is_empty() {
        return bad("a GET request cannot carry a body".to_string());
    }
    Ok(())
}

/// RFC 9110 token characters, which is what a header name may contain.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Printable ASCII plus tab: a header value with no way to end the line.
fn is_field_byte(b: u8) -> bool {
    b == b'\t' || (0x20..0x7f).contains(&b)
}

// ---- responses -------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// The first value for `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(have, _)| have.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

// ---- the seam --------------------------------------------------------------

/// Where a response goes as it arrives. Returning `Err` from either method
/// cancels the transfer, which is how a `^C` stops a streaming turn.
pub trait HttpSink {
    fn on_head(&mut self, head: &ResponseHead) -> std::io::Result<()>;
    fn on_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

pub trait HttpClient {
    /// Deliver the head and then the body to `sink`, returning once the body
    /// is complete. A non-2xx response is *not* an error: its body carries
    /// the provider's error detail, and the caller interprets the status.
    fn execute(&self, req: &HttpRequest, sink: &mut dyn HttpSink)
    -> Result<ResponseHead, NetError>;
}

/// A sink that keeps the whole response in memory, for callers that have no
/// use for streaming (`fetch`, tests).
#[derive(Debug, Default)]
pub struct CollectSink {
    pub head: Option<ResponseHead>,
    pub body: Vec<u8>,
}

impl HttpSink for CollectSink {
    fn on_head(&mut self, head: &ResponseHead) -> std::io::Result<()> {
        self.head = Some(head.clone());
        Ok(())
    }

    fn on_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.body.extend_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn parses_the_shapes_gears_uses() {
        let u = url("https://openrouter.ai/api/v1/chat/completions");
        assert_eq!(u.scheme(), Scheme::Https);
        assert_eq!(u.host(), "openrouter.ai");
        assert_eq!(u.port(), None);
        assert_eq!(u.path(), "/api/v1/chat/completions");
        assert_eq!(u.as_str(), "https://openrouter.ai/api/v1/chat/completions");

        let u = url("http://127.0.0.1:8099/v1?a=b&c=d");
        assert_eq!(u.scheme(), Scheme::Http);
        assert_eq!(u.host(), "127.0.0.1");
        assert_eq!(u.port(), Some(8099));
        assert_eq!(u.path(), "/v1?a=b&c=d");

        assert_eq!(url("https://example.com").path(), "/");
        assert_eq!(url("https://example.com?q=1").path(), "?q=1");
        assert_eq!(url("HTTPS://Example.COM/").host(), "example.com");
        assert_eq!(url("https://[::1]:443/x").host(), "::1");
    }

    #[test]
    fn refuses_everything_exotic() {
        for bad in [
            "openrouter.ai/v1",                // no scheme
            "ftp://example.com/",              // wrong scheme
            "https://user:pw@example.com/",    // userinfo
            "https://allowed.host@evil.test/", // userinfo, the dangerous form
            "https://example.com/x#frag",      // fragment
            "https://exa mple.com/",           // space
            "https://example.com/\n",          // control character
            "https://:443/",                   // no host
            "https://example.com:0/",          // port 0
            "https://example.com:99999/",      // port out of range
            "https://example.com:https/",      // non-numeric port
            "https://ex_ample.com/",           // invalid host character
            "https://[::zz]/",                 // invalid IPv6 literal
        ] {
            assert!(Url::parse(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn policy_requires_https_and_the_allowlist() {
        let policy = EgressPolicy::new(&["openrouter.ai".to_string()]);
        assert!(policy.check(&url("https://openrouter.ai/api")).is_ok());

        // Not on the list.
        assert!(matches!(
            policy.check(&url("https://evil.test/api")),
            Err(NetError::Forbidden(_))
        ));
        // Subdomains are not implied by the parent.
        assert!(policy.check(&url("https://api.openrouter.ai/x")).is_err());
        // Plain HTTP, including to loopback, without the test carve-out.
        assert!(policy.check(&url("http://openrouter.ai/api")).is_err());
        assert!(policy.check(&url("http://127.0.0.1:8099/x")).is_err());
    }

    /// What the permission gate said yes to, and what it did not.
    #[test]
    fn a_granted_host_passes_without_becoming_policy() {
        let policy = EgressPolicy::new(&["openrouter.ai".to_string()]);
        assert!(policy.check(&url("https://docs.rs/serde")).is_err());
        policy.grant("docs.rs");
        assert!(policy.check(&url("https://docs.rs/serde")).is_ok());
        // The config is still the config: `fetch` asks about this host again.
        assert!(!policy.allowlisted("docs.rs"));
        assert!(policy.allowlisted("OpenRouter.AI"));
        // A grant is one host, and it does not relax the scheme.
        assert!(policy.check(&url("https://evil.test/x")).is_err());
        assert!(policy.check(&url("http://docs.rs/serde")).is_err());
        // The client built from a policy and the tool holding it agree.
        assert!(policy.clone().check(&url("https://docs.rs/serde")).is_ok());
    }

    #[test]
    fn the_loopback_carve_out_relaxes_only_the_scheme() {
        let policy = EgressPolicy::new(&["127.0.0.1".to_string()]).allow_loopback_http_for_tests();
        assert!(policy.check(&url("http://127.0.0.1:8099/x")).is_ok());
        // Still allowlisted-only: another host over plain HTTP stays refused,
        // and so does a loopback address that was not configured.
        assert!(policy.check(&url("http://192.168.1.5/x")).is_err());
        assert!(policy.check(&url("http://[::1]:8099/x")).is_err());
    }

    #[test]
    fn errors_say_what_happened() {
        let text = NetError::Timeout("no data for 90s".to_string()).to_string();
        assert_eq!(text, "timed out: no data for 90s");
    }

    #[test]
    fn requests_carry_headers_and_bodies() {
        let req = HttpRequest::post(url("https://openrouter.ai/api"), b"{}".to_vec())
            .header("Content-Type", "application/json")
            .secret_header("Authorization", "Bearer ", "OPENROUTER_API_KEY");
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.body, b"{}");
        assert_eq!(
            req.headers[0],
            (
                "Content-Type".to_string(),
                HeaderValue::Literal("application/json".to_string())
            )
        );
        assert_eq!(
            req.headers[1].1,
            HeaderValue::Secret {
                prefix: "Bearer ".to_string(),
                env: "OPENROUTER_API_KEY".to_string(),
            }
        );
        check_request(&req).unwrap();
    }

    #[test]
    fn header_injection_is_refused() {
        let base = || HttpRequest::get(url("https://openrouter.ai/api"));
        for req in [
            base().header("X-Evil", "ok\r\nX-Injected: yes"),
            base().header("X-Evil", "ok\nX-Injected: yes"),
            base().header("X-Ev il", "ok"),
            base().header("", "ok"),
            base().secret_header("Authorization", "Bearer \r\nX: y", "KEY"),
            // `{{` in the prefix would be expanded a second time by curl.
            base().secret_header("Authorization", "{{OTHER}} ", "KEY"),
            base().secret_header("Authorization", "Bearer ", "bad name"),
            base().secret_header("Authorization", "Bearer ", ""),
        ] {
            assert!(
                matches!(check_request(&req), Err(NetError::BadRequest(_))),
                "accepted {:?}",
                req.headers
            );
        }
    }

    #[test]
    fn a_get_may_not_carry_a_body() {
        let mut req = HttpRequest::get(url("https://openrouter.ai/api"));
        req.body = b"x".to_vec();
        assert!(check_request(&req).is_err());
    }

    #[test]
    fn response_head_lookup_ignores_case() {
        let head = ResponseHead {
            status: 200,
            reason: "OK".to_string(),
            headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
        };
        assert_eq!(head.header("content-type"), Some("text/event-stream"));
        assert_eq!(head.header("CONTENT-TYPE"), Some("text/event-stream"));
        assert_eq!(head.header("content-length"), None);
        assert!(head.is_success());
        assert!(
            !ResponseHead {
                status: 429,
                ..Default::default()
            }
            .is_success()
        );
    }

    #[test]
    fn collect_sink_keeps_head_and_body() {
        let head = ResponseHead {
            status: 200,
            reason: "OK".to_string(),
            headers: Vec::new(),
        };
        let mut sink = CollectSink::default();
        sink.on_head(&head).unwrap();
        sink.on_chunk(b"hel").unwrap();
        sink.on_chunk(b"lo").unwrap();
        assert_eq!(sink.head, Some(head));
        assert_eq!(sink.body, b"hello");
    }
}
