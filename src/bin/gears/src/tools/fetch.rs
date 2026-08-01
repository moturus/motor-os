//! `fetch`: one GET, through the same transport as everything else gears
//! sends.
//!
//! The rule is the proposal's: hosts on the config allowlist go through
//! without a word, and anything else is a question for the user. That is why
//! this is the one tool whose gating depends on its arguments — it changes
//! nothing, and still asks.

use serde_json::{Value, json};

use super::{Tool, schema, string_arg};
use crate::net::{CollectSink, HttpClient, HttpRequest, ResponseHead, Timeouts, Url};
use crate::provider::ToolSpec;

/// A page is not a model conversation: it either arrives promptly or it is not
/// worth the turn.
const FETCH_TIMEOUTS: Timeouts = Timeouts {
    connect: std::time::Duration::from_secs(15),
    total: std::time::Duration::from_secs(60),
    stall: std::time::Duration::from_secs(30),
};

pub struct FetchTool {
    client: Box<dyn HttpClient + Send + Sync>,
    /// The same policy the client enforces, so that a granted host reaches it.
    policy: crate::net::EgressPolicy,
}

pub fn tool(
    client: Box<dyn HttpClient + Send + Sync>,
    policy: crate::net::EgressPolicy,
) -> Box<dyn Tool> {
    Box::new(FetchTool { client, policy })
}

/// The host a call names, or `None` if it names nothing usable.
fn host_of(args: &Value) -> Option<String> {
    let Value::String(text) = &args["url"] else {
        return None;
    };
    Url::parse(text).ok().map(|url| url.host().to_string())
}

impl Tool for FetchTool {
    fn name(&self) -> &'static str {
        "fetch"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "fetch",
            "Fetch a URL and return what it sent. Text comes back as text; \
             anything else is reported by size. Hosts the configuration does \
             not already allow have to be approved.",
            schema(
                json!({"url": {"type": "string", "description": "An http:// or https:// URL."}}),
                &["url"],
            ),
        )
    }

    /// Nothing here changes the workspace — a read-only sub-agent may fetch.
    fn mutates(&self) -> bool {
        false
    }

    fn gated(&self, args: &Value) -> bool {
        match host_of(args) {
            Some(host) => !self.policy.allowlisted(&host),
            // A URL that will not parse is refused by `call` anyway; asking
            // about it would be putting an unanswerable question.
            None => false,
        }
    }

    fn permission_key(&self, args: &Value) -> String {
        match host_of(args) {
            Some(host) => format!("fetch:{host}"),
            None => "fetch".to_string(),
        }
    }

    /// The user has said yes to this host, so the transport must let it past.
    fn approved(&self, args: &Value) {
        if let Some(host) = host_of(args) {
            self.policy.grant(&host);
        }
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let url = Url::parse(&string_arg(args, "url")?).map_err(|e| e.to_string())?;
        let mut request = HttpRequest::get(url);
        request.timeouts = FETCH_TIMEOUTS;
        let mut body = CollectSink::default();
        let head = self
            .client
            .execute(&request, &mut body)
            .map_err(|e| e.to_string())?;
        Ok(render(&head, &body.body))
    }
}

/// A response as the model reads it. A 404 is not a tool failure: what the
/// server said about it is the useful part.
fn render(head: &ResponseHead, body: &[u8]) -> String {
    let mut text = format!("HTTP {} {}", head.status, head.reason);
    let kind = head.header("content-type").unwrap_or("unknown");
    if body.iter().take(8192).any(|byte| *byte == 0) {
        text.push_str(&format!("\n[{} bytes of {kind}]", body.len()));
        return text;
    }
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(body));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockServer, Script};
    use crate::net::{EgressPolicy, host_curl::HostCurl};

    fn page(body: &str, kind: &str) -> Script {
        Script::new().write(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ))
    }

    /// The tool against a real transport and a scripted server, with the
    /// server's own loopback host as the one the config allows.
    fn fixture(scripts: Vec<Script>) -> (MockServer, Box<dyn Tool>) {
        let server = MockServer::start(scripts).unwrap();
        let policy = EgressPolicy::new(&["127.0.0.1".to_string()]).allow_loopback_http_for_tests();
        let client = HostCurl::new(policy.clone()).unwrap();
        (server, tool(Box::new(client), policy))
    }

    #[test]
    fn an_allowlisted_host_is_fetched_without_asking() {
        let (server, tool) = fixture(vec![page("hello there", "text/plain")]);
        let args = json!({ "url": format!("{}/page", server.base_url()) });
        assert!(!tool.gated(&args));
        assert!(!tool.mutates());
        assert_eq!(
            tool.call(&args).unwrap(),
            "HTTP 200 OK\nhello there".to_string()
        );
    }

    #[test]
    fn a_host_the_config_does_not_name_is_asked_about() {
        let (_server, tool) = fixture(vec![]);
        let args = json!({"url": "https://docs.rs/serde"});
        assert!(tool.gated(&args));
        assert_eq!(tool.permission_key(&args), "fetch:docs.rs");
        // And the workspace-relative shorthands a file tool takes are not URLs.
        for bad in ["docs.rs", "file:///etc/passwd", "https://a b/"] {
            let error = tool.call(&json!({ "url": bad })).unwrap_err();
            assert!(error.contains("bad url"), "{bad}: {error}");
        }
    }

    /// Consent is what lets a host past the transport, and it is the *only*
    /// thing that does: the tool cannot reach one the user has not agreed to
    /// even when it is called directly.
    #[test]
    fn nothing_reaches_a_host_until_it_is_approved() {
        let server = MockServer::start(vec![page("granted", "text/plain")]).unwrap();
        // An empty allowlist: the scheme is fine, the host is nobody's yet.
        let policy = EgressPolicy::new(&[]).allow_loopback_http_for_tests();
        let client = HostCurl::new(policy.clone()).unwrap();
        let tool = tool(Box::new(client), policy);
        let args = json!({ "url": format!("{}/page", server.base_url()) });

        assert!(tool.gated(&args));
        let error = tool.call(&args).unwrap_err();
        assert!(error.contains("egress allowlist"), "{error}");

        tool.approved(&args);
        assert_eq!(tool.call(&args).unwrap(), "HTTP 200 OK\ngranted");
    }

    #[test]
    fn a_response_says_what_it_was() {
        let (server, tool) = fixture(vec![
            Script::new().write("HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nno such x"),
            page("\u{0}\u{1}binary", "image/png"),
        ]);
        // A 404 is an answer, not a tool failure.
        let out = tool
            .call(&json!({ "url": format!("{}/missing", server.base_url()) }))
            .unwrap();
        assert_eq!(out, "HTTP 404 Not Found\nno such x");

        let out = tool
            .call(&json!({ "url": format!("{}/pic", server.base_url()) }))
            .unwrap();
        assert_eq!(out, "HTTP 200 OK\n[8 bytes of image/png]");
    }
}
