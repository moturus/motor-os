//! The client for the OpenAI-compatible chat-completions dialect: one
//! streamed POST per completion, over any [`HttpClient`].
//!
//! Endpoints differ in small ways, and those differences live in [`Quirks`]
//! rather than in the request-building code — how usage is asked for, and
//! whether the answer is priced. Everything else is the same wire format at
//! OpenRouter, a Hugging Face router, vLLM or Ollama.

use crate::net::sse::{SseEvent, SseSink};
use crate::net::{HttpClient, HttpRequest, NetError, ResponseHead, Timeouts, Url};
use crate::trace::{self, Level};

use super::assembler::DeltaAssembler;
use super::types::{ApiError, ChatRequest, Completion, StreamChunk};
use super::{EventSink, KEY_ENV, ModelProvider, ProviderError};

/// The blessed default: the one endpoint validated against a real key.
pub const OPENROUTER_BASE_URL: &str = "https://openrouter.ai/api/v1";

/// How an endpoint wants usage reporting turned on for a streamed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageStyle {
    /// OpenRouter: `"usage": {"include": true}`.
    Include,
    /// The generic dialect: `"stream_options": {"include_usage": true}`.
    StreamOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quirks {
    pub usage: UsageStyle,
    /// Whether usage comes priced. Without it a spend budget can only be
    /// counted in tokens.
    pub reports_cost: bool,
}

impl Quirks {
    /// The table, keyed by host — which is exactly what a base URL names.
    /// Anything unlisted gets the generic dialect's answers, which is also
    /// what makes an unknown endpoint merely untested rather than unusable.
    pub fn for_host(host: &str) -> Quirks {
        match host {
            "openrouter.ai" => Quirks {
                usage: UsageStyle::Include,
                reports_cost: true,
            },
            _ => Quirks {
                usage: UsageStyle::StreamOptions,
                reports_cost: false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    url: Url,
    quirks: Quirks,
}

impl Endpoint {
    /// `base_url` is the API root — `https://openrouter.ai/api/v1` — and the
    /// completions path is appended to it.
    pub fn new(base_url: &str) -> Result<Endpoint, NetError> {
        let base = base_url.trim_end_matches('/');
        let url = Url::parse(&format!("{base}/chat/completions"))?;
        let quirks = Quirks::for_host(url.host());
        Ok(Endpoint { url, quirks })
    }

    pub fn openrouter() -> Endpoint {
        Endpoint::new(OPENROUTER_BASE_URL).expect("the default base url parses")
    }

    /// Override the table, for an endpoint it guesses wrong about.
    pub fn with_quirks(mut self, quirks: Quirks) -> Endpoint {
        self.quirks = quirks;
        self
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn quirks(&self) -> Quirks {
        self.quirks
    }
}

pub struct OpenAiCompat<C> {
    http: C,
    endpoint: Endpoint,
    /// The environment variable holding the key, or `None` for an endpoint
    /// that wants no `Authorization` at all (a local inference server).
    key_env: Option<String>,
    extra_headers: Vec<(String, String)>,
    timeouts: Timeouts,
}

impl<C: HttpClient> OpenAiCompat<C> {
    pub fn new(http: C, endpoint: Endpoint) -> OpenAiCompat<C> {
        OpenAiCompat {
            http,
            endpoint,
            key_env: Some(KEY_ENV.to_string()),
            extra_headers: Vec::new(),
            timeouts: Timeouts::default(),
        }
    }

    pub fn with_key_env(mut self, env: &str) -> OpenAiCompat<C> {
        self.key_env = Some(env.to_string());
        self
    }

    /// Send no `Authorization` header.
    pub fn without_key(mut self) -> OpenAiCompat<C> {
        self.key_env = None;
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> OpenAiCompat<C> {
        self.extra_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    pub fn with_timeouts(mut self, timeouts: Timeouts) -> OpenAiCompat<C> {
        self.timeouts = timeouts;
        self
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    fn request(&self, body: Vec<u8>) -> HttpRequest {
        let mut request = HttpRequest::post(self.endpoint.url.clone(), body)
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream");
        for (name, value) in &self.extra_headers {
            request = request.header(name, value);
        }
        if let Some(env) = &self.key_env {
            // The value never passes through here: the transport expands it
            // from its child's environment.
            request = request.secret_header("Authorization", "Bearer ", env);
        }
        request.timeouts = self.timeouts;
        request
    }
}

impl<C: HttpClient> ModelProvider for OpenAiCompat<C> {
    fn complete(
        &self,
        req: &ChatRequest,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        let body = build_body(req, self.endpoint.quirks)?;
        trace::log(
            Level::Debug,
            &format!(
                "-> POST {} {}",
                self.endpoint.url,
                clipped(&String::from_utf8_lossy(&body), MAX_TRACE_CHARS)
            ),
        );

        let mut assembler = DeltaAssembler::new();
        // Our own error, kept aside: the transport only learns that the sink
        // refused, and the refusal's cause is the useful half.
        let mut failure: Option<ProviderError> = None;

        let (outcome, head, raw, sse_error) = {
            let mut sse = SseSink::new(|event: SseEvent| {
                if event.is_done() {
                    assembler.mark_done();
                    return Ok(());
                }
                match feed(&mut assembler, &event.data, sink) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let message = e.to_string();
                        failure = Some(e);
                        Err(std::io::Error::other(message))
                    }
                }
            });
            let mut outcome = self.http.execute(&self.request(body), &mut sse);
            if outcome.is_ok()
                && let Err(e) = sse.finish()
            {
                outcome = Err(NetError::Aborted(e.to_string()));
            }
            (
                outcome,
                sse.head().cloned(),
                sse.raw().to_vec(),
                sse.take_error(),
            )
        };

        if let Some(failure) = failure {
            return Err(failure);
        }
        if let Some(e) = sse_error {
            return Err(ProviderError::Protocol(e.to_string()));
        }
        let head = match outcome {
            Ok(head) => head,
            // A transfer that failed after delivering a failing head: the
            // status says more about it than the disconnect does.
            Err(e) => match head.filter(|head| !head.is_success()) {
                Some(head) => return Err(status_error(&head, &raw)),
                None => return Err(e.into()),
            },
        };
        trace::log(Level::Debug, &format!("<- {} {}", head.status, head.reason));
        if !head.is_success() {
            return Err(status_error(&head, &raw));
        }
        // A 200 that was not an event stream: the endpoint ignored `stream`,
        // and the body it sent instead is not a shape gears reads.
        if !raw.is_empty() {
            return Err(ProviderError::Protocol(format!(
                "expected an event stream, got {} ({} bytes)",
                head.header("content-type").unwrap_or("no content type"),
                raw.len()
            )));
        }

        let completion = assembler.finish()?;
        trace::log(
            Level::Debug,
            &format!(
                "<- {} chars, {} tool calls, {} tokens",
                completion.content.chars().count(),
                completion.tool_calls.len(),
                completion.usage.total()
            ),
        );
        Ok(completion)
    }
}

/// Serialize the request and add what the endpoint needs on top: streaming,
/// always, and its usage knob unless the caller set one itself.
fn build_body(req: &ChatRequest, quirks: Quirks) -> Result<Vec<u8>, ProviderError> {
    let mut value = serde_json::to_value(req)
        .map_err(|e| ProviderError::Protocol(format!("cannot serialize the request: {e}")))?;
    let object = value
        .as_object_mut()
        .expect("a chat request serializes to an object");
    object.insert("stream".to_string(), serde_json::Value::Bool(true));
    let (name, knob) = match quirks.usage {
        UsageStyle::Include => ("usage", serde_json::json!({"include": true})),
        UsageStyle::StreamOptions => ("stream_options", serde_json::json!({"include_usage": true})),
    };
    object.entry(name).or_insert(knob);
    serde_json::to_vec(&value)
        .map_err(|e| ProviderError::Protocol(format!("cannot serialize the request: {e}")))
}

/// Decode one `data:` payload into the assembler. A payload that is not a
/// chunk is an error rather than a skip: dropping it would lose content.
fn feed(
    assembler: &mut DeltaAssembler,
    data: &str,
    sink: &mut dyn EventSink,
) -> Result<(), ProviderError> {
    let chunk: StreamChunk = serde_json::from_str(data).map_err(|e| {
        ProviderError::Protocol(format!("bad completion chunk: {e}: {}", clipped(data, 200)))
    })?;
    assembler.push(chunk, sink)
}

fn status_error(head: &ResponseHead, body: &[u8]) -> ProviderError {
    let detail = match ApiError::from_body(body) {
        Some(error) => error.detail(),
        None if body.is_empty() => match head.reason.is_empty() {
            true => "the endpoint sent no explanation".to_string(),
            false => head.reason.clone(),
        },
        None => clipped(&String::from_utf8_lossy(body), 400),
    };
    let retry_after = head
        .header("retry-after")
        .and_then(|value| value.trim().parse().ok());
    ProviderError::from_status(head.status, retry_after, detail)
}

const MAX_TRACE_CHARS: usize = 4096;

/// Trim text for the trace, saying how much was left out.
fn clipped(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        None => text.to_string(),
        Some((at, _)) => format!("{}… [{} more bytes]", &text[..at], text.len() - at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::provider_conformance_corpus;
    use crate::net::HttpSink;
    use crate::provider::{ChatMessage, ToolSpec};
    use serde_json::{Value, json};

    struct MemoryResponse {
        chunks: Vec<Vec<u8>>,
    }

    impl HttpClient for MemoryResponse {
        fn execute(
            &self,
            _req: &HttpRequest,
            sink: &mut dyn HttpSink,
        ) -> Result<ResponseHead, NetError> {
            let head = ResponseHead {
                status: 200,
                reason: "OK".to_string(),
                headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
            };
            sink.on_head(&head)
                .map_err(|error| NetError::Aborted(error.to_string()))?;
            for chunk in &self.chunks {
                sink.on_chunk(chunk)
                    .map_err(|error| NetError::Aborted(error.to_string()))?;
            }
            Ok(head)
        }
    }

    fn body(req: &ChatRequest, quirks: Quirks) -> Value {
        serde_json::from_slice(&build_body(req, quirks).unwrap()).unwrap()
    }

    fn request() -> ChatRequest {
        ChatRequest::new("m", vec![ChatMessage::user("hi")])
    }

    #[test]
    fn the_provider_corpus_passes_through_the_adapter_in_memory() {
        for case in provider_conformance_corpus() {
            let provider = OpenAiCompat::new(
                MemoryResponse {
                    chunks: case.response_chunks(),
                },
                Endpoint::new("https://provider.test/v1").unwrap(),
            );
            let completion = provider
                .complete(&request(), &mut crate::provider::Discard)
                .unwrap_or_else(|error| panic!("case {:?}: {error}", case.name));
            assert_eq!(completion, case.expected, "case {:?}", case.name);
        }
    }

    #[test]
    fn the_completions_url_is_built_from_the_base() {
        assert_eq!(
            Endpoint::openrouter().url().as_str(),
            "https://openrouter.ai/api/v1/chat/completions"
        );
        // A trailing slash in the config must not double up.
        assert_eq!(
            Endpoint::new("https://openrouter.ai/api/v1/")
                .unwrap()
                .url(),
            Endpoint::openrouter().url()
        );
        assert_eq!(
            Endpoint::new("http://127.0.0.1:9/v1").unwrap().url().path(),
            "/v1/chat/completions"
        );
        assert!(Endpoint::new("openrouter.ai/api/v1").is_err());
    }

    #[test]
    fn quirks_follow_the_host() {
        let openrouter = Endpoint::openrouter().quirks();
        assert_eq!(openrouter.usage, UsageStyle::Include);
        assert!(openrouter.reports_cost);

        // Anything else gets the generic dialect: usable, just untested.
        let other = Endpoint::new("https://router.huggingface.co/v1")
            .unwrap()
            .quirks();
        assert_eq!(other.usage, UsageStyle::StreamOptions);
        assert!(!other.reports_cost);
    }

    #[test]
    fn requests_always_stream_and_ask_for_usage() {
        let openrouter = body(&request(), Quirks::for_host("openrouter.ai"));
        assert_eq!(openrouter["stream"], json!(true));
        assert_eq!(openrouter["usage"], json!({"include": true}));
        assert!(openrouter.get("stream_options").is_none());
        assert_eq!(openrouter["messages"][0]["content"], json!("hi"));

        let generic = body(&request(), Quirks::for_host("elsewhere.test"));
        assert_eq!(generic["stream"], json!(true));
        assert_eq!(generic["stream_options"], json!({"include_usage": true}));
        assert!(generic.get("usage").is_none());
    }

    #[test]
    fn the_callers_own_passthrough_wins() {
        let mut req = request();
        req.extra
            .insert("usage".to_string(), json!({"include": false}));
        // The quirk table supplies a default, not an override: `extra` is a
        // passthrough, and clobbering it would make it useless.
        let sent = body(&req, Quirks::for_host("openrouter.ai"));
        assert_eq!(sent["usage"], json!({"include": false}));
        // `stream` is not negotiable: the client only knows how to stream.
        req.extra.insert("stream".to_string(), json!(false));
        assert_eq!(
            body(&req, Quirks::for_host("openrouter.ai"))["stream"],
            json!(true)
        );
    }

    #[test]
    fn tool_schemas_reach_the_wire() {
        let req = request().with_tools(vec![ToolSpec::new(
            "read_file",
            "Read a file.",
            json!({"type": "object"}),
        )]);
        let sent = body(&req, Quirks::for_host("openrouter.ai"));
        assert_eq!(sent["tools"][0]["function"]["name"], json!("read_file"));
        assert_eq!(sent["tools"][0]["type"], json!("function"));
    }

    #[test]
    fn error_bodies_become_typed_errors() {
        let head = |status: u16, headers: Vec<(&str, &str)>| ResponseHead {
            status,
            reason: "Nope".to_string(),
            headers: headers
                .into_iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        };

        let error = status_error(
            &head(401, vec![]),
            br#"{"error":{"message":"No auth credentials found"}}"#,
        );
        assert_eq!(
            error,
            ProviderError::Auth("No auth credentials found".to_string())
        );

        let error = status_error(&head(429, vec![("Retry-After", "12")]), b"{}");
        assert!(
            matches!(
                error,
                ProviderError::RateLimited {
                    retry_after: Some(12),
                    ..
                }
            ),
            "{error}"
        );

        // Not every failure comes as JSON; the body is still the evidence.
        let error = status_error(&head(502, vec![]), b"<html>bad gateway</html>");
        assert_eq!(
            error,
            ProviderError::Unavailable("<html>bad gateway</html>".to_string())
        );
        assert_eq!(
            status_error(&head(500, vec![]), b""),
            ProviderError::Unavailable("Nope".to_string())
        );
    }

    #[test]
    fn traced_text_is_clipped_with_a_marker() {
        assert_eq!(clipped("short", 10), "short");
        let long = "x".repeat(50);
        assert_eq!(clipped(&long, 10), "xxxxxxxxxx… [40 more bytes]");
        // Clipping happens on character boundaries, not byte offsets.
        assert_eq!(clipped("héllo", 2), "hé… [3 more bytes]");
    }
}
