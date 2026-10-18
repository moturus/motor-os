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
use sha2::{Digest, Sha256};

use super::assembler::DeltaAssembler;
use super::wire::{ApiError, StreamChunk};
use super::{
    Completion, ContentBlock, EventSink, KEY_ENV, Message, Provider, ProviderError, Request, Role,
    StreamEvent,
};

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
    /// Echo plaintext assistant reasoning in later requests.
    pub reasoning_echo: bool,
    pub prompt_cache_key: bool,
    pub cache_markers: bool,
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
                reasoning_echo: true,
                prompt_cache_key: true,
                cache_markers: true,
            },
            _ => Quirks {
                usage: UsageStyle::StreamOptions,
                reports_cost: false,
                reasoning_echo: false,
                prompt_cache_key: false,
                cache_markers: false,
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

    /// Override the table, for an endpoint it guesses wrong about.
    pub fn with_quirks(mut self, quirks: Quirks) -> Endpoint {
        self.quirks = quirks;
        self
    }

    pub fn with_reasoning_echo(mut self, enabled: Option<bool>) -> Endpoint {
        if let Some(enabled) = enabled {
            self.quirks.reasoning_echo = enabled;
        }
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
    cache_identity: String,
}

impl<C: HttpClient> OpenAiCompat<C> {
    pub fn new(http: C, endpoint: Endpoint) -> OpenAiCompat<C> {
        let cache_identity = endpoint.url.as_str().to_string();
        OpenAiCompat {
            http,
            endpoint,
            key_env: Some(KEY_ENV.to_string()),
            extra_headers: Vec::new(),
            timeouts: Timeouts::default(),
            cache_identity,
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

    pub fn with_cache_identity(mut self, identity: &str) -> OpenAiCompat<C> {
        self.cache_identity = identity.to_string();
        self
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    fn request(
        &self,
        body: Vec<u8>,
        cancellation: Option<crate::cancellation::Cancellation>,
    ) -> HttpRequest {
        let mut request = HttpRequest::post(self.endpoint.url.clone(), body)
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .with_cancellation(cancellation);
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

impl<C: HttpClient> OpenAiCompat<C> {
    fn complete_once(
        &self,
        req: &Request,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        let body = build_body(req, self.endpoint.quirks, &self.cache_identity)?;
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
            let mut outcome = self
                .http
                .execute(&self.request(body, req.cancellation.clone()), &mut sse);
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

impl<C: HttpClient + Send + Sync> Provider for OpenAiCompat<C> {
    fn complete(
        &self,
        req: &Request,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        for attempt in 0..3 {
            if req
                .cancellation
                .as_ref()
                .is_some_and(|token| token.cancelled())
            {
                return Err(ProviderError::Aborted("turn cancelled".into()));
            }
            let mut visible = VisibleSink {
                sink,
                visible: false,
            };
            let result = self.complete_once(req, &mut visible);
            let error = match result {
                Ok(completion) => return Ok(completion),
                Err(error) => error,
            };
            if visible.visible || attempt == 2 {
                return Err(error);
            }
            let Some(wait) = retry_delay(&error, attempt) else {
                return Err(error);
            };
            sink.on_event(StreamEvent::Notice(format!(
                "provider request failed: {error}; retrying in {}s (attempt {}/3)",
                wait.as_secs(),
                attempt + 2
            )))
            .map_err(|failure| ProviderError::Aborted(failure.to_string()))?;
            wait_or_cancel(req, wait)?;
        }
        unreachable!("the bounded retry loop returns on its last attempt")
    }
}

struct VisibleSink<'a> {
    sink: &'a mut dyn EventSink,
    visible: bool,
}

impl EventSink for VisibleSink<'_> {
    fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()> {
        if matches!(event, StreamEvent::Text(_) | StreamEvent::Reasoning(_)) {
            self.visible = true;
        }
        self.sink.on_event(event)
    }
}

fn retry_delay(error: &ProviderError, attempt: usize) -> Option<std::time::Duration> {
    let seconds = match error {
        ProviderError::RateLimited {
            retry_after: Some(seconds),
            ..
        } => *seconds,
        ProviderError::RateLimited { .. }
        | ProviderError::Unavailable(_)
        | ProviderError::Net(
            NetError::Dns(_)
            | NetError::Connect(_)
            | NetError::Timeout(_)
            | NetError::Disconnected(_),
        ) => 1 << attempt,
        _ => return None,
    };
    (seconds <= 30).then(|| std::time::Duration::from_secs(seconds))
}

fn wait_or_cancel(req: &Request, delay: std::time::Duration) -> Result<(), ProviderError> {
    let deadline = std::time::Instant::now() + delay;
    loop {
        if req
            .cancellation
            .as_ref()
            .is_some_and(|token| token.cancelled())
        {
            return Err(ProviderError::Aborted("turn cancelled".into()));
        }
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            return Ok(());
        };
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(50)));
    }
}

/// Serialize the request and add what the endpoint needs on top: streaming,
/// always, and its usage knob unless the caller set one itself.
fn build_body(
    req: &Request,
    quirks: Quirks,
    cache_identity: &str,
) -> Result<Vec<u8>, ProviderError> {
    let mut messages = Vec::new();
    if !req.system.is_empty() {
        let text = req.system.join("\n\n");
        messages.push(serde_json::json!({
            "role": "system",
            "content": if quirks.cache_markers {
                serde_json::json!([marked_text(&text)])
            } else {
                serde_json::json!(text)
            },
        }));
    }
    let cacheable =
        req.messages
            .iter()
            .enumerate()
            .filter(|(_, message)| {
                message.role != Role::Tool
                    && message.content.iter().any(
                        |block| matches!(block, ContentBlock::Text { text } if !text.is_empty()),
                    )
            })
            .map(|(index, _)| index)
            .rev()
            .take(2)
            .collect::<Vec<_>>();
    for (index, message) in req.messages.iter().enumerate() {
        messages.extend(wire_messages(
            message,
            quirks,
            quirks.cache_markers && cacheable.contains(&index),
        )?);
    }
    let tools = req
        .tools
        .iter()
        .map(|tool| {
            serde_json::json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                }
            })
        })
        .collect::<Vec<_>>();
    let mut object = serde_json::Map::new();
    object.insert("model".to_string(), serde_json::json!(req.model));
    object.insert("messages".to_string(), serde_json::Value::Array(messages));
    if quirks.prompt_cache_key {
        // Conversation compaction must not change routing for the stable prefix.
        let start = serde_json::to_vec(&(cache_identity, &req.model, &req.system, &req.tools))
            .map_err(|e| ProviderError::Protocol(format!("cannot hash prompt start: {e}")))?;
        let digest = Sha256::digest(start);
        object.insert(
            "prompt_cache_key".to_string(),
            serde_json::Value::String(format!("gears-{}", hex_prefix(&digest[..16]))),
        );
    }
    if !tools.is_empty() {
        object.insert("tools".to_string(), serde_json::Value::Array(tools));
    }
    if let Some(max_tokens) = req.max_output_tokens {
        object.insert("max_tokens".to_string(), serde_json::json!(max_tokens));
    }
    object.insert("stream".to_string(), serde_json::Value::Bool(true));
    let (name, knob) = match quirks.usage {
        UsageStyle::Include => ("usage", serde_json::json!({"include": true})),
        UsageStyle::StreamOptions => ("stream_options", serde_json::json!({"include_usage": true})),
    };
    object.entry(name.to_string()).or_insert(knob);
    serde_json::to_vec(&object)
        .map_err(|e| ProviderError::Protocol(format!("cannot serialize the request: {e}")))
}

fn marked_text(text: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "text",
        "text": text,
        "cache_control": {"type": "ephemeral"},
    })
}

fn hex_prefix(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn wire_text(text: &str, marked: bool) -> serde_json::Value {
    if marked {
        serde_json::json!([marked_text(text)])
    } else {
        serde_json::Value::String(text.to_string())
    }
}

fn wire_messages(
    message: &Message,
    quirks: Quirks,
    mark_text: bool,
) -> Result<Vec<serde_json::Value>, ProviderError> {
    let text = message
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    match message.role {
        Role::User => Ok(vec![serde_json::json!({
            "role": "user",
            "content": wire_text(&text, mark_text),
        })]),
        Role::Assistant => {
            let calls = message
                .content
                .iter()
                .filter_map(|block| match block {
                    ContentBlock::ToolCall { call } => Some(serde_json::json!({
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": call.arguments,
                        }
                    })),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let mut value = serde_json::json!({
                "role": "assistant",
                "content": if text.is_empty() {
                    serde_json::Value::Null
                } else {
                    wire_text(&text, mark_text)
                },
            });
            if !calls.is_empty() {
                value["tool_calls"] = serde_json::Value::Array(calls);
            }
            if quirks.reasoning_echo
                && let Some(reasoning) = message.reasoning.as_deref()
            {
                value["reasoning"] = serde_json::Value::String(reasoning.to_string());
            }
            Ok(vec![value])
        }
        Role::Tool => {
            let mut values = Vec::new();
            for block in &message.content {
                let ContentBlock::ToolResult {
                    call_id, content, ..
                } = block
                else {
                    continue;
                };
                values.push(serde_json::json!({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": content,
                }));
            }
            if values.is_empty() {
                return Err(ProviderError::Protocol(
                    "a tool message contains no tool result".to_string(),
                ));
            }
            Ok(values)
        }
    }
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
    use crate::provider::{Message, StreamEvent, ToolSpec};
    use serde_json::{Value, json};

    struct CorpusSink {
        abort_after_content: bool,
    }

    impl EventSink for CorpusSink {
        fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()> {
            if self.abort_after_content && matches!(event, StreamEvent::Text(_)) {
                return Err(std::io::Error::other("scripted cancellation"));
            }
            Ok(())
        }
    }

    fn body(req: &Request, quirks: Quirks) -> Value {
        serde_json::from_slice(&build_body(req, quirks, "default").unwrap()).unwrap()
    }

    fn request() -> Request {
        Request::new("m", vec![Message::user("hi")])
    }

    #[test]
    fn the_provider_corpus_passes_through_the_adapter_in_memory() {
        for case in provider_conformance_corpus() {
            let provider = OpenAiCompat::new(
                case.memory_reply(),
                Endpoint::new("https://provider.test/v1").unwrap(),
            )
            .with_timeouts(case.timeouts);
            let actual = provider.complete(
                &request(),
                &mut CorpusSink {
                    abort_after_content: case.abort_after_content,
                },
            );
            assert!(
                case.expected.accepts(&actual),
                "case {:?}: expected {:?}, got {actual:?}",
                case.name,
                case.expected
            );
        }
    }

    #[test]
    fn the_completions_url_is_built_from_the_base() {
        assert_eq!(
            Endpoint::new("https://openrouter.ai/api/v1")
                .unwrap()
                .url()
                .as_str(),
            "https://openrouter.ai/api/v1/chat/completions"
        );
        // A trailing slash in the config must not double up.
        assert_eq!(
            Endpoint::new("https://openrouter.ai/api/v1/")
                .unwrap()
                .url(),
            Endpoint::new("https://openrouter.ai/api/v1").unwrap().url()
        );
        assert_eq!(
            Endpoint::new("http://127.0.0.1:9/v1").unwrap().url().path(),
            "/v1/chat/completions"
        );
        assert!(Endpoint::new("openrouter.ai/api/v1").is_err());
    }

    #[test]
    fn quirks_follow_the_host() {
        let openrouter = Endpoint::new("https://openrouter.ai/api/v1")
            .unwrap()
            .quirks();
        assert_eq!(openrouter.usage, UsageStyle::Include);
        assert!(openrouter.reports_cost);
        assert!(openrouter.reasoning_echo);
        assert!(openrouter.prompt_cache_key);
        assert!(openrouter.cache_markers);

        // Anything else gets the generic dialect: usable, just untested.
        let other = Endpoint::new("https://router.huggingface.co/v1")
            .unwrap()
            .quirks();
        assert_eq!(other.usage, UsageStyle::StreamOptions);
        assert!(!other.reports_cost);
        assert!(!other.reasoning_echo);
        assert!(!other.prompt_cache_key);
        assert!(!other.cache_markers);
        assert!(
            !Endpoint::new("https://openrouter.ai/api/v1")
                .unwrap()
                .with_reasoning_echo(Some(false))
                .quirks()
                .reasoning_echo
        );
        assert!(
            Endpoint::new("https://provider.test/v1")
                .unwrap()
                .with_reasoning_echo(Some(true))
                .quirks()
                .reasoning_echo
        );
    }

    #[test]
    fn requests_always_stream_and_ask_for_usage() {
        let openrouter = body(&request(), Quirks::for_host("openrouter.ai"));
        assert_eq!(openrouter["stream"], json!(true));
        assert_eq!(openrouter["usage"], json!({"include": true}));
        assert!(openrouter.get("stream_options").is_none());
        assert_eq!(openrouter["messages"][0]["content"][0]["text"], json!("hi"));

        let generic = body(&request(), Quirks::for_host("elsewhere.test"));
        assert_eq!(generic["stream"], json!(true));
        assert_eq!(generic["stream_options"], json!({"include_usage": true}));
        assert!(generic.get("usage").is_none());
    }

    #[test]
    fn assistant_reasoning_is_echoed_only_for_enabled_hosts() {
        let completion = Completion {
            content: "answer".into(),
            reasoning: "thought".into(),
            ..Completion::default()
        };
        let message = completion.message();
        assert_eq!(message.reasoning.as_deref(), Some("thought"));
        let restored: Message =
            serde_json::from_slice(&serde_json::to_vec(&message).unwrap()).unwrap();
        let req = Request::new("m", vec![Message::user("question"), restored]);

        let openrouter = body(&req, Quirks::for_host("openrouter.ai"));
        assert_eq!(openrouter["messages"][1]["reasoning"], "thought");
        let generic = body(&req, Quirks::for_host("elsewhere.test"));
        assert!(generic["messages"][1].get("reasoning").is_none());
    }

    #[test]
    fn cache_key_tracks_the_stable_prefix_and_selected_provider() {
        let quirks = Quirks::for_host("openrouter.ai");
        let first = request().with_system(vec!["instructions".into()]);
        let mut continued = first.clone();
        continued.messages.push(Message::assistant("answer"));
        continued.messages.push(Message::user("follow up"));
        let key = body(&first, quirks)["prompt_cache_key"].clone();
        assert_eq!(body(&continued, quirks)["prompt_cache_key"], key);
        continued.messages = vec![Message::user("[Conversation summary]\nCompacted history")];
        assert_eq!(body(&continued, quirks)["prompt_cache_key"], key);
        continued
            .tools
            .push(ToolSpec::new("read", "Read a file", serde_json::json!({})));
        assert_ne!(body(&continued, quirks)["prompt_cache_key"], key);
        assert_ne!(
            body(&request().with_system(vec!["different".into()]), quirks)["prompt_cache_key"],
            key
        );
        assert_ne!(
            body(
                &Request::new("other-model", first.messages.clone()).with_system(first.system),
                quirks
            )["prompt_cache_key"],
            key
        );
        let second_provider: Value =
            serde_json::from_slice(&build_body(&request(), quirks, "second").unwrap()).unwrap();
        assert_ne!(
            second_provider["prompt_cache_key"],
            body(&request(), quirks)["prompt_cache_key"]
        );
        assert!(
            body(&request(), Quirks::for_host("elsewhere.test"))
                .get("prompt_cache_key")
                .is_none()
        );
    }

    #[test]
    fn cache_markers_follow_the_last_two_text_messages() {
        let req = Request::new(
            "m",
            vec![
                Message::user("first"),
                Message::assistant("second"),
                Message::assistant_response(
                    "".into(),
                    vec![super::super::ToolCall::new("1", "sh", "{}")],
                ),
                Message::tool_result("1", "sh", "done", false),
                Message::user("third"),
            ],
        );
        let marked = body(&req, Quirks::for_host("openrouter.ai"));
        assert_eq!(marked["messages"][0]["content"], "first");
        assert_eq!(marked["messages"][1]["content"][0]["text"], "second");
        assert_eq!(marked["messages"][4]["content"][0]["text"], "third");
        assert!(
            marked["messages"][4]["content"][0]
                .get("cache_control")
                .is_some()
        );
        assert!(marked["messages"][2]["content"].is_null());
        assert_eq!(marked["messages"][3]["content"], "done");
        let generic = body(&req, Quirks::for_host("elsewhere.test"));
        assert_eq!(generic["messages"][4]["content"], "third");
    }

    #[test]
    fn system_and_tool_results_are_mapped_only_at_the_wire_boundary() {
        let mut req = request().with_system(vec!["system one".into(), "system two".into()]);
        req.messages
            .push(Message::tool_result("call_1", "sh", "exit status 0", false));
        let sent = body(&req, Quirks::for_host("openrouter.ai"));
        assert_eq!(sent["messages"][0]["role"], "system");
        assert_eq!(
            sent["messages"][0]["content"][0]["text"],
            "system one\n\nsystem two"
        );
        assert_eq!(
            sent["messages"][0]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
        assert_eq!(sent["messages"][2]["role"], "tool");
        assert_eq!(sent["messages"][2]["tool_call_id"], "call_1");
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
