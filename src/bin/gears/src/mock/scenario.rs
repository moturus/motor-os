//! Hermetic transport and provider conformance corpora: response shapes gears
//! must survive, paired with what each layer has to make of them.
//!
//! This is written once and replayed against *every* backend — step 10 of
//! the plan runs this same corpus against the Motor OS client, which is the
//! cheapest way to find out whether the port really behaves like the host.

use std::time::Duration;

use super::Script;
use crate::net::sse::{SseEvent, SseSink};
use crate::net::{HttpClient, HttpRequest, HttpSink, NetError, ResponseHead, Timeouts, Url};
use crate::provider::{Completion, FinishReason, ProviderError, ToolCall, Usage};

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderExpectation {
    Completion(Completion),
    Auth,
    Credits,
    RateLimited(Option<u64>),
    Unavailable,
    Api(Option<u16>),
    Truncated,
    Protocol,
    Timeout,
    Aborted,
}

impl ProviderExpectation {
    pub fn accepts(&self, actual: &Result<Completion, ProviderError>) -> bool {
        match (self, actual) {
            (Self::Completion(expected), Ok(actual)) => expected == actual,
            (Self::Auth, Err(ProviderError::Auth(_)))
            | (Self::Credits, Err(ProviderError::Credits(_)))
            | (Self::Unavailable, Err(ProviderError::Unavailable(_)))
            | (Self::Truncated, Err(ProviderError::Truncated(_)))
            | (Self::Protocol, Err(ProviderError::Protocol(_)))
            | (Self::Aborted, Err(ProviderError::Aborted(_))) => true,
            (Self::RateLimited(expected), Err(ProviderError::RateLimited { retry_after, .. })) => {
                expected == retry_after
            }
            (Self::Api(expected), Err(ProviderError::Api { status, .. })) => expected == status,
            (Self::Timeout, Err(ProviderError::Net(NetError::Timeout(_)))) => true,
            _ => false,
        }
    }
}

#[derive(Clone)]
enum ResponseStep {
    Bytes(Vec<u8>),
    Pause(Duration),
}

#[derive(Clone)]
pub struct ProviderReply {
    head: ResponseHead,
    steps: Vec<ResponseStep>,
}

impl HttpClient for ProviderReply {
    fn execute(
        &self,
        req: &HttpRequest,
        sink: &mut dyn HttpSink,
    ) -> Result<ResponseHead, NetError> {
        sink.on_head(&self.head)
            .map_err(|error| NetError::Aborted(error.to_string()))?;
        for step in &self.steps {
            match step {
                ResponseStep::Bytes(bytes) => sink
                    .on_chunk(bytes)
                    .map_err(|error| NetError::Aborted(error.to_string()))?,
                ResponseStep::Pause(delay)
                    if *delay >= req.timeouts.total || *delay >= req.timeouts.stall =>
                {
                    return Err(NetError::Timeout("scripted provider stall".to_string()));
                }
                ResponseStep::Pause(delay) => std::thread::sleep(*delay),
            }
        }
        Ok(self.head.clone())
    }
}

pub struct ProviderCase {
    pub name: &'static str,
    reply: ProviderReply,
    pub expected: ProviderExpectation,
    pub timeouts: Timeouts,
    pub abort_after_content: bool,
}

impl ProviderCase {
    pub fn memory_reply(&self) -> ProviderReply {
        self.reply.clone()
    }

    /// The same response, including its HTTP head, for a real transport.
    pub fn script(&self) -> Script {
        let mut script = Script::new().write(wire_head(&self.reply.head));
        for step in &self.reply.steps {
            script = match step {
                ResponseStep::Bytes(bytes) => script.write(bytes.clone()),
                ResponseStep::Pause(delay) => script.pause(*delay),
            };
        }
        script
    }
}

/// OpenAI-compatible success and failure shapes. Each case is replayed both
/// directly through the adapter's HTTP seam and through the loopback server.
pub fn provider_conformance_corpus() -> Vec<ProviderCase> {
    let text = vec![
        r#"{"model":"openai/gpt-5-2026-01-01","choices":[{"index":0,"delta":{"content":"hé"}}]}"#
            .to_string(),
        r#"{"choices":[{"index":0,"delta":{"reasoning":"carefully "}}]}"#.to_string(),
        r#"{"choices":[{"index":0,"delta":{"content":"llo 🦀"}}]}"#.to_string(),
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
        r#"{"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":3}}"#.to_string(),
    ];
    let parallel = [
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"read_file","arguments":""}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","type":"function","function":{"name":"grep","arguments":""}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":\"src/"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"q\":\"fn "}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"main.rs\"}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"main\"}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let mut cases = vec![
        ProviderCase {
            name: "fragmented text, reasoning, and usage",
            reply: sse_reply(text, 3),
            expected: ProviderExpectation::Completion(Completion {
                content: "héllo 🦀".to_string(),
                reasoning: "carefully ".to_string(),
                finish_reason: Some(FinishReason::Stop),
                usage: Usage {
                    prompt_tokens: 9,
                    completion_tokens: 3,
                    ..Usage::default()
                },
                model: Some("openai/gpt-5-2026-01-01".to_string()),
                ..Completion::default()
            }),
            timeouts: Timeouts::default(),
            abort_after_content: false,
        },
        ProviderCase {
            name: "interleaved parallel tool calls",
            reply: sse_reply(parallel, 11),
            expected: ProviderExpectation::Completion(Completion {
                tool_calls: vec![
                    ToolCall::new("call_a", "read_file", r#"{"path":"src/main.rs"}"#),
                    ToolCall::new("call_b", "grep", r#"{"q":"fn main"}"#),
                ],
                finish_reason: Some(FinishReason::ToolCalls),
                ..Completion::default()
            }),
            timeouts: Timeouts::default(),
            abort_after_content: false,
        },
    ];

    for (name, reply, expected) in [
        (
            "401 with an error body",
            plain_reply(
                401,
                "Unauthorized",
                "application/json",
                r#"{"error":{"message":"No auth credentials found","code":401}}"#,
            ),
            ProviderExpectation::Auth,
        ),
        (
            "402 out of credit",
            plain_reply(
                402,
                "Payment Required",
                "application/json",
                r#"{"error":{"message":"Insufficient credits","code":402}}"#,
            ),
            ProviderExpectation::Credits,
        ),
        (
            "502 non-JSON gateway error",
            plain_reply(502, "Bad Gateway", "text/html", "<html>upstream</html>"),
            ProviderExpectation::Unavailable,
        ),
        (
            "400 provider API error",
            plain_reply(
                400,
                "Bad Request",
                "application/json",
                r#"{"error":{"message":"model not found","code":400}}"#,
            ),
            ProviderExpectation::Api(Some(400)),
        ),
        (
            "200 non-stream response",
            plain_reply(
                200,
                "OK",
                "application/json",
                r#"{"choices":[{"message":{"content":"unstreamed"}}]}"#,
            ),
            ProviderExpectation::Protocol,
        ),
    ] {
        cases.push(provider_case(name, reply, expected));
    }

    let mut rate = plain_reply(429, "Too Many Requests", "application/json", "{}");
    rate.head
        .headers
        .push(("Retry-After".to_string(), "12".to_string()));
    cases.push(provider_case(
        "429 with Retry-After",
        rate,
        ProviderExpectation::RateLimited(Some(12)),
    ));
    cases.push(provider_case(
        "mid-stream provider error",
        sse_reply(
            vec![
                r#"{"choices":[{"index":0,"delta":{"content":"starting"}}]}"#.to_string(),
                r#"{"error":{"message":"upstream is overloaded","code":503}}"#.to_string(),
            ],
            usize::MAX,
        ),
        ProviderExpectation::Unavailable,
    ));
    cases.push(provider_case(
        "truncated event stream",
        sse_raw(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half\"}}]}\n\n",
            7,
        ),
        ProviderExpectation::Truncated,
    ));
    cases.push(provider_case(
        "malformed completion chunk",
        sse_raw("data: not json\n\n", 5),
        ProviderExpectation::Protocol,
    ));

    let mut cancelled = provider_case(
        "caller cancellation",
        ProviderReply {
            head: sse_head(),
            steps: vec![
                ResponseStep::Bytes(
                    b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"first\"}}]}\n\n"
                        .to_vec(),
                ),
                ResponseStep::Pause(Duration::from_secs(5)),
            ],
        },
        ProviderExpectation::Aborted,
    );
    cancelled.abort_after_content = true;
    cases.push(cancelled);

    let mut timeout = provider_case(
        "stalled provider",
        ProviderReply {
            head: sse_head(),
            steps: vec![ResponseStep::Pause(Duration::from_secs(30))],
        },
        ProviderExpectation::Timeout,
    );
    timeout.timeouts = Timeouts {
        connect: Duration::from_secs(5),
        total: Duration::from_secs(2),
        stall: Duration::from_secs(2),
    };
    cases.push(timeout);
    cases
}

fn provider_case(
    name: &'static str,
    reply: ProviderReply,
    expected: ProviderExpectation,
) -> ProviderCase {
    ProviderCase {
        name,
        reply,
        expected,
        timeouts: Timeouts::default(),
        abort_after_content: false,
    }
}

fn sse_head() -> ResponseHead {
    ResponseHead {
        status: 200,
        reason: "OK".to_string(),
        headers: vec![("Content-Type".to_string(), "text/event-stream".to_string())],
    }
}

fn sse_reply(payloads: Vec<String>, chunk_bytes: usize) -> ProviderReply {
    sse_raw(&stream_body_strings(&payloads), chunk_bytes)
}

fn sse_raw(body: &str, chunk_bytes: usize) -> ProviderReply {
    ProviderReply {
        head: sse_head(),
        steps: body
            .as_bytes()
            .chunks(chunk_bytes.max(1))
            .map(|bytes| ResponseStep::Bytes(bytes.to_vec()))
            .collect(),
    }
}

fn plain_reply(status: u16, reason: &str, content_type: &str, body: &str) -> ProviderReply {
    ProviderReply {
        head: ResponseHead {
            status,
            reason: reason.to_string(),
            headers: vec![
                ("Content-Type".to_string(), content_type.to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
            ],
        },
        steps: vec![ResponseStep::Bytes(body.as_bytes().to_vec())],
    }
}

fn wire_head(head: &ResponseHead) -> String {
    let mut wire = format!("HTTP/1.1 {} {}\r\n", head.status, head.reason);
    for (name, value) in &head.headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    wire.push_str("\r\n");
    wire
}

pub struct SseCase {
    pub name: &'static str,
    pub script: Script,
    /// The `data` payload of each event, in order.
    pub expected: Vec<String>,
}

/// Split `bytes` into writes of at most `size`, so a client sees the stream
/// arrive in pieces that fall wherever `size` puts them — mid-event,
/// mid-token, mid-character.
pub fn fragmented(bytes: &[u8], size: usize) -> Script {
    bytes
        .chunks(size.max(1))
        .fold(Script::new(), |script, piece| script.write(piece))
}

fn head(extra: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{extra}\r\n")
}

/// A whole event-stream response carrying `payloads`, ending in `[DONE]`.
pub fn sse_response(payloads: &[&str]) -> Script {
    let body = stream_body(payloads);
    let framed_head = head(&format!("Content-Length: {}\r\n", body.len()));
    Script::new().write(format!("{framed_head}{body}"))
}

/// A response that is not a stream, which is what every error path looks
/// like: a status, a content type and a body of that type.
pub fn plain_response(status: u16, reason: &str, content_type: &str, body: &str) -> Script {
    Script::new().write(format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    ))
}

/// Frame `payloads` as an event stream ending in the `[DONE]` sentinel.
fn stream_body(payloads: &[&str]) -> String {
    let mut text = String::new();
    for payload in payloads {
        text.push_str(&format!("data: {payload}\n\n"));
    }
    text.push_str("data: [DONE]\n\n");
    text
}

fn stream_body_strings(payloads: &[String]) -> String {
    let borrowed: Vec<_> = payloads.iter().map(String::as_str).collect();
    stream_body(&borrowed)
}

fn expected(payloads: &[&str]) -> Vec<String> {
    payloads
        .iter()
        .map(|p| p.to_string())
        .chain(std::iter::once("[DONE]".to_string()))
        .collect()
}

pub fn sse_corpus() -> Vec<SseCase> {
    let payloads = [
        r#"{"choices":[{"delta":{"content":"He"}}]}"#,
        r#"{"choices":[{"delta":{"content":"llo"}}]}"#,
    ];
    let body = stream_body(&payloads);
    let mut cases = Vec::new();

    cases.push(SseCase {
        name: "one write",
        script: Script::new().write(format!("{}{body}", head(""))),
        expected: expected(&payloads),
    });

    cases.push(SseCase {
        name: "head and body written apart",
        script: Script::new()
            .write(head(""))
            .pause(Duration::from_millis(20))
            .write(body.clone()),
        expected: expected(&payloads),
    });

    cases.push(SseCase {
        name: "one byte at a time",
        script: fragmented(format!("{}{body}", head("")).as_bytes(), 1),
        expected: expected(&payloads),
    });

    cases.push(SseCase {
        name: "seven bytes at a time",
        script: fragmented(format!("{}{body}", head("")).as_bytes(), 7),
        expected: expected(&payloads),
    });

    cases.push(SseCase {
        name: "crlf terminators",
        script: Script::new().write(format!(
            "{}data: {}\r\n\r\ndata: [DONE]\r\n\r\n",
            head(""),
            payloads[0]
        )),
        expected: vec![payloads[0].to_string(), "[DONE]".to_string()],
    });

    // What a long think looks like: comment keep-alives, then the answer.
    cases.push(SseCase {
        name: "keep-alives while thinking",
        script: Script::new()
            .write(head(""))
            .write(": OPENROUTER PROCESSING\n\n")
            .pause(Duration::from_millis(20))
            .write(": OPENROUTER PROCESSING\n\n")
            .pause(Duration::from_millis(20))
            .write(body.clone()),
        expected: expected(&payloads),
    });

    // A multi-byte character split across writes must not be mangled.
    let emoji_body = stream_body(&[r#"{"delta":"héllo 🦀"}"#]);
    cases.push(SseCase {
        name: "utf-8 split across writes",
        script: fragmented(format!("{}{emoji_body}", head("")).as_bytes(), 3),
        expected: vec![r#"{"delta":"héllo 🦀"}"#.to_string(), "[DONE]".to_string()],
    });

    // One event far larger than any single read.
    let big = "x".repeat(200_000);
    let big_payload = format!(r#"{{"delta":"{big}"}}"#);
    cases.push(SseCase {
        name: "an event larger than the read buffer",
        script: Script::new().write(format!("{}{}", head(""), stream_body(&[&big_payload]))),
        expected: vec![big_payload, "[DONE]".to_string()],
    });

    // Several data lines make one event, joined with newlines.
    cases.push(SseCase {
        name: "multi-line data",
        script: Script::new().write(format!("{}data: a\ndata: b\n\ndata: [DONE]\n\n", head(""))),
        expected: vec!["a\nb".to_string(), "[DONE]".to_string()],
    });

    cases
}

/// Scenarios understood by the standalone development-image provider mock.
pub const PROVIDER_SCENARIOS: &[&str] = &[
    "streamed-text",
    "attachment",
    "manual-compact",
    "fragmented-sse",
    "tool-round",
    "quality-round",
    "patch-round",
    "patch-mode-round",
    "explore-round",
    "p0-workflow",
    "build-round",
    "cargo-round",
    "run-cancel",
    "run-flood",
    "interrupt-stream",
    "usage",
    "malformed-response",
    "error",
];

/// Return the ordered responses for one provider scenario. This module stays
/// dependency-free so host tests and the Motor TLS server share exact bytes.
pub fn provider_scenario(name: &str) -> Option<Vec<Script>> {
    let text =
        |value: &str| format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{value}"}}}}]}}"#);
    let finish = r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#;
    let usage = r#"{"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#;

    match name {
        "streamed-text" => Some(vec![sse_response(&[
            &text("hello "),
            &text("from the mock"),
            finish,
        ])]),
        "attachment" => Some(vec![sse_response(&[
            &text("attachment received"),
            finish,
            usage,
        ])]),
        "manual-compact" => Some(vec![
            sse_response(&[&text("answer one"), finish, usage]),
            sse_response(&[&text("answer two"), finish, usage]),
            sse_response(&[&text("answer three"), finish, usage]),
            sse_response(&[&text("concise history"), finish, usage]),
            sse_response(&[&text("answer four"), finish, usage]),
        ]),
        "fragmented-sse" => {
            let response = format!(
                "{}{}",
                head(""),
                stream_body(&[&text("fragmented"), finish])
            );
            Some(vec![
                response
                    .as_bytes()
                    .chunks(3)
                    .fold(Script::new(), |script, piece| {
                        script.write(piece).pause(Duration::from_millis(1))
                    }),
            ])
        }
        "tool-round" => {
            let tool = r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_write","type":"function","function":{"name":"write_file","arguments":"{\"path\":\"result.txt\",\"content\":\"made by gears\\n\"}"}}]},"finish_reason":"tool_calls"}]}"#;
            Some(vec![
                sse_response(&[tool]),
                sse_response(&[&text("tool complete"), finish, usage]),
            ])
        }
        "quality-round" => Some(tool_round(
            "call_quality_write",
            "write_file",
            serde_json::json!({"path": "result.txt", "content": "q".repeat(70_000)}),
            "quality complete",
        )),
        "patch-round" => {
            let arguments = serde_json::json!({"version": 1, "operations": [
                {"kind": "create", "path": "created", "content": "new\n"},
                {"kind": "edit", "path": "edited", "hunks": [
                    {"old": "old", "new": "changed"}]},
                {"kind": "delete", "path": "deleted"},
                {"kind": "rename", "path": "source", "to": "destination",
                    "hunks": [{"old": "move", "new": "moved"}]}
            ]});
            Some(tool_round(
                "call_patch",
                "patch",
                arguments,
                "patch complete",
            ))
        }
        "patch-mode-round" => {
            let arguments = serde_json::json!({"version": 1, "operations": [
                {"kind": "create", "path": "must-not-exist", "content": "no\n",
                    "executable": true}
            ]});
            Some(tool_round(
                "call_patch_mode",
                "patch",
                arguments,
                "mode refusal complete",
            ))
        }
        "explore-round" => {
            let tools = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {"tool_calls": [
                        {
                            "index": 0,
                            "id": "call_grep",
                            "type": "function",
                            "function": {"name": "grep", "arguments":
                                serde_json::json!({"pattern": "step5-motor-needle"}).to_string()},
                        },
                        {
                            "index": 1,
                            "id": "call_profile",
                            "type": "function",
                            "function": {"name": "repository_profile", "arguments": "{}"},
                        },
                        {
                            "index": 2,
                            "id": "call_instructions",
                            "type": "function",
                            "function": {"name": "project_instructions", "arguments":
                                serde_json::json!({"path": "nested/code.rs"}).to_string()},
                        },
                    ]},
                    "finish_reason": "tool_calls",
                }],
            })
            .to_string();
            Some(vec![
                sse_response(&[&tools]),
                sse_response(&[&text("exploration complete"), finish, usage]),
            ])
        }
        "p0-workflow" => Some(vec![
            tool_calls(vec![
                scripted_call(
                    0,
                    "read",
                    "read_file",
                    serde_json::json!({
                        "path": "Cargo.toml", "line_start": 1, "line_count": 20,
                    }),
                ),
                scripted_call(
                    1,
                    "search",
                    "grep",
                    serde_json::json!({"pattern": "P0_WORKFLOW_OLD"}),
                ),
                scripted_call(
                    2,
                    "instructions",
                    "project_instructions",
                    serde_json::json!({"path": "nested/lib.rs"}),
                ),
                scripted_call(3, "profile", "repository_profile", serde_json::json!({})),
                scripted_call(
                    4,
                    "plan",
                    "task",
                    serde_json::json!({
                        "action": "add",
                        "text": "Apply the reviewed atomic change and verify it",
                    }),
                ),
            ]),
            tool_calls(vec![scripted_call(
                0,
                "code",
                "task",
                serde_json::json!({
                    "action": "mode", "from_mode": "plan", "to_mode": "code",
                }),
            )]),
            tool_calls(vec![scripted_call(
                0,
                "patch",
                "patch",
                serde_json::json!({"version": 1, "operations": [
                    {"kind": "edit", "path": "src/lib.rs", "hunks": [{
                        "old": "P0_WORKFLOW_OLD", "new": "P0_WORKFLOW_NEW",
                    }]},
                    {"kind": "create", "path": "CHANGELOG.md", "content": "p0 workflow\n"},
                ]}),
            )]),
            sse_response(&[&text("p0 change ready"), finish, usage]),
            tool_calls(vec![scripted_call(
                0,
                "test",
                "test",
                serde_json::json!({"offline": true}),
            )]),
            tool_calls(vec![scripted_call(
                0,
                "review",
                "task",
                serde_json::json!({
                    "action": "mode", "from_mode": "code", "to_mode": "review",
                }),
            )]),
            tool_calls(vec![scripted_call(
                0,
                "finish-original",
                "task",
                serde_json::json!({
                    "action": "transition", "id": 1,
                    "from": "active", "to": "completed",
                }),
            )]),
            tool_calls(vec![scripted_call(
                0,
                "start-plan",
                "task",
                serde_json::json!({
                    "action": "transition", "id": 2,
                    "from": "pending", "to": "active",
                }),
            )]),
            tool_calls(vec![scripted_call(
                0,
                "finish-plan",
                "task",
                serde_json::json!({
                    "action": "transition", "id": 2,
                    "from": "active", "to": "completed",
                }),
            )]),
            tool_calls(vec![scripted_call(
                0,
                "report",
                "completion",
                serde_json::json!({
                    "action": "report", "evidence": [1], "assumptions": [],
                }),
            )]),
            sse_response(&[&text("p0 workflow complete"), finish, usage]),
        ]),
        "build-round" => {
            let tool = r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_build","type":"function","function":{"name":"build","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#;
            Some(vec![
                sse_response(&[tool]),
                sse_response(&[&text("build complete"), finish, usage]),
            ])
        }
        "cargo-round" => {
            let tool = r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_cargo","type":"function","function":{"name":"run","arguments":"{\"command\":\"cargo\",\"args\":[\"build\"]}"}}]},"finish_reason":"tool_calls"}]}"#;
            Some(vec![
                sse_response(&[tool]),
                sse_response(&[&text("cargo refusal complete"), finish, usage]),
            ])
        }
        "run-cancel" => {
            let tool = r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_sleep","type":"function","function":{"name":"run","arguments":"{\"command\":\"/bin/sleep\",\"args\":[\"30\"]}"}}]},"finish_reason":"tool_calls"}]}"#;
            Some(vec![sse_response(&[tool])])
        }
        "run-flood" => {
            let stdout = "x".repeat(3000);
            let stderr = "y".repeat(3000);
            let command = format!(
                "i=0; echo BEGIN; while [ \"$i\" -lt 200 ]; do \
                 printf 'stdout-%04d-{stdout}\\n' \"$i\"; \
                 printf 'stderr-%04d-{stderr}\\n' \"$i\" >&2; \
                 i=$((i+1)); done; echo END >&2"
            );
            let arguments = serde_json::json!({
                "command": "/bin/rush",
                "args": ["-c", command],
                "timeout_seconds": 30,
            });
            let tool = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {"tool_calls": [{
                        "index": 0,
                        "id": "call_flood",
                        "type": "function",
                        "function": {"name": "run", "arguments": arguments.to_string()},
                    }]},
                    "finish_reason": "tool_calls",
                }],
            })
            .to_string();
            Some(vec![
                sse_response(&[&tool]),
                sse_response(&[&text("flood complete"), finish, usage]),
            ])
        }
        "interrupt-stream" => Some(vec![
            Script::new()
                .write(head(""))
                .write(format!("data: {}\n\n", text("before cancel")))
                .pause(Duration::from_secs(2))
                .write(format!(
                    "data: {}\n\ndata: [DONE]\n\n",
                    text(" after cancel")
                )),
        ]),
        "usage" => Some(vec![sse_response(&[usage])]),
        "malformed-response" => Some(vec![sse_response(&["{not-json"])]),
        "error" => Some(vec![plain_response(
            429,
            "Too Many Requests",
            "application/json",
            r#"{"error":{"message":"mock rate limit","code":429}}"#,
        )]),
        _ => None,
    }
}

/// Validate scenario-specific request facts that a scripted response cannot
/// express. The attachment scenario has one response, so this validates its
/// first and only request before sending that response.
pub fn validate_provider_request(name: &str, body: &[u8]) -> Result<(), String> {
    match name {
        "attachment" => validate_attachment_request(body),
        "manual-compact" => validate_manual_compaction_request(body),
        _ => Ok(()),
    }
}

fn validate_attachment_request(body: &[u8]) -> Result<(), String> {
    let request: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("bad request JSON: {error}"))?;
    let content = request["messages"]
        .as_array()
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| message["role"] == "user")
        })
        .and_then(|message| message["content"].as_str())
        .ok_or("request has no user content")?;
    for expected in [
        "Gears attachment \"context.txt\"",
        "kind: file",
        "attachment fixture bytes",
    ] {
        if !content.contains(expected) {
            return Err(format!("attachment request is missing {expected:?}"));
        }
    }
    Ok(())
}

fn validate_manual_compaction_request(body: &[u8]) -> Result<(), String> {
    let request: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("bad request JSON: {error}"))?;
    let messages = request["messages"]
        .as_array()
        .ok_or("request messages must be an array")?;
    let last = messages
        .last()
        .and_then(|message| message["content"].as_str())
        .ok_or("request has no final message content")?;
    if last.contains("Additional focus requested by the user:") {
        if request.get("tools").is_some() || !last.ends_with("focus on decisions") {
            return Err("manual summary request has tools or lost its focus".to_string());
        }
    } else if last == "question four" {
        let conversation = messages
            .iter()
            .filter(|message| message["role"] != "system")
            .filter_map(|message| message["content"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for expected in [
            "concise history",
            "question three",
            "answer three",
            "question four",
        ] {
            if !conversation.contains(expected) {
                return Err(format!("post-compaction request is missing {expected:?}"));
            }
        }
        for replaced in ["question one", "question two"] {
            if conversation.contains(replaced) {
                return Err(format!(
                    "post-compaction request retained replaced text {replaced:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Serialized bytes occupied by the message context in one provider request.
pub fn request_context_bytes(body: &[u8]) -> Result<usize, String> {
    let request: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("bad request JSON: {error}"))?;
    let messages = request
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .ok_or("request messages must be an array")?;
    serde_json::to_vec(messages)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("cannot measure request messages: {error}"))
}

fn tool_round(id: &str, name: &str, arguments: serde_json::Value, done: &str) -> Vec<Script> {
    let tool = serde_json::json!({
        "choices": [{
            "index": 0,
            "delta": {"tool_calls": [{
                "index": 0,
                "id": id,
                "type": "function",
                "function": {"name": name, "arguments": arguments.to_string()},
            }]},
            "finish_reason": "tool_calls",
        }],
    })
    .to_string();
    let text = format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{done}"}}}}]}}"#);
    let finish = r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#;
    vec![sse_response(&[&tool]), sse_response(&[&text, finish])]
}

fn scripted_call(
    index: usize,
    id: &str,
    name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "index": index,
        "id": id,
        "type": "function",
        "function": {"name": name, "arguments": arguments.to_string()},
    })
}

fn tool_calls(calls: Vec<serde_json::Value>) -> Script {
    let payload = serde_json::json!({
        "choices": [{
            "index": 0,
            "delta": {"tool_calls": calls},
            "finish_reason": "tool_calls",
        }],
    })
    .to_string();
    sse_response(&[&payload])
}

/// Run one case: fetch `url` and collect the event payloads.
pub fn collect_sse(
    client: &dyn HttpClient,
    url: &str,
) -> Result<(ResponseHead, Vec<String>), NetError> {
    let request = HttpRequest::get(Url::parse(url)?);
    let mut payloads: Vec<String> = Vec::new();
    let head = {
        let mut sink = SseSink::new(|event: SseEvent| {
            payloads.push(event.data);
            Ok(())
        });
        let head = client.execute(&request, &mut sink);
        if let Some(e) = sink.take_error() {
            return Err(NetError::BadResponse(e.to_string()));
        }
        let head = head?;
        sink.finish()
            .map_err(|e| NetError::BadResponse(e.to_string()))?;
        head
    };
    Ok((head, payloads))
}

#[cfg(test)]
mod provider_scenario_tests {
    use super::*;
    use crate::mock::Piece;

    fn written(script: Script) -> Vec<u8> {
        script
            .into_pieces()
            .filter_map(|piece| match piece {
                Piece::Write(bytes) => Some(bytes),
                Piece::Pause(_) | Piece::Close => None,
            })
            .flatten()
            .collect()
    }

    #[test]
    fn every_advertised_provider_scenario_has_a_response() {
        for name in PROVIDER_SCENARIOS {
            assert!(!provider_scenario(name).unwrap().is_empty(), "{name}");
        }
        assert!(provider_scenario("unknown").is_none());
    }

    #[test]
    fn attachment_scenario_requires_the_snapshot_in_its_first_request() {
        let body = serde_json::json!({"messages": [{
            "role": "user",
            "content": "Gears attachment \"context.txt\"\nkind: file\nattachment fixture bytes"
        }]});
        validate_provider_request("attachment", body.to_string().as_bytes()).unwrap();
        assert!(validate_provider_request("attachment", br#"{"messages":[]}"#).is_err());
        validate_provider_request("streamed-text", br#"not JSON"#).unwrap();
    }

    #[test]
    fn manual_compaction_scenario_checks_summary_and_followup_shapes() {
        let summary = serde_json::json!({
            "messages": [{"role": "user", "content":
                "summary instruction\nAdditional focus requested by the user:\nfocus on decisions"}]
        });
        validate_provider_request("manual-compact", summary.to_string().as_bytes()).unwrap();

        let followup = serde_json::json!({"messages": [
            {"role": "system", "content": "question one in task state"},
            {"role": "assistant", "content": "concise history"},
            {"role": "user", "content": "question three"},
            {"role": "assistant", "content": "answer three"},
            {"role": "user", "content": "question four"}
        ]});
        validate_provider_request("manual-compact", followup.to_string().as_bytes()).unwrap();
        let broken = followup
            .to_string()
            .replace("concise history", "question two");
        assert!(validate_provider_request("manual-compact", broken.as_bytes()).is_err());
    }

    #[test]
    fn request_context_measurement_is_exact_and_rejects_bad_shapes() {
        let messages = serde_json::json!([
            {"role": "system", "content": "instructions"},
            {"role": "user", "content": "hello"}
        ]);
        let body = serde_json::json!({"model": "test", "messages": messages});
        assert_eq!(
            request_context_bytes(body.to_string().as_bytes()).unwrap(),
            serde_json::to_vec(&messages).unwrap().len()
        );
        assert!(request_context_bytes(br#"{"messages":"wrong"}"#).is_err());
        assert!(request_context_bytes(b"not JSON").is_err());
    }

    #[test]
    fn scripted_sse_has_exact_http_body_framing() {
        let wire = String::from_utf8(written(sse_response(&["hello"]))).unwrap();
        let (head, body) = wire.split_once("\r\n\r\n").unwrap();
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{head}"
        );
        assert!(body.ends_with("data: [DONE]\n\n"), "{body}");
    }

    #[test]
    fn tool_round_is_two_requests_with_one_exact_write() {
        let scripts = provider_scenario("tool-round").unwrap();
        assert_eq!(scripts.len(), 2);
        let first = String::from_utf8(written(scripts.into_iter().next().unwrap())).unwrap();
        assert!(first.contains(r#""name":"write_file""#), "{first}");
        assert!(first.contains(r#"result.txt"#), "{first}");
        assert!(first.contains("finish_reason"), "{first}");
    }

    #[test]
    fn platform_rounds_request_the_generic_tools() {
        let first = |name| {
            let script = provider_scenario(name).unwrap().remove(0);
            String::from_utf8(written(script)).unwrap()
        };
        let build = first("build-round");
        assert!(build.contains(r#""name":"build""#), "{build}");

        let cargo = first("cargo-round");
        assert!(cargo.contains(r#""name":"run""#), "{cargo}");
        assert!(cargo.contains(r#"\"command\":\"cargo\""#), "{cargo}");

        let explore = first("explore-round");
        for name in ["grep", "repository_profile", "project_instructions"] {
            assert!(
                explore.contains(&format!(r#""name":"{name}""#)),
                "{explore}"
            );
        }
    }

    #[test]
    fn patch_rounds_request_versioned_atomic_patches() {
        for name in ["patch-round", "patch-mode-round"] {
            let script = provider_scenario(name).unwrap().remove(0);
            let first = String::from_utf8(written(script)).unwrap();
            assert!(first.contains(r#""name":"patch""#), "{first}");
            assert!(first.contains(r#"\"version\":1"#), "{first}");
        }
    }

    #[test]
    fn fragmented_sse_really_has_paced_pieces() {
        let script = provider_scenario("fragmented-sse").unwrap().remove(0);
        let pieces: Vec<_> = script.into_pieces().collect();
        assert!(pieces.len() > 10);
        assert!(pieces.iter().any(|piece| matches!(piece, Piece::Pause(_))));
    }
}
