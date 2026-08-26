//! Hermetic transport and provider response corpora.

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
        request: &HttpRequest,
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
                    if *delay >= request.timeouts.total || *delay >= request.timeouts.stall =>
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

pub fn provider_conformance_corpus() -> Vec<ProviderCase> {
    let text = vec![
        r#"{"model":"test/model","choices":[{"index":0,"delta":{"content":"hé"}}]}"#.to_string(),
        r#"{"choices":[{"index":0,"delta":{"reasoning":"carefully "}}]}"#.to_string(),
        r#"{"choices":[{"index":0,"delta":{"content":"llo 🦀"}}]}"#.to_string(),
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#.to_string(),
        r#"{"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":3}}"#.to_string(),
    ];
    let calls = [
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"sh","arguments":""}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"hook_tool","arguments":""}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":\"printf "}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"value\":"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ok\"}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"1}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let mut cases = vec![
        ProviderCase {
            name: "fragmented text reasoning and usage",
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
                model: Some("test/model".to_string()),
                ..Completion::default()
            }),
            timeouts: Timeouts::default(),
            abort_after_content: false,
        },
        ProviderCase {
            name: "interleaved tool calls",
            reply: sse_reply(calls, 11),
            expected: ProviderExpectation::Completion(Completion {
                tool_calls: vec![
                    ToolCall::new("call_a", "sh", r#"{"command":"printf ok"}"#),
                    ToolCall::new("call_b", "hook_tool", r#"{"value":1}"#),
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
            "authentication",
            plain_reply(
                401,
                "Unauthorized",
                "application/json",
                r#"{"error":{"message":"bad key","code":401}}"#,
            ),
            ProviderExpectation::Auth,
        ),
        (
            "credits",
            plain_reply(
                402,
                "Payment Required",
                "application/json",
                r#"{"error":{"message":"no credit","code":402}}"#,
            ),
            ProviderExpectation::Credits,
        ),
        (
            "unavailable",
            plain_reply(502, "Bad Gateway", "text/plain", "upstream"),
            ProviderExpectation::Unavailable,
        ),
        (
            "api error",
            plain_reply(
                400,
                "Bad Request",
                "application/json",
                r#"{"error":{"message":"bad request","code":400}}"#,
            ),
            ProviderExpectation::Api(Some(400)),
        ),
        (
            "non-stream success",
            plain_reply(200, "OK", "application/json", r#"{"choices":[]}"#),
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
        "rate limit",
        rate,
        ProviderExpectation::RateLimited(Some(12)),
    ));
    cases.push(provider_case(
        "mid-stream error",
        sse_reply(
            vec![r#"{"error":{"message":"overloaded","code":503}}"#.to_string()],
            usize::MAX,
        ),
        ProviderExpectation::Unavailable,
    ));
    cases.push(provider_case(
        "truncated stream",
        sse_raw(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half\"}}]}\n\n",
            7,
        ),
        ProviderExpectation::Truncated,
    ));
    cases.push(provider_case(
        "malformed chunk",
        sse_raw("data: not-json\n\n", 5),
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
        "provider timeout",
        ProviderReply {
            head: sse_head(),
            steps: vec![ResponseStep::Pause(Duration::from_secs(30))],
        },
        ProviderExpectation::Timeout,
    );
    timeout.timeouts = Timeouts {
        connect: Duration::from_secs(2),
        total: Duration::from_secs(1),
        stall: Duration::from_secs(1),
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
    pub expected: Vec<String>,
}

pub fn fragmented(bytes: &[u8], size: usize) -> Script {
    bytes
        .chunks(size.max(1))
        .fold(Script::new(), |script, piece| script.write(piece))
}

fn stream_head(extra: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{extra}\r\n")
}

pub fn sse_response(payloads: &[&str]) -> Script {
    let body = stream_body(payloads);
    Script::new().write(format!(
        "{}{body}",
        stream_head(&format!("Content-Length: {}\r\n", body.len()))
    ))
}

pub fn plain_response(status: u16, reason: &str, content_type: &str, body: &str) -> Script {
    Script::new().write(format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn stream_body(payloads: &[&str]) -> String {
    let mut text = String::new();
    for payload in payloads {
        text.push_str(&format!("data: {payload}\n\n"));
    }
    text.push_str("data: [DONE]\n\n");
    text
}

fn stream_body_strings(payloads: &[String]) -> String {
    stream_body(&payloads.iter().map(String::as_str).collect::<Vec<_>>())
}

pub fn sse_corpus() -> Vec<SseCase> {
    let payloads = [
        r#"{"choices":[{"delta":{"content":"He"}}]}"#,
        r#"{"choices":[{"delta":{"content":"llo"}}]}"#,
    ];
    let body = stream_body(&payloads);
    let expected = || {
        payloads
            .iter()
            .map(|payload| payload.to_string())
            .chain(std::iter::once("[DONE]".to_string()))
            .collect()
    };
    vec![
        SseCase {
            name: "one write",
            script: Script::new().write(format!("{}{body}", stream_head(""))),
            expected: expected(),
        },
        SseCase {
            name: "one byte writes",
            script: fragmented(format!("{}{body}", stream_head("")).as_bytes(), 1),
            expected: expected(),
        },
        SseCase {
            name: "keep alive",
            script: Script::new()
                .write(stream_head(""))
                .write(": processing\n\n")
                .pause(Duration::from_millis(10))
                .write(body),
            expected: expected(),
        },
        SseCase {
            name: "multi line data",
            script: Script::new().write(format!(
                "{}data: a\ndata: b\n\ndata: [DONE]\n\n",
                stream_head("")
            )),
            expected: vec!["a\nb".to_string(), "[DONE]".to_string()],
        },
    ]
}

pub const PROVIDER_SCENARIOS: &[&str] = &[
    "streamed-text",
    "fragmented-sse",
    "sh-round",
    "hook-round",
    "compaction",
    "interrupt-stream",
    "usage",
    "malformed-response",
    "error",
];

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
            usage,
        ])]),
        "fragmented-sse" => {
            let response = format!(
                "{}{}",
                stream_head(""),
                stream_body(&[&text("fragmented"), finish])
            );
            Some(vec![fragmented(response.as_bytes(), 3)])
        }
        "sh-round" => Some(tool_round(
            "call_sh",
            "sh",
            serde_json::json!({"command": "printf mock-sh"}),
            "sh complete",
        )),
        "hook-round" => Some(tool_round(
            "call_hook",
            "echo_hook",
            serde_json::json!({"value": "mock"}),
            "hook complete",
        )),
        "compaction" => Some(vec![
            sse_response(&[&text("answer one"), finish, usage]),
            sse_response(&[&text("answer two"), finish, usage]),
            sse_response(&[&text("summary"), finish, usage]),
            sse_response(&[&text("answer three"), finish, usage]),
        ]),
        "interrupt-stream" => Some(vec![
            Script::new()
                .write(stream_head(""))
                .write(format!("data: {}\n\n", text("before cancel")))
                .pause(Duration::from_secs(10))
                .write(format!("data: {}\n\ndata: [DONE]\n\n", text(" after"))),
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

fn tool_round(id: &str, name: &str, arguments: serde_json::Value, done: &str) -> Vec<Script> {
    let call = serde_json::json!({
        "choices": [{
            "index": 0,
            "delta": {"tool_calls": [{
                "index": 0,
                "id": id,
                "function": {"name": name, "arguments": arguments.to_string()}
            }]},
            "finish_reason": "tool_calls"
        }]
    })
    .to_string();
    let text = format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{done}"}}}}]}}"#);
    vec![
        sse_response(&[&call]),
        sse_response(&[
            &text,
            r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        ]),
    ]
}

pub fn validate_provider_request(name: &str, body: &[u8]) -> Result<(), String> {
    let request: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("bad request JSON: {error}"))?;
    let messages = request
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .ok_or("request messages must be an array")?;
    if name == "sh-round" {
        if messages.is_empty() {
            return Err("sh-round request messages must not be empty".to_string());
        }
        let tools = request
            .get("tools")
            .and_then(serde_json::Value::as_array)
            .ok_or("sh-round request has no tools")?;
        if !tools
            .iter()
            .any(|tool| tool["function"]["name"].as_str() == Some("sh"))
        {
            return Err("sh-round request does not advertise sh".to_string());
        }
    }
    Ok(())
}

pub fn request_context_bytes(body: &[u8]) -> Result<usize, String> {
    let request: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| format!("bad request JSON: {error}"))?;
    let messages = request
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .ok_or("request messages must be an array")?;
    serde_json::to_vec(messages)
        .map(|bytes| bytes.len())
        .map_err(|error| format!("cannot measure messages: {error}"))
}

pub fn collect_sse(
    client: &dyn HttpClient,
    url: &str,
) -> Result<(ResponseHead, Vec<String>), NetError> {
    let request = HttpRequest::get(Url::parse(url)?);
    let mut payloads = Vec::new();
    let head = {
        let mut sink = SseSink::new(|event: SseEvent| {
            payloads.push(event.data);
            Ok(())
        });
        let head = client.execute(&request, &mut sink)?;
        if let Some(error) = sink.take_error() {
            return Err(NetError::BadResponse(error.to_string()));
        }
        sink.finish()
            .map_err(|error| NetError::BadResponse(error.to_string()))?;
        head
    };
    Ok((head, payloads))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_scenario_exists() {
        for scenario in PROVIDER_SCENARIOS {
            assert!(!provider_scenario(scenario).unwrap().is_empty());
        }
    }

    #[test]
    fn sh_scenario_requires_the_new_tool() {
        let good = serde_json::json!({
            "messages": [{"role": "user", "content": "go"}],
            "tools": [{"function": {"name": "sh"}}]
        });
        validate_provider_request("sh-round", good.to_string().as_bytes()).unwrap();
        let bad = serde_json::json!({
            "messages": [{"role": "user", "content": "go"}],
            "tools": []
        });
        assert!(validate_provider_request("sh-round", bad.to_string().as_bytes()).is_err());
    }

    #[test]
    fn context_measurement_is_exact() {
        let body = br#"{"messages":[{"role":"user","content":"hello"}]}"#;
        assert_eq!(
            request_context_bytes(body).unwrap(),
            serde_json::to_vec(&serde_json::json!([
                {"role": "user", "content": "hello"}
            ]))
            .unwrap()
            .len()
        );
    }
}
