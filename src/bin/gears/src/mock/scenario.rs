//! The transport conformance corpus: the response shapes gears must survive,
//! paired with what a client has to make of them.
//!
//! This is written once and replayed against *every* backend — step 10 of
//! the plan runs this same corpus against the Motor OS client, which is the
//! cheapest way to find out whether the port really behaves like the host.

use std::time::Duration;

use super::Script;
use crate::net::sse::{SseEvent, SseSink};
use crate::net::{HttpClient, HttpRequest, NetError, ResponseHead, Url};

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
    Script::new().write(format!("{}{}", head(""), stream_body(payloads)))
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
    "fragmented-sse",
    "tool-round",
    "patch-round",
    "patch-mode-round",
    "explore-round",
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
