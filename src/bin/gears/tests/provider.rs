//! The provider against scripted endpoints: real curl, the in-process mock
//! server, no model provider anywhere. The corpus below is every response
//! shape gears has to survive, including all the ways one can fail.

use std::time::Duration;

use gears::mock::{MockServer, Script, plain_response, sse_response};
use gears::net::host_curl::HostCurl;
use gears::net::{EgressPolicy, Timeouts};
use gears::provider::{
    ChatMessage, ChatRequest, Discard, Endpoint, EventSink, FinishReason, ModelProvider,
    OpenAiCompat, ProviderError, UsageMeter,
};

const KEY: &str = "sk-mock-not-a-real-key";

fn provider(server: &MockServer) -> OpenAiCompat<HostCurl> {
    let policy = EgressPolicy::new(&["127.0.0.1".to_string()]).allow_loopback_http_for_tests();
    let http = HostCurl::new(policy)
        .unwrap()
        .with_secret(gears::provider::KEY_ENV, KEY);
    let endpoint = Endpoint::new(&format!("{}/v1", server.base_url())).unwrap();
    OpenAiCompat::new(http, endpoint)
}

fn request() -> ChatRequest {
    ChatRequest::new(
        "openai/gpt-5",
        vec![ChatMessage::system("be brief"), ChatMessage::user("hello")],
    )
}

fn text_chunk(text: &str) -> String {
    format!(r#"{{"choices":[{{"index":0,"delta":{{"content":"{text}"}}}}]}}"#)
}

fn finish_chunk(reason: &str) -> String {
    format!(r#"{{"choices":[{{"index":0,"delta":{{}},"finish_reason":"{reason}"}}]}}"#)
}

/// Collects deltas as the UI would, so a test can tell streaming from a
/// single lump delivered at the end.
#[derive(Default)]
struct Rendered(Vec<String>);

impl EventSink for Rendered {
    fn on_content(&mut self, text: &str) -> std::io::Result<()> {
        self.0.push(text.to_string());
        Ok(())
    }
}

#[test]
fn a_scripted_completion_streams_and_assembles() {
    let usage =
        r#"{"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":3,"cost":0.00042}}"#;
    let payloads = [
        r#"{"model":"openai/gpt-5-2026-01-01","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}"#,
        &text_chunk("Hello"),
        &text_chunk(", "),
        &text_chunk("world"),
        &finish_chunk("stop"),
        usage,
    ];
    let server = MockServer::start_one(sse_response(&payloads)).unwrap();

    let mut rendered = Rendered::default();
    let completion = provider(&server)
        .complete(&request(), &mut rendered)
        .unwrap();

    assert_eq!(completion.content, "Hello, world");
    assert_eq!(completion.finish_reason, Some(FinishReason::Stop));
    assert_eq!(completion.model.as_deref(), Some("openai/gpt-5-2026-01-01"));
    assert_eq!(completion.usage.cost, Some(0.00042));
    assert_eq!(rendered.0, ["Hello", ", ", "world"]);

    let mut meter = UsageMeter::new();
    meter.add(&completion.usage);
    assert_eq!(meter.summary(), "1 completions, 9 + 3 tokens, $0.0004");

    // What went out: the dialect's request, streaming, with the key expanded
    // by the transport and never seen by this layer.
    let sent = &server.requests()[0];
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.target, "/v1/chat/completions");
    assert_eq!(sent.header("content-type"), Some("application/json"));
    assert_eq!(sent.header("accept"), Some("text/event-stream"));
    assert_eq!(
        sent.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(body["stream"], serde_json::json!(true));
    assert_eq!(body["model"], serde_json::json!("openai/gpt-5"));
    assert_eq!(body["messages"][1]["content"], serde_json::json!("hello"));
    // A loopback endpoint is not OpenRouter, so it gets the generic knob.
    assert_eq!(
        body["stream_options"],
        serde_json::json!({"include_usage": true})
    );
}

#[test]
fn a_fragmented_stream_reassembles_over_the_wire() {
    // The stream arrives in pieces that fall mid-event and mid-character.
    let body = format!(
        "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
        text_chunk("héllo 🦀"),
        finish_chunk("stop")
    );
    let whole = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n{body}");
    let script = whole
        .as_bytes()
        .chunks(3)
        .fold(Script::new(), |script, piece| {
            script.write(piece).pause(Duration::from_millis(1))
        });
    let server = MockServer::start_one(script).unwrap();

    let completion = provider(&server)
        .complete(&request(), &mut Discard)
        .unwrap();
    assert_eq!(completion.content, "héllo 🦀");
}

#[test]
fn parallel_tool_calls_survive_the_wire() {
    let payloads = [
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"read_file","arguments":""}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","type":"function","function":{"name":"grep","arguments":""}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"path\":\"src/"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"{\"q\":\"fn "}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"main.rs\"}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"main\"}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
    ];
    let server = MockServer::start_one(sse_response(&payloads)).unwrap();

    let completion = provider(&server)
        .complete(&request(), &mut Discard)
        .unwrap();

    assert_eq!(completion.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(completion.tool_calls.len(), 2);
    assert_eq!(completion.tool_calls[0].name(), "read_file");
    assert_eq!(
        completion.tool_calls[0].arguments(),
        r#"{"path":"src/main.rs"}"#
    );
    assert_eq!(completion.tool_calls[1].name(), "grep");
    assert_eq!(completion.tool_calls[1].arguments(), r#"{"q":"fn main"}"#);
}

/// Every way a completion can fail, each one landing on the variant the
/// agent layer reacts to.
#[test]
fn every_error_path_is_typed() {
    type Check = fn(&ProviderError) -> bool;
    let cases: Vec<(&str, Script, Check)> =
        vec![
        (
            "401 with an error body",
            plain_response(
                401,
                "Unauthorized",
                "application/json",
                r#"{"error":{"message":"No auth credentials found","code":401}}"#,
            ),
            |e| matches!(e, ProviderError::Auth(detail) if detail.contains("No auth")),
        ),
        (
            "402 out of credit",
            plain_response(
                402,
                "Payment Required",
                "application/json",
                r#"{"error":{"message":"Insufficient credits","code":402}}"#,
            ),
            |e| matches!(e, ProviderError::Credits(_)),
        ),
        (
            "429 with Retry-After",
            Script::new().write(
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 12\r\nContent-Length: 2\r\n\r\n{}",
            ),
            |e| matches!(e, ProviderError::RateLimited { retry_after: Some(12), .. }),
        ),
        (
            "502 from a gateway, not even JSON",
            plain_response(502, "Bad Gateway", "text/html", "<html>upstream</html>"),
            |e| matches!(e, ProviderError::Unavailable(detail) if detail.contains("upstream")),
        ),
        (
            "400 the endpoint explains",
            plain_response(
                400,
                "Bad Request",
                "application/json",
                r#"{"error":{"message":"model not found","code":400}}"#,
            ),
            |e| matches!(e, ProviderError::Api { status: Some(400), .. }),
        ),
        (
            "an error event mid-stream",
            sse_response(&[
                &text_chunk("starting"),
                r#"{"error":{"message":"upstream is overloaded","code":503}}"#,
            ]),
            |e| matches!(e, ProviderError::Unavailable(_)),
        ),
        (
            "the connection drops mid-stream",
            Script::new()
                .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
                .write(format!("data: {}\n\n", text_chunk("half an ans")))
                .close(),
            |e| matches!(e, ProviderError::Truncated(_)),
        ),
        (
            "a 200 that is not a stream at all",
            plain_response(
                200,
                "OK",
                "application/json",
                r#"{"choices":[{"message":{"content":"unstreamed"}}]}"#,
            ),
            |e| matches!(e, ProviderError::Protocol(detail) if detail.contains("event stream")),
        ),
        (
            "a data payload that is not a chunk",
            Script::new().write(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: not json\n\n",
            ),
            |e| matches!(e, ProviderError::Protocol(_)),
        ),
    ];

    let (scripts, expectations): (Vec<_>, Vec<_>) = cases
        .into_iter()
        .map(|(name, script, check)| (script, (name, check)))
        .unzip();
    let server = MockServer::start(scripts).unwrap();
    let provider = provider(&server);

    for (name, check) in expectations {
        let error = provider.complete(&request(), &mut Discard).expect_err(name);
        assert!(check(&error), "case {name:?}: {error}");
    }
}

#[test]
fn a_cancelled_turn_kills_the_request() {
    struct StopAfterFirst;
    impl EventSink for StopAfterFirst {
        fn on_content(&mut self, _text: &str) -> std::io::Result<()> {
            Err(std::io::Error::other("^C"))
        }
    }

    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            .write(format!("data: {}\n\n", text_chunk("first")))
            // Long enough that a prompt return proves the transfer was cut
            // rather than left to run out.
            .pause(Duration::from_secs(5))
            .write(format!("data: {}\n\n", finish_chunk("stop"))),
    )
    .unwrap();

    let started = std::time::Instant::now();
    let error = provider(&server)
        .complete(&request(), &mut StopAfterFirst)
        .unwrap_err();
    let elapsed = started.elapsed();

    assert!(matches!(error, ProviderError::Aborted(_)), "{error}");
    assert!(
        elapsed < Duration::from_secs(3),
        "not cancelled: {elapsed:?}"
    );
}

#[test]
fn a_stalled_endpoint_times_out() {
    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            .pause(Duration::from_secs(30)),
    )
    .unwrap();

    let provider = provider(&server).with_timeouts(Timeouts {
        connect: Duration::from_secs(5),
        total: Duration::from_secs(2),
        stall: Duration::from_secs(2),
    });
    let error = provider.complete(&request(), &mut Discard).unwrap_err();

    assert!(
        matches!(error, ProviderError::Net(gears::net::NetError::Timeout(_))),
        "{error}"
    );
}
