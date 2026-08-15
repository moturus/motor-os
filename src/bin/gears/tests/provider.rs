//! The provider against scripted endpoints: real curl, the in-process mock
//! server, no model provider anywhere. The corpus below is every response
//! shape gears has to survive, including all the ways one can fail.

use gears::mock::{MockServer, provider_conformance_corpus, provider_scenario, sse_response};
use gears::net::EgressPolicy;
use gears::net::host_curl::HostCurl;
use gears::provider::{
    ChatMessage, ChatRequest, Discard, Endpoint, EventSink, FinishReason, ModelProvider,
    OpenAiCompat, UsageMeter,
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

struct CorpusSink {
    abort_after_content: bool,
}

impl EventSink for CorpusSink {
    fn on_content(&mut self, _text: &str) -> std::io::Result<()> {
        if self.abort_after_content {
            return Err(std::io::Error::other("scripted cancellation"));
        }
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
fn the_provider_corpus_survives_the_loopback_transport() {
    let cases = provider_conformance_corpus();
    let server = MockServer::start(cases.iter().map(|case| case.script()).collect()).unwrap();

    for case in cases {
        let started = std::time::Instant::now();
        let actual = provider(&server).with_timeouts(case.timeouts).complete(
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
        if case.abort_after_content {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(3),
                "case {:?} did not cancel promptly",
                case.name
            );
        }
    }
}

#[test]
fn the_shared_tool_round_is_valid_provider_traffic() {
    let server = MockServer::start(provider_scenario("tool-round").unwrap()).unwrap();

    let tool = provider(&server)
        .complete(&request(), &mut Discard)
        .unwrap();
    assert_eq!(tool.finish_reason, Some(FinishReason::ToolCalls));
    assert_eq!(tool.tool_calls.len(), 1);
    assert_eq!(tool.tool_calls[0].name(), "write_file");
    assert_eq!(
        tool.tool_calls[0].arguments(),
        r#"{"path":"result.txt","content":"made by gears\n"}"#
    );

    let final_answer = provider(&server)
        .complete(&request(), &mut Discard)
        .unwrap();
    assert_eq!(final_answer.content, "tool complete");
    assert_eq!(final_answer.finish_reason, Some(FinishReason::Stop));
    assert_eq!(final_answer.usage.prompt_tokens, 7);
    assert_eq!(final_answer.usage.completion_tokens, 3);
}
