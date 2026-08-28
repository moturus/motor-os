#![cfg(unix)]

use std::time::{Duration, Instant};

use gears::cancellation::Cancellation;
use gears::mock::{MockServer, Script, provider_conformance_corpus, sse_response};
use gears::net::host_curl::HostCurl;
use gears::net::{EgressPolicy, Timeouts};
use gears::provider::{
    Endpoint, EventSink, Message, OpenAiCompat, Provider, Request, StreamEvent, ToolSpec,
};

fn provider(server: &MockServer) -> OpenAiCompat<HostCurl> {
    let policy = EgressPolicy::new(&["127.0.0.1".to_string()]).allow_loopback_http_for_tests();
    OpenAiCompat::new(
        HostCurl::new(policy).unwrap(),
        Endpoint::new(&server.url("/v1")).unwrap(),
    )
    .without_key()
    .with_timeouts(Timeouts {
        connect: std::time::Duration::from_secs(2),
        total: std::time::Duration::from_secs(10),
        stall: std::time::Duration::from_secs(2),
    })
}

fn request() -> Request {
    Request::new("test/model", vec![Message::user("hello")])
}

#[derive(Default)]
struct Rendered {
    events: Vec<StreamEvent>,
    abort_after_content: bool,
}

impl EventSink for Rendered {
    fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()> {
        if self.abort_after_content && matches!(event, StreamEvent::Text(_)) {
            return Err(std::io::Error::other("scripted cancellation"));
        }
        self.events.push(event);
        Ok(())
    }
}

#[test]
fn normalized_request_streams_through_the_real_transport() {
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"reasoning":"think "}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"hello"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let mut rendered = Rendered::default();
    let completion = provider(&server)
        .complete(&request(), &mut rendered)
        .unwrap();
    assert_eq!(completion.content, "hello");
    assert_eq!(
        rendered.events,
        [
            StreamEvent::Reasoning("think ".to_string()),
            StreamEvent::Text("hello".to_string())
        ]
    );
    let body: serde_json::Value = serde_json::from_slice(&server.requests()[0].body).unwrap();
    assert_eq!(body["messages"][0]["role"], "user");
}

#[test]
fn cancellation_interrupts_a_silent_transport() {
    let first = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"before\"}}]}\n\n";
    let last = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" after\"}}]}\n\ndata: [DONE]\n\n";
    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            .write(first)
            .pause(Duration::from_secs(5))
            .write(last),
    )
    .unwrap();
    let cancellation = Cancellation::new();
    let signal = cancellation.clone();
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        signal.cancel();
    });
    let started = Instant::now();
    let mut rendered = Rendered::default();
    let result =
        provider(&server).complete(&request().with_cancellation(cancellation), &mut rendered);
    cancel.join().unwrap();

    assert!(
        matches!(result, Err(gears::provider::ProviderError::Aborted(_))),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(rendered.events, [StreamEvent::Text("before".to_string())]);
}

#[test]
fn the_provider_corpus_survives_subprocess_curl() {
    let cases = provider_conformance_corpus();
    let scripts = cases.iter().map(|case| case.script()).collect();
    let server = MockServer::start(scripts).unwrap();
    for case in cases {
        let mut rendered = Rendered {
            abort_after_content: case.abort_after_content,
            ..Rendered::default()
        };
        let actual = provider(&server)
            .with_timeouts(case.timeouts)
            .complete(&request(), &mut rendered);
        assert!(
            case.expected.accepts(&actual),
            "case {:?}: {actual:?}",
            case.name
        );
    }
}

#[test]
fn tool_specs_are_mapped_at_the_adapter_boundary() {
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    provider(&server)
        .complete(
            &request().with_tools(vec![ToolSpec::new(
                "sh",
                "shell",
                serde_json::json!({
                    "type": "object",
                    "properties": {"command": {"type": "string"}}
                }),
            )]),
            &mut Rendered::default(),
        )
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&server.requests()[0].body).unwrap();
    assert_eq!(body["tools"][0]["function"]["name"], "sh");
    assert!(body["messages"][0].get("tool_calls").is_none());
}
