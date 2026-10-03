#![cfg(unix)]

use std::time::{Duration, Instant};

use gears::cancellation::Cancellation;
use gears::mock::{MockServer, Script, plain_response, provider_conformance_corpus, sse_response};
use gears::net::host_curl::HostCurl;
use gears::net::motor_curl::MotorCurl;
use gears::net::{EgressPolicy, Timeouts};
use gears::provider::{
    Endpoint, EventSink, Message, OpenAiCompat, Provider, Request, StreamEvent, ToolSpec,
};

fn provider(server: &MockServer) -> OpenAiCompat<HostCurl> {
    let policy = EgressPolicy::new(&["127.0.0.1".to_string()])
        .with_plain_http_allowlist(&["127.0.0.1".to_string()]);
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
    cancel_on_notice: Option<Cancellation>,
    signal_text: Option<std::sync::mpsc::Sender<()>>,
}

impl EventSink for Rendered {
    fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()> {
        if self.abort_after_content && matches!(event, StreamEvent::Text(_)) {
            return Err(std::io::Error::other("scripted cancellation"));
        }
        if matches!(event, StreamEvent::Notice(_))
            && let Some(signal) = &self.cancel_on_notice
        {
            signal.cancel();
        }
        if matches!(event, StreamEvent::Text(_))
            && let Some(signal) = self.signal_text.take()
        {
            signal.send(()).unwrap();
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
fn rate_limit_retries_before_output_and_reports_the_wait() {
    let limited = Script::new()
        .write("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n");
    let server = MockServer::start(vec![
        limited,
        sse_response(&[
            r#"{"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}"#,
        ]),
    ])
    .unwrap();
    let mut rendered = Rendered::default();
    let completion = provider(&server)
        .complete(&request(), &mut rendered)
        .unwrap();
    assert_eq!(completion.content, "ok");
    assert_eq!(server.requests().len(), 2);
    assert!(
        matches!(&rendered.events[0], StreamEvent::Notice(text) if text.contains("429") || text.contains("rate limited"))
    );
    assert_eq!(rendered.events[1], StreamEvent::Text("ok".into()));
}

#[test]
fn visible_partial_output_is_never_retried() {
    let partial = Script::new()
        .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
        .write("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"part\"}}]}\n\n")
        .close();
    let server = MockServer::start(vec![partial, sse_response(&[])]).unwrap();
    let mut rendered = Rendered::default();
    assert!(
        provider(&server)
            .complete(&request(), &mut rendered)
            .is_err()
    );
    assert_eq!(server.requests().len(), 1);
    assert_eq!(rendered.events, [StreamEvent::Text("part".into())]);
}

#[test]
fn cancellation_ends_a_retry_wait() {
    let limited = Script::new()
        .write("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 5\r\nContent-Length: 0\r\n\r\n");
    let server = MockServer::start(vec![limited, sse_response(&[])]).unwrap();
    let cancellation = Cancellation::new();
    let signal = cancellation.clone();
    let mut rendered = Rendered {
        cancel_on_notice: Some(signal),
        ..Rendered::default()
    };
    let started = Instant::now();
    let result =
        provider(&server).complete(&request().with_cancellation(cancellation), &mut rendered);
    assert!(matches!(
        result,
        Err(gears::provider::ProviderError::Aborted(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(server.requests().len(), 1);
    assert!(matches!(
        rendered.events.as_slice(),
        [StreamEvent::Notice(_)]
    ));
}

#[test]
fn client_errors_are_not_retried() {
    let server = MockServer::start(vec![
        plain_response(400, "Bad Request", "text/plain", "invalid"),
        sse_response(&[]),
    ])
    .unwrap();
    assert!(
        provider(&server)
            .complete(&request(), &mut Rendered::default())
            .is_err()
    );
    assert_eq!(server.requests().len(), 1);
}

/// The component gate selects the in-tree curl binary; ordinary host tests
/// exercise the same Motor transport against upstream curl.
#[test]
fn provider_streams_through_the_motor_curl_transport() {
    let program = std::env::var_os("MOTOR_CURL_TEST_PROGRAM").unwrap_or_else(|| "curl".into());
    let server = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"content":"hello "}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"motor"},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let policy =
        EgressPolicy::new(&["127.0.0.1".into()]).with_plain_http_allowlist(&["127.0.0.1".into()]);
    let http = MotorCurl::with_program(program.to_str().expect("curl path must be UTF-8"), policy)
        .with_secret("OPENROUTER_API_KEY", "fixture-motor-key");
    let provider = OpenAiCompat::new(http, Endpoint::new(&server.url("/v1")).unwrap());
    let mut rendered = Rendered::default();
    let completion = provider.complete(&request(), &mut rendered).unwrap();
    assert_eq!(completion.content, "hello motor");
    assert_eq!(
        rendered.events,
        [
            StreamEvent::Text("hello ".into()),
            StreamEvent::Text("motor".into())
        ]
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target, "/v1/chat/completions");
    assert_eq!(
        requests[0].header("Authorization"),
        Some("Bearer fixture-motor-key")
    );
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["model"], "test/model");
    assert_eq!(body["stream"], true);
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
    let (sender, receiver) = std::sync::mpsc::channel();
    let cancel = std::thread::spawn(move || {
        receiver
            .recv()
            .expect("transport must deliver its first text");
        signal.cancel();
    });
    let started = Instant::now();
    let mut rendered = Rendered {
        signal_text: Some(sender),
        ..Rendered::default()
    };
    let result =
        provider(&server).complete(&request().with_cancellation(cancellation), &mut rendered);
    rendered.signal_text.take();
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
    let scripts = cases
        .iter()
        .flat_map(|case| {
            let attempts = match case.expected {
                gears::mock::ProviderExpectation::RateLimited(_)
                | gears::mock::ProviderExpectation::Unavailable
                | gears::mock::ProviderExpectation::Timeout => 3,
                _ => 1,
            };
            (0..attempts).map(move |_| case.script())
        })
        .collect();
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
