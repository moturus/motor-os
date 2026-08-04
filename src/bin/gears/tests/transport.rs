//! The host transport driving the real `curl` binary against the in-process
//! mock server. Nothing here touches a model provider or the network beyond
//! loopback.

use std::time::{Duration, Instant};

use gears::mock::{MockServer, Script};
use gears::net::host_curl::HostCurl;
use gears::net::{
    CollectSink, EgressPolicy, HttpClient, HttpRequest, HttpSink, NetError, ResponseHead, Url,
};

fn client() -> HostCurl {
    let policy = EgressPolicy::new(&["127.0.0.1".to_string()]).allow_loopback_http_for_tests();
    HostCurl::new(policy).unwrap()
}

fn get(server: &MockServer, path: &str) -> HttpRequest {
    HttpRequest::get(Url::parse(&server.url(path)).unwrap())
}

/// A sink that keeps chunk boundaries, so a test can tell streaming from
/// buffering.
#[derive(Default)]
struct ChunkSink {
    head: Option<ResponseHead>,
    chunks: Vec<Vec<u8>>,
}

impl ChunkSink {
    fn body(&self) -> Vec<u8> {
        self.chunks.concat()
    }
}

impl HttpSink for ChunkSink {
    fn on_head(&mut self, head: &ResponseHead) -> std::io::Result<()> {
        self.head = Some(head.clone());
        Ok(())
    }

    fn on_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.chunks.push(bytes.to_vec());
        Ok(())
    }
}

#[test]
fn fetches_a_whole_response() {
    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"),
    )
    .unwrap();

    let mut sink = CollectSink::default();
    let head = client().execute(&get(&server, "/x"), &mut sink).unwrap();

    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-type"), Some("text/plain"));
    assert_eq!(sink.body, b"hello");
    assert_eq!(sink.head, Some(head));
    assert_eq!(server.requests()[0].method, "GET");
    assert_eq!(server.requests()[0].target, "/x");
}

#[test]
fn posts_a_body_and_streams_the_reply_in_pieces() {
    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            .pause(Duration::from_millis(60))
            .write("data: one\n\n")
            .pause(Duration::from_millis(60))
            .write("data: two\n\n"),
    )
    .unwrap();

    let request = HttpRequest::post(
        Url::parse(&server.url("/api/v1/chat/completions")).unwrap(),
        br#"{"model":"m"}"#.to_vec(),
    )
    .header("Content-Type", "application/json");

    let mut sink = ChunkSink::default();
    let head = client().execute(&request, &mut sink).unwrap();

    assert_eq!(head.status, 200);
    assert_eq!(sink.body(), b"data: one\n\ndata: two\n\n");
    // The point of the pauses: the body reached the sink as it arrived
    // rather than in one buffered lump at the end.
    assert!(sink.chunks.len() >= 2, "not streamed: {:?}", sink.chunks);

    let request = &server.requests()[0];
    assert_eq!(request.method, "POST");
    assert_eq!(request.body, br#"{"model":"m"}"#);
    assert_eq!(request.header("content-type"), Some("application/json"));
    // -H 'Expect:' suppresses the 100-continue handshake.
    assert_eq!(request.header("expect"), None);
    assert_eq!(request.header("accept-encoding"), Some("identity"));
}

#[test]
fn an_error_status_keeps_its_body() {
    let body = r#"{"error":{"code":429,"message":"rate limited"}}"#;
    let server = MockServer::start_one(Script::new().write(format!(
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )))
    .unwrap();

    let mut sink = CollectSink::default();
    // Not an Err: the status and the body are what the provider layer needs
    // to build a useful error, which is why curl runs without --fail.
    let head = client().execute(&get(&server, "/x"), &mut sink).unwrap();

    assert_eq!(head.status, 429);
    assert!(!head.is_success());
    assert_eq!(head.header("retry-after"), Some("7"));
    assert_eq!(sink.body, body.as_bytes());
}

#[test]
fn a_truncated_body_is_a_typed_error() {
    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
            .close(),
    )
    .unwrap();

    let mut sink = CollectSink::default();
    let error = client()
        .execute(&get(&server, "/x"), &mut sink)
        .unwrap_err();

    assert!(matches!(error, NetError::Disconnected(_)), "{error}");
    // The head and the partial body still reached the sink.
    assert_eq!(sink.head.map(|h| h.status), Some(200));
    assert_eq!(sink.body, b"partial");
}

#[test]
fn a_sink_error_cancels_the_transfer() {
    struct Refuse;
    impl HttpSink for Refuse {
        fn on_head(&mut self, _: &ResponseHead) -> std::io::Result<()> {
            Ok(())
        }
        fn on_chunk(&mut self, _: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("cancelled"))
        }
    }

    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            .write("data: one\n\n")
            // Long enough that returning promptly proves curl was killed
            // rather than left to finish.
            .pause(Duration::from_secs(5))
            .write("data: two\n\n"),
    )
    .unwrap();

    let started = Instant::now();
    let error = client()
        .execute(&get(&server, "/x"), &mut Refuse)
        .unwrap_err();
    let elapsed = started.elapsed();

    assert!(matches!(error, NetError::Aborted(_)), "{error}");
    assert!(
        elapsed < Duration::from_secs(3),
        "curl outlived the abort: {elapsed:?}"
    );
}

#[test]
fn a_secret_header_is_expanded_without_entering_the_environment() {
    const ENV: &str = "GEARS_TEST_TRANSPORT_KEY";
    assert!(
        std::env::var_os(ENV).is_none(),
        "the test's premise is that gears does not hold the key in its own environment"
    );

    let server =
        MockServer::start_one(Script::new().write("HTTP/1.1 204 No Content\r\n\r\n")).unwrap();
    let request = get(&server, "/x").secret_header("Authorization", "Bearer ", ENV);

    let head = client()
        .with_secret(ENV, "sk-mock-42")
        .execute(&request, &mut CollectSink::default())
        .unwrap();

    assert_eq!(head.status, 204);
    assert_eq!(
        server.requests()[0].header("authorization"),
        Some("Bearer sk-mock-42")
    );
}

#[test]
fn an_unset_secret_fails_before_anything_is_sent() {
    let server = MockServer::start_one(Script::new().write("HTTP/1.1 200 OK\r\n\r\n")).unwrap();
    let request =
        get(&server, "/x").secret_header("Authorization", "Bearer ", "GEARS_TEST_UNSET_KEY");

    let error = client()
        .execute(&request, &mut CollectSink::default())
        .unwrap_err();

    assert!(matches!(error, NetError::BadRequest(_)), "{error}");
    assert!(server.requests().is_empty(), "a request went out anyway");
}

#[test]
fn egress_policy_blocks_before_curl_runs() {
    let server = MockServer::start_one(Script::new().write("HTTP/1.1 200 OK\r\n\r\n")).unwrap();
    let strict = HostCurl::new(EgressPolicy::new(&["openrouter.ai".to_string()])).unwrap();

    let error = strict
        .execute(&get(&server, "/x"), &mut CollectSink::default())
        .unwrap_err();

    assert!(matches!(error, NetError::Forbidden(_)), "{error}");
    assert!(server.requests().is_empty(), "a request went out anyway");
}

/// Step 1's exit criterion: every response shape in the corpus, streamed
/// through subprocess curl, reconstructs the exact event sequence. Step 10
/// replays this same corpus against the Motor backend.
#[test]
fn the_sse_corpus_survives_the_host_transport() {
    let cases = gears::mock::sse_corpus();
    let (scripts, expectations): (Vec<_>, Vec<_>) = cases
        .into_iter()
        .map(|case| (case.script, (case.name, case.expected)))
        .unzip();
    let server = MockServer::start(scripts).unwrap();
    let client = client();

    for (name, expected) in expectations {
        let (head, payloads) =
            gears::mock::collect_sse(&client, &server.url("/v1/chat/completions"))
                .unwrap_or_else(|e| panic!("case {name:?}: {e}"));
        assert_eq!(head.status, 200, "case {name:?}");
        assert_eq!(payloads, expected, "case {name:?}");
        assert_eq!(
            payloads.last().map(String::as_str),
            Some("[DONE]"),
            "case {name:?}: the stream did not finish"
        );
    }
}

/// A stream cut before `[DONE]` reaches the sink as a short event list, not
/// as an error: with no Content-Length, the close *is* the end of the body.
/// Detecting the truncation is the provider layer's job in step 2.
#[test]
fn a_cut_stream_ends_without_the_done_sentinel() {
    let server = MockServer::start_one(
        Script::new()
            .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
            .write("data: one\n\n")
            .close(),
    )
    .unwrap();

    let (head, payloads) =
        gears::mock::collect_sse(&client(), &server.url("/v1/chat/completions")).unwrap();

    assert_eq!(head.status, 200);
    assert_eq!(payloads, ["one"]);
}

#[test]
fn an_error_response_is_not_parsed_as_a_stream() {
    let body = r#"{"error":{"message":"no credits"}}"#;
    let server = MockServer::start_one(Script::new().write(format!(
        "HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )))
    .unwrap();

    let mut payloads: Vec<String> = Vec::new();
    let (head, raw) = {
        let mut sink = gears::net::sse::SseSink::new(|event: gears::net::sse::SseEvent| {
            payloads.push(event.data);
            Ok(())
        });
        let head = client()
            .execute(&get(&server, "/v1/chat/completions"), &mut sink)
            .unwrap();
        (head, sink.raw().to_vec())
    };

    assert_eq!(head.status, 402);
    assert!(payloads.is_empty(), "an error body was parsed as events");
    // The body is kept verbatim: it is what explains the failure.
    assert_eq!(raw, body.as_bytes());
}

#[test]
fn a_refused_connection_is_a_typed_error() {
    // Port 1 on loopback: nothing listens there.
    let request = HttpRequest::get(Url::parse("http://127.0.0.1:1/x").unwrap());
    let error = client()
        .execute(&request, &mut CollectSink::default())
        .unwrap_err();
    assert!(matches!(error, NetError::Connect(_)), "{error}");
}
