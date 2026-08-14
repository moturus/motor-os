//! A scripted HTTP server on loopback. Responses are written piece by piece
//! with the connection in no-delay mode, so a test can split a stream
//! mid-event, mid-token or mid-UTF-8 and have the client really see it that
//! way.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// One step of a scripted response.
pub enum Piece {
    /// Write these bytes and flush them as their own segment.
    Write(Vec<u8>),
    /// Wait, leaving the client blocked on a read.
    Pause(Duration),
    /// Close the connection here, mid-response.
    Close,
}

/// What the server does for one connection.
#[derive(Default)]
pub struct Script {
    pieces: Vec<Piece>,
}

impl Script {
    pub fn new() -> Script {
        Script::default()
    }

    pub fn write(mut self, bytes: impl Into<Vec<u8>>) -> Script {
        self.pieces.push(Piece::Write(bytes.into()));
        self
    }

    pub fn pause(mut self, delay: Duration) -> Script {
        self.pieces.push(Piece::Pause(delay));
        self
    }

    /// Hang up here. Anything scripted after this never runs.
    pub fn close(mut self) -> Script {
        self.pieces.push(Piece::Close);
        self
    }

    /// Consume the script for an out-of-process transport. Scenario content
    /// stays in this std-only module; the Motor TLS mock only plays the pieces.
    pub fn into_pieces(self) -> impl Iterator<Item = Piece> {
        self.pieces.into_iter()
    }
}

/// A script and what it is for. With one agent talking, order is enough to
/// say which response belongs to which request; with several, whose request
/// arrives first is nobody's to decide, so a route says what the request has
/// to contain — `"model":"test/scout"` picks out one agent's traffic.
pub struct Route {
    needle: String,
    script: Script,
}

impl Route {
    pub fn new(needle: impl Into<String>, script: Script) -> Route {
        Route {
            needle: needle.into(),
            script,
        }
    }

    /// A script for whatever asks next: what an ordered list of scripts is.
    fn anything(script: Script) -> Route {
        Route::new("", script)
    }
}

/// A request as the server received it.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(have, _)| have.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub struct MockServer {
    addr: SocketAddr,
    base_url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MockServer {
    /// Start a server that plays `scripts` to successive connections. A
    /// connection arriving after the scripts run out gets a 500, so an
    /// unexpected extra request fails a test instead of hanging it.
    pub fn start(scripts: Vec<Script>) -> std::io::Result<MockServer> {
        MockServer::start_routed(scripts.into_iter().map(Route::anything).collect())
    }

    /// The same, for tests where more than one agent is talking: each request
    /// gets the first unused route whose needle its body contains.
    pub fn start_routed(routes: Vec<Route>) -> std::io::Result<MockServer> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread = std::thread::spawn({
            let requests = Arc::clone(&requests);
            let shutdown = Arc::clone(&shutdown);
            move || serve(listener, routes, requests, shutdown)
        });

        Ok(MockServer {
            addr,
            base_url: format!("http://{addr}"),
            requests,
            shutdown,
            thread: Some(thread),
        })
    }

    pub fn start_one(script: Script) -> std::io::Result<MockServer> {
        MockServer::start(vec![script])
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The URL of `path` on this server; `path` starts with `/`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept: the loop re-checks the flag as soon as a
        // connection arrives, and this one carries no request.
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Accept forever, and give every connection a thread of its own. One at a
/// time would be simpler, and wrong: two agents talking at the same time is
/// exactly what this has to be able to serve, and a paused script must not
/// hold up somebody else's request.
fn serve(
    listener: TcpListener,
    routes: Vec<Route>,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    shutdown: Arc<AtomicBool>,
) {
    let routes = Arc::new(Mutex::new(routes));
    let mut connections: Vec<JoinHandle<()>> = Vec::new();
    for stream in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else { break };
        connections.push(std::thread::spawn({
            let routes = Arc::clone(&routes);
            let requests = Arc::clone(&requests);
            let shutdown = Arc::clone(&shutdown);
            move || answer(stream, &routes, &requests, &shutdown)
        }));
    }
    for connection in connections {
        let _ = connection.join();
    }
}

fn answer(
    mut stream: TcpStream,
    routes: &Mutex<Vec<Route>>,
    requests: &Mutex<Vec<RecordedRequest>>,
    shutdown: &AtomicBool,
) {
    let _ = stream.set_nodelay(true);
    // Read the request first: a connection that carries none (the shutdown
    // wake-up, a probe) must not consume a script.
    let Ok(request) = read_request(&mut stream) else {
        return;
    };
    let body = String::from_utf8_lossy(&request.body).into_owned();
    requests.lock().unwrap().push(request);
    let script = {
        let mut routes = routes.lock().unwrap();
        routes
            .iter()
            .position(|route| body.contains(&route.needle))
            .map(|index| routes.remove(index).script)
    };
    match script {
        Some(script) => play(&mut stream, script, shutdown),
        None => {
            let _ = stream.write_all(
                b"HTTP/1.1 500 No Script\r\nContent-Length: 22\r\n\r\nno script for this one",
            );
        }
    }
}

fn play(stream: &mut TcpStream, script: Script, shutdown: &AtomicBool) {
    for piece in script.pieces {
        match piece {
            Piece::Write(bytes) => {
                if stream.write_all(&bytes).is_err() || stream.flush().is_err() {
                    return; // The client hung up; nothing left to do.
                }
            }
            // Slice the wait so dropping the server does not have to sit
            // through a pause whose client already went away.
            Piece::Pause(delay) => {
                let slice = Duration::from_millis(20);
                let mut left = delay;
                while !left.is_zero() && !shutdown.load(Ordering::SeqCst) {
                    let step = left.min(slice);
                    std::thread::sleep(step);
                    left -= step;
                }
            }
            Piece::Close => return,
        }
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<RecordedRequest> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    let mut parts = line.trim_end().split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.to_string(), value.trim().to_string()));
        }
    }

    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;

    Ok(RecordedRequest {
        method,
        target,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal client: send `request`, read until the server hangs up.
    fn round_trip(server: &MockServer, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(server.addr).unwrap();
        stream.write_all(request).unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    }

    #[test]
    fn replays_a_script_and_records_the_request() {
        let server = MockServer::start_one(
            Script::new().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
        )
        .unwrap();
        let response = round_trip(
            &server,
            b"POST /api/v1/chat HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer sk-1\r\n\
              Content-Length: 7\r\n\r\n{\"a\":1}",
        );
        assert_eq!(response, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");

        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].target, "/api/v1/chat");
        assert_eq!(requests[0].header("authorization"), Some("Bearer sk-1"));
        assert_eq!(requests[0].body, b"{\"a\":1}");
    }

    #[test]
    fn pieces_arrive_separately() {
        let server = MockServer::start_one(
            Script::new()
                .write("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
                .pause(Duration::from_millis(50))
                .write("data: one\n\n")
                .pause(Duration::from_millis(50))
                .write("data: two\n\n"),
        )
        .unwrap();

        let mut stream = TcpStream::connect(server.addr).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        // The pause means the first read cannot see the body yet: the pacing
        // is what makes fragmented parsing testable.
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
        );

        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"data: one\n\ndata: two\n\n");
    }

    #[test]
    fn closing_mid_body_truncates_the_response() {
        let server = MockServer::start_one(
            Script::new()
                .write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
                .close()
                .write("never sent"),
        )
        .unwrap();
        let response = round_trip(&server, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(response.ends_with(b"\r\n\r\npartial"), "{response:?}");
    }

    /// Which script a request gets can depend on the request rather than on
    /// the order it arrived in — which is the only way to script two agents
    /// talking at once, since neither of them is waiting for the other.
    #[test]
    fn a_routed_script_goes_to_whoever_asked_for_it() {
        let body = |text: &str| {
            format!(
                "POST /v1/chat HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{text}",
                text.len()
            )
        };
        let server = MockServer::start_routed(vec![
            Route::new(
                r#""model":"scout""#,
                Script::new().write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nscout"),
            ),
            Route::new(
                r#""model":"root""#,
                Script::new().write("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nroot"),
            ),
        ])
        .unwrap();

        // The root asks second and still gets its own answer.
        let response = round_trip(&server, body(r#"{"model":"root"}"#).as_bytes());
        assert!(response.ends_with(b"root"), "{response:?}");
        let response = round_trip(&server, body(r#"{"model":"scout"}"#).as_bytes());
        assert!(response.ends_with(b"scout"), "{response:?}");
        // And each route is used once.
        let response = round_trip(&server, body(r#"{"model":"root"}"#).as_bytes());
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 500"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }

    #[test]
    fn an_unscripted_request_gets_an_error_not_a_hang() {
        let server = MockServer::start(Vec::new()).unwrap();
        let response = round_trip(&server, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 500 No Script"),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
}
