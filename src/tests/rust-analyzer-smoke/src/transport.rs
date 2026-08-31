use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};

use serde_json::{Value, json};

pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
pub const MAX_PENDING_REQUESTS: usize = 64;
pub const MAX_RETAINED_NOTIFICATIONS: usize = 256;
pub const MAX_RETAINED_NOTIFICATION_BYTES: usize = 32 * 1024 * 1024;
const MAX_HEADER_LEN: usize = 8 * 1024;

pub struct FrameReader<R> {
    input: BufReader<R>,
}

impl<R: Read> FrameReader<R> {
    pub fn new(input: R) -> Self {
        Self {
            input: BufReader::new(input),
        }
    }

    pub fn read(&mut self) -> io::Result<Option<Value>> {
        let mut content_len = None;
        let mut header_len: usize = 0;

        loop {
            let mut line = Vec::new();
            let remaining = MAX_HEADER_LEN - header_len;
            let read = self
                .input
                .by_ref()
                .take((remaining + 1) as u64)
                .read_until(b'\n', &mut line)?;
            if read == 0 {
                return if header_len == 0 {
                    Ok(None)
                } else {
                    Err(invalid("truncated LSP header"))
                };
            }
            if read > remaining {
                return Err(invalid("LSP header is too large"));
            }
            header_len += read;
            if !line.ends_with(b"\r\n") {
                return Err(invalid("LSP header line lacks CRLF"));
            }
            line.truncate(line.len() - 2);
            if line.is_empty() {
                break;
            }

            let (name, value) = split_header(&line)?;
            if name.eq_ignore_ascii_case(b"Content-Length") {
                if content_len.is_some() {
                    return Err(invalid("duplicate Content-Length"));
                }
                content_len = Some(parse_content_len(value)?);
            }
        }

        let content_len = content_len.ok_or_else(|| invalid("missing Content-Length"))?;
        if content_len > MAX_FRAME_LEN {
            return Err(invalid("LSP frame is too large"));
        }
        let mut body = vec![0; content_len];
        self.input.read_exact(&mut body)?;
        serde_json::from_slice(&body)
            .map(Some)
            .map_err(|error| invalid(format!("invalid LSP JSON: {error}")))
    }
}

pub fn write_frame(mut output: impl Write, message: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(message)
        .map_err(|error| invalid(format!("cannot encode LSP JSON: {error}")))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(invalid("LSP frame is too large"));
    }
    write!(output, "Content-Length: {}\r\n\r\n", body.len())?;
    output.write_all(&body)?;
    output.flush()
}

pub struct Dispatcher {
    next_id: u64,
    pending: HashMap<u64, Pending>,
    notifications: VecDeque<Notification>,
    notification_bytes: usize,
}

enum Pending {
    Waiting,
    Ready(Value),
}

#[derive(Debug, PartialEq)]
pub struct Notification {
    pub method: String,
    pub params: Value,
    encoded_len: usize,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self {
            next_id: 1,
            pending: HashMap::new(),
            notifications: VecDeque::new(),
            notification_bytes: 0,
        }
    }
}

impl Dispatcher {
    pub fn send_request(
        &mut self,
        output: impl Write,
        method: &str,
        params: Value,
    ) -> io::Result<u64> {
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(invalid("too many pending LSP requests"));
        }
        let id = self.next_id;
        let next_id = id
            .checked_add(1)
            .ok_or_else(|| invalid("LSP request ID exhausted"))?;
        write_frame(
            output,
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        )?;
        self.next_id = next_id;
        self.pending.insert(id, Pending::Waiting);
        Ok(id)
    }

    pub fn dispatch(&mut self, message: Value) -> io::Result<Option<Value>> {
        let object = message
            .as_object()
            .ok_or_else(|| invalid("LSP message is not an object"))?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(invalid("invalid LSP jsonrpc version"));
        }

        match (object.get("method"), object.get("id")) {
            (Some(method), id) => {
                let method = method
                    .as_str()
                    .ok_or_else(|| invalid("LSP method is not a string"))?;
                if let Some(id) = id {
                    Ok(Some(server_response(id, method)))
                } else {
                    self.record_notification(method, object.get("params"));
                    Ok(None)
                }
            }
            (None, Some(id)) => {
                let id = id
                    .as_u64()
                    .ok_or_else(|| invalid("unexpected LSP response ID"))?;
                if object.contains_key("result") == object.contains_key("error") {
                    return Err(invalid("LSP response needs one result or error"));
                }
                let state = self
                    .pending
                    .get_mut(&id)
                    .ok_or_else(|| invalid("response for unknown LSP request"))?;
                if matches!(state, Pending::Ready(_)) {
                    return Err(invalid("duplicate LSP response"));
                }
                *state = Pending::Ready(message);
                Ok(None)
            }
            (None, None) => Err(invalid("unclassified LSP message")),
        }
    }

    pub fn take_response(&mut self, id: u64) -> Option<Value> {
        if !matches!(self.pending.get(&id), Some(Pending::Ready(_))) {
            return None;
        }
        match self.pending.remove(&id) {
            Some(Pending::Ready(message)) => Some(message),
            _ => unreachable!(),
        }
    }

    pub fn notifications(&self) -> impl DoubleEndedIterator<Item = &Notification> {
        self.notifications.iter()
    }

    fn record_notification(&mut self, method: &str, params: Option<&Value>) {
        if !matches!(
            method,
            "textDocument/publishDiagnostics" | "$/progress" | "experimental/serverStatus"
        ) {
            return;
        }
        let params = params.cloned().unwrap_or(Value::Null);
        let encoded_len = method.len() + params.to_string().len();
        while self.notifications.len() == MAX_RETAINED_NOTIFICATIONS
            || self.notification_bytes.saturating_add(encoded_len) > MAX_RETAINED_NOTIFICATION_BYTES
        {
            let Some(discarded) = self.notifications.pop_front() else {
                return;
            };
            self.notification_bytes -= discarded.encoded_len;
        }
        self.notification_bytes += encoded_len;
        self.notifications.push_back(Notification {
            method: method.to_owned(),
            params,
            encoded_len,
        });
    }
}

fn server_response(id: &Value, method: &str) -> Value {
    match method {
        "window/workDoneProgress/create" | "client/registerCapability" => {
            json!({"jsonrpc": "2.0", "id": id, "result": null})
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": "unsupported server request"}
        }),
    }
}

fn split_header(line: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let split = line
        .windows(2)
        .position(|bytes| bytes == b": ")
        .ok_or_else(|| invalid("malformed LSP header"))?;
    let (name, rest) = line.split_at(split);
    if name.is_empty() {
        return Err(invalid("empty LSP header name"));
    }
    Ok((name, &rest[2..]))
}

fn parse_content_len(value: &[u8]) -> io::Result<usize> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(invalid("invalid Content-Length"));
    }
    let value = std::str::from_utf8(value).map_err(|_| invalid("invalid Content-Length"))?;
    value.parse().map_err(|_| invalid("invalid Content-Length"))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut bytes = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn reads_multiple_frames_and_eof() {
        let mut bytes = frame(br#"{"jsonrpc":"2.0","id":1}"#);
        bytes.extend(frame(br#"{"method":"initialized"}"#));
        let mut reader = FrameReader::new(bytes.as_slice());
        assert_eq!(reader.read().unwrap().unwrap()["id"], 1);
        assert_eq!(reader.read().unwrap().unwrap()["method"], "initialized");
        assert_eq!(reader.read().unwrap(), None);
    }

    #[test]
    fn writes_canonical_frame() {
        let message = json!({"jsonrpc": "2.0", "id": 7, "result": null});
        let body = serde_json::to_vec(&message).unwrap();
        let mut output = Vec::new();
        write_frame(&mut output, &message).unwrap();
        assert_eq!(output, frame(&body));
    }

    #[test]
    fn rejects_malformed_headers() {
        for bytes in [
            b"Content-Length: 2\n\n{}".as_slice(),
            b"Content-Type: x\r\n\r\n{}",
            b"Content-Length: x\r\n\r\n{}",
            b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"Broken\r\n\r\n{}",
        ] {
            assert_eq!(
                FrameReader::new(bytes).read().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn rejects_oversize_truncated_and_invalid_json() {
        let oversized = format!("Content-Length: {}\r\n\r\n", MAX_FRAME_LEN + 1);
        assert!(FrameReader::new(oversized.as_bytes()).read().is_err());
        let oversized_header = vec![b'x'; MAX_HEADER_LEN + 1];
        assert!(
            FrameReader::new(oversized_header.as_slice())
                .read()
                .is_err()
        );
        assert_eq!(
            FrameReader::new(b"Content-Length: 2\r\n\r\n{".as_slice())
                .read()
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(FrameReader::new(frame(b"xx").as_slice()).read().is_err());
    }

    #[test]
    fn correlates_responses_and_bounds_pending_requests() {
        let mut dispatcher = Dispatcher::default();
        let mut output = Vec::new();
        let first = dispatcher
            .send_request(&mut output, "initialize", json!({}))
            .unwrap();
        let second = dispatcher
            .send_request(&mut output, "shutdown", Value::Null)
            .unwrap();
        let mut sent = FrameReader::new(output.as_slice());
        assert_eq!(sent.read().unwrap().unwrap()["id"], first);
        assert_eq!(sent.read().unwrap().unwrap()["method"], "shutdown");
        dispatcher
            .dispatch(json!({"jsonrpc": "2.0", "id": second, "result": null}))
            .unwrap();
        assert!(dispatcher.take_response(first).is_none());
        assert_eq!(dispatcher.take_response(second).unwrap()["id"], second);
        assert!(
            dispatcher
                .dispatch(json!({"jsonrpc": "2.0", "id": 999, "result": null}))
                .is_err()
        );

        let mut full = Dispatcher::default();
        for _ in 0..MAX_PENDING_REQUESTS {
            full.send_request(io::sink(), "test", Value::Null).unwrap();
        }
        assert!(full.send_request(io::sink(), "test", Value::Null).is_err());
    }

    #[test]
    fn answers_server_requests() {
        let mut dispatcher = Dispatcher::default();
        for (id, method) in [
            (json!(7), "window/workDoneProgress/create"),
            (json!("server-id"), "client/registerCapability"),
        ] {
            let reply = dispatcher
                .dispatch(json!({"jsonrpc": "2.0", "id": id, "method": method}))
                .unwrap()
                .unwrap();
            assert_eq!(reply["id"], id);
            assert_eq!(reply["result"], Value::Null);
        }
        let reply = dispatcher
            .dispatch(json!({"jsonrpc": "2.0", "id": 8, "method": "unknown"}))
            .unwrap()
            .unwrap();
        assert_eq!(reply["error"]["code"], -32601);
    }

    #[test]
    fn retains_only_bounded_relevant_notifications() {
        let mut dispatcher = Dispatcher::default();
        dispatcher
            .dispatch(json!({"jsonrpc": "2.0", "method": "window/logMessage"}))
            .unwrap();
        for method in ["$/progress", "experimental/serverStatus"] {
            dispatcher
                .dispatch(json!({"jsonrpc": "2.0", "method": method}))
                .unwrap();
        }
        assert_eq!(dispatcher.notifications().count(), 2);

        let mut dispatcher = Dispatcher::default();
        for sequence in 0..MAX_RETAINED_NOTIFICATIONS + 3 {
            dispatcher
                .dispatch(json!({
                    "jsonrpc": "2.0",
                    "method": "textDocument/publishDiagnostics",
                    "params": {"sequence": sequence}
                }))
                .unwrap();
        }
        let retained: Vec<_> = dispatcher.notifications().collect();
        assert_eq!(retained.len(), MAX_RETAINED_NOTIFICATIONS);
        assert_eq!(retained[0].params["sequence"], 3);
    }
}
