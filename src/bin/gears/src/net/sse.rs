//! Server-sent events, parsed incrementally.
//!
//! Streamed completions arrive as `text/event-stream`, and the bytes are
//! split wherever the network put them: mid-event, mid-line, mid-UTF-8
//! character. This parser holds partial input and emits only whole events,
//! following the WHATWG event-stream rules — all three line terminators,
//! `data:` lines joined with newlines, and `:` comment lines dropped, which
//! is what a provider's keep-alives during a long think look like.

/// A dispatched event. `event` and `id` are carried for completeness; the
/// OpenAI-compatible dialect gears speaks puts everything in `data`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub id: Option<String>,
}

impl SseEvent {
    /// The end-of-stream sentinel. A stream that ends without it was cut
    /// short, which is how a truncated completion is detected.
    pub fn is_done(&self) -> bool {
        self.data == "[DONE]"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseError {
    /// A line or event grew past what gears will buffer.
    TooLarge(String),
}

impl std::fmt::Display for SseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SseError::TooLarge(what) => write!(f, "event stream: {what}"),
        }
    }
}

impl std::error::Error for SseError {}

const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_DATA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub struct SseParser {
    line: Vec<u8>,
    /// The previous byte was CR: a following LF belongs to that terminator
    /// rather than ending a second, empty line.
    pending_cr: bool,
    event: Option<String>,
    data: String,
    has_data: bool,
    /// The last `id:` seen, which every later event carries.
    id: Option<String>,
}

impl SseParser {
    pub fn new() -> SseParser {
        SseParser::default()
    }

    /// Feed the next bytes, returning whatever events completed.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        let mut events = Vec::new();
        for &byte in bytes {
            if self.pending_cr {
                self.pending_cr = false;
                if byte == b'\n' {
                    continue; // The CR already ended that line.
                }
            }
            match byte {
                b'\r' => {
                    self.pending_cr = true;
                    self.end_line(&mut events)?;
                }
                b'\n' => self.end_line(&mut events)?,
                _ => {
                    if self.line.len() >= MAX_LINE_BYTES {
                        return Err(SseError::TooLarge(format!(
                            "a line exceeded {MAX_LINE_BYTES} bytes"
                        )));
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(events)
    }

    /// Dispatch a final event that the stream ended without a blank line
    /// after. The spec discards it; gears hands it over so a caller can
    /// decide, and an incomplete trailing *line* is always discarded.
    pub fn finish(&mut self) -> Option<SseEvent> {
        self.line.clear();
        self.dispatch()
    }

    fn end_line(&mut self, events: &mut Vec<SseEvent>) -> Result<(), SseError> {
        let line = String::from_utf8_lossy(&self.line).into_owned();
        self.line.clear();

        if line.is_empty() {
            if let Some(event) = self.dispatch() {
                events.push(event);
            }
            return Ok(());
        }
        if line.starts_with(':') {
            return Ok(()); // A comment, i.e. a keep-alive.
        }

        let (field, value) = match line.split_once(':') {
            // Exactly one leading space is part of the delimiter.
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line.as_str(), ""),
        };
        match field {
            "data" => {
                if self.data.len() + value.len() > MAX_DATA_BYTES {
                    return Err(SseError::TooLarge(format!(
                        "an event exceeded {MAX_DATA_BYTES} bytes"
                    )));
                }
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            "event" => self.event = Some(value.to_string()),
            "id" if !value.contains('\0') => self.id = Some(value.to_string()),
            // `retry` included: gears never reconnects on its own.
            _ => {}
        }
        Ok(())
    }

    fn dispatch(&mut self) -> Option<SseEvent> {
        if !self.has_data {
            // No data means no event, but a stray `event:` is still spent.
            self.event = None;
            return None;
        }
        self.has_data = false;
        Some(SseEvent {
            event: self.event.take(),
            data: std::mem::take(&mut self.data),
            id: self.id.clone(),
        })
    }
}

/// Cap on a non-stream body kept in memory. Error responses are small; a
/// completions endpoint answering with megabytes of something else is a
/// failure worth reporting rather than buffering.
const MAX_RAW_BYTES: usize = 1024 * 1024;

/// An [`HttpSink`](super::HttpSink) that decodes an event stream and hands
/// each event to a callback, which returns `Err` to cancel the transfer.
///
/// A response that is *not* an event stream — any error status, or a
/// provider answering with plain JSON — is collected verbatim into
/// [`raw`](Self::raw) instead, because that body is what explains why.
pub struct SseSink<F> {
    on_event: F,
    parser: SseParser,
    head: Option<super::ResponseHead>,
    is_stream: bool,
    raw: Vec<u8>,
    error: Option<SseError>,
}

impl<F: FnMut(SseEvent) -> std::io::Result<()>> SseSink<F> {
    pub fn new(on_event: F) -> SseSink<F> {
        SseSink {
            on_event,
            parser: SseParser::new(),
            head: None,
            is_stream: false,
            raw: Vec::new(),
            error: None,
        }
    }

    pub fn head(&self) -> Option<&super::ResponseHead> {
        self.head.as_ref()
    }

    /// The body of a response that was not an event stream.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The parse failure that stopped the transfer, if one did. Check this
    /// before reporting a transfer as merely aborted.
    pub fn take_error(&mut self) -> Option<SseError> {
        self.error.take()
    }

    /// Deliver a trailing event the stream ended without a blank line after.
    pub fn finish(&mut self) -> std::io::Result<()> {
        match self.parser.finish() {
            Some(event) => (self.on_event)(event),
            None => Ok(()),
        }
    }
}

impl<F: FnMut(SseEvent) -> std::io::Result<()>> super::HttpSink for SseSink<F> {
    fn on_head(&mut self, head: &super::ResponseHead) -> std::io::Result<()> {
        self.is_stream = head.is_success()
            && head
                .header("content-type")
                .is_some_and(|value| value.starts_with("text/event-stream"));
        self.head = Some(head.clone());
        Ok(())
    }

    fn on_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if !self.is_stream {
            if self.raw.len() + bytes.len() > MAX_RAW_BYTES {
                self.error = Some(SseError::TooLarge(format!(
                    "a non-stream body exceeded {MAX_RAW_BYTES} bytes"
                )));
                return Err(std::io::Error::other("body too large"));
            }
            self.raw.extend_from_slice(bytes);
            return Ok(());
        }
        match self.parser.feed(bytes) {
            Ok(events) => {
                for event in events {
                    (self.on_event)(event)?;
                }
                Ok(())
            }
            Err(e) => {
                let message = e.to_string();
                self.error = Some(e);
                Err(std::io::Error::other(message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &[u8]) -> Vec<SseEvent> {
        let mut parser = SseParser::new();
        parser.feed(input).unwrap()
    }

    fn data_of(events: &[SseEvent]) -> Vec<&str> {
        events.iter().map(|e| e.data.as_str()).collect()
    }

    #[test]
    fn parses_a_plain_stream() {
        let events = parse(b"data: one\n\ndata: two\n\n");
        assert_eq!(data_of(&events), ["one", "two"]);
        assert_eq!(events[0].event, None);
        assert_eq!(events[0].id, None);
    }

    #[test]
    fn accepts_every_line_terminator() {
        for terminator in ["\n", "\r\n", "\r"] {
            let input = format!("data: one{t}{t}data: two{t}{t}", t = terminator);
            let events = parse(input.as_bytes());
            assert_eq!(data_of(&events), ["one", "two"], "with {terminator:?}");
        }
    }

    #[test]
    fn joins_multiple_data_lines_with_newlines() {
        let events = parse(b"data: line one\ndata: line two\ndata: line three\n\n");
        assert_eq!(data_of(&events), ["line one\nline two\nline three"]);

        // An empty data line contributes an empty line, not nothing.
        assert_eq!(data_of(&parse(b"data:\ndata:\n\n")), ["\n"]);
        // A lone `data:` dispatches an event whose data is empty.
        assert_eq!(data_of(&parse(b"data:\n\n")), [""]);
    }

    #[test]
    fn drops_comments_and_keeps_alive() {
        // What OpenRouter sends while a model is thinking.
        let events = parse(b": OPENROUTER PROCESSING\n\n: OPENROUTER PROCESSING\n\ndata: x\n\n");
        assert_eq!(data_of(&events), ["x"]);
    }

    #[test]
    fn reads_event_id_and_unknown_fields() {
        let events = parse(b"event: delta\nid: 42\nretry: 500\nfuture: ?\ndata: x\n\ndata: y\n\n");
        assert_eq!(events[0].event.as_deref(), Some("delta"));
        assert_eq!(events[0].id.as_deref(), Some("42"));
        assert_eq!(events[0].data, "x");
        // The id persists; the event name does not.
        assert_eq!(events[1].id.as_deref(), Some("42"));
        assert_eq!(events[1].event, None);
    }

    #[test]
    fn handles_the_delimiter_exactly() {
        // One leading space is the delimiter; further spaces are data.
        assert_eq!(data_of(&parse(b"data:x\n\n")), ["x"]);
        assert_eq!(data_of(&parse(b"data: x\n\n")), ["x"]);
        assert_eq!(data_of(&parse(b"data:  x\n\n")), [" x"]);
        // A line with no colon is a field with an empty value, so a bare
        // `data` line does dispatch an event — with empty data.
        assert_eq!(data_of(&parse(b"data\n\n")), [""]);
        // Any other valueless field is ignored, as always.
        assert!(parse(b"event\n\n").is_empty());
        // Colons inside the value are kept.
        assert_eq!(
            data_of(&parse(b"data: {\"a\":\"b\"}\n\n")),
            ["{\"a\":\"b\"}"]
        );
    }

    #[test]
    fn blank_lines_alone_dispatch_nothing() {
        assert!(parse(b"\n\n\n").is_empty());
        assert!(parse(b"event: ping\n\n").is_empty());
        assert_eq!(data_of(&parse(b"\n\ndata: x\n\n\n\n")), ["x"]);
    }

    #[test]
    fn recognizes_the_done_sentinel() {
        let events = parse(b"data: {\"delta\":1}\n\ndata: [DONE]\n\n");
        assert!(!events[0].is_done());
        assert!(events[1].is_done());
    }

    #[test]
    fn split_anywhere_gives_the_same_events() {
        let stream: &[u8] = b": keep-alive\n\nevent: delta\nid: 9\ndata: {\"a\":1}\r\n\
                             data: more\r\n\r\ndata: [DONE]\n\n";
        let whole = parse(stream);
        assert_eq!(whole.len(), 2);

        for split in 1..stream.len() {
            let mut parser = SseParser::new();
            let mut events = parser.feed(&stream[..split]).unwrap();
            events.extend(parser.feed(&stream[split..]).unwrap());
            assert_eq!(events, whole, "differs when split at {split}");
        }
    }

    #[test]
    fn holds_utf8_split_across_chunks() {
        let stream = "data: héllo 🦀\n\n".as_bytes();
        for split in 1..stream.len() {
            let mut parser = SseParser::new();
            let mut events = parser.feed(&stream[..split]).unwrap();
            events.extend(parser.feed(&stream[split..]).unwrap());
            assert_eq!(data_of(&events), ["héllo 🦀"], "split at {split}");
        }
    }

    #[test]
    fn byte_at_a_time_gives_the_same_events() {
        let stream: &[u8] = b"data: one\r\n\r\n: tick\r\n\r\ndata: two\ndata: three\n\n";
        let mut parser = SseParser::new();
        let mut events = Vec::new();
        for byte in stream {
            events.extend(parser.feed(&[*byte]).unwrap());
        }
        assert_eq!(data_of(&events), ["one", "two\nthree"]);
    }

    #[test]
    fn finish_flushes_a_stream_that_ended_without_a_blank_line() {
        let mut parser = SseParser::new();
        assert!(parser.feed(b"data: one\n\ndata: two\n").unwrap().len() == 1);
        assert_eq!(parser.finish().map(|e| e.data), Some("two".to_string()));
        assert_eq!(parser.finish(), None);

        // A line that never ended is not an event.
        let mut parser = SseParser::new();
        assert!(parser.feed(b"data: half").unwrap().is_empty());
        assert_eq!(parser.finish(), None);
    }

    #[test]
    fn refuses_to_buffer_without_bound() {
        let mut parser = SseParser::new();
        let filler = vec![b'x'; 64 * 1024];
        let mut result = Ok(Vec::new());
        while result.is_ok() && parser.line.len() <= MAX_LINE_BYTES {
            result = parser.feed(&filler);
        }
        assert!(matches!(result, Err(SseError::TooLarge(_))), "{result:?}");
    }
}
