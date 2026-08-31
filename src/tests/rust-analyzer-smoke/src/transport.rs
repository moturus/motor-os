use std::io::{self, BufRead, BufReader, Read, Write};

use serde_json::Value;

pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
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
}
