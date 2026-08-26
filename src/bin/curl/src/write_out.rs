use std::io::Write;

use crate::{CurlError, CurlResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferInfo {
    pub response_code: u16,
    pub url_effective: String,
    pub redirect_url: String,
    pub content_type: String,
    pub size_download: u64,
}

pub fn write_out(
    format: &str,
    info: &TransferInfo,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> CurlResult<()> {
    let bytes = format.as_bytes();
    let mut position = 0;
    let mut destination = Destination::Stdout;
    let mut literal = Vec::new();

    while position < bytes.len() {
        match bytes[position] {
            b'%' if bytes.get(position + 1) == Some(&b'%') => {
                literal.push(b'%');
                position += 2;
            }
            b'%' if bytes.get(position + 1) == Some(&b'{') => {
                let end = bytes[position + 2..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|offset| position + 2 + offset)
                    .ok_or_else(|| CurlError::usage("unterminated --write-out variable"))?;
                let name = &format[position + 2..end];
                match name {
                    "stderr" => {
                        flush(&mut literal, destination, stdout, stderr)?;
                        destination = Destination::Stderr;
                    }
                    "response_code" => {
                        literal.extend_from_slice(info.response_code.to_string().as_bytes())
                    }
                    "url_effective" => literal.extend_from_slice(info.url_effective.as_bytes()),
                    "redirect_url" => literal.extend_from_slice(info.redirect_url.as_bytes()),
                    "content_type" => literal.extend_from_slice(info.content_type.as_bytes()),
                    "size_download" => {
                        literal.extend_from_slice(info.size_download.to_string().as_bytes())
                    }
                    _ => {
                        return Err(CurlError::usage(format!(
                            "unsupported --write-out variable: {name}"
                        )));
                    }
                }
                position = end + 1;
            }
            b'\\' => {
                let escaped = match bytes.get(position + 1) {
                    Some(b'\\') => b'\\',
                    Some(b'n') => b'\n',
                    Some(b'r') => b'\r',
                    Some(b't') => b'\t',
                    _ => return Err(CurlError::usage("invalid --write-out escape")),
                };
                literal.push(escaped);
                position += 2;
            }
            byte => {
                literal.push(byte);
                position += 1;
            }
        }
    }
    flush(&mut literal, destination, stdout, stderr)
}

#[derive(Clone, Copy)]
enum Destination {
    Stdout,
    Stderr,
}

fn flush(
    bytes: &mut Vec<u8>,
    destination: Destination,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> CurlResult<()> {
    write_value(bytes, destination, stdout, stderr)?;
    bytes.clear();
    Ok(())
}

fn write_value(
    bytes: &[u8],
    destination: Destination,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> CurlResult<()> {
    let result = match destination {
        Destination::Stdout => stdout.write_all(bytes),
        Destination::Stderr => stderr.write_all(bytes),
    };
    result.map_err(|error| {
        CurlError::new(
            CurlError::LOCAL_WRITE,
            format!("failed writing local output: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingWriter(Vec<Vec<u8>>);

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.push(bytes.to_vec());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn info() -> TransferInfo {
        TransferInfo {
            response_code: 302,
            url_effective: "https://example.test/old".into(),
            redirect_url: "https://example.test/new".into(),
            content_type: "application/octet-stream".into(),
            size_download: 17,
        }
    }

    #[test]
    fn expands_lorry_control_trailer_to_stderr() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write_out(
            "%{stderr}\\nstatus=%{response_code}\\nurl=%{url_effective}\\n\
             redirect=%{redirect_url}\\ntype=%{content_type}\\nsize=%{size_download}\\n%%\\\\",
            &info(),
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "\nstatus=302\nurl=https://example.test/old\n\
             redirect=https://example.test/new\ntype=application/octet-stream\nsize=17\n%\\"
        );
    }

    #[test]
    fn rejects_unknown_variables_and_bad_escapes() {
        for format in ["%{unknown}", "%{response_code", "\\q"] {
            assert!(write_out(format, &info(), &mut Vec::new(), &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn emits_each_contiguous_destination_once() {
        let mut stdout = RecordingWriter::default();
        let mut stderr = RecordingWriter::default();
        write_out(
            "prefix%{stderr}status=%{response_code}\nurl=%{url_effective}\n",
            &info(),
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert_eq!(stdout.0, [b"prefix".to_vec()]);
        assert_eq!(
            stderr.0,
            [b"status=302\nurl=https://example.test/old\n".to_vec()]
        );
    }
}
