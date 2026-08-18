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
                flush(&mut literal, destination, stdout, stderr)?;
                let end = bytes[position + 2..]
                    .iter()
                    .position(|byte| *byte == b'}')
                    .map(|offset| position + 2 + offset)
                    .ok_or_else(|| CurlError::usage("unterminated --write-out variable"))?;
                let name = &format[position + 2..end];
                match name {
                    "stderr" => destination = Destination::Stderr,
                    "response_code" => write_value(
                        info.response_code.to_string().as_bytes(),
                        destination,
                        stdout,
                        stderr,
                    )?,
                    "url_effective" => {
                        write_value(info.url_effective.as_bytes(), destination, stdout, stderr)?
                    }
                    "redirect_url" => {
                        write_value(info.redirect_url.as_bytes(), destination, stdout, stderr)?
                    }
                    "content_type" => {
                        write_value(info.content_type.as_bytes(), destination, stdout, stderr)?
                    }
                    "size_download" => write_value(
                        info.size_download.to_string().as_bytes(),
                        destination,
                        stdout,
                        stderr,
                    )?,
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
}
