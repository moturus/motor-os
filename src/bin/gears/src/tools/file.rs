//! Streaming, identity-bearing file slices for model-facing reads.

use std::io::Read;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
enum Range {
    Bytes { start: u64, length: usize },
    Lines { start: u64, end: u64 },
}

pub fn read(path: &Path, shown: &str, args: &Value, max: usize) -> Result<String, String> {
    if max == 0 {
        return Err("file read limit must be positive".to_string());
    }
    let expected = super::opt_string(args, "expected_identity")?;
    if expected
        .as_deref()
        .is_some_and(|value| !valid_identity(value))
    {
        return Err(
            "'expected_identity' must be 'sha256:' followed by 64 lowercase hexadecimal digits"
                .to_string(),
        );
    }
    let slice = read_slice(path, shown, Range::parse(args, max)?, max)?;
    if expected
        .as_deref()
        .is_some_and(|value| value != slice.identity)
    {
        return Err(format!(
            "{shown} changed since the supplied identity; read it again before using stale content"
        ));
    }
    Ok(slice.render(shown))
}

impl Range {
    fn parse(args: &Value, max: usize) -> Result<Range, String> {
        let byte_start = number(args, "byte_start")?;
        let byte_length = number(args, "byte_length")?;
        let line_start = number(args, "line_start")?;
        let line_count = number(args, "line_count")?;
        match (byte_start, byte_length, line_start, line_count) {
            (None, None, None, None) => Ok(Range::Bytes {
                start: 0,
                length: max,
            }),
            (Some(start), Some(length), None, None) => {
                let length = usize::try_from(length)
                    .map_err(|_| format!("'byte_length' must be between 1 and {max}"))?;
                if length == 0 || length > max {
                    return Err(format!("'byte_length' must be between 1 and {max}"));
                }
                start.checked_add(length as u64).ok_or("byte range overflow")?;
                Ok(Range::Bytes { start, length })
            }
            (None, None, Some(start), Some(count)) if start > 0 && count > 0 => {
                let end = start.checked_add(count).ok_or("line range overflow")?;
                Ok(Range::Lines { start, end })
            }
            _ => Err(
                "use exactly one complete range: byte_start with byte_length, or line_start with line_count"
                    .to_string(),
            ),
        }
    }
}

struct Slice {
    bytes: Vec<u8>,
    total_size: u64,
    identity: String,
    label: String,
}

impl Slice {
    fn render(self, path: &str) -> String {
        let (encoding, content) = match std::str::from_utf8(&self.bytes) {
            Ok(text)
                if text
                    .chars()
                    .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t')) =>
            {
                ("utf-8", text.to_string())
            }
            _ => ("hex", super::hex(&self.bytes)),
        };
        format!(
            "file {path}: {}; {} bytes returned of {}; identity {}; encoding {encoding}\n{content}",
            self.label,
            self.bytes.len(),
            self.total_size,
            self.identity
        )
    }
}

fn read_slice(path: &Path, shown: &str, range: Range, max: usize) -> Result<Slice, String> {
    let mut file = std::fs::File::open(path).map_err(|error| format!("{shown}: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("{shown}: {error}"))?;
    if !before.is_file() {
        return Err(format!("{shown}: expected a regular file"));
    }
    if let Range::Bytes { start, .. } = range
        && start > before.len()
    {
        return Err(format!(
            "{shown}: byte {start} is past its {}-byte end",
            before.len()
        ));
    }

    let mut digest = Sha256::new();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut offset = 0u64;
    let mut line = 1u64;
    let mut saw_byte = false;
    let mut ended_with_newline = false;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("{shown}: {error}"))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        digest.update(chunk);
        match range {
            Range::Bytes { start, length } => {
                let chunk_end = offset + read as u64;
                let wanted_end = start + length as u64;
                if chunk_end > start && offset < wanted_end {
                    let from = start.saturating_sub(offset) as usize;
                    let to = u64::min(read as u64, wanted_end.saturating_sub(offset)) as usize;
                    bytes.extend_from_slice(&chunk[from..to]);
                }
            }
            Range::Lines { start, end } => {
                for &byte in chunk {
                    saw_byte = true;
                    ended_with_newline = byte == b'\n';
                    if line >= start && line < end {
                        if bytes.len() == max {
                            return Err(format!(
                                "{shown}: requested lines exceed the {max}-byte read limit; use a byte range"
                            ));
                        }
                        bytes.push(byte);
                    }
                    if byte == b'\n' {
                        line += 1;
                    }
                }
            }
        }
        offset += read as u64;
    }

    if let Range::Lines { start, .. } = range {
        let lines = u64::from(saw_byte) + line - 1 - u64::from(ended_with_newline);
        if start > lines && !(lines == 0 && start == 1) {
            return Err(format!(
                "{shown}: line {start} is past its {lines}-line end"
            ));
        }
    }
    let after = file
        .metadata()
        .map_err(|error| format!("{shown}: {error}"))?;
    let modified = match (before.modified(), after.modified()) {
        (Ok(before), Ok(after)) => before != after,
        _ => false,
    };
    if before.len() != offset || after.len() != offset || modified {
        return Err(format!("{shown}: file changed while it was being read"));
    }
    let label = match range {
        Range::Bytes { start, .. } => format!("bytes {start}..{}", start + bytes.len() as u64),
        Range::Lines { start, end } => format!("lines {start}..{end}"),
    };
    Ok(Slice {
        bytes,
        total_size: offset,
        identity: format!("sha256:{}", super::hex(&digest.finalize())),
        label,
    })
}

fn number(args: &Value, name: &str) -> Result<Option<u64>, String> {
    match &args[name] {
        Value::Null => Ok(None),
        Value::Number(number) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("'{name}' must be a non-negative whole number")),
        _ => Err(format!("'{name}' must be a number")),
    }
}

fn valid_identity(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ranges_are_precise_and_stale_identities_are_refused() {
        let path = std::env::temp_dir().join(format!("gears-file-range-{}", std::process::id()));
        let content = b"one\n\xfftwo\nthree";
        std::fs::write(&path, content).unwrap();

        let prefix = read(&path, "ranges.txt", &json!({}), 5).unwrap();
        assert!(prefix.contains("bytes 0..5; 5 bytes returned of 14"));
        assert!(prefix.ends_with("encoding hex\n6f6e650aff"));
        let identity = prefix
            .split("; identity ")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let line = read(
            &path,
            "ranges.txt",
            &json!({"line_start": 1, "line_count": 1, "expected_identity": identity}),
            5,
        )
        .unwrap();
        assert!(line.ends_with("encoding utf-8\none\n"));
        let binary = read(
            &path,
            "ranges.txt",
            &json!({"byte_start": 4, "byte_length": 5}),
            5,
        )
        .unwrap();
        assert!(binary.ends_with("encoding hex\nff74776f0a"));
        for args in [
            json!({"byte_start": 15, "byte_length": 1}),
            json!({"line_start": 4, "line_count": 1}),
            json!({"byte_start": 0, "byte_length": 6}),
        ] {
            assert!(read(&path, "ranges.txt", &args, 5).is_err());
        }

        std::fs::write(&path, b"one\n\xffTWO\nthree").unwrap();
        let stale = read(
            &path,
            "ranges.txt",
            &json!({"byte_start": 0, "byte_length": 1, "expected_identity": identity}),
            5,
        )
        .unwrap_err();
        assert!(stale.contains("changed since"), "{stale}");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn an_empty_file_has_the_standard_sha256_identity() {
        let path = std::env::temp_dir().join(format!("gears-file-empty-{}", std::process::id()));
        std::fs::write(&path, []).unwrap();
        let output = read(&path, "empty", &json!({}), 5).unwrap();
        assert!(output.contains("0 bytes returned of 0"));
        assert!(
            output.contains(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
        );
        std::fs::remove_file(path).unwrap();
    }
}
