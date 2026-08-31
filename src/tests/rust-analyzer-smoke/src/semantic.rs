use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

pub struct Toolchain {
    pub name: String,
    pub sysroot: PathBuf,
    pub sysroot_src: PathBuf,
    pub rust_analyzer: PathBuf,
}

impl Toolchain {
    pub fn discover(repo: &Path) -> io::Result<Self> {
        let output = Command::new("rustc")
            .args(["--print", "sysroot"])
            .current_dir(repo)
            .output()?;
        if !output.status.success() {
            return Err(invalid("selected rustc could not report its sysroot"));
        }
        let sysroot = PathBuf::from(
            std::str::from_utf8(&output.stdout)
                .map_err(|_| invalid("rustc printed a non-UTF-8 sysroot"))?
                .trim(),
        )
        .canonicalize()?;
        let name = sysroot
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("selected sysroot has no UTF-8 name"))?
            .to_owned();
        let rust_analyzer = sysroot.join("bin/rust-analyzer").canonicalize()?;
        let rustup = Command::new("rustup")
            .args(["which", "rust-analyzer", "--toolchain", &name])
            .current_dir(repo)
            .output()?;
        if !rustup.status.success() {
            return Err(invalid("rustup could not resolve rust-analyzer"));
        }
        let rustup_path = PathBuf::from(
            std::str::from_utf8(&rustup.stdout)
                .map_err(|_| invalid("rustup printed a non-UTF-8 path"))?
                .trim(),
        )
        .canonicalize()?;
        if rustup_path != rust_analyzer {
            return Err(invalid("rustup resolved a different rust-analyzer"));
        }
        let sysroot_src = sysroot.join("lib/rustlib/src/rust/library");
        if !sysroot_src.is_dir() {
            return Err(invalid("selected sysroot has no rust-src"));
        }
        Ok(Self {
            name,
            sysroot,
            sysroot_src,
            rust_analyzer,
        })
    }
}

pub fn file_uri(path: &Path) -> String {
    let text = path.to_str().expect("test paths must be UTF-8");
    let mut uri = String::from("file://");
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

pub fn uri_path(uri: &str) -> io::Result<PathBuf> {
    let encoded = uri
        .strip_prefix("file://")
        .ok_or_else(|| invalid("definition did not return a file URI"))?;
    let mut bytes = Vec::new();
    let mut chars = encoded.as_bytes().iter().copied();
    while let Some(byte) = chars.next() {
        if byte != b'%' {
            bytes.push(byte);
            continue;
        }
        let high = chars
            .next()
            .ok_or_else(|| invalid("truncated URI escape"))?;
        let low = chars
            .next()
            .ok_or_else(|| invalid("truncated URI escape"))?;
        let digits = [high, low];
        let digits = std::str::from_utf8(&digits).map_err(|_| invalid("invalid URI escape"))?;
        bytes.push(u8::from_str_radix(digits, 16).map_err(|_| invalid("invalid URI escape"))?);
    }
    Ok(PathBuf::from(
        String::from_utf8(bytes).map_err(|_| invalid("definition URI is not UTF-8"))?,
    ))
}

pub fn position(text: &str, needle: &str) -> io::Result<Value> {
    let mut matches = text.match_indices(needle);
    let offset = matches
        .next()
        .map(|(offset, _)| offset)
        .ok_or_else(|| invalid(format!("source lacks {needle:?}")))?;
    if matches.next().is_some() {
        return Err(invalid(format!("source contains multiple {needle:?}")));
    }
    let prefix = &text[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let column = prefix.rsplit_once('\n').map_or(prefix, |(_, line)| line);
    Ok(json!({"line": line, "character": column.encode_utf16().count()}))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_file_uris() {
        let path = Path::new("/tmp/a b/c.rs");
        let uri = file_uri(path);
        assert_eq!(uri, "file:///tmp/a%20b/c.rs");
        assert_eq!(uri_path(&uri).unwrap(), path);
    }

    #[test]
    fn computes_utf16_positions() {
        assert_eq!(
            position("one\nλ needle", "needle").unwrap(),
            json!({
                "line": 1,
                "character": 2
            })
        );
        assert!(position("same same", "same").is_err());
    }
}
