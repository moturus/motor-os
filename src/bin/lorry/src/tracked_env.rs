//! Environment variables that a compiled unit read. Like Cargo, Lorry keys a
//! unit on the variables it sets for rustc and then rechecks only the process
//! variables that rustc reported in dep-info (`# env-dep:` lines).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;

use crate::diagnostic::{Error, Result};
use crate::json::Value;

/// Variable name to the value rustc saw, or `None` when it was unset.
pub type Tracked = BTreeMap<String, Option<String>>;

/// Returns the env-dep entries of a rustc dep-info document.
pub fn parse(dep_info: &[u8]) -> Result<Tracked> {
    let mut tracked = Tracked::new();
    for line in dep_info.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(entry) = line.strip_prefix(b"# env-dep:") else {
            continue;
        };
        let entry = std::str::from_utf8(entry)
            .map_err(|_| Error::failure("rustc emitted a non-UTF-8 env-dep entry"))?;
        let (name, value) = match entry.split_once('=') {
            Some((name, value)) => (unescape(name)?, Some(unescape(value)?)),
            None => (unescape(entry)?, None),
        };
        if name.is_empty() {
            return Err(Error::failure("rustc emitted an empty env-dep name"));
        }
        tracked.insert(name, value);
    }
    Ok(tracked)
}

// rustc escapes `\`, newline, and carriage return in env-dep names and values.
fn unescape(value: &str) -> Result<String> {
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        match characters.next() {
            Some('\\') => output.push('\\'),
            Some('n') => output.push('\n'),
            Some('r') => output.push('\r'),
            _ => return Err(Error::failure("rustc emitted an invalid env-dep escape")),
        }
    }
    Ok(output)
}

/// The value of a process variable as rustc receives it from Lorry.
pub fn current(name: &str) -> Option<OsString> {
    if crate::process::is_removed_cargo_client_environment(OsStr::new(name))
        || name == "CARGO_PRIMARY_PACKAGE"
    {
        return None;
    }
    std::env::var_os(name)
}

/// Whether every tracked variable still has the value rustc saw.
pub fn matches_current(tracked: &Tracked) -> bool {
    tracked.iter().all(|(name, value)| {
        let current = current(name);
        match (value, &current) {
            (None, None) => true,
            (Some(value), Some(current)) => current.to_str() == Some(value.as_str()),
            _ => false,
        }
    })
}

pub fn encode(tracked: &Tracked) -> Vec<u8> {
    Value::Object(
        tracked
            .iter()
            .map(|(name, value)| {
                let value = value.clone().map_or(Value::Null, Value::String);
                (name.clone(), value)
            })
            .collect(),
    )
    .canonical_bytes()
}

pub fn decode(bytes: &[u8]) -> Option<Tracked> {
    let value = Value::parse(
        Path::new("<tracked environment>"),
        "tracked environment",
        bytes,
    )
    .ok()?;
    (value.canonical_bytes() == bytes).then_some(())?;
    value
        .as_object()?
        .iter()
        .map(|(name, value)| match value {
            Value::Null => Some((name.clone(), None)),
            Value::String(value) => Some((name.clone(), Some(value.clone()))),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rustc_env_dep_lines() {
        let document = concat!(
            "/out/lib.rlib: /src/lib.rs\n",
            "/src/lib.rs:\n",
            "\n",
            "# env-dep:CARGO_PKG_NAME=demo\n",
            "# env-dep:LORRY_UNSET\n",
            "# env-dep:LORRY_ESCAPED=a\\\\b\\nc=d\r\n",
        );
        let tracked = parse(document.as_bytes()).unwrap();
        assert_eq!(
            tracked,
            Tracked::from([
                ("CARGO_PKG_NAME".to_owned(), Some("demo".to_owned())),
                ("LORRY_ESCAPED".to_owned(), Some("a\\b\nc=d".to_owned())),
                ("LORRY_UNSET".to_owned(), None),
            ])
        );
        assert!(parse(b"# env-dep:BAD=\\q\n").is_err());
        assert!(parse(b"# env-dep:=value\n").is_err());
    }

    #[test]
    fn encodes_round_trip_and_rejects_other_documents() {
        let tracked = Tracked::from([
            ("A".to_owned(), Some("1".to_owned())),
            ("B".to_owned(), None),
        ]);
        assert_eq!(decode(&encode(&tracked)), Some(tracked));
        assert_eq!(decode(b"{\"A\":1}\n"), None);
        assert_eq!(decode(b"{ \"A\": null }\n"), None);
    }

    #[test]
    fn compares_with_the_variables_rustc_receives() {
        let path = std::env::var("PATH").unwrap();
        assert!(matches_current(&Tracked::from([(
            "PATH".to_owned(),
            Some(path)
        )])));
        assert!(!matches_current(&Tracked::from([(
            "PATH".to_owned(),
            Some("/nowhere".to_owned())
        )])));
        assert!(matches_current(&Tracked::from([(
            "LORRY_TRACKED_ENV_TEST_UNSET".to_owned(),
            None
        )])));
        // Lorry strips these before starting rustc.
        assert!(matches_current(&Tracked::from([(
            "RUSTUP_TOOLCHAIN".to_owned(),
            None
        )])));
    }
}
