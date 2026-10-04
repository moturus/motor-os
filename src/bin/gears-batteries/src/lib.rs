//! Optional coding workflows using Gears' command-hook protocol.

pub mod instructions;

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

const MAX_EVENT_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
pub struct Event {
    pub protocol_version: u32,
    pub event: String,
    pub workspace: PathBuf,
    pub session: Session,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Deserialize)]
pub struct Session {
    pub id: String,
    pub path: Option<PathBuf>,
    pub state: Option<Value>,
}

pub fn read_event(reader: impl Read) -> Result<Event, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_EVENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read hook event: {error}"))?;
    if bytes.len() > MAX_EVENT_BYTES {
        return Err("hook event exceeds 1 MiB".into());
    }
    let event: Event =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid hook event: {error}"))?;
    if event.protocol_version != gears::hooks::PROTOCOL_VERSION {
        return Err("incompatible hook protocol_version".into());
    }
    if !gears::hooks::EVENTS.contains(&event.event.as_str()) {
        return Err(format!("unknown hook event {:?}", event.event));
    }
    Ok(event)
}

pub fn hook(event: Event) -> Result<Value, String> {
    // Until a policy is installed, this optional hook grants no authority.
    Ok(if event.event == "permission" {
        json!({"decision": "deny"})
    } else {
        json!({})
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_events_and_defaults_permissions_to_denial() {
        let event = json!({"protocol_version": 1, "event": "permission",
            "workspace": "/work", "session": {"id": "s1"}, "future_field": true});
        let parsed = read_event(event.to_string().as_bytes()).unwrap();
        assert_eq!(hook(parsed).unwrap()["decision"], "deny");
        for (field, value) in [
            ("protocol_version", json!(2)),
            ("event", json!("typo")),
            ("session", json!(null)),
        ] {
            let mut invalid = event.clone();
            invalid[field] = value;
            assert!(read_event(invalid.to_string().as_bytes()).is_err());
        }
        assert!(read_event(b"{}".as_slice()).is_err());
        assert!(read_event(b"{}{}".as_slice()).is_err());
        assert!(
            read_event(vec![b' '; MAX_EVENT_BYTES + 1].as_slice())
                .err()
                .unwrap()
                .contains("exceeds")
        );
    }
}
