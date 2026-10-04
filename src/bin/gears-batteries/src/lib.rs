//! Optional coding workflows using Gears' command-hook protocol.

pub mod check;
pub mod check_approval;
pub mod check_config;
pub mod check_state;
pub mod command_policy;
pub mod file_patch;
pub mod file_read;
pub mod file_record;
pub mod file_write;
pub mod instructions;
pub mod journal;
pub mod patch_match;
pub mod paths;
pub mod policy;
pub mod provenance;
pub mod search;
pub mod shell_words;
pub mod snapshot;
pub mod todo;
pub mod tool;
pub mod turns;

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

pub(crate) fn hook_state(event: &Event) -> Result<Value, String> {
    match event.session.state.as_ref() {
        None | Some(Value::Null) => Ok(json!({})),
        Some(Value::Object(_)) => Ok(event.session.state.clone().unwrap()),
        _ => Err("batteries hook state must be an object".into()),
    }
}

pub fn hook(event: Event) -> Result<Value, String> {
    if event.event == "tool_result" {
        return Ok(provenance::transform(&event).unwrap_or_else(
            |error| json!({"notice": format!("output provenance unavailable: {error}")}),
        ));
    }
    if matches!(
        event.event.as_str(),
        "turn_start" | "entry" | "turn_end" | "before_stop"
    ) {
        return Ok(observe_features(event));
    }
    if event.event == "tool_execute" {
        return todo::execute(&event);
    }
    if event.event == "initialize" {
        let result = default_root().and_then(gears::state::StateRoot::new);
        return Ok(match result {
            Ok(root) => initialize_at(&event, &root),
            Err(error) => with_tools(initialization_notice(error)),
        });
    }
    Ok(if event.event == "permission" {
        policy::permission(&event)
    } else {
        json!({})
    })
}

fn observe_features(mut event: Event) -> Value {
    let context = match paths::ToolContext::for_event(&event) {
        Ok(context) => context,
        Err(error) => {
            return json!({"notice": format!("batteries observations unavailable: {error}")});
        }
    };
    let mut response = json!({});
    let mut notices = Vec::new();
    for observe in [check_state::observe, turns::observe] {
        match observe(&event, &context) {
            Ok(feature) => {
                for (name, value) in feature.as_object().unwrap() {
                    if name == "state" {
                        event.session.state = Some(value.clone());
                    }
                    if name == "notice" {
                        notices.push(value.as_str().unwrap().to_string());
                    } else {
                        response[name] = value.clone();
                    }
                }
            }
            Err(error) => notices.push(format!("batteries observation failed: {error}")),
        }
    }
    if !notices.is_empty() {
        response["notice"] = json!(notices.join("\n"));
    }
    response
}

pub fn initialize_at(event: &Event, root: &gears::state::StateRoot) -> Value {
    with_tools(snapshot::initialize(event, root).unwrap_or_else(initialization_notice))
}

fn with_tools(mut response: Value) -> Value {
    response["tools"] = json!([todo::specification()]);
    response
}

fn initialization_notice(error: String) -> Value {
    json!({"notice": format!("project instructions and prompt snapshot unavailable: {error}")})
}

pub fn default_root() -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".gears"))
            .ok_or_else(|| "HOME is not set; cannot locate Gears directory".into())
    }
    #[cfg(not(unix))]
    {
        Ok(PathBuf::from("/user/cfg/gears"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_initialization_failure_keeps_previous_hook_state() {
        let root =
            std::env::temp_dir().join(format!("batteries-failed-setup-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let previous = json!({"prompt_snapshot": "invalid", "tasks": ["keep me"]});
        let event = read_event(
            json!({"protocol_version": 1, "event": "initialize",
            "workspace": root.join("workspace"), "session": {"id": "fixture", "state": previous}})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let state = gears::state::StateRoot::new(root.join("state")).unwrap();
        let response = initialize_at(&event, &state);
        assert!(
            response["notice"]
                .as_str()
                .unwrap()
                .contains("invalid prompt snapshot hash")
        );
        assert!(response.get("state").is_none());
        assert_eq!(event.session.state, Some(previous));
        std::fs::remove_dir_all(root).unwrap();
    }

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
