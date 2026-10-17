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
pub mod memory;
pub mod memory_cli;
pub mod memory_config;
pub mod memory_format;
pub mod memory_history;
pub mod memory_options;
pub mod memory_question;
pub mod memory_tool;
pub mod patch_match;
pub mod paths;
pub mod policy;
pub mod provenance;
pub mod remember;
pub mod search;
pub mod session_search;
pub mod shell_words;
pub mod skill_catalog;
pub mod skill_config;
pub mod skill_format;
pub mod skill_store;
pub mod skill_view;
pub mod snapshot;
pub mod todo;
pub mod tool;

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

const MAX_EVENT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Deserialize)]
pub struct Event {
    pub protocol_version: u32,
    pub event: String,
    pub workspace: PathBuf,
    pub session: Session,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Clone, Deserialize)]
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
        return Err("hook event exceeds 2 MiB".into());
    }
    let event: Event =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid hook event: {error}"))?;
    if event.protocol_version != crate::hooks::PROTOCOL_VERSION {
        return Err("incompatible hook protocol_version".into());
    }
    if !crate::hooks::EVENTS.contains(&event.event.as_str()) {
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
    let context = || paths::ToolContext::for_event(&event);
    match event.event.as_str() {
        "tool_result" => {
            let mut response = provenance::transform(&event).unwrap_or_else(
                |error| json!({"notice": format!("output provenance unavailable: {error}")}),
            );
            if event.payload["tool_call"]["name"] == "memory" {
                merge_optional(
                    &mut response,
                    context().and_then(|context| memory_question::after_result(&event, &context)),
                );
            }
            Ok(response)
        }
        "answer" => context().and_then(|context| memory_question::answer(&event, &context)),
        "command" => context().and_then(|context| remember::command(&event, &context)),
        "turn_start" | "entry" | "turn_end" | "before_stop" => {
            let mut response = json!({});
            merge_optional(
                &mut response,
                context().and_then(|context| check_state::observe(&event, &context)),
            );
            Ok(response)
        }
        "tool_execute" => match event.payload["tool_call"]["name"].as_str() {
            Some("memory") => context().and_then(|context| memory_tool::execute(&event, &context)),
            Some("skill_view") => {
                context().and_then(|context| skill_view::execute(&event, &context))
            }
            _ => todo::execute(&event),
        },
        "initialize" => Ok(
            match default_root().and_then(crate::state::StateRoot::new) {
                Ok(root) => initialize_at(&event, &root),
                Err(error) => with_tools(&event, initialization_notice(error)),
            },
        ),
        "permission" => Ok(policy::permission(&event)),
        _ => Ok(json!({})),
    }
}

pub fn initialize_at(event: &Event, root: &crate::state::StateRoot) -> Value {
    let mut response = snapshot::initialize(event, root).unwrap_or_else(initialization_notice);
    let cleanup = paths::ToolContext::new(
        event.workspace.clone(),
        root.path().to_path_buf(),
        event.session.id.clone(),
        event.session.path.as_deref(),
    )
    .and_then(|context| {
        let workspace_state = crate::state::StateRoot::new(context.workspace.join(".gears"))?;
        let discarded = workspace_state.cleanup_temporary_files()?;
        Ok(if discarded == 0 {
            json!({})
        } else {
            json!({"notice": format!("discarded {discarded} temporary batteries workspace files")})
        })
    });
    merge_optional(&mut response, cleanup);
    with_tools(event, response)
}

fn with_tools(event: &Event, mut response: Value) -> Value {
    response["commands"] = if remember::subscribed(event) {
        remember::specifications()
    } else {
        json!([])
    };
    response["tools"] = json!([
        todo::specification(),
        memory_tool::specification(),
        skill_view::specification()
    ]);
    response
}

fn initialization_notice(error: String) -> Value {
    json!({"notice": format!("project instructions and prompt snapshot unavailable: {error}")})
}

pub fn default_root() -> Result<PathBuf, String> {
    crate::directory::default_root()
}

/// A failed optional feature becomes a notice; the other fields are merged.
fn merge_optional(response: &mut Value, feature: Result<Value, String>) {
    let feature = feature.unwrap_or_else(
        |error| json!({"notice": format!("batteries feature unavailable: {error}")}),
    );
    for (name, value) in feature.as_object().unwrap() {
        if name == "notice" && response.get("notice").is_some() {
            response["notice"] = json!(format!(
                "{}\n{}",
                response["notice"].as_str().unwrap(),
                value.as_str().unwrap()
            ));
        } else if name == "context" && response.get(name).is_some() {
            let previous: crate::provider::Message =
                serde_json::from_value(response[name].clone()).expect("internal context message");
            let added: crate::provider::Message =
                serde_json::from_value(value.clone()).expect("internal context message");
            response[name] = json!(crate::provider::Message::user(format!(
                "{}\n{}",
                previous.text_content(),
                added.text_content()
            )));
        } else {
            response[name] = value.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_registers_the_hook_tools_and_preserves_other_features() {
        let previous = json!({"tasks": ["keep me"]});
        let mut event = read_event(
            json!({"protocol_version": 1, "event": "initialize", "workspace": "/work",
            "session": {"id": "s1"}, "payload": {"subscribed_events": ["initialize"]}})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let response = with_tools(
            &event,
            json!({"state": previous, "notice": "previous notice"}),
        );
        assert_eq!(response["commands"], json!([]));
        event.payload["subscribed_events"] = json!(["initialize", "command"]);
        let names = with_tools(&event, json!({}))["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["name"].clone())
            .collect::<Vec<_>>();
        assert_eq!(names, ["remember", "remember-host"]);
        assert_eq!(response["tools"].as_array().unwrap().len(), 3);
        assert_eq!(response["state"], previous);
        assert_eq!(response["notice"], "previous notice");
    }

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
        let state = crate::state::StateRoot::new(root.join("state")).unwrap();
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
