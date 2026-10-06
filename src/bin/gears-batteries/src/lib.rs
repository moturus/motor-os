//! Optional coding workflows using Gears' command-hook protocol.

pub mod acceptance;
pub mod check;
pub mod check_approval;
pub mod check_config;
pub mod check_state;
pub mod command_policy;
pub mod eval_task;
pub mod file_patch;
pub mod file_read;
pub mod file_record;
pub mod file_write;
pub mod instructions;
pub mod journal;
pub mod memory;
pub mod memory_cli;
pub mod memory_config;
pub mod memory_context;
pub mod memory_format;
pub mod memory_history;
pub mod memory_options;
pub mod memory_question;
pub mod memory_snapshot;
pub mod memory_sources;
pub mod memory_tool;
pub mod patch_match;
pub mod paths;
pub mod pending;
pub mod pending_files;
pub mod policy;
pub mod provenance;
pub mod review_config;
pub mod review_instructions;
pub mod review_launch;
pub mod review_marks;
pub mod review_proposals;
pub mod review_resume;
pub mod review_runner;
pub mod review_status;
pub mod review_triggers;
pub mod search;
pub mod session_search;
pub mod shell_words;
pub mod skill_archive;
pub mod skill_catalog;
pub mod skill_cleanup;
pub mod skill_config;
pub mod skill_context;
pub mod skill_format;
pub mod skill_loads;
pub mod skill_manage;
pub mod skill_observation;
pub mod skill_pending;
pub mod skill_snapshot;
pub mod skill_sources;
pub mod skill_store;
pub mod skill_usage;
pub mod skill_view;
pub mod snapshot;
pub mod todo;
pub mod tool;
pub mod turns;
pub mod workspace_memory;

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

const MAX_EVENT_BYTES: usize = 2 * 1024 * 1024;

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
        return Err("hook event exceeds 2 MiB".into());
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

/// Historical resources are separate from current permissions and run metadata.
pub(crate) fn prefix_state(event: &Event) -> Result<Option<&Value>, String> {
    if event.payload["preserve_prefix"] != true {
        return Ok(None);
    }
    match event.payload.get("prefix_state") {
        None => Ok(None),
        Some(value @ (Value::Object(_) | Value::Null)) => Ok(Some(value)),
        _ => Err("historical prefix state must be an object or null".into()),
    }
}

pub fn hook(event: Event) -> Result<Value, String> {
    if event.event == "command" {
        return if event.payload["name"] == "review" {
            paths::ToolContext::for_event(&event)
                .and_then(|context| review_triggers::record(&event, &context))
        } else {
            acceptance::execute(&event)
        };
    }
    if event.event == "before_compact" {
        let mut response = json!({});
        merge_optional(
            &mut response,
            paths::ToolContext::for_event(&event)
                .and_then(|context| review_triggers::record(&event, &context)),
        );
        return Ok(response);
    }
    if event.event == "tool_result" {
        let mut response = provenance::transform(&event).unwrap_or_else(
            |error| json!({"notice": format!("output provenance unavailable: {error}")}),
        );
        if event.payload["tool_call"]["name"] == "memory" {
            merge_optional(
                &mut response,
                paths::ToolContext::for_event(&event)
                    .and_then(|context| memory_question::after_result(&event, &context)),
            );
        }
        return Ok(response);
    }
    if event.event == "context" {
        let context = paths::ToolContext::for_event(&event)?;
        return Ok(context_at(event, &context));
    }
    if event.event == "answer" {
        return paths::ToolContext::for_event(&event).and_then(|context| {
            if event.session.state.as_ref().is_some_and(|state| {
                state["awaiting_workspace_memory"] == event.payload["id"]
                    && event.payload["id"].is_string()
            }) {
                let mut response = workspace_memory::answer(&event, &context)?;
                if let Some(state) = response.get("state") {
                    let question = review_resume::question(&context, state);
                    merge_optional(&mut response, question);
                }
                Ok(response)
            } else if review_resume::owns_answer(&event, &context) {
                review_resume::answer(&event, &context)
            } else {
                memory_question::answer(&event, &context)
            }
        });
    }
    if matches!(
        event.event.as_str(),
        "turn_start" | "entry" | "turn_end" | "before_stop"
    ) {
        return Ok(observe_features(event));
    }
    if event.event == "tool_execute" {
        return if event.payload["tool_call"]["name"] == "memory" {
            paths::ToolContext::for_event(&event)
                .and_then(|context| memory_tool::execute(&event, &context))
        } else if event.payload["tool_call"]["name"] == "skill_manage" {
            paths::ToolContext::for_event(&event)
                .and_then(|context| skill_manage::execute(&event, &context))
        } else if event.payload["tool_call"]["name"] == "skill_view" {
            paths::ToolContext::for_event(&event)
                .and_then(|context| skill_view::execute(&event, &context))
        } else {
            todo::execute(&event)
        };
    }
    if event.event == "initialize" {
        let result = default_root().and_then(gears::state::StateRoot::new);
        return Ok(match result {
            Ok(root) => initialize_at(&event, &root),
            Err(error) => with_tools(&event, initialization_notice(error)),
        });
    }
    Ok(if event.event == "permission" {
        policy::permission(&event)
    } else {
        json!({})
    })
}

pub fn context_at(mut event: Event, context: &paths::ToolContext) -> Value {
    let mut response = json!({});
    for observe in [memory_context::observe, skill_context::observe] {
        let feature = observe(&event, context);
        if let Ok(feature) = &feature
            && let Some(state) = feature.get("state")
        {
            event.session.state = Some(state.clone());
        }
        merge_optional(&mut response, feature);
    }
    response
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
    for observe in [
        check_state::observe,
        skill_observation::observe,
        turns::observe,
    ] {
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
    let mut response = snapshot::initialize(event, root).unwrap_or_else(initialization_notice);
    let state = response
        .get("state")
        .cloned()
        .or_else(|| event.session.state.clone())
        .unwrap_or_else(|| json!({}));
    if state.is_object() {
        merge_optional(
            &mut response,
            paths::ToolContext::new(
                event.workspace.clone(),
                root.path().to_path_buf(),
                event.session.id.clone(),
                event.session.path.as_deref(),
            )
            .and_then(|context| {
                let workspace_state =
                    gears::state::StateRoot::new(context.workspace.join(".gears"))?;
                let discarded = workspace_state.cleanup_temporary_files()?;
                let mut feature = workspace_memory::question(event, &context, &state)?;
                if discarded != 0 {
                    let notice =
                        format!("discarded {discarded} temporary batteries workspace files");
                    let prefix = feature
                        .get("notice")
                        .and_then(Value::as_str)
                        .map(|text| format!("{text}\n"))
                        .unwrap_or_default();
                    feature["notice"] = json!(format!("{prefix}{notice}"));
                }
                Ok(feature)
            }),
        );
    }
    if response.get("prompt_fragments").is_some() {
        let mut skill_event = Event {
            protocol_version: event.protocol_version,
            event: event.event.clone(),
            workspace: event.workspace.clone(),
            session: Session {
                id: event.session.id.clone(),
                path: event.session.path.clone(),
                state: response
                    .get("state")
                    .cloned()
                    .or_else(|| event.session.state.clone()),
            },
            payload: event.payload.clone(),
        };
        skill_event.session.state = response
            .get("state")
            .cloned()
            .or_else(|| event.session.state.clone());
        merge_optional(
            &mut response,
            paths::ToolContext::new(
                event.workspace.clone(),
                root.path().to_path_buf(),
                event.session.id.clone(),
                event.session.path.as_deref(),
            )
            .and_then(|context| skill_context::initialize(&skill_event, &context)),
        );
    }
    let state = response
        .get("state")
        .cloned()
        .or_else(|| event.session.state.clone())
        .unwrap_or_else(|| json!({}));
    if state.is_object() {
        let defer = response.get("question").is_some();
        let reviews = paths::ToolContext::new(
            event.workspace.clone(),
            root.path().to_path_buf(),
            event.session.id.clone(),
            event.session.path.as_deref(),
        )
        .and_then(|context| review_resume::initialize(event, &context, &state, defer));
        merge_optional(&mut response, reviews);
    }
    with_tools(event, response)
}

fn with_tools(event: &Event, mut response: Value) -> Value {
    let events = event.payload.get("subscribed_events");
    let commands = match events {
        Some(Value::Null) => true,
        Some(Value::Array(events)) => events.iter().any(|event| event == "command"),
        _ => false,
    };
    response["commands"] = if commands {
        json!([
            acceptance::specification(),
            review_triggers::specification()
        ])
    } else {
        let notice = if matches!(events, Some(Value::Array(_))) {
            "The batteries' /accept command is disabled; add \"command\" to this hook's events to enable it."
        } else {
            "Update Gears to enable the batteries' /accept command."
        };
        merge_optional(&mut response, Ok(json!({"notice": notice})));
        json!([])
    };
    response["tools"] = json!([
        todo::specification(),
        memory_tool::specification(),
        skill_view::specification(),
        skill_manage::specification()
    ]);
    response
}

fn initialization_notice(error: String) -> Value {
    json!({"notice": format!("project instructions and prompt snapshot unavailable: {error}")})
}

pub fn default_root() -> Result<PathBuf, String> {
    gears::directory::default_root()
}

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
        } else if name == "prompt_fragments" && response[name].is_array() {
            response[name]
                .as_array_mut()
                .unwrap()
                .extend(value.as_array().unwrap().iter().cloned());
        } else if name == "context" && response.get(name).is_some() {
            let previous: gears::provider::Message =
                serde_json::from_value(response[name].clone()).expect("internal context message");
            let added: gears::provider::Message =
                serde_json::from_value(value.clone()).expect("internal context message");
            response[name] = json!(gears::provider::Message::user(format!(
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
    fn commands_require_reported_subscriptions_and_preserve_other_features() {
        for (payload, enabled) in [
            (json!({}), false),
            (json!({"subscribed_events": null}), true),
            (json!({"subscribed_events": []}), false),
            (json!({"subscribed_events": ["initialize"]}), false),
            (
                json!({"subscribed_events": ["initialize", "command"]}),
                true,
            ),
            (json!({"subscribed_events": "invalid"}), false),
        ] {
            let event = read_event(
                json!({"protocol_version": 1, "event": "initialize",
                "workspace": "/work", "session": {"id": "fixture"}, "payload": payload})
                .to_string()
                .as_bytes(),
            )
            .unwrap();
            let previous = json!({"tasks": ["keep me"]});
            let response = with_tools(
                &event,
                json!({"state": previous, "notice": "previous notice"}),
            );
            assert_eq!(
                response["commands"].as_array().unwrap().len(),
                2 * usize::from(enabled),
                "{payload}"
            );
            assert_eq!(response["tools"].as_array().unwrap().len(), 4);
            assert_eq!(response["state"], previous);
            assert!(
                response["notice"]
                    .as_str()
                    .unwrap()
                    .starts_with("previous notice")
            );
        }
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
