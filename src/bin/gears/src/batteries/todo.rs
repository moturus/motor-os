//! A bounded task list kept in Gears' branch-aware hook state.

use std::collections::HashSet;

use crate::provider::ToolCall;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::batteries::Event;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    id: String,
    text: String,
    status: Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pending,
    InProgress,
    Completed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    items: Option<Vec<Item>>,
}

#[derive(Serialize, Deserialize)]
struct Tasks {
    version: u32,
    items: Vec<Item>,
}

pub fn specification() -> Value {
    json!({"name": "todo", "description": "Read the task list with {}, or replace it with items. Tasks follow conversation branches.",
        "parameters": {"type": "object", "additionalProperties": false,
        "properties": {"items": {"type": "array", "maxItems": 128, "items": {
            "type": "object", "additionalProperties": false, "required": ["id", "text", "status"],
            "properties": {"id": {"type": "string"}, "text": {"type": "string"},
            "status": {"type": "string", "enum": ["pending", "in_progress", "completed"]}}}}}}})
}

pub fn execute(event: &Event) -> Result<Value, String> {
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| format!("invalid todo call: {error}"))?;
    if call.name != "todo" {
        return Err("unknown batteries hook tool".into());
    }
    let arguments: Arguments = serde_json::from_str(&call.arguments)
        .map_err(|error| format!("invalid todo arguments: {error}"))?;
    let replacing = arguments.items.is_some();
    let mut state = crate::batteries::hook_state(event)?;
    let tasks = if let Some(items) = arguments.items {
        Tasks { version: 1, items }
    } else if let Some(tasks) = state.get("tasks") {
        serde_json::from_value(tasks.clone())
            .map_err(|error| format!("invalid task state: {error}"))?
    } else {
        Tasks {
            version: 1,
            items: Vec::new(),
        }
    };
    if tasks.version != 1 {
        return Err("unsupported task-list version".into());
    }
    validate(&tasks.items)?;
    let content = serde_json::to_string(&tasks).map_err(|error| error.to_string())?;
    let mut response = json!({"tool_result": {"content": content, "is_error": false}});
    if replacing {
        state["tasks"] = serde_json::to_value(tasks).map_err(|error| error.to_string())?;
        if event.session.state.as_ref() != Some(&state) {
            response["state"] = state;
        }
    }
    Ok(response)
}

fn validate(items: &[Item]) -> Result<(), String> {
    if items.len() > 128 {
        return Err("todo supports at most 128 items".into());
    }
    let mut ids = HashSet::new();
    let mut bytes = 0;
    for item in items {
        if item.id.is_empty()
            || item.id.len() > 64
            || !item
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !ids.insert(&item.id)
        {
            return Err(
                "todo ids must be unique ASCII letters, digits, underscores or hyphens".into(),
            );
        }
        if item.text.trim().is_empty()
            || item.text.len() > 2048
            || item
                .text
                .chars()
                .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
        {
            return Err(
                "todo text must be nonempty, at most 2048 bytes and contain no control characters"
                    .into(),
            );
        }
        bytes += item.id.len() + item.text.len();
    }
    if bytes > 32 * 1024 {
        return Err("todo text exceeds 32 KiB".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(arguments: Value, state: Option<Value>) -> Event {
        Event {
            protocol_version: 1,
            event: "tool_execute".into(),
            workspace: "/work".into(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state,
            },
            payload: json!({"tool_call": ToolCall::new("c1", "todo", arguments.to_string())}),
        }
    }

    #[test]
    fn branch_copies_keep_tasks_and_unrelated_hook_state() {
        let original = execute(&event(
            json!({"items": [{"id": "build", "text": "Build it", "status": "pending"}]}),
            Some(json!({"prompt_snapshot": "keep"})),
        ))
        .unwrap()["state"]
            .clone();
        let fork = execute(&event(
            json!({"items": [{"id": "build", "text": "Build it", "status": "completed"}]}),
            Some(original.clone()),
        ))
        .unwrap()["state"]
            .clone();
        assert_eq!(original["tasks"]["items"][0]["status"], "pending");
        assert_eq!(fork["tasks"]["items"][0]["status"], "completed");
        assert_eq!(fork["prompt_snapshot"], "keep");
        let resumed = execute(&event(json!({}), Some(original.clone()))).unwrap();
        assert!(resumed.get("state").is_none());
        let returned: Value =
            serde_json::from_str(resumed["tool_result"]["content"].as_str().unwrap()).unwrap();
        assert_eq!(returned["version"], 1);
        assert_eq!(returned["items"][0]["status"], "pending");
    }

    #[test]
    fn malformed_or_oversized_task_lists_do_not_replace_prior_state() {
        let previous = json!({"tasks": {"version": 1, "items": []}});
        let item = json!({"id": "one", "text": "task", "status": "pending"});
        for invalid in [
            json!({"items": [item.clone(), item]}),
            json!({"items": [{"id": "../escape", "text": "task", "status": "pending"}]}),
            json!({"items": [{"id": "one", "text": "x", "status": "unknown"}]}),
            json!({"items": [{"id": "one", "text": "x".repeat(2049), "status": "pending"}]}),
            json!({"unknown": true}),
        ] {
            let event = event(invalid, Some(previous.clone()));
            assert!(execute(&event).is_err());
            assert_eq!(event.session.state, Some(previous.clone()));
        }
    }
}
