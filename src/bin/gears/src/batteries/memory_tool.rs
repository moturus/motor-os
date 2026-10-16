//! The memory tool proposes one entry change; the hook asks the user before writing.

use crate::provider::ToolCall;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::memory::{Action, Change};
use crate::batteries::memory_format::{Entry, Target};
use crate::batteries::paths::ToolContext;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Requested {
    List,
    Add,
    Replace,
    Remove,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    action: Requested,
    target: Target,
    id: Option<String>,
    text: Option<String>,
}

pub fn specification() -> Value {
    json!({"name": "memory", "description": "List memory entries, or propose adding, replacing or removing one entry. The user is asked to approve every change and nothing is written otherwise. Facts about the user go to user memory, facts about this computer to global memory, and facts about this project to workspace memory with paths relative to the workspace. A fact true on one system should name it.",
        "parameters": {"type": "object", "additionalProperties": false, "required": ["action", "target"],
        "properties": {"action": {"type": "string", "enum": ["list", "add", "replace", "remove"]},
        "target": {"type": "string", "enum": ["user", "global", "workspace"]},
        "id": {"type": "string", "description": "The entry to replace or remove."},
        "text": {"type": "string", "description": "The entry text for add or replace."}}}})
}

pub fn execute(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| format!("invalid memory call: {error}"))?;
    if call.name != "memory" {
        return Err("unknown memory tool".into());
    }
    let arguments: Arguments = serde_json::from_str(&call.arguments)
        .map_err(|error| format!("invalid memory arguments: {error}"))?;
    let document = crate::batteries::memory::load(context, arguments.target)?;
    let action = match arguments.action {
        Requested::List => {
            if arguments.id.is_some() || arguments.text.is_some() {
                return Err("memory list takes only action and target".into());
            }
            return Ok(result(json!({"version": 2, "entries": document.entries})));
        }
        Requested::Add => Action::Add,
        Requested::Replace => Action::Replace,
        Requested::Remove => Action::Remove,
    };
    let before = if action == Action::Add {
        None
    } else {
        let id = arguments
            .id
            .as_ref()
            .ok_or("memory replace/remove requires an entry id")?;
        Some(
            document
                .entries
                .iter()
                .find(|entry| entry.id == *id)
                .cloned()
                .ok_or("memory entry id does not exist")?,
        )
    };
    let after = if action == Action::Remove {
        if arguments.text.is_some() {
            return Err("memory remove takes an id, without replacement text".into());
        }
        None
    } else {
        let text = arguments
            .text
            .ok_or("memory add/replace requires entry text")?
            .trim_end_matches('\n')
            .to_string();
        let (date, time_ms) = crate::batteries::memory_format::today()?;
        let id = match (&before, arguments.id) {
            (Some(before), _) => before.id.clone(),
            (None, Some(id)) => id,
            (None, None) => crate::batteries::memory::new_id(
                &document,
                &format!("{}:{}:{time_ms}", context.session, call.id),
            ),
        };
        Some(Entry {
            id,
            date,
            session: context.session.clone(),
            text,
        })
    };
    let change = Change {
        version: 2,
        target: arguments.target,
        action,
        before,
        after,
    };
    if !crate::batteries::memory::propose(context, &change)? {
        return Ok(result(
            json!({"version": 2, "status": "already_remembered"}),
        ));
    }
    let mut state = crate::batteries::hook_state(event)?;
    state["awaiting_memory"] =
        json!({"version": 2, "question": format!("memory-{}", call.id), "change": change});
    let mut response = result(
        json!({"version": 2, "status": "proposed", "note": "The user is being asked; the answer follows."}),
    );
    response["state"] = state;
    Ok(response)
}

fn result(content: Value) -> Value {
    json!({"tool_result": {"content": content.to_string(), "is_error": false}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals_wait_in_hook_state_and_malformed_calls_are_refused() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-tool-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let mut event = Event {
            protocol_version: 1,
            event: "tool_execute".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: Some(json!({"tasks": ["keep"], "prompt_snapshot": "unchanged"})),
            },
            payload: json!({"tool_call": ToolCall::new("c1", "memory", json!({"action": "add", "target": "user", "text": "Prefer Rust.\n"}).to_string())}),
        };
        let response = execute(&event, &context).unwrap();
        assert_eq!(response["state"]["tasks"], json!(["keep"]));
        assert_eq!(response["state"]["prompt_snapshot"], "unchanged");
        assert_eq!(
            response["state"]["awaiting_memory"]["question"],
            "memory-c1"
        );
        let change: Change =
            serde_json::from_value(response["state"]["awaiting_memory"]["change"].clone()).unwrap();
        assert_eq!(change.action, Action::Add);
        let after = change.after.unwrap();
        assert_eq!(
            (after.text.as_str(), after.session.as_str(), after.id.len()),
            ("Prefer Rust.", "s1", 4)
        );
        assert!(
            crate::batteries::memory::load(&context, Target::User)
                .unwrap()
                .entries
                .is_empty()
        );
        event.payload["tool_call"] = json!(ToolCall::new(
            "c2",
            "memory",
            json!({"action": "list", "target": "user"}).to_string()
        ));
        assert!(
            execute(&event, &context).unwrap()["tool_result"]["content"]
                .as_str()
                .unwrap()
                .contains("\"entries\":[]")
        );
        for bad in [
            json!({"action": "replace", "target": "user", "text": "whole file"}),
            json!({"action": "replace", "target": "user", "id": "absent", "text": "x"}),
            json!({"action": "add", "target": "user", "file": "USER.md", "text": "whole file"}),
            json!({"action": "add", "target": "user", "kind": "user", "text": "old field"}),
            json!({"action": "remove", "target": "user", "id": "one", "text": "replacement"}),
            json!({"action": "list", "target": "user", "text": "extra"}),
        ] {
            event.payload["tool_call"] = json!(ToolCall::new("bad", "memory", bad.to_string()));
            assert!(execute(&event, &context).is_err(), "{bad}");
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
