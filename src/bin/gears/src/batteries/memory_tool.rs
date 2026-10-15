//! The memory tool proposes entry changes; it never writes live memory itself.

use crate::provider::ToolCall;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::memory_format::{Entry, Kind, Metadata, Source, Target};
use crate::batteries::paths::ToolContext;
use crate::batteries::pending::Proposal;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Action {
    List,
    Add,
    Replace,
    Remove,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    action: Action,
    target: Target,
    id: Option<String>,
    kind: Option<Kind>,
    text: Option<String>,
    applies_to: Option<String>,
    source_entries: Option<Vec<String>>,
}

pub fn specification() -> Value {
    json!({"name": "memory", "description": "List memory entries or propose adding, replacing or removing one entry by id. Every change requires user approval; unattended proposals stay pending. Workspace facts use workspace memory and relative paths, facts true on one system name it, and machine facts use global memory. Kind records whether the user said it, a tool outcome shows it, or it was inferred; approval does not prove usefulness. source_entries can cite saved evidence ids; the proposal also records its calling entry. Whole-file replacement is refused.",
        "parameters": {"type": "object", "additionalProperties": false, "required": ["action", "target"],
        "properties": {"action": {"type": "string", "enum": ["list", "add", "replace", "remove"]},
        "target": {"type": "string", "enum": ["user", "global", "workspace"]},
        "id": {"type": "string", "description": "Required existing entry id for replace/remove; optional ASCII id for add."},
        "kind": {"type": "string", "enum": ["user", "observed", "inferred"], "description": "Defaults to user for USER.md, inferred otherwise."},
        "text": {"type": "string", "description": "Required entry body for add/replace."},
        "applies_to": {"type": "string", "description": "Relevant project/tool versions or system."},
        "source_entries": {"type": "array", "maxItems": 31, "items": {"type": "string"}}}}})
}

pub fn execute(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| format!("invalid memory call: {error}"))?;
    if call.name != "memory" {
        return Err("unknown memory tool".into());
    }
    let arguments: Arguments = serde_json::from_str(&call.arguments)
        .map_err(|error| format!("invalid memory arguments: {error}"))?;
    if arguments.target == Target::Workspace {
        crate::batteries::workspace_memory::require_approved(context)?;
    }
    let document = crate::batteries::memory::load(context, arguments.target)?;
    if arguments.action == Action::List {
        if arguments.id.is_some()
            || arguments.kind.is_some()
            || arguments.text.is_some()
            || arguments.applies_to.is_some()
            || arguments.source_entries.is_some()
        {
            return Err("memory list takes only action and target".into());
        }
        return Ok(result(json!({"version": 1, "entries": document.entries})));
    }
    if arguments.action == Action::Remove
        && (arguments.kind.is_some() || arguments.text.is_some() || arguments.applies_to.is_some())
    {
        return Err("memory remove takes an id, without replacement text or metadata".into());
    }
    let mut state = crate::batteries::hook_state(event)?;
    let caller = state["turn_record"]["last_entry_id"].as_str().ok_or(
        "memory proposal has no saved calling entry; enable the entry and turn_start hooks",
    )?;
    let mut entries = vec![caller.to_string()];
    entries.extend(arguments.source_entries.unwrap_or_default());
    entries.dedup();
    let source = Source {
        review: None,
        session: context.session.clone(),
        entries,
    };
    let source = crate::batteries::review_proposals::source(event, context, source)?;
    let date_ms = crate::batteries::pending::now_ms()?;
    let before = if matches!(arguments.action, Action::Replace | Action::Remove) {
        let id = arguments
            .id
            .as_ref()
            .ok_or("memory replace/remove requires an entry id")?;
        Some(
            document
                .entries
                .into_iter()
                .find(|entry| entry.metadata.id == *id)
                .ok_or("memory entry id does not exist")?,
        )
    } else {
        None
    };
    let after = if arguments.action != Action::Remove {
        let id = arguments.id.unwrap_or_else(|| {
            crate::batteries::snapshot::digest(
                json!([context.session, caller, call.id, date_ms])
                    .to_string()
                    .as_bytes(),
            )
        });
        let kind = arguments
            .kind
            .unwrap_or(if arguments.target == Target::User {
                Kind::User
            } else {
                Kind::Inferred
            });
        Some(Entry {
            metadata: Metadata {
                id,
                kind,
                scope: arguments.target.scope(),
                source: source.clone(),
                date_ms,
                applies_to: arguments.applies_to,
            },
            text: arguments
                .text
                .ok_or("memory add/replace requires entry text")?
                .trim_end_matches('\n')
                .to_string(),
        })
    } else {
        None
    };
    let proposal = Proposal {
        version: 1,
        target: arguments.target,
        before,
        after,
        source,
        date_ms,
    };
    let Some(id) = crate::batteries::memory::propose(context, &proposal)? else {
        return Ok(result(json!({"version": 1, "status": "duplicate_ignored"})));
    };
    state["awaiting_memory"] = json!({"version": 1, "id": id, "target": arguments.target});
    let mut response = result(json!({"version": 1, "status": "pending", "proposal_id": id}));
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
    fn proposals_record_calling_entry_preserve_branch_state_and_refuse_whole_files() {
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
                state: Some(
                    json!({"tasks": ["keep"], "prompt_snapshot": "unchanged", "turn_record": {"last_entry_id": "e-call"}}),
                ),
            },
            payload: json!({"tool_call": ToolCall::new("c1", "memory", json!({"action": "add", "target": "user", "text": "Prefer Rust.\n", "source_entries": ["e-user"]}).to_string())}),
        };
        let response = execute(&event, &context).unwrap();
        assert_eq!(response["state"]["tasks"], json!(["keep"]));
        assert_eq!(response["state"]["prompt_snapshot"], "unchanged");
        let id = response["state"]["awaiting_memory"]["id"].as_str().unwrap();
        let proposal = crate::batteries::pending::load(&context, Target::User, id).unwrap();
        assert_eq!(proposal.source.entries, ["e-call", "e-user"]);
        assert_eq!(proposal.after.as_ref().unwrap().metadata.kind, Kind::User);
        assert_eq!(proposal.after.as_ref().unwrap().text, "Prefer Rust.");
        assert!(
            crate::batteries::memory::load(&context, Target::User)
                .unwrap()
                .entries
                .is_empty()
        );
        for bad in [
            json!({"action": "replace", "target": "user", "text": "whole file"}),
            json!({"action": "add", "target": "user", "file": "USER.md", "text": "whole file"}),
            json!({"action": "remove", "target": "user", "id": "one", "text": "replacement"}),
        ] {
            event.payload["tool_call"] = json!(ToolCall::new("bad", "memory", bad.to_string()));
            assert!(execute(&event, &context).is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
