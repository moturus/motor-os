//! Agent-written skills and notes always wait for a user decision.

use crate::provider::ToolCall;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::memory_format::Source;
use crate::batteries::paths::ToolContext;
use crate::batteries::skill_format::Content;
use crate::batteries::skill_pending::Proposal;

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Action {
    Add,
    Replace,
    Remove,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    action: Action,
    name: String,
    skill_md: Option<String>,
    notes_md: Option<String>,
    #[serde(default)]
    source_entries: Vec<String>,
}

pub fn specification() -> Value {
    json!({"name": "skill_manage", "description": "Propose adding, replacing or removing a skill by directory name. All changes wait in gears-batteries pending for user approval of exact SKILL.md and NOTES.md contents; approval does not prove usefulness. New or rewritten SKILL.md requires YAML name/description and Markdown headings: ## When it applies, ## Steps, ## How to check, ## Pitfalls. Put explicit platform names in metadata.platforms (e.g. motor linux). Replace may omit skill_md or notes_md to preserve them; notes_md=null removes notes. Source ids are provenance claims.",
        "parameters": {"type": "object", "additionalProperties": false, "required": ["action", "name"],
        "properties": {"action": {"type": "string", "enum": ["add", "replace", "remove"]}, "name": {"type": "string"},
        "skill_md": {"type": "string"}, "notes_md": {"type": ["string", "null"]},
        "source_entries": {"type": "array", "maxItems": 31, "items": {"type": "string"}}}}})
}

pub fn execute(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| error.to_string())?;
    if call.name != "skill_manage" {
        return Err("unknown skill management tool".into());
    }
    let value: Value = serde_json::from_str(&call.arguments)
        .map_err(|error| format!("invalid skill_manage arguments: {error}"))?;
    let arguments: Arguments = serde_json::from_value(value.clone())
        .map_err(|error| format!("invalid skill_manage arguments: {error}"))?;
    if !crate::batteries::skill_format::valid_name(&arguments.name) {
        return Err("invalid skill name".into());
    }
    if arguments.source_entries.len() > 31 {
        return Err("at most 31 additional skill source entries are allowed".into());
    }
    let before = crate::batteries::skill_store::current(context, &arguments.name)?;
    if arguments.action == Action::Add && before.is_some() {
        return Err("skill already exists; use replace".into());
    }
    if arguments.action != Action::Add && before.is_none() {
        return Err("skill does not exist".into());
    }
    if arguments.action == Action::Remove
        && (value.get("skill_md").is_some() || value.get("notes_md").is_some())
    {
        return Err("skill remove takes no replacement content".into());
    }
    if arguments.action == Action::Replace
        && value.get("skill_md").is_none()
        && value.get("notes_md").is_none()
    {
        return Err("skill replace needs skill_md or notes_md".into());
    }
    let after = if arguments.action == Action::Remove {
        None
    } else {
        let skill_md = arguments
            .skill_md
            .or_else(|| before.as_ref().map(|before| before.skill_md.clone()))
            .ok_or("skill add requires skill_md")?;
        let notes_md = if value.get("notes_md").is_some() {
            arguments.notes_md
        } else {
            before.as_ref().and_then(|before| before.notes_md.clone())
        };
        Some(Content { skill_md, notes_md })
    };
    let state = crate::batteries::hook_state(event)?;
    let caller = state["turn_record"]["last_entry_id"]
        .as_str()
        .ok_or("skill proposal has no saved calling entry; enable entry and turn_start hooks")?;
    let mut entries = vec![caller.to_string()];
    entries.extend(arguments.source_entries);
    entries.dedup();
    let proposal = Proposal {
        version: 1,
        kind: "skill".into(),
        cleanup: None,
        name: arguments.name,
        before,
        after,
        source: Source {
            review: None,
            session: context.session.clone(),
            entries,
        },
        date_ms: crate::batteries::pending::now_ms()?,
    };
    let proposal = Proposal {
        source: crate::batteries::review_proposals::source(event, context, proposal.source)?,
        ..proposal
    };
    let id = crate::batteries::skill_pending::propose(context, &proposal)?;
    Ok(
        json!({"tool_result": {"content": json!({"version": 1, "status": if id.is_some() { "pending" } else { "duplicate_ignored" },
        "proposal_id": id, "review": "Use gears-batteries pending to approve, deny or postpone. Pending content is not available to skill_view."}).to_string(), "is_error": false}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::pending::Decision;

    #[test]
    fn proposals_remain_hidden_and_notes_edits_preserve_the_existing_skill() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-manage-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let skill_md = "---\nname: checks\ndescription: Run checks.\nmetadata: {platforms: motor linux}\n---\n## When it applies\nRust.\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n";
        let mut event = Event {
            protocol_version: 1,
            event: "tool_execute".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: Some(json!({"turn_record": {"last_entry_id": "e1"}})),
            },
            payload: json!({"tool_call": ToolCall::new("c1", "skill_manage", json!({"action": "add", "name": "checks", "skill_md": skill_md}).to_string())}),
        };
        let response = execute(&event, &context).unwrap();
        let result: Value =
            serde_json::from_str(response["tool_result"]["content"].as_str().unwrap()).unwrap();
        let id = result["proposal_id"].as_str().unwrap();
        assert!(
            crate::batteries::skill_store::current(&context, "checks")
                .unwrap()
                .is_none()
        );
        let proposal = crate::batteries::skill_pending::load(&context, id).unwrap();
        assert_eq!(proposal.source.entries, ["e1"]);
        crate::batteries::skill_pending::decide(&context, id, Decision::Approve).unwrap();
        event.payload = json!({"tool_call": ToolCall::new("c2", "skill_manage", json!({"action": "replace", "name": "checks", "notes_md": "New quirk."}).to_string())});
        execute(&event, &context).unwrap();
        let pending = crate::batteries::skill_pending::list(&context).unwrap();
        assert_eq!(pending[0].1.after.as_ref().unwrap().skill_md, skill_md);
        assert_eq!(
            pending[0].1.after.as_ref().unwrap().notes_md.as_deref(),
            Some("New quirk.")
        );
        assert!(
            crate::batteries::skill_store::current(&context, "checks")
                .unwrap()
                .unwrap()
                .notes_md
                .is_none()
        );
        for arguments in [
            json!({"action": "replace", "name": "checks"}),
            json!({"action": "remove", "name": "checks", "notes_md": null}),
            json!({"action": "add", "name": "../escape", "skill_md": skill_md}),
            json!({"action": "replace", "name": "checks", "unknown": "data"}),
        ] {
            event.payload =
                json!({"tool_call": ToolCall::new("bad", "skill_manage", arguments.to_string())});
            assert!(execute(&event, &context).is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
