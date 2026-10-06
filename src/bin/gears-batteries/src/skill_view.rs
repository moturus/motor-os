//! Loading exposes only approved bytes and records the version on this branch.

use gears::provider::ToolCall;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::Event;
use crate::memory_format::Source;
use crate::paths::ToolContext;
use crate::skill_snapshot::Loaded;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    name: Option<String>,
}

pub fn specification() -> Value {
    json!({"name": "skill_view", "description": "Load one approved skill and its NOTES.md by name, or omit name to list the session catalog. Load at most three relevant skills per task. Loading is an observation, not proof of usefulness; current instructions take precedence. New skills enter the catalog at a new session or compaction.",
        "parameters": {"type": "object", "additionalProperties": false, "properties": {"name": {"type": "string"}}}})
}

pub fn execute(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let call: ToolCall = serde_json::from_value(event.payload["tool_call"].clone())
        .map_err(|error| error.to_string())?;
    if call.name != "skill_view" {
        return Err("unknown skill view tool".into());
    }
    let arguments: Arguments = serde_json::from_str(&call.arguments)
        .map_err(|error| format!("invalid skill_view arguments: {error}"))?;
    let mut state = crate::hook_state(event)?;
    let hash = state["skill_snapshot"]
        .as_str()
        .ok_or("skill catalog is unavailable; initialize the batteries hook")?;
    let mut frozen = crate::skill_snapshot::load(context, hash)?;
    let (catalog, _) = crate::skill_catalog::load(context, crate::skill_catalog::platform());
    let mut desired = crate::skill_snapshot::reconcile(context, &frozen, &catalog)?;
    let Some(name) = arguments.name else {
        return Ok(
            json!({"tool_result": {"content": json!({"version": 1, "skills": desired.catalog}).to_string(), "is_error": false}}),
        );
    };
    let descriptor = desired
        .catalog
        .iter()
        .find(|skill| skill.name == name)
        .ok_or("skill is unavailable or not approved in this session catalog")?;
    let content = crate::skill_store::current(context, &name)?.ok_or("skill is unavailable")?;
    if content.hash() != descriptor.hash {
        return Err("skill changed before it could be loaded".into());
    }
    if frozen.loaded.len() == 3 && !frozen.loaded.iter().any(|skill| skill.name == name) {
        return Err("at most three skills may be loaded in a session; start a new session or compact to refresh skills".into());
    }
    let caller = state["turn_record"]["last_entry_id"]
        .as_str()
        .ok_or("skill load has no saved calling entry; enable entry and turn_start hooks")?;
    let loaded = Loaded {
        name: name.clone(),
        content: content.clone(),
        source: Source {
            review: None,
            session: context.session.clone(),
            entries: vec![caller.into()],
        },
    };
    frozen.loaded.retain(|skill| skill.name != name);
    desired.loaded.retain(|skill| skill.name != name);
    frozen.loaded.push(loaded.clone());
    desired.loaded.push(loaded.clone());
    state["skill_snapshot"] = json!(crate::skill_snapshot::save(context, &frozen)?);
    state["skill_view_snapshot"] = json!(crate::skill_snapshot::save(context, &desired)?);
    crate::skill_loads::record(context, &name, &descriptor.hash, loaded.source)?;
    Ok(
        json!({"state": state, "tool_result": {"content": json!({"version": 1, "name": name,
        "hash": descriptor.hash, "content": content, "observation": "Loaded an approved skill; this does not establish successful use or usefulness."}).to_string(), "is_error": false}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::Decision;
    use crate::skill_format::Content;

    #[test]
    fn view_returns_notes_without_changing_the_catalog_and_rejects_unapproved_edits() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-view-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let mut content = Content { skill_md: "---\nname: checks\ndescription: Run checks.\nmetadata: {platforms: motor linux}\n---\nInstructions.\n".into(), notes_md: Some("A quirk.".into()) };
        crate::skill_store::write(&context, "checks", Some(&content)).unwrap();
        crate::skill_store::admit(&context, "checks", &content.hash(), Decision::Approve).unwrap();
        let mut event = Event {
            protocol_version: 1,
            event: "initialize".into(),
            workspace: context.workspace.clone(),
            session: crate::Session {
                id: "s1".into(),
                path: None,
                state: Some(json!({"turn_record": {"last_entry_id": "e1"}})),
            },
            payload: json!({}),
        };
        let initial = crate::skill_context::initialize(&event, &context).unwrap();
        event.session.state = Some(initial["state"].clone());
        event.event = "tool_execute".into();
        event.payload =
            json!({"tool_call": ToolCall::new("c1", "skill_view", r#"{"name":"checks"}"#)});
        let result = execute(&event, &context).unwrap();
        assert!(
            result["tool_result"]["content"]
                .as_str()
                .unwrap()
                .contains("A quirk.")
        );
        event.session.state = Some(result["state"].clone());
        let resumed = crate::skill_context::initialize(&event, &context).unwrap();
        assert_eq!(resumed["prompt_fragments"], initial["prompt_fragments"]);
        assert!(resumed.get("state").is_none());
        content.notes_md = Some("Unapproved note.".into());
        crate::skill_store::write(&context, "checks", Some(&content)).unwrap();
        assert!(
            execute(&event, &context)
                .unwrap_err()
                .contains("not approved")
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
