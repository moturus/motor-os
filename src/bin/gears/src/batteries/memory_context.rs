//! A durable view makes each memory correction visible once on its active branch.

use crate::provider::Message;
use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::paths::ToolContext;
use crate::batteries::snapshot::Snapshot;

pub fn observe(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let mut state = crate::batteries::hook_state(event)?;
    let Some(hash) = state.get("prompt_snapshot") else {
        return Ok(json!({}));
    };
    let frozen = crate::batteries::snapshot::load(
        &context.state,
        hash.as_str().ok_or("invalid prompt snapshot hash")?,
    )?;
    if frozen.memory.is_empty() {
        return Ok(json!({}));
    }
    let previous = if let Some(hash) = state.get("memory_view_snapshot") {
        let view = crate::batteries::snapshot::load(
            &context.state,
            hash.as_str().ok_or("invalid memory view hash")?,
        )?;
        if !view.fragments.is_empty() {
            return Err("memory view contains project fragments".into());
        }
        view.memory
    } else {
        frozen.memory.clone()
    };
    let (live, notices) = crate::batteries::memory_snapshot::load(context);
    let desired = crate::batteries::memory_snapshot::reconcile(&frozen.memory, &live)?;
    let mut response = json!({});
    if let Some(note) = crate::batteries::memory_snapshot::changes(&previous, &desired)? {
        let view = Snapshot {
            version: 2,
            fragments: Vec::new(),
            memory: desired,
        };
        state["memory_view_snapshot"] =
            json!(crate::batteries::snapshot::save(&context.state, &view)?);
        response["state"] = state;
        response["context"] = json!(Message::user(note));
    }
    if !notices.is_empty() {
        response["notice"] = json!(notices.join("\n"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::memory_format::{Document, Entry, Target};
    use serde_json::json;

    #[test]
    fn corrections_are_branch_local_and_removed_material_is_absent_on_resume() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-context-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let mut entry: Entry = serde_json::from_value(json!({"metadata": {"id": "preference", "kind": "user",
            "scope": "global", "source": {"session": "s1", "entries": ["e1"]}, "date_ms": 1}, "text": "Old fact."})).unwrap();
        let mut document = Document {
            entries: vec![entry.clone()],
        };
        context
            .state
            .replace_file(
                Target::User.relative(),
                document.encode(Target::User, 1375).unwrap().as_bytes(),
            )
            .unwrap();
        let mut event = Event {
            protocol_version: 1,
            event: "initialize".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: None,
            },
            payload: json!({"reason": "startup"}),
        };
        let initial = crate::batteries::snapshot::initialize(&event, &context.state).unwrap();
        event.session.state = Some(initial["state"].clone());
        let frozen_branch = event.session.state.clone();
        assert!(observe(&event, &context).unwrap().get("context").is_none());
        entry.text = "Corrected fact.".into();
        document.entries[0] = entry;
        context
            .state
            .replace_file(
                Target::User.relative(),
                document.encode(Target::User, 1375).unwrap().as_bytes(),
            )
            .unwrap();
        let corrected = observe(&event, &context).unwrap();
        assert!(corrected["context"].to_string().contains("Corrected fact."));
        assert_eq!(
            corrected["state"]["prompt_snapshot"],
            initial["state"]["prompt_snapshot"]
        );
        event.session.state = Some(corrected["state"].clone());
        assert!(observe(&event, &context).unwrap().get("context").is_none());
        let corrected_branch = event.session.state.clone();
        event.session.state = frozen_branch;
        assert!(
            observe(&event, &context).unwrap()["context"]
                .to_string()
                .contains("Corrected fact.")
        );
        event.session.state = corrected_branch;
        context
            .state
            .replace_file(Target::User.relative(), b"# Gears memory v1\n")
            .unwrap();
        let removed = observe(&event, &context).unwrap();
        assert!(
            removed["context"]
                .to_string()
                .contains("Withdraw User memory entry preference")
        );
        event.session.state = Some(removed["state"].clone());
        assert!(observe(&event, &context).unwrap().get("context").is_none());
        event.payload = json!({"reason": "resume"});
        let resumed = crate::batteries::snapshot::initialize(&event, &context.state).unwrap();
        assert!(
            !resumed["prompt_fragments"]
                .to_string()
                .contains("Old fact.")
        );
        assert!(
            !resumed["prompt_fragments"]
                .to_string()
                .contains("Corrected fact.")
        );
        assert!(resumed["state"].get("memory_view_snapshot").is_none());
        std::fs::remove_dir_all(path).unwrap();
    }
}
