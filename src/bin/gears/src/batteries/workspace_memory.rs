//! Imported or hand-edited workspace memory is admitted only by its exact hash.

use std::io::Read;
use std::path::Path;

use crate::state::StateRoot;
use serde_json::json;

use crate::batteries::memory_format::{Document, MAX_BYTES, Target};
use crate::batteries::paths::ToolContext;
use crate::batteries::pending::Decision;

pub fn current(context: &ToolContext) -> Result<Option<(String, String)>, String> {
    let root = StateRoot::new(context.workspace.clone())?;
    let Some(path) = root.existing_file(Target::Workspace.relative())? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("workspace memory exceeds 256 KiB".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "workspace memory is not UTF-8")?;
    Ok(Some((
        crate::batteries::snapshot::digest(text.as_bytes()),
        text,
    )))
}

pub fn approved(context: &ToolContext, hash: &str) -> Result<bool, String> {
    let mut found = false;
    crate::batteries::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record["version"] != 1
                || !matches!(record["decision"].as_str(), Some("approve" | "deny"))
            {
                return Err("unsupported or malformed memory decision record".into());
            }
            found |= record["decision"] == "approve" && record["workspace_memory_hash"] == hash;
            Ok(())
        },
    )?;
    Ok(found)
}

pub fn require_approved(context: &ToolContext) -> Result<(), String> {
    if let Some((hash, _)) = current(context)?
        && !approved(context, &hash)?
    {
        return Err("workspace MEMORY.md has not been approved; approve its exact contents before proposing entry changes".into());
    }
    Ok(())
}

/// Approval admits the displayed bytes. A changed file needs another question.
pub fn decide(context: &ToolContext, hash: &str, decision: Decision) -> Result<(), String> {
    if decision == Decision::Postpone {
        return Ok(());
    }
    let (actual, text) = current(context)?.ok_or("workspace memory is unavailable")?;
    if actual != hash {
        return Err("workspace memory changed since it was shown".into());
    }
    let limit =
        crate::batteries::memory_config::load(&context.state)?.for_target(Target::Workspace);
    Document::parse(&text, Target::Workspace, limit)?;
    let record = json!({"version": 1, "kind": "workspace_memory", "decision": decision,
        "date_ms": crate::batteries::pending::now_ms()?, "workspace_memory_hash": hash,
        "source": {"path": ".gears/MEMORY.md"}, "memory": text});
    let path = context.state.file(Path::new("batteries/changes.jsonl"))?;
    crate::batteries::journal::append_at(&context.state, &path, &record)
}

pub fn question(
    event: &crate::batteries::Event,
    context: &ToolContext,
    state: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let Some((hash, text)) = current(context)? else {
        return Ok(json!({}));
    };
    if approved(context, &hash)? {
        return Ok(json!({}));
    }
    let limit =
        crate::batteries::memory_config::load(&context.state)?.for_target(Target::Workspace);
    Document::parse(&text, Target::Workspace, limit)?;
    let mut state = state.clone();
    state["awaiting_workspace_memory"] = json!(hash);
    let mut response = json!({"notice": format!("Unapproved workspace .gears/MEMORY.md (hash {hash}):\n{text}"),
        "question": {"id": hash, "text": "Approve these exact workspace memory contents for future sessions?",
        "choices": [{"value": "approve", "label": "Approve"}, {"value": "deny", "label": "Deny"},
            {"value": "postpone", "label": "Postpone"}]}});
    if event.session.state.as_ref() != Some(&state) {
        response["state"] = state;
    }
    Ok(response)
}

pub fn answer(
    event: &crate::batteries::Event,
    context: &ToolContext,
) -> Result<serde_json::Value, String> {
    let mut state = crate::batteries::hook_state(event)?;
    let hash = state["awaiting_workspace_memory"]
        .as_str()
        .ok_or("no workspace memory question is waiting")?
        .to_string();
    if event.payload["id"] != hash {
        return Err("workspace memory answer has the wrong hash".into());
    }
    let decision = crate::batteries::memory_question::decision(event)?;
    if let Err(error) = decide(context, &hash, decision) {
        let text = format!(
            "Workspace memory decision failed: {error}. The displayed version has not been admitted."
        );
        return Ok(json!({"notice": text, "context": crate::provider::Message::user(text)}));
    }
    state
        .as_object_mut()
        .unwrap()
        .remove("awaiting_workspace_memory");
    let outcome = match decision {
        Decision::Approve => "approved; available at the next new session or compaction",
        Decision::Deny => "denied; not used",
        Decision::Postpone => "postponed; not used",
    };
    let text = format!("Workspace memory {hash}: {outcome}. Approval admits use, not usefulness.");
    Ok(json!({"state": state, "notice": text, "context": crate::provider::Message::user(text)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::memory_format::{Entry, Kind, Metadata, Scope, Source};

    #[test]
    fn cloning_and_hand_edits_cannot_reuse_an_approval_for_other_bytes() {
        let path =
            std::env::temp_dir().join(format!("batteries-workspace-memory-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace/.gears")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        require_approved(&context).unwrap();
        let document = Document {
            entries: vec![Entry {
                metadata: Metadata {
                    id: "entry-1".into(),
                    kind: Kind::Observed,
                    scope: Scope::Workspace,
                    source: Source {
                        review: None,
                        session: "elsewhere".into(),
                        entries: vec!["e1".into()],
                    },
                    date_ms: 1,
                    applies_to: None,
                },
                text: "Project fact from another machine.".into(),
            }],
        };
        let text = document.encode(Target::Workspace, 2200).unwrap();
        let file = context.workspace.join(".gears/MEMORY.md");
        std::fs::write(&file, &text).unwrap();
        let (hash, _) = current(&context).unwrap().unwrap();
        assert!(!approved(&context, &hash).unwrap());
        assert!(require_approved(&context).is_err());
        decide(&context, &hash, Decision::Postpone).unwrap();
        decide(&context, &hash, Decision::Deny).unwrap();
        assert!(!approved(&context, &hash).unwrap());
        let mut event = crate::batteries::Event {
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
        let temporary = context.workspace.join(".gears/pending/.gears-tmp-crashed");
        std::fs::create_dir_all(temporary.parent().unwrap()).unwrap();
        std::fs::write(&temporary, "partial").unwrap();
        let response = crate::batteries::initialize_at(&event, &context.state);
        assert_eq!(response["question"]["id"], hash);
        assert!(!temporary.exists());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
        assert!(
            response["notice"]
                .as_str()
                .unwrap()
                .contains("Project fact from another machine.")
        );
        assert!(
            !response["prompt_fragments"]
                .to_string()
                .contains("Project fact from another machine.")
        );
        event.session.state = Some(response["state"].clone());
        event.event = "answer".into();
        event.payload =
            json!({"id": hash, "answer": "approve", "attended": true, "cancelled": false});
        let answer = answer(&event, &context).unwrap();
        assert!(answer["context"].to_string().contains("approved"));
        assert!(answer["state"].get("awaiting_workspace_memory").is_none());
        event.session.state = None;
        event.event = "initialize".into();
        event.payload = json!({"reason": "new"});
        let next = crate::batteries::initialize_at(&event, &context.state);
        assert!(
            next["prompt_fragments"]
                .to_string()
                .contains("Project fact from another machine.")
        );
        assert!(next.get("question").is_none());
        require_approved(&context).unwrap();
        std::fs::write(&file, text.replace("another machine", "a hand edit")).unwrap();
        assert!(require_approved(&context).is_err());
        assert!(
            decide(&context, &hash, Decision::Approve)
                .unwrap_err()
                .contains("changed")
        );
        let cloned = ToolContext::new(
            context.workspace.clone(),
            path.join("other-state"),
            "s2".into(),
            None,
        )
        .unwrap();
        std::fs::write(&file, text).unwrap();
        assert!(require_approved(&cloned).is_err());
        assert!(approved(&context, &hash).unwrap());
        assert_eq!(current(&context).unwrap().unwrap().0, hash);
        std::fs::remove_dir_all(path).unwrap();
    }
}
