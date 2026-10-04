//! Imported or hand-edited workspace memory is admitted only by its exact hash.

use std::io::Read;
use std::path::Path;

use gears::state::StateRoot;
use serde_json::json;

use crate::memory_format::{Document, MAX_BYTES, Target};
use crate::paths::ToolContext;
use crate::pending::Decision;

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
    Ok(Some((crate::snapshot::digest(text.as_bytes()), text)))
}

pub fn approved(context: &ToolContext, hash: &str) -> Result<bool, String> {
    let mut found = false;
    crate::journal::visit(
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
    let limit = crate::memory_config::load(&context.state)?.for_target(Target::Workspace);
    Document::parse(&text, Target::Workspace, limit)?;
    let record = json!({"version": 1, "kind": "workspace_memory", "decision": decision,
        "date_ms": crate::pending::now_ms()?, "workspace_memory_hash": hash,
        "source": {"path": ".gears/MEMORY.md"}, "memory": text});
    let path = context.state.file(Path::new("batteries/changes.jsonl"))?;
    crate::journal::append_at(&context.state, &path, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_format::{Entry, Kind, Metadata, Scope, Source};

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
        decide(&context, &hash, Decision::Approve).unwrap();
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
