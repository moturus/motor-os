//! Frozen memory admits additions later while following corrections by entry id.

use serde::{Deserialize, Serialize};

use crate::memory_format::{Document, Entry, Target};
use crate::paths::ToolContext;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Stored {
    pub target: Target,
    pub document: String,
}

impl Stored {
    pub fn entries(&self) -> Result<Vec<Entry>, String> {
        Ok(Document::parse(&self.document, self.target, 65536)?.entries)
    }

    pub fn prompt(&self) -> String {
        format!(
            "Approved {:?} memory. Kinds and source ids record provenance claims; approval admits use, not usefulness. Current user and project instructions take precedence.\n{}",
            self.target, self.document
        )
    }
}

/// Optional memory failures affect their own file and never project instructions.
pub fn load(context: &ToolContext) -> (Vec<Stored>, Vec<String>) {
    let limits = match crate::memory_config::load(&context.state) {
        Ok(limits) => limits,
        Err(error) => {
            return (
                Vec::new(),
                vec![format!("memory settings unavailable: {error}")],
            );
        }
    };
    let mut stored = Vec::new();
    let mut notices = Vec::new();
    for target in [Target::User, Target::Global, Target::Workspace] {
        let result: Result<Option<Stored>, String> = (|| {
            if target == Target::Workspace {
                crate::workspace_memory::require_approved(context)?;
            }
            let document = crate::memory_format::load(
                &crate::memory::root(context, target)?,
                target,
                limits.for_target(target),
            )?;
            if document.entries.is_empty() {
                return Ok(None);
            }
            Ok(Some(Stored {
                target,
                document: document.encode(target, limits.for_target(target))?,
            }))
        })();
        match result {
            Ok(Some(memory)) => stored.push(memory),
            Ok(None) => {}
            Err(error) => notices.push(format!("{target:?} memory unavailable: {error}")),
        }
    }
    (stored, notices)
}

/// Keep only ids in the original snapshot. Live additions stay out of this session.
pub fn reconcile(frozen: &[Stored], live: &[Stored]) -> Result<Vec<Stored>, String> {
    let mut result = Vec::new();
    for stored in frozen {
        let current = live
            .iter()
            .find(|memory| memory.target == stored.target)
            .map(Stored::entries)
            .transpose()?
            .unwrap_or_default();
        let entries = stored
            .entries()?
            .into_iter()
            .filter_map(|old| {
                current
                    .iter()
                    .find(|entry| entry.metadata.id == old.metadata.id)
                    .cloned()
            })
            .collect();
        let document = Document { entries };
        if !document.entries.is_empty() {
            result.push(Stored {
                target: stored.target,
                document: document.encode(stored.target, 65536)?,
            });
        }
    }
    Ok(result)
}

fn entries(stored: &[Stored]) -> Result<Vec<(Target, Entry)>, String> {
    let mut result = Vec::new();
    let mut targets = Vec::new();
    for memory in stored {
        if targets.contains(&memory.target) {
            return Err("duplicate memory snapshot target".into());
        }
        targets.push(memory.target);
        result.extend(
            memory
                .entries()?
                .into_iter()
                .map(|entry| (memory.target, entry)),
        );
    }
    Ok(result)
}

/// Compare with the last delivered view, so removal and restoration are each noted once.
pub fn changes(previous: &[Stored], desired: &[Stored]) -> Result<Option<String>, String> {
    let previous = entries(previous)?;
    let desired = entries(desired)?;
    let mut lines = Vec::new();
    for (target, before) in &previous {
        let after = desired
            .iter()
            .find(|(scope, entry)| scope == target && entry.metadata.id == before.metadata.id);
        match after {
            None => lines.push(format!(
                "Withdraw {target:?} memory entry {}. Do not use its earlier text.",
                before.metadata.id
            )),
            Some((_, after)) if after != before => lines.push(format!(
                "Correct {target:?} memory entry {}. Its earlier text is superseded by: {}",
                before.metadata.id,
                serde_json::to_string(after).map_err(|error| error.to_string())?
            )),
            _ => {}
        }
    }
    for (target, after) in &desired {
        if !previous
            .iter()
            .any(|(scope, entry)| scope == target && entry.metadata.id == after.metadata.id)
        {
            lines.push(format!(
                "Restore {target:?} memory entry {}: {}",
                after.metadata.id,
                serde_json::to_string(after).map_err(|error| error.to_string())?
            ));
        }
    }
    Ok((!lines.is_empty()).then(|| {
        format!(
            "Memory updates: current instructions take precedence over remembered heuristics.\n{}",
            lines.join("\n")
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(id: &str, text: &str) -> Entry {
        serde_json::from_value(
            json!({"metadata": {"id": id, "kind": "user", "scope": "global",
            "source": {"session": "s1", "entries": ["e1"]}, "date_ms": 1}, "text": text}),
        )
        .unwrap()
    }

    fn stored(entries: Vec<Entry>) -> Stored {
        Stored {
            target: Target::User,
            document: Document { entries }.encode(Target::User, 1375).unwrap(),
        }
    }

    #[test]
    fn frozen_ids_exclude_additions_and_follow_corrections_removals_and_restorations() {
        let frozen = vec![stored(vec![entry("one", "Old preference.")])];
        let mut live = vec![stored(vec![
            entry("one", "Old preference."),
            entry("two", "Added later."),
        ])];
        assert_eq!(reconcile(&frozen, &live).unwrap(), frozen);
        assert!(
            changes(&frozen, &reconcile(&frozen, &live).unwrap())
                .unwrap()
                .is_none()
        );
        live[0] = stored(vec![
            entry("one", "Corrected preference."),
            entry("two", "Added later."),
        ]);
        let corrected = reconcile(&frozen, &live).unwrap();
        let note = changes(&frozen, &corrected).unwrap().unwrap();
        assert!(note.contains("Correct User memory entry one"));
        assert!(note.contains("Corrected preference."));
        assert!(!note.contains("Added later."));
        assert!(changes(&corrected, &corrected).unwrap().is_none());
        live[0] = stored(vec![entry("two", "Added later.")]);
        let removed = reconcile(&frozen, &live).unwrap();
        assert!(removed.is_empty());
        assert!(
            changes(&corrected, &removed)
                .unwrap()
                .unwrap()
                .contains("Withdraw User memory entry one")
        );
        assert!(changes(&removed, &removed).unwrap().is_none());
        assert!(
            changes(&removed, &frozen)
                .unwrap()
                .unwrap()
                .contains("Restore User memory entry one")
        );
    }

    #[test]
    fn a_broken_file_or_unapproved_import_does_not_hide_other_memory() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-snapshot-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let original = stored(vec![entry("one", "Global user preference.")]);
        context
            .state
            .replace_file(Target::User.relative(), original.document.as_bytes())
            .unwrap();
        context
            .state
            .replace_file(Target::Global.relative(), b"broken file")
            .unwrap();
        let mut workspace_entry = entry("project", "Unapproved workspace fact.");
        workspace_entry.metadata.scope = Target::Workspace.scope();
        let text = Document {
            entries: vec![workspace_entry],
        }
        .encode(Target::Workspace, 2200)
        .unwrap();
        crate::memory::root(&context, Target::Workspace)
            .unwrap()
            .replace_file(Target::Workspace.relative(), text.as_bytes())
            .unwrap();
        let (memory, notices) = load(&context);
        assert_eq!(memory, [original]);
        assert_eq!(notices.len(), 2);
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("not been approved"))
        );
        assert!(!memory[0].prompt().contains("Unapproved workspace fact."));
        std::fs::remove_dir_all(path).unwrap();
    }
}
