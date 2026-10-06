//! Memory proposals validate against current entries before any decision is written.

use gears::state::StateRoot;

use crate::memory_format::{Document, Entry, Target};
use crate::paths::ToolContext;
use crate::pending::{Decision, Proposal};

pub fn root(context: &ToolContext, target: Target) -> Result<StateRoot, String> {
    if target == Target::Workspace {
        StateRoot::new(context.workspace.clone())
    } else {
        Ok(context.state.clone())
    }
}

pub fn load(context: &ToolContext, target: Target) -> Result<Document, String> {
    let limit = crate::memory_config::load(&context.state)?.for_target(target);
    crate::memory_format::load(&root(context, target)?, target, limit)
}

fn same_memory(a: &Entry, b: &Entry) -> bool {
    a.text == b.text
        && a.metadata.kind == b.metadata.kind
        && a.metadata.scope == b.metadata.scope
        && a.metadata.applies_to == b.metadata.applies_to
}

fn preview(context: &ToolContext, proposal: &Proposal) -> Result<String, String> {
    proposal.validate()?;
    if proposal.target == Target::Workspace {
        crate::workspace_memory::require_approved(context)?;
    }
    let mut document = load(context, proposal.target)?;
    if let Some(before) = &proposal.before {
        let index = document
            .entries
            .iter()
            .position(|entry| entry.metadata.id == before.metadata.id)
            .ok_or("memory entry was removed since the proposal was made")?;
        if document.entries[index] != *before {
            return Err("memory entry changed since the proposal was made".into());
        }
        if let Some(after) = &proposal.after {
            document.entries[index] = after.clone();
        } else {
            document.entries.remove(index);
        }
    } else if let Some(after) = &proposal.after {
        if document
            .entries
            .iter()
            .any(|entry| entry.metadata.id == after.metadata.id)
        {
            return Err("memory entry id already exists".into());
        }
        document.entries.push(after.clone());
    }
    let limit = crate::memory_config::load(&context.state)?.for_target(proposal.target);
    document.encode(proposal.target, limit)
}

/// None means the requested entry already exists, without a new proposal.
pub fn propose(context: &ToolContext, proposal: &Proposal) -> Result<Option<String>, String> {
    proposal.validate()?;
    if proposal.target == Target::Workspace {
        crate::workspace_memory::require_approved(context)?;
    }
    let document = load(context, proposal.target)?;
    if let Some(before) = &proposal.before
        && !document.entries.iter().any(|entry| entry == before)
    {
        return Err("memory entry changed or was removed since the proposal was made".into());
    }
    if proposal.after.as_ref().is_some_and(|after| {
        document
            .entries
            .iter()
            .any(|entry| same_memory(entry, after))
    }) {
        return Ok(None);
    }
    preview(context, proposal)?;
    for (id, existing) in crate::pending::list(context, proposal.target)? {
        if existing.target == proposal.target
            && existing.before == proposal.before
            && match (&existing.after, &proposal.after) {
                (Some(a), Some(b)) => same_memory(a, b),
                (None, None) => true,
                _ => false,
            }
        {
            return Ok(Some(id));
        }
    }
    crate::pending::stage(context, proposal).map(Some)
}

pub fn decide(
    context: &ToolContext,
    target: Target,
    id: &str,
    decision: Decision,
) -> Result<(), String> {
    let proposal = crate::pending::load(context, target, id)?;
    if decision == Decision::Postpone {
        return Ok(());
    }
    let encoded = if decision == Decision::Approve {
        Some(preview(context, &proposal)?)
    } else {
        None
    };
    let hash = encoded
        .as_ref()
        .filter(|_| proposal.target == Target::Workspace)
        .map(|text| crate::snapshot::digest(text.as_bytes()));
    // Deliberately no transaction or replay: stop at the first failed write.
    crate::pending::record(context, id, proposal.clone(), decision, hash)?;
    if let Some(text) = encoded {
        root(context, proposal.target)?
            .replace_file(proposal.target.relative(), text.as_bytes())?;
    }
    crate::pending::remove(context, proposal.target, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_format::{Kind, Metadata, Source};

    fn fixture(label: &str) -> (std::path::PathBuf, ToolContext, Proposal) {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-{label}-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let source = Source {
            review: None,
            session: "s1".into(),
            entries: vec!["e1".into()],
        };
        let proposal = Proposal {
            version: 1,
            target: Target::Global,
            before: None,
            date_ms: 1,
            source: source.clone(),
            after: Some(Entry {
                metadata: Metadata {
                    id: "entry-1".into(),
                    kind: Kind::User,
                    scope: Target::Global.scope(),
                    source,
                    date_ms: 1,
                    applies_to: None,
                },
                text: "Prefer Rust.".into(),
            }),
        };
        (path, context, proposal)
    }

    #[test]
    fn admission_postpones_denies_and_ignores_duplicates_without_changing_live_memory() {
        let (path, context, mut proposal) = fixture("admission");
        let id = propose(&context, &proposal).unwrap().unwrap();
        proposal.date_ms = 2;
        assert_eq!(propose(&context, &proposal).unwrap(), Some(id.clone()));
        assert!(load(&context, Target::Global).unwrap().entries.is_empty());
        decide(&context, Target::Global, &id, Decision::Postpone).unwrap();
        assert_eq!(
            crate::pending::list(&context, Target::Global)
                .unwrap()
                .len(),
            1
        );
        decide(&context, Target::Global, &id, Decision::Deny).unwrap();
        assert!(load(&context, Target::Global).unwrap().entries.is_empty());
        assert!(
            crate::pending::list(&context, Target::Global)
                .unwrap()
                .is_empty()
        );
        let id = propose(&context, &proposal).unwrap().unwrap();
        decide(&context, Target::Global, &id, Decision::Approve).unwrap();
        assert_eq!(
            load(&context, Target::Global).unwrap().entries,
            [proposal.after.clone().unwrap()]
        );
        proposal.after.as_mut().unwrap().metadata.id = "duplicate".into();
        assert!(propose(&context, &proposal).unwrap().is_none());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn stale_entries_and_failed_history_writes_leave_memory_and_pending_untouched() {
        let (path, context, mut proposal) = fixture("stale");
        let id = propose(&context, &proposal).unwrap().unwrap();
        let history = context.state.path().join("batteries/changes.jsonl");
        std::fs::create_dir(&history).unwrap();
        assert!(decide(&context, Target::Global, &id, Decision::Approve).is_err());
        assert!(load(&context, Target::Global).unwrap().entries.is_empty());
        assert!(crate::pending::load(&context, Target::Global, &id).is_ok());
        std::fs::remove_dir(&history).unwrap();
        decide(&context, Target::Global, &id, Decision::Approve).unwrap();
        proposal.before = proposal.after.clone();
        proposal.after.as_mut().unwrap().text = "Prefer native APIs.".into();
        let id = propose(&context, &proposal).unwrap().unwrap();
        let unchanged = std::fs::read(&history).unwrap();
        context
            .state
            .replace_file(Target::Global.relative(), b"# Gears memory v1\n")
            .unwrap();
        assert!(
            decide(&context, Target::Global, &id, Decision::Approve)
                .unwrap_err()
                .contains("removed")
        );
        assert_eq!(std::fs::read(&history).unwrap(), unchanged);
        let mut changed = Document {
            entries: vec![proposal.before.unwrap()],
        };
        changed.entries[0].text = "A hand correction.".into();
        context
            .state
            .replace_file(
                Target::Global.relative(),
                changed.encode(Target::Global, 2200).unwrap().as_bytes(),
            )
            .unwrap();
        assert!(
            decide(&context, Target::Global, &id, Decision::Approve)
                .unwrap_err()
                .contains("changed")
        );
        assert_eq!(load(&context, Target::Global).unwrap(), changed);
        assert!(crate::pending::load(&context, Target::Global, &id).is_ok());
        let removal = Proposal {
            before: changed.entries.first().cloned(),
            after: None,
            ..proposal
        };
        let remove_id = propose(&context, &removal).unwrap().unwrap();
        decide(&context, Target::Global, &remove_id, Decision::Approve).unwrap();
        assert!(load(&context, Target::Global).unwrap().entries.is_empty());
        assert!(crate::pending::load(&context, Target::Global, &id).is_ok());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn approving_one_workspace_entry_does_not_admit_an_unreviewed_import() {
        let (path, context, mut proposal) = fixture("workspace");
        proposal.target = Target::Workspace;
        proposal.after.as_mut().unwrap().metadata.scope = Target::Workspace.scope();
        let id = propose(&context, &proposal).unwrap().unwrap();
        let document = Document {
            entries: vec![proposal.after.clone().unwrap()],
        };
        let text = document.encode(Target::Workspace, 2200).unwrap();
        root(&context, Target::Workspace)
            .unwrap()
            .replace_file(Target::Workspace.relative(), text.as_bytes())
            .unwrap();
        assert!(
            decide(&context, Target::Workspace, &id, Decision::Approve)
                .unwrap_err()
                .contains("not been approved")
        );
        let hash = crate::snapshot::digest(text.as_bytes());
        crate::workspace_memory::decide(&context, &hash, Decision::Approve).unwrap();
        proposal.before = proposal.after.clone();
        proposal.after.as_mut().unwrap().text = "Corrected project fact.".into();
        let id = propose(&context, &proposal).unwrap().unwrap();
        decide(&context, Target::Workspace, &id, Decision::Approve).unwrap();
        crate::workspace_memory::require_approved(&context).unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }
}
