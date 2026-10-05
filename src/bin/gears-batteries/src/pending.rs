//! One immutable file per proposal; decision history is kept in the Gears root.

use std::path::Path;

use gears::state::StateRoot;
use serde::{Deserialize, Serialize};

use crate::memory_format::{Entry, Source, Target};
use crate::paths::ToolContext;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub version: u32,
    pub target: Target,
    pub before: Option<Entry>,
    pub after: Option<Entry>,
    pub source: Source,
    pub date_ms: u64,
}

impl Proposal {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err("unsupported pending memory version".into());
        }
        if self.before.is_none() && self.after.is_none() {
            return Err("empty memory proposal".into());
        }
        for entry in self.before.iter().chain(&self.after) {
            entry.validate(self.target)?;
        }
        if self
            .before
            .as_ref()
            .zip(self.after.as_ref())
            .is_some_and(|(before, after)| before.metadata.id != after.metadata.id)
        {
            return Err("replacement must retain the memory entry id".into());
        }
        if !crate::memory_format::identifier(&self.source.session)
            || self.source.entries.is_empty()
            || self.source.entries.len() > 32
            || self
                .source
                .entries
                .iter()
                .any(|id| !crate::memory_format::identifier(id))
        {
            return Err("invalid memory proposal source".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
    Postpone,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub proposal_id: String,
    pub proposal: Proposal,
    pub decision: Decision,
    pub date_ms: u64,
    pub workspace_memory_hash: Option<String>,
}

pub fn now_ms() -> Result<u64, String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("cannot date memory change: {error}"))?;
    u64::try_from(duration.as_millis()).map_err(|_| "memory date is out of range".into())
}

fn storage(context: &ToolContext, target: Target) -> Result<(StateRoot, &'static Path), String> {
    Ok(if target == Target::Workspace {
        (
            StateRoot::new(context.workspace.clone())?,
            Path::new(".gears/pending"),
        )
    } else {
        (context.state.clone(), Path::new("batteries/pending"))
    })
}

pub fn stage(context: &ToolContext, proposal: &Proposal) -> Result<String, String> {
    proposal.validate()?;
    let (root, directory) = storage(context, proposal.target)?;
    crate::pending_files::stage(&root, directory, proposal)
}

fn parse(value: serde_json::Value, target: Target) -> Result<Proposal, String> {
    let proposal: Proposal = serde_json::from_value(value).map_err(|error| error.to_string())?;
    proposal.validate()?;
    if (proposal.target == Target::Workspace) != (target == Target::Workspace) {
        return Err("pending proposal is in the wrong scope".into());
    }
    Ok(proposal)
}

pub fn load(context: &ToolContext, target: Target, id: &str) -> Result<Proposal, String> {
    let (root, directory) = storage(context, target)?;
    parse(crate::pending_files::load(&root, directory, id)?, target)
}

pub fn list(context: &ToolContext, target: Target) -> Result<Vec<(String, Proposal)>, String> {
    let (root, directory) = storage(context, target)?;
    let mut proposals = Vec::new();
    for (id, value) in crate::pending_files::list(&root, directory)? {
        if value["kind"] == "skill" && target != Target::Workspace {
            continue;
        }
        proposals.push((id, parse(value, target)?));
    }
    proposals.sort_by(|a, b| a.1.date_ms.cmp(&b.1.date_ms).then(a.0.cmp(&b.0)));
    Ok(proposals)
}

/// Call only after validating the change, before applying it or removing pending.
pub fn record(
    context: &ToolContext,
    id: &str,
    proposal: Proposal,
    decision: Decision,
    workspace_memory_hash: Option<String>,
) -> Result<(), String> {
    if decision == Decision::Postpone {
        return Ok(());
    }
    let record = Record {
        version: 1,
        proposal_id: id.into(),
        proposal,
        decision,
        date_ms: now_ms()?,
        workspace_memory_hash,
    };
    let path = context.state.file(Path::new("batteries/changes.jsonl"))?;
    crate::journal::append_at(&context.state, &path, &record)
}

pub fn remove(context: &ToolContext, target: Target, id: &str) -> Result<(), String> {
    let (root, directory) = storage(context, target)?;
    crate::pending_files::remove(&root, directory, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_format::{Kind, Metadata};

    #[test]
    fn proposals_are_separate_checked_files_and_decisions_retain_the_source() {
        let root = std::env::temp_dir().join(format!("batteries-pending-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let source = Source {
            session: "s1".into(),
            entries: vec!["e1".into()],
        };
        let mut proposal = Proposal {
            version: 1,
            target: Target::Workspace,
            before: None,
            after: Some(Entry {
                metadata: Metadata {
                    id: "entry-1".into(),
                    kind: Kind::Observed,
                    scope: crate::memory_format::Scope::Workspace,
                    source: source.clone(),
                    date_ms: 2,
                    applies_to: None,
                },
                text: "Use a relative src/lib.rs path.".into(),
            }),
            source,
            date_ms: 2,
        };
        let id = stage(&context, &proposal).unwrap();
        assert_eq!(
            list(&context, Target::Workspace).unwrap(),
            [(id.clone(), proposal.clone())]
        );
        assert!(list(&context, Target::Global).unwrap().is_empty());
        assert!(!context.workspace.join(".gears/MEMORY.md").exists());
        assert!(load(&context, Target::Workspace, "../escape").is_err());
        proposal.after.as_mut().unwrap().text = "Changed proposal".into();
        let second = stage(&context, &proposal).unwrap();
        assert_ne!(second, id);
        record(
            &context,
            &id,
            load(&context, Target::Workspace, &id).unwrap(),
            Decision::Postpone,
            None,
        )
        .unwrap();
        assert!(
            !context
                .state
                .path()
                .join("batteries/changes.jsonl")
                .exists()
        );
        record(
            &context,
            &id,
            load(&context, Target::Workspace, &id).unwrap(),
            Decision::Deny,
            None,
        )
        .unwrap();
        remove(&context, Target::Workspace, &id).unwrap();
        assert!(load(&context, Target::Workspace, &id).is_err());
        crate::journal::visit(
            &context.state,
            Path::new("batteries/changes.jsonl"),
            |value| {
                let record: Record = serde_json::from_value(value).unwrap();
                assert_eq!(record.decision, Decision::Deny);
                assert_eq!(record.proposal_id, id);
                assert_eq!(record.proposal.source.entries, ["e1"]);
                Ok(())
            },
        )
        .unwrap();
        let file = context
            .workspace
            .join(format!(".gears/pending/{second}.json"));
        std::fs::write(&file, "{}").unwrap();
        assert!(
            load(&context, Target::Workspace, &second)
                .unwrap_err()
                .contains("hash changed")
        );
        #[cfg(unix)]
        {
            std::fs::remove_file(&file).unwrap();
            std::os::unix::fs::symlink(root.join("outside"), &file).unwrap();
            assert!(load(&context, Target::Workspace, &second).is_err());
            assert!(remove(&context, Target::Workspace, &second).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
