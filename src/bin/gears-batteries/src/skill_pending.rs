//! Skill proposals preserve complete before/after versions until a user decides.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::memory_format::Source;
use crate::paths::ToolContext;
use crate::pending::Decision;
use crate::skill_format::Content;

const DIRECTORY: &str = "batteries/pending";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub version: u32,
    pub kind: String,
    pub name: String,
    pub before: Option<Content>,
    pub after: Option<Content>,
    pub source: Source,
    pub date_ms: u64,
}

impl Proposal {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 || self.kind != "skill" || !crate::skill_format::valid_name(&self.name)
        {
            return Err("invalid skill proposal version, kind or name".into());
        }
        if self.before.is_none() && self.after.is_none() {
            return Err("empty skill proposal".into());
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
            return Err("invalid skill proposal source".into());
        }
        Ok(())
    }

    fn validate_after(&self, context: &ToolContext) -> Result<(), String> {
        if let Some(after) = &self.after {
            let limits = crate::skill_config::load(&context.state)?;
            if self
                .before
                .as_ref()
                .is_none_or(|before| before.skill_md != after.skill_md)
            {
                after.validate_written(&self.name, limits.skill_chars, limits.notes_chars)?;
            } else {
                after.parse(&self.name, limits.skill_chars, limits.notes_chars)?;
            }
        }
        Ok(())
    }

    fn check_current(&self, context: &ToolContext) -> Result<(), String> {
        if crate::skill_store::current(context, &self.name)? != self.before {
            return Err("skill changed or was removed since the proposal was made".into());
        }
        Ok(())
    }
}

fn parse(value: serde_json::Value) -> Result<Proposal, String> {
    let proposal: Proposal = serde_json::from_value(value).map_err(|error| error.to_string())?;
    proposal.validate()?;
    Ok(proposal)
}

pub fn load(context: &ToolContext, id: &str) -> Result<Proposal, String> {
    parse(crate::pending_files::load(
        &context.state,
        Path::new(DIRECTORY),
        id,
    )?)
}

pub fn list(context: &ToolContext) -> Result<Vec<(String, Proposal)>, String> {
    let mut proposals = Vec::new();
    for (id, value) in crate::pending_files::list(&context.state, Path::new(DIRECTORY))? {
        if value["kind"] == "skill" {
            proposals.push((id, parse(value)?));
        }
    }
    proposals.sort_by(|a, b| a.1.date_ms.cmp(&b.1.date_ms).then(a.0.cmp(&b.0)));
    Ok(proposals)
}

pub fn propose(context: &ToolContext, proposal: &Proposal) -> Result<Option<String>, String> {
    proposal.validate()?;
    proposal.check_current(context)?;
    proposal.validate_after(context)?;
    if proposal.before == proposal.after
        && proposal
            .after
            .as_ref()
            .map(|content| crate::skill_store::approved(context, &proposal.name, &content.hash()))
            .transpose()?
            .unwrap_or(false)
    {
        return Ok(None);
    }
    for (id, existing) in list(context)? {
        if existing.name == proposal.name
            && existing.before == proposal.before
            && existing.after == proposal.after
        {
            return Ok(Some(id));
        }
    }
    crate::pending_files::stage(&context.state, Path::new(DIRECTORY), proposal).map(Some)
}

pub fn decide(context: &ToolContext, id: &str, decision: Decision) -> Result<(), String> {
    let proposal = load(context, id)?;
    if decision == Decision::Postpone {
        return Ok(());
    }
    if decision == Decision::Approve {
        proposal.check_current(context)?;
        proposal.validate_after(context)?;
    }
    let path = context.state.file(Path::new("batteries/changes.jsonl"))?;
    crate::journal::append_at(
        &context.state,
        &path,
        &json!({"version": 1, "kind": "skill",
        "name": proposal.name, "content_hash": proposal.after.as_ref().map(Content::hash), "proposal_id": id,
        "proposal": proposal, "decision": decision, "date_ms": crate::pending::now_ms()?}),
    )?;
    if decision == Decision::Approve {
        crate::skill_store::write(context, &proposal.name, proposal.after.as_ref())?;
    }
    crate::pending_files::remove(&context.state, Path::new(DIRECTORY), id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_skills_stay_hidden_and_stale_versions_fail_before_decision_logging() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-pending-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let mut proposal = Proposal { version: 1, kind: "skill".into(), name: "checks".into(), before: None,
            after: Some(Content { skill_md: "---\nname: checks\ndescription: Run checks.\n---\n## When it applies\nRust.\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n".into(), notes_md: None }),
            source: Source { session: "s1".into(), entries: vec!["e1".into()] }, date_ms: 1 };
        let id = propose(&context, &proposal).unwrap().unwrap();
        assert!(
            crate::pending::list(&context, crate::memory_format::Target::Global)
                .unwrap()
                .is_empty()
        );
        assert!(
            crate::skill_store::current(&context, "checks")
                .unwrap()
                .is_none()
        );
        assert_eq!(propose(&context, &proposal).unwrap(), Some(id.clone()));
        decide(&context, &id, Decision::Postpone).unwrap();
        assert_eq!(list(&context).unwrap().len(), 1);
        decide(&context, &id, Decision::Approve).unwrap();
        let content = crate::skill_store::current(&context, "checks")
            .unwrap()
            .unwrap();
        assert!(crate::skill_store::approved(&context, "checks", &content.hash()).unwrap());
        proposal.before = Some(content);
        proposal.after.as_mut().unwrap().notes_md = Some("New quirk.\n".into());
        let stale = propose(&context, &proposal).unwrap().unwrap();
        crate::skill_store::write(&context, "checks", None).unwrap();
        assert!(
            decide(&context, &stale, Decision::Approve)
                .unwrap_err()
                .contains("removed since")
        );
        assert_eq!(
            crate::memory_history::history(&context, 0, 20).unwrap()["total"],
            1
        );
        assert_eq!(list(&context).unwrap().len(), 1);
        decide(&context, &stale, Decision::Deny).unwrap();
        assert_eq!(
            crate::memory_history::history(&context, 0, 20).unwrap()["total"],
            2
        );
        assert!(list(&context).unwrap().is_empty());
        std::fs::remove_dir_all(path).unwrap();
    }
}
