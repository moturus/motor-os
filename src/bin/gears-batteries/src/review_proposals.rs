//! Review provenance and limits use the durable proposals and decision history.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{
    Event,
    memory_format::{Source, Target},
    paths::ToolContext,
    review_marks,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub session: String,
    pub path: PathBuf,
    pub mark: String,
}

pub fn source(event: &Event, context: &ToolContext, mut source: Source) -> Result<Source, String> {
    let state = crate::hook_state(event)?;
    if state["run_kind"] != "review" {
        return Ok(source);
    }
    let run: Run = serde_json::from_value(state["review_run"].clone())
        .map_err(|error| format!("invalid review run: {error}"))?;
    let parent = ToolContext::new(
        context.workspace.clone(),
        context.state.path().into(),
        run.session,
        Some(&run.path),
    )?;
    let mark = review_marks::load(&parent, &run.mark)?.ok_or("review mark is missing")?;
    if mark.disposition != review_marks::Disposition::Due {
        return Err("review mark is no longer due".into());
    }
    let settings = crate::review_config::load(&context.state)?;
    if !settings.enabled_for(&mark.executor.provider, &mark.executor.model) {
        return Err("reviews are disabled for this mark's executor".into());
    }
    let snapshot = gears::session::read_snapshot(&run.path)?;
    if snapshot.id() != parent.session || snapshot.workspace() != parent.workspace {
        return Err("review source belongs to another session or workspace".into());
    }
    let selected = snapshot.at(&mark.entry)?;
    let mut entries = vec![mark.entry];
    // The ephemeral calling entry is not durable evidence. Cite the saved parent.
    for entry in source.entries.iter().skip(1) {
        if selected.entry(entry).is_none() {
            return Err(format!(
                "review citation {entry:?} is outside the marked history"
            ));
        }
        if !entries.contains(entry) {
            entries.push(entry.clone());
        }
    }
    if count(&parent, &run.mark)? >= settings.max_proposals {
        return Err(format!(
            "review proposal limit ({}) exhausted",
            settings.max_proposals
        ));
    }
    source.session = parent.session;
    source.entries = entries;
    source.review = Some(run.mark);
    Ok(source)
}

fn count(context: &ToolContext, mark: &str) -> Result<usize, String> {
    let mut ids = HashSet::new();
    let belongs = |source: &Source| {
        source.session == context.session && source.review.as_deref() == Some(mark)
    };
    for target in [Target::Global, Target::Workspace] {
        for (id, proposal) in crate::pending::list(context, target)? {
            if belongs(&proposal.source) {
                ids.insert(id);
            }
        }
    }
    for (id, proposal) in crate::skill_pending::list(context)? {
        if belongs(&proposal.source) {
            ids.insert(id);
        }
    }
    // A decision may have moved a proposal out of pending while the review stopped.
    crate::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record["version"] != 1
                || !matches!(record["decision"].as_str(), Some("approve" | "deny"))
            {
                return Err("unsupported or malformed memory decision record".into());
            }
            let source = &record["proposal"]["source"];
            if source["session"] == context.session && source["review"] == mark {
                ids.insert(
                    record["proposal_id"]
                        .as_str()
                        .ok_or("review decision has no proposal id")?
                        .to_string(),
                );
            }
            Ok(())
        },
    )?;
    Ok(ids.len())
}
