//! Current denials and saved mechanical evidence follow the frozen prefix.

use std::path::Path;

use serde_json::json;

use crate::{paths::ToolContext, review_marks::Mark};

const MAX_BYTES: usize = 64 * 1024;
const INSTRUCTIONS: &str = include_str!("review_instructions.md");

pub fn build(
    context: &ToolContext,
    parent_path: &Path,
    mark: &Mark,
    hook: &str,
) -> Result<String, String> {
    let snapshot = gears::session::read_snapshot(parent_path)?;
    if snapshot.id() != context.session
        || snapshot.workspace() != context.workspace
        || mark.session != context.session
    {
        return Err("review evidence belongs to another session or workspace".into());
    }
    let selected = snapshot.at(&mark.entry)?;
    let settings = crate::review_config::load(&context.state)?;
    let mut text = format!(
        "{INSTRUCTIONS}\nSaved parent session: {}\nMarked entry: {}\nMaximum proposals: {}\n",
        context.session, mark.entry, settings.max_proposals
    );
    // JSON quoting keeps the user's literal focus separate from evidence markers.
    text.push_str(&format!("User review focus: {}\n", json!(mark.focus)));
    crate::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record["version"] != 1
                || !matches!(record["decision"].as_str(), Some("approve" | "deny"))
            {
                return Err("unsupported or malformed review decision record".into());
            }
            if record["decision"] == "deny" {
                append(&mut text, "denied change", &record)?;
            }
            Ok(())
        },
    )?;
    let relative = format!("batteries/sessions/{}/turns.jsonl", context.session);
    crate::journal::visit(&context.state, Path::new(&relative), |record| {
        let turn: crate::turns::Turn = serde_json::from_value(record.clone())
            .map_err(|error| format!("invalid review turn record: {error}"))?;
        if turn.version != 1 {
            return Err("unsupported review turn record".into());
        }
        if turn
            .last_entry_id
            .as_ref()
            .is_some_and(|id| selected.entry(id).is_some())
        {
            append(&mut text, "completed turn record", &record)?;
        }
        Ok(())
    })?;
    if let Some(turn) = selected
        .hook_state(hook)
        .and_then(|state| state.get("turn_record").cloned())
    {
        let partial: crate::turns::Turn = serde_json::from_value(turn.clone())
            .map_err(|error| format!("invalid partial review turn record: {error}"))?;
        if partial.version != 1 {
            return Err("unsupported partial review turn record".into());
        }
        append(
            &mut text,
            "partial turn record at the mark (not a completed result)",
            &turn,
        )?;
    }
    if text.len() > MAX_BYTES {
        return Err("review instructions and evidence exceed 64 KiB; mark remains due".into());
    }
    Ok(text)
}

fn append(text: &mut String, source: &str, value: &serde_json::Value) -> Result<(), String> {
    let serialized = serde_json::to_string(value).map_err(|error| error.to_string())?;
    let evidence = crate::provenance::wrap(source, &serialized);
    if text.len().saturating_add(evidence.len() + 2) > MAX_BYTES {
        return Err("review instructions and evidence exceed 64 KiB; mark remains due".into());
    }
    text.push('\n');
    text.push_str(&evidence);
    text.push('\n');
    Ok(())
}
