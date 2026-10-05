//! Bounded pages of decision history and a compact view of implemented features.

use serde_json::{Value, json};
use std::path::Path;

use crate::memory_format::Target;
use crate::paths::ToolContext;

pub fn history(context: &ToolContext, offset: usize, limit: usize) -> Result<Value, String> {
    if !(1..=100).contains(&limit) {
        return Err("history limit must be 1–100".into());
    }
    let mut total = 0_usize;
    let mut records = Vec::new();
    crate::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |value| {
            if value["version"] != 1
                || !matches!(value["decision"].as_str(), Some("approve" | "deny"))
            {
                return Err("unsupported or malformed memory decision record".into());
            }
            if total >= offset && records.len() < limit {
                records.push(value);
            }
            total = total.checked_add(1).ok_or("too many memory decisions")?;
            Ok(())
        },
    )?;
    let next = offset.saturating_add(records.len());
    Ok(json!({"version": 1, "records": records, "total": total,
        "next_offset": (next < total).then_some(next)}))
}

pub fn status(context: &ToolContext) -> Value {
    let count = |target| match crate::pending::list(context, target) {
        Ok(items) if target == Target::Global => match crate::skill_pending::list(context) {
            Ok(skills) => {
                json!({"count": items.len() + skills.len(), "memory": items.len(), "skills": skills.len()})
            }
            Err(error) => json!({"unavailable": error}),
        },
        Ok(items) => json!({"count": items.len()}),
        Err(error) => json!({"unavailable": error}),
    };
    let workspace = crate::workspace_memory::current(context)
        .and_then(|current| {
            current
                .map(|(hash, _)| {
                    crate::workspace_memory::approved(context, &hash)
                        .map(|approved| json!({"hash": hash, "approved": approved}))
                })
                .transpose()
                .map(|memory| memory.unwrap_or_else(|| json!({"present": false})))
        })
        .unwrap_or_else(|error| json!({"unavailable": error}));
    json!({"version": 1, "reviews": "not implemented", "review_models": [],
        "pending_global": count(Target::Global), "pending_workspace": count(Target::Workspace),
        "workspace_memory": workspace, "last_review": "not implemented", "last_eval": "not implemented"})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::Decision;

    #[test]
    fn history_pages_decisions_ignores_a_crash_tail_and_reports_optional_status_failures() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-history-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "cli".into(),
            None,
        )
        .unwrap();
        let log = context
            .state
            .file(Path::new("batteries/changes.jsonl"))
            .unwrap();
        for (number, decision) in [Decision::Approve, Decision::Deny, Decision::Approve]
            .into_iter()
            .enumerate()
        {
            crate::journal::append_at(
                &context.state,
                &log,
                &json!({"version": 1, "number": number, "decision": decision}),
            )
            .unwrap();
        }
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"{unfinished")
            .unwrap();
        let page = history(&context, 1, 1).unwrap();
        assert_eq!(page["total"], 3);
        assert_eq!(page["next_offset"], 2);
        assert_eq!(page["records"][0]["decision"], "deny");
        assert!(
            history(&context, 3, 20).unwrap()["records"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(history(&context, 0, 0).is_err());
        let status = status(&context);
        assert_eq!(status["pending_global"]["count"], 0);
        assert_eq!(status["reviews"], "not implemented");
        let pending = context
            .state
            .directory(Path::new("batteries/pending"))
            .unwrap();
        std::fs::write(pending.join("broken.json"), "{}").unwrap();
        assert!(super::status(&context)["pending_global"]["unavailable"].is_string());
        assert_eq!(super::status(&context)["pending_workspace"]["count"], 0);
        std::fs::write(&log, b"{broken}\n").unwrap();
        assert!(
            history(&context, 0, 20)
                .unwrap_err()
                .contains("invalid journal record")
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
