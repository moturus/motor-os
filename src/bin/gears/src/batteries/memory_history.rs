//! Pages of the change log and a one-screen status; a bad log line is counted, not fatal.

use std::collections::VecDeque;
use std::path::Path;

use serde_json::{Value, json};

use crate::batteries::memory_format::Target;
use crate::batteries::paths::ToolContext;

const LOG: &str = "batteries/changes.jsonl";

pub fn history(context: &ToolContext, offset: usize, limit: usize) -> Result<Value, String> {
    if !(1..=100).contains(&limit) {
        return Err("history limit must be 1–100".into());
    }
    let mut total = 0_usize;
    let mut unreadable = 0_usize;
    let mut records = Vec::new();
    crate::batteries::journal::visit_lenient(&context.state, Path::new(LOG), |record| {
        match record {
            Ok(value) => {
                if total >= offset && records.len() < limit {
                    records.push(value);
                }
                total += 1;
            }
            Err(_) => unreadable += 1,
        }
        Ok(())
    })?;
    let next = offset.saturating_add(records.len());
    Ok(
        json!({"version": 2, "records": records, "total": total, "unreadable": unreadable,
        "next_offset": (next < total).then_some(next)}),
    )
}

/// The texts of the last `count` declined changes, each cut to 120 characters.
pub fn declines(context: &ToolContext, count: usize) -> Result<Vec<String>, String> {
    let mut texts = VecDeque::new();
    crate::batteries::journal::visit_lenient(&context.state, Path::new(LOG), |record| {
        if let Ok(value) = record
            && value["version"] == 2
            && value["decision"] == "no"
            && let Some(text) = value["text"].as_str()
        {
            texts.push_back(text.chars().take(120).collect::<String>());
            if texts.len() > count {
                texts.pop_front();
            }
        }
        Ok(())
    })?;
    Ok(texts.into())
}

pub fn status(context: &ToolContext) -> Value {
    let offers = crate::batteries::memory_config::load(&context.state)
        .map(|limits| json!(limits.offer_lessons))
        .unwrap_or_else(|error| json!({"unavailable": error}));
    let count = |target| match crate::batteries::memory::load(context, target) {
        Ok(document) => json!(document.entries.len()),
        Err(error) => json!({"unavailable": error}),
    };
    let (catalog, notices) =
        crate::batteries::skill_catalog::load(context, crate::batteries::skill_catalog::platform());
    let mut yes = 0;
    let mut no = 0;
    let mut unreadable = 0;
    let decisions =
        crate::batteries::journal::visit_lenient(&context.state, Path::new(LOG), |record| {
            match record.map(|value| value["decision"].as_str().map(str::to_string)) {
                Ok(Some(decision)) if matches!(decision.as_str(), "yes" | "approve") => yes += 1,
                Ok(Some(decision)) if matches!(decision.as_str(), "no" | "deny") => no += 1,
                _ => unreadable += 1,
            }
            Ok(())
        })
        .map(|()| json!({"yes": yes, "no": no, "unreadable": unreadable}))
        .unwrap_or_else(|error| json!({"unavailable": error}));
    let mut status = json!({"version": 2, "offer_lessons": offers,
        "entries": {"user": count(Target::User), "global": count(Target::Global), "workspace": count(Target::Workspace)},
        "skills": catalog.iter().map(|skill| skill.name.clone()).collect::<Vec<_>>(),
        "decisions": decisions});
    if !notices.is_empty() {
        status["skill_notices"] = json!(notices);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_pages_decisions_counts_bad_lines_and_status_reports_what_is_there() {
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
        let log = context.state.file(Path::new(LOG)).unwrap();
        for (number, decision) in ["yes", "no", "yes"].into_iter().enumerate() {
            crate::batteries::journal::append_at(
                &context.state,
                &log,
                &json!({"version": 2, "number": number, "decision": decision, "text": format!("entry {number}")}),
            )
            .unwrap();
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        file.write_all(b"{broken}\n{\"version\":1,\"decision\":\"approve\"}\n{unfinished")
            .unwrap();
        let page = history(&context, 1, 1).unwrap();
        assert_eq!(page["total"], 4);
        assert_eq!(page["unreadable"], 1);
        assert_eq!(page["next_offset"], 2);
        assert_eq!(page["records"][0]["decision"], "no");
        assert!(
            history(&context, 4, 20).unwrap()["records"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(history(&context, 0, 0).is_err());
        assert_eq!(declines(&context, 5).unwrap(), ["entry 1"]);
        let status = status(&context);
        assert_eq!(status["offer_lessons"], false);
        assert_eq!(status["entries"]["user"], 0);
        assert_eq!(status["skills"], json!([]));
        assert_eq!(
            status["decisions"],
            json!({"yes": 3, "no": 1, "unreadable": 1})
        );
        context
            .state
            .replace_file(Target::Global.relative(), b"not a memory file")
            .unwrap();
        assert!(super::status(&context)["entries"]["global"]["unavailable"].is_string());
        std::fs::remove_dir_all(path).unwrap();
    }
}
