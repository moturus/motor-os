//! Read-only evidence and old prompt membership for a pending memory entry.

use crate::provider::Message;
use serde_json::{Value, json};
use std::path::Path;

use crate::batteries::paths::ToolContext;
use crate::batteries::pending::Proposal;

pub fn describe(context: &ToolContext, proposal: &Proposal) -> Result<Value, String> {
    describe_with(context, &proposal.source, |session| {
        let Some(before) = &proposal.before else {
            return Ok(false);
        };
        let mut matched = false;
        for entry in session
            .entries()
            .iter()
            .filter(|entry| entry.kind == "hook_state")
        {
            let Some(hash) = entry.data["state"]["prompt_snapshot"].as_str() else {
                continue;
            };
            let snapshot = crate::batteries::snapshot::load(&context.state, hash)?;
            for memory in snapshot
                .memory
                .iter()
                .filter(|memory| memory.target == proposal.target)
            {
                matched |= memory.entries()?.iter().any(|entry| entry == before);
            }
        }
        Ok(matched)
    })
}

pub fn describe_with(
    context: &ToolContext,
    source: &crate::batteries::memory_format::Source,
    contains: impl Fn(&crate::session::Session) -> Result<bool, String>,
) -> Result<Value, String> {
    let mut evidence: Vec<Value> = source
        .entries
        .iter()
        .map(|id| json!({"id": id, "available": false}))
        .collect();
    let mut containing = Vec::new();
    let mut unavailable = Vec::new();
    let Some(root) = context.state.existing_directory(Path::new(""))? else {
        return Ok(
            json!({"source_session": source.session, "evidence": evidence,
            "sessions_with_old_snapshot": containing, "unavailable": unavailable}),
        );
    };
    let mut files = Vec::new();
    crate::session::discover(&root, &mut files, &mut unavailable)?;
    for file in files {
        let loaded = std::fs::metadata(&file)
            .map_err(|error| error.to_string())
            .and_then(|metadata| {
                if metadata.len() > 32 * 1024 * 1024 {
                    return Err("session exceeds 32 MiB".into());
                }
                crate::session::read_snapshot(&file)
            });
        let session = match loaded {
            Ok(session) => session,
            Err(error) => {
                unavailable.push((file, error));
                continue;
            }
        };
        if session.id() == source.session {
            for value in &mut evidence {
                if let Some(entry) = session
                    .entries()
                    .iter()
                    .find(|entry| value["id"] == entry.id)
                {
                    value["available"] = json!(true);
                    value["type"] = json!(entry.kind);
                    if let Ok(message) = serde_json::from_value::<Message>(entry.data.clone()) {
                        value["text"] =
                            json!(message.text_content().chars().take(512).collect::<String>());
                    }
                }
            }
        }
        let matched = match contains(&session) {
            Ok(matched) => matched,
            Err(error) => {
                unavailable.push((file.clone(), error));
                false
            }
        };
        if matched {
            containing.push(session.id().to_string());
        }
    }
    containing.sort();
    containing.dedup();
    let count = unavailable.len();
    let unavailable: Vec<_> = unavailable.into_iter().take(10).map(|(path, error)|
        json!({"file": path.strip_prefix(&root).unwrap_or(&path), "error": error})).collect();
    Ok(
        json!({"source_session": source.session, "evidence": evidence,
        "sessions_with_old_snapshot": containing, "unavailable": unavailable, "unavailable_count": count}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::memory_format::{Document, Entry, Target};
    use crate::session::{HookState, Store};

    #[test]
    fn evidence_and_past_snapshots_are_read_without_changing_sessions_or_their_locks() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-sources-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let store = Store::with_root(&path.join("workspace"), path.join("state")).unwrap();
        let mut session = store.create(false, None).unwrap();
        let source = session
            .append_message(&Message::user("Prefer Rust."))
            .unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            session.id().into(),
            session.path(),
        )
        .unwrap();
        let entry: Entry = serde_json::from_value(json!({"metadata": {"id": "preference", "kind": "user", "scope": "global",
            "source": {"session": session.id(), "entries": [source]}, "date_ms": 1}, "text": "Prefer Rust."})).unwrap();
        let document = Document {
            entries: vec![entry.clone()],
        }
        .encode(Target::User, 1375)
        .unwrap();
        context
            .state
            .replace_file(Target::User.relative(), document.as_bytes())
            .unwrap();
        let event = crate::batteries::Event {
            protocol_version: 1,
            event: "initialize".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: session.id().into(),
                path: session.path().map(Path::to_path_buf),
                state: None,
            },
            payload: json!({}),
        };
        let setup = crate::batteries::snapshot::initialize(&event, &context.state).unwrap();
        session
            .append_hook_state(&HookState {
                hook: "batteries".into(),
                state: setup["state"].clone(),
                context: None,
            })
            .unwrap();
        let bytes = std::fs::read(session.path().unwrap()).unwrap();
        let proposal = Proposal {
            version: 1,
            target: Target::User,
            before: Some(entry),
            after: None,
            source: crate::batteries::memory_format::Source {
                review: None,
                session: session.id().into(),
                entries: vec![source, "missing".into()],
            },
            date_ms: 2,
        };
        let result = describe(&context, &proposal).unwrap();
        assert_eq!(result["evidence"][0]["available"], true);
        assert_eq!(result["evidence"][0]["text"], "Prefer Rust.");
        assert_eq!(result["evidence"][1]["available"], false);
        assert_eq!(result["sessions_with_old_snapshot"], json!([session.id()]));
        assert_eq!(std::fs::read(session.path().unwrap()).unwrap(), bytes);
        drop(session);
        std::fs::remove_dir_all(path).unwrap();
    }
}
