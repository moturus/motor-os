//! Reads old branches and ephemeral loads; damaged history stays unavailable.

use gears::{
    provider::{Message, ToolCall},
    session::Store,
};
use gears_batteries::{
    memory_format::Source, paths::ToolContext, skill_format::Content, skill_loads, skill_usage,
};
use serde_json::json;
use std::{io::Write, path::Path};

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let store = Store::with_root(workspace, root.join("sessions"))?;
    let mut session = store.create(false, None)?;
    let parent = session.append_message(&Message::user("Use the skill."))?;
    session.append_message(&Message::assistant_response(
        String::new(),
        vec![ToolCall::new("c1", "skill_view", r#"{"name":"checks"}"#)],
    ))?;
    let content = Content {
        skill_md: "---\nname: checks\ndescription: Run checks.\n---\nSteps.\n".into(),
        notes_md: None,
    };
    let result = session.append_message(&Message::tool_result(
        "c1",
        "skill_view",
        json!({"version": 1, "name": "checks", "hash": content.hash(), "content": content})
            .to_string(),
        false,
    ))?;
    session.append_message(&Message::assistant("Loaded."))?;
    session.select(&parent)?;
    session.append_message(&Message::assistant("A different branch."))?;
    assert!(
        session
            .active_entries()?
            .iter()
            .all(|entry| entry.id != result)
    );
    let context = ToolContext::new(
        workspace.into(),
        root.into(),
        session.id().into(),
        session.path(),
    )?;
    skill_loads::record(
        &context,
        "ephemeral",
        &content.hash(),
        Source {
            review: None,
            session: "ephemeral".into(),
            entries: vec!["e1".into()],
        },
    )?;
    let file = session.path().unwrap().to_path_buf();
    let bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
    let usage = skill_usage::scan(&context)?;
    assert_eq!(usage.sessions_read, 1);
    assert!(usage.unavailable.is_empty());
    assert!(usage.source_available(&Source {
        review: None,
        session: session.id().into(),
        entries: vec![parent]
    }));
    assert_eq!(usage.last_load["checks"].source.entries, [result]);
    assert_eq!(usage.last_load["ephemeral"].source.session, "ephemeral");
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    drop(session);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&file)
        .unwrap()
        .write_all(b"{partial")
        .unwrap();
    let damaged = std::fs::read(&file).unwrap();
    let usage = skill_usage::scan(&context)?;
    assert_eq!(usage.unavailable.len(), 1);
    assert_eq!(usage.sessions_read, 0);
    assert_eq!(std::fs::read(&file).unwrap(), damaged);
    std::fs::write(&file, &bytes).unwrap();
    let ledger = context.state.file(Path::new(skill_loads::FILE))?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&ledger)
        .unwrap()
        .write_all(b"{partial")
        .unwrap();
    let usage = skill_usage::scan(&context)?;
    assert_eq!(usage.unavailable.len(), 1);
    assert!(std::fs::read(&ledger).unwrap().ends_with(b"{partial"));
    std::fs::write(&ledger, b"{\"version\":2}\n").unwrap();
    assert_eq!(skill_usage::scan(&context)?.unavailable.len(), 1);
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
