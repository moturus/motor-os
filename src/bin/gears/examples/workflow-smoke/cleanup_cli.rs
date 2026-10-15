//! The real CLI needs a cutoff and an independent explicit approval to archive.

use gears::batteries::{
    memory_format::Source, paths::ToolContext, skill_cleanup, skill_pending, skill_store,
};
use gears::{provider::Message, session::Store};
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Stdio},
};

pub fn run(binary: &Path, workspace: &Path, root: &Path) -> Result<(), String> {
    let store = Store::with_root(workspace, root.join("sessions"))?;
    let mut session = store.create(false, None)?;
    let entry = session.append_message(&Message::user("Recorded old skill origin."))?;
    let context = ToolContext::new(
        workspace.into(),
        root.into(),
        session.id().into(),
        session.path(),
    )?;
    let content = super::cleanup_proposals::install(
        &context,
        "idle",
        Source {
            review: None,
            session: session.id().into(),
            entries: vec![entry],
        },
    )?;
    let call = |args: &[&str]| {
        Command::new(binary)
            .args(args)
            .arg("--workspace")
            .arg(workspace)
            .arg("--root")
            .arg(root)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| e.to_string())
    };
    for args in [
        vec!["cleanup"],
        vec!["cleanup", "--since", "2023-02-29"],
        vec!["cleanup", "--since", "1970-01-02", "--since", "1970-01-03"],
        vec!["cleanup", "--since", "9999-01-01"],
    ] {
        let output = call(&args)?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cleanup")
                || String::from_utf8_lossy(&output.stderr).contains("--since")
        );
        assert!(skill_pending::list(&context)?.is_empty());
    }
    let output = call(&["cleanup", "--since", "1970-01-02"])?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into());
    }
    let report: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    assert_eq!(report["since_ms"], skill_cleanup::cutoff("1970-01-02")?);
    assert_eq!(report["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(
        skill_store::current(&context, "idle")?,
        Some(content.clone())
    );
    let archive = gears::batteries::skill_archive::relative("idle", &content);
    assert!(context.state.existing_file(&archive)?.is_none());
    let id = report["proposals"][0]["id"].as_str().unwrap();
    let pending = call(&["pending", "--list"])?;
    assert!(pending.status.success());
    let text = String::from_utf8_lossy(&pending.stdout);
    for expected in [
        "archive_on_approval",
        "since_ms",
        "Recorded old skill origin.",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    let approved = call(&["pending", "--approve", id])?;
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    assert!(skill_store::current(&context, "idle")?.is_none());
    let saved: Value = serde_json::from_slice(
        &std::fs::read(context.state.file(&archive)?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(
        serde_json::from_value::<gears::batteries::skill_format::Content>(saved["content"].clone())
            .unwrap(),
        content
    );
    assert!(skill_pending::list(&context)?.is_empty());
    let output = call(&["cleanup", "--since", "1970-01-02"])?;
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    assert!(report["proposals"].as_array().unwrap().is_empty());
    drop(session);
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
