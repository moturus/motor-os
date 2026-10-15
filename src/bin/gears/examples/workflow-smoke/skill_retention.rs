//! A recorded load is independent of session persistence; only approval archives.

use gears::batteries::{
    memory_format::Source, paths::ToolContext, pending::Decision, skill_archive,
    skill_format::Content, skill_loads, skill_pending, skill_store,
};
use std::path::Path;

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let context = ToolContext::new(workspace.into(), root.into(), "ephemeral".into(), None)?;
    let content = Content { skill_md: "---\nname: checks\ndescription: Run checks.\n---\n## When it applies\nRust.\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n".into(), notes_md: Some("Keep this note.".into()) };
    let source = Source {
        review: None,
        session: "ephemeral".into(),
        entries: vec!["e1".into()],
    };
    skill_store::write(&context, "checks", Some(&content))?;
    skill_loads::record(&context, "checks", &content.hash(), source.clone())?;
    let mut loads = Vec::new();
    gears::batteries::journal::visit(&context.state, Path::new(skill_loads::FILE), |record| {
        loads.push(serde_json::from_value::<skill_loads::Load>(record).map_err(|e| e.to_string())?);
        Ok(())
    })?;
    assert_eq!(loads.len(), 1);
    assert_eq!(loads[0].source, source);
    assert_eq!(loads[0].content_hash, content.hash());
    assert!(loads[0].date_ms > 0);
    let proposal = skill_pending::Proposal {
        version: 1,
        kind: "skill".into(),
        cleanup: None,
        name: "checks".into(),
        before: Some(content.clone()),
        after: None,
        source,
        date_ms: 1,
    };
    let archive = skill_archive::relative("checks", &content);
    let id = skill_pending::propose(&context, &proposal)?.unwrap();
    skill_pending::decide(&context, &id, Decision::Postpone)?;
    assert!(context.state.existing_file(&archive)?.is_none());
    assert_eq!(
        skill_store::current(&context, "checks")?,
        Some(content.clone())
    );
    skill_pending::decide(&context, &id, Decision::Deny)?;
    assert!(context.state.existing_file(&archive)?.is_none());
    let id = skill_pending::propose(&context, &proposal)?.unwrap();
    let mut edited = content.clone();
    edited.notes_md = Some("Changed meanwhile.".into());
    skill_store::write(&context, "checks", Some(&edited))?;
    assert!(skill_pending::decide(&context, &id, Decision::Approve).is_err());
    assert!(context.state.existing_file(&archive)?.is_none());
    skill_store::write(&context, "checks", Some(&content))?;
    skill_pending::decide(&context, &id, Decision::Approve)?;
    assert!(skill_store::current(&context, "checks")?.is_none());
    let saved: serde_json::Value = serde_json::from_slice(
        &std::fs::read(context.state.file(&archive)?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["content_hash"], content.hash());
    assert_eq!(
        serde_json::from_value::<Content>(saved["content"].clone()).unwrap(),
        content
    );
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
