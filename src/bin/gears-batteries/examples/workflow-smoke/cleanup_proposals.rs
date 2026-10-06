//! Cleanup stages approvals, protects recent activity and respects user denials.

use gears::{
    provider::Message,
    session::{HookState, Store},
};
use gears_batteries::{
    memory_format::Source,
    paths::ToolContext,
    pending::Decision,
    skill_cleanup,
    skill_format::Content,
    skill_pending,
    skill_snapshot::{Loaded, Snapshot},
    skill_store,
};
use serde_json::json;
use std::path::Path;

fn install(context: &ToolContext, name: &str, source: Source) -> Result<Content, String> {
    let content = Content {
        skill_md: format!(
            "---\nname: {name}\ndescription: Run checks.\n---\n## When it applies\nRust work.\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n"
        ),
        notes_md: Some("Retain this note.".into()),
    };
    skill_store::write(context, name, Some(&content))?;
    let proposal = skill_pending::Proposal {
        version: 1,
        kind: "skill".into(),
        name: name.into(),
        before: None,
        after: Some(content.clone()),
        source,
        date_ms: 1,
        cleanup: None,
    };
    gears_batteries::journal::append_at(
        &context.state,
        &context.state.file(Path::new("batteries/changes.jsonl"))?,
        &json!({"version": 1, "kind": "skill", "name": name, "content_hash": content.hash(),
            "proposal": proposal, "decision": "approve", "date_ms": 1}),
    )?;
    Ok(content)
}

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let store = Store::with_root(workspace, root.into())?;
    let mut session = store.create(false, None)?;
    let entry = session.append_message(&Message::user("Recorded skill origin."))?;
    let context = ToolContext::new(
        workspace.into(),
        root.into(),
        session.id().into(),
        session.path(),
    )?;
    let source = Source {
        review: None,
        session: session.id().into(),
        entries: vec![entry],
    };
    let idle = install(&context, "idle", source.clone())?;
    let recent = install(&context, "recent", source.clone())?;
    let snapshot = install(&context, "snapshot", source.clone())?;
    let user = install(&context, "user", source.clone())?;
    skill_store::admit(&context, "user", &user.hash(), Decision::Approve)?;
    let mut missing = source.clone();
    missing.entries = vec!["missing".into()];
    install(&context, "missing", missing)?;
    gears_batteries::skill_loads::record(&context, "recent", &recent.hash(), source.clone())?;
    let hash = gears_batteries::skill_snapshot::save(
        &context,
        &Snapshot {
            version: 1,
            catalog: vec![],
            loaded: vec![Loaded {
                name: "snapshot".into(),
                content: snapshot,
                source: source.clone(),
            }],
        },
    )?;
    session.append_hook_state(&HookState {
        hook: "batteries".into(),
        state: json!({"skill_snapshot": hash}),
        context: None,
    })?;
    let report = skill_cleanup::propose(&context, 86400000)?;
    assert_eq!(report["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(report["retained"].as_array().unwrap().len(), 4);
    assert_eq!(report["overlaps"].as_array().unwrap().len(), 1);
    assert_eq!(report["coverage"]["sessions_read"], 1);
    assert_eq!(report["proposals"][0]["change"]["name"], "idle");
    assert_eq!(
        report["proposals"][0]["change"]["cleanup"]["since_ms"],
        86400000
    );
    assert!(
        report["proposals"][0]["change"]["cleanup"]["limitations"]
            .as_str()
            .unwrap()
            .contains("prior ephemeral")
    );
    let id = report["proposals"][0]["id"].as_str().unwrap();
    assert_eq!(
        skill_cleanup::propose(&context, 86400000)?["proposals"][0]["id"],
        id
    );
    assert_eq!(skill_pending::list(&context)?.len(), 1);
    assert_eq!(skill_store::current(&context, "idle")?, Some(idle.clone()));
    assert!(
        context
            .state
            .existing_file(&gears_batteries::skill_archive::relative("idle", &idle))?
            .is_none()
    );
    let mut invalid = skill_pending::load(&context, id)?;
    invalid.cleanup.as_mut().unwrap().last_load_ms = Some(86400000);
    assert!(invalid.validate().is_err());
    skill_pending::decide(&context, id, Decision::Deny)?;
    assert!(
        skill_cleanup::propose(&context, 86400000)?["proposals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    install(&context, "new-idle", source)?;
    std::fs::write(
        context
            .state
            .file(Path::new(gears_batteries::skill_loads::FILE))?,
        b"{\"version\":2}\n",
    )
    .unwrap();
    let blocked = skill_cleanup::propose(&context, 86400000)?;
    assert_eq!(
        blocked["coverage"]["unavailable"].as_array().unwrap().len(),
        1
    );
    assert!(blocked["proposals"].as_array().unwrap().is_empty());
    assert!(skill_pending::list(&context)?.is_empty());
    assert!(skill_cleanup::propose(&context, u64::MAX).is_err());
    drop(session);
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
