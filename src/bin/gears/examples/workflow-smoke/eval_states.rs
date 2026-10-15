//! Capture accepted learning separately from user entries and manual curation.

use gears::batteries::{
    eval_state, memory,
    memory_format::{Document, Entry, Kind, Metadata, Source, Target},
    paths::ToolContext,
    pending::{Decision, Proposal},
};
use std::path::Path;

fn entry(id: &str, target: Target, kind: Kind) -> Entry {
    Entry {
        metadata: Metadata {
            id: id.into(),
            kind,
            scope: target.scope(),
            date_ms: 1,
            source: Source {
                session: "origin".into(),
                entries: vec!["e1".into()],
                review: None,
            },
            applies_to: None,
        },
        text: format!("Content for {id}."),
    }
}

pub fn prepare(root: &Path) -> Result<ToolContext, String> {
    std::fs::create_dir_all(root.join("source")).unwrap();
    let context = ToolContext::new(
        root.join("source"),
        root.join("state"),
        "origin".into(),
        None,
    )?;
    context.state.replace_file(Path::new("batteries.toml"), b"version=1\n[memory]\nuser_chars=2000\nmemory_chars=4000\n[reviews]\nenabled=true\n[reviews.executor]\nprovider='local'\nmodel='executor'\n[reviews.reviewer]\nprovider='local'\nmodel='reviewer'\n")?;
    for (target, id) in [
        (Target::Global, "learned"),
        (Target::Workspace, "project-learned"),
    ] {
        let e = entry(id, target, Kind::Observed);
        let proposal = Proposal {
            version: 1,
            target,
            before: None,
            after: Some(e.clone()),
            source: e.metadata.source,
            date_ms: 1,
        };
        let id = memory::propose(&context, &proposal)?.unwrap();
        memory::decide(&context, target, &id, Decision::Approve)?;
    }
    let mut global = memory::load(&context, Target::Global)?;
    global
        .entries
        .push(entry("global-user", Target::Global, Kind::User));
    global
        .entries
        .push(entry("curated-fact", Target::Global, Kind::Observed));
    let user = Document {
        entries: vec![entry("user", Target::User, Kind::User)],
    };
    for (target, doc) in [(Target::User, user), (Target::Global, global)] {
        context
            .state
            .replace_file(target.relative(), doc.encode(target, 4000)?.as_bytes())?;
    }
    Ok(context)
}

pub fn run_fixture(root: &Path) -> Result<(), String> {
    let context = prepare(root)?;
    let frozen = eval_state::capture(&context)?;
    assert_eq!(frozen.memory(Target::Global, false).entries.len(), 2);
    assert_eq!(frozen.memory(Target::Global, true).entries.len(), 3);
    assert_eq!(
        frozen.memory(Target::User, false).entries,
        frozen.memory(Target::User, true).entries
    );
    assert!(frozen.memory(Target::Workspace, false).entries.is_empty());
    assert_eq!(frozen.memory(Target::Workspace, true).entries.len(), 1);
    let settings: toml::Value = toml::from_str(frozen.settings()).unwrap();
    assert_eq!(settings["reviews"]["enabled"].as_bool(), Some(false));
    assert!(gears::batteries::review_config::load(&context.state)?.enabled);
    let (hash, _) = gears::batteries::workspace_memory::current(&context)?.unwrap();
    gears::batteries::workspace_memory::decide(&context, &hash, Decision::Approve)?;
    let readmitted = eval_state::capture(&context)?;
    assert_eq!(readmitted.memory(Target::Workspace, false).entries.len(), 1);
    assert!(frozen.memory(Target::Workspace, false).entries.is_empty());
    let path = context.state.path().join("batteries/changes.jsonl");
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"incomplete\":")
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(eval_state::capture(&context).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
