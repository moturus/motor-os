//! Run memory commands and prompt transitions on both Linux and Motor OS.

use std::path::Path;
use std::process::{Command, Stdio};

use gears_batteries::memory_format::{Document, Entry, Target};
use gears_batteries::paths::ToolContext;
use gears_batteries::pending::Proposal;
use serde_json::{Value, json};

pub fn run(binary: &Path, base: &Path) -> Result<(), String> {
    let workspace = base.join("memory-workspace");
    std::fs::create_dir(&workspace).map_err(|error| error.to_string())?;
    let context = ToolContext::new(
        workspace.clone(),
        base.join("memory-state"),
        "source".into(),
        None,
    )?;
    let cli = |args: &[&str]| {
        let output = Command::new(binary)
            .args(args)
            .arg("--root")
            .arg(context.state.path())
            .arg("--workspace")
            .arg(&workspace)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        String::from_utf8(output.stdout).map_err(|error| error.to_string())
    };
    let event = |state: Option<Value>| gears_batteries::Event {
        protocol_version: 1,
        event: "initialize".into(),
        workspace: workspace.clone(),
        session: gears_batteries::Session {
            id: "source".into(),
            path: None,
            state,
        },
        payload: json!({}),
    };
    let old = gears_batteries::snapshot::initialize(&event(None), &context.state)?;
    let entry: Entry = serde_json::from_value(json!({"metadata": {"id": "native-fact", "kind": "observed", "scope": "global",
        "source": {"session": "source", "entries": ["evidence"]}, "date_ms": 1}, "text": "Use literal check arguments."})).unwrap();
    let proposal = Proposal {
        version: 1,
        target: Target::Global,
        before: None,
        after: Some(entry.clone()),
        source: entry.metadata.source.clone(),
        date_ms: 2,
    };
    let id = gears_batteries::memory::propose(&context, &proposal)?.unwrap();
    assert!(cli(&["pending"])?.contains("postpone"));
    assert!(cli(&["pending", "--list"])?.contains("Use literal check arguments."));
    assert!(
        gears_batteries::memory::load(&context, Target::Global)?
            .entries
            .is_empty()
    );
    cli(&["pending", "--approve", &id])?;
    let still_old =
        gears_batteries::snapshot::initialize(&event(Some(old["state"].clone())), &context.state)?;
    assert!(
        !still_old["prompt_fragments"]
            .to_string()
            .contains("Use literal check arguments.")
    );
    let fresh = gears_batteries::snapshot::initialize(&event(None), &context.state)?;
    assert!(
        fresh["prompt_fragments"]
            .to_string()
            .contains("Use literal check arguments.")
    );
    let removal = Proposal {
        version: 1,
        target: Target::Global,
        before: Some(entry.clone()),
        after: None,
        source: entry.metadata.source.clone(),
        date_ms: 3,
    };
    let id = gears_batteries::memory::propose(&context, &removal)?.unwrap();
    cli(&["pending", "--approve", &id])?;
    let mut running = event(Some(fresh["state"].clone()));
    running.event = "context".into();
    let note = gears_batteries::memory_context::observe(&running, &context)?;
    assert!(
        note["context"]
            .to_string()
            .contains("Withdraw Global memory entry native-fact")
    );
    running.session.state = Some(note["state"].clone());
    assert!(
        gears_batteries::memory_context::observe(&running, &context)?
            .get("context")
            .is_none()
    );
    let resumed = gears_batteries::snapshot::initialize(
        &event(Some(fresh["state"].clone())),
        &context.state,
    )?;
    assert!(
        !resumed["prompt_fragments"]
            .to_string()
            .contains("Use literal check arguments.")
    );
    // A cloned workspace file is displayed to the user but excluded from prompts.
    let mut local = entry;
    local.metadata.scope = Target::Workspace.scope();
    local.text = "Workspace facts use relative paths.".into();
    let document = Document {
        entries: vec![local],
    }
    .encode(Target::Workspace, 2200)?;
    let root = gears::state::StateRoot::new(workspace.clone())?;
    root.replace_file(Target::Workspace.relative(), document.as_bytes())?;
    let imported = gears_batteries::initialize_at(&event(None), &context.state);
    assert!(imported["question"]["id"].is_string());
    assert!(
        !imported["prompt_fragments"]
            .to_string()
            .contains("Workspace facts use relative paths.")
    );
    let hash = imported["question"]["id"].as_str().unwrap();
    cli(&["pending", "--approve", hash])?;
    let approved = gears_batteries::snapshot::initialize(&event(None), &context.state)?;
    assert!(
        approved["prompt_fragments"]
            .to_string()
            .contains("Workspace facts use relative paths.")
    );
    let history: Value = serde_json::from_str(&cli(&["history", "--limit", "2"])?).unwrap();
    assert_eq!(history["total"], 3);
    assert_eq!(history["next_offset"], 2);
    let status: Value = serde_json::from_str(&cli(&["status"])?).unwrap();
    assert_eq!(status["pending_global"]["count"], 0);
    assert_eq!(status["workspace_memory"]["approved"], true);
    Ok(())
}
