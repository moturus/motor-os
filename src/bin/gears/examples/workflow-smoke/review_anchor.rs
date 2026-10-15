//! A native review must read its saved entry even after the parent compacts.

use std::path::Path;

use gears::provider::Message;
use gears::session::{Compaction, HookState, Store};

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let store = Store::with_root(workspace, root.into())?;
    let mut parent = store.create(false, None)?;
    parent.append_hook_state(&HookState {
        hook: "batteries".into(),
        state: serde_json::json!({"prompt_snapshot": "frozen"}),
        context: None,
    })?;
    parent.append_message(&Message::user("Original task"))?;
    let entry = parent.append_message(&Message::assistant("Original answer"))?;
    let messages = parent.context_messages()?;
    parent.append_compaction(&Compaction {
        summary: "Later summary".into(),
        retained_tail: Vec::new(),
        tokens_before: 100,
    })?;
    parent.append_hook_state(&HookState {
        hook: "batteries".into(),
        state: serde_json::json!({"prompt_snapshot": "new"}),
        context: None,
    })?;
    parent.append_message(&Message::user("Later task"))?;
    let path = parent.path().unwrap();
    let before = std::fs::read(path).map_err(|error| error.to_string())?;
    let snapshot = store.read(parent.id())?;
    assert_ne!(snapshot.context_messages()?, messages);
    let selected = snapshot.at(&entry)?;
    let child = store.clone_active_with_options(&selected, true)?;
    assert_eq!(child.context_messages()?, messages);
    assert_eq!(
        child.hook_state("batteries").unwrap()["prompt_snapshot"],
        "frozen"
    );
    assert_eq!(
        std::fs::read(path).map_err(|error| error.to_string())?,
        before
    );
    assert!(snapshot.at("missing").is_err());
    drop(child);
    drop(selected);
    drop(snapshot);
    parent.append_message(&Message::assistant("Parent continued"))?;
    println!("gears batteries anchored snapshot ALL PASS");
    Ok(())
}
