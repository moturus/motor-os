//! Memory files, frozen prompts and the history/status commands on both systems.

use std::path::Path;
use std::process::{Command, Stdio};

use gears::batteries::memory::{self, Action, Change};
use gears::batteries::memory_format::{Entry, Target};
use gears::batteries::paths::ToolContext;
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
    let event = |state: Option<Value>| gears::batteries::Event {
        protocol_version: 1,
        event: "initialize".into(),
        workspace: workspace.clone(),
        session: gears::batteries::Session {
            id: "source".into(),
            path: None,
            state,
        },
        payload: json!({}),
    };
    let entry = |id: &str, date: &str, text: &str| Entry {
        id: id.into(),
        date: date.into(),
        session: "source".into(),
        text: text.into(),
    };
    let old = gears::batteries::snapshot::initialize(&event(None), &context.state)?;
    context.state.replace_file(
        Target::Global.relative(),
        "# Gears memory v2\n§ old 1970-01-01 source\nUse literal check arguments.\n".as_bytes(),
    )?;
    let add = Change {
        version: 2,
        target: Target::Global,
        action: Action::Add,
        before: None,
        after: Some(entry("fact", "2026-10-15", "Prefer native APIs.")),
    };
    assert!(memory::propose(&context, &add)?);
    memory::apply(&context, &add)?;
    memory::log(&context, &add, true)?;
    let text = std::fs::read_to_string(context.state.path().join(Target::Global.relative()))
        .map_err(|error| error.to_string())?;
    assert_eq!(
        text,
        "# Gears memory v2\n§ old 1970-01-01 source\nUse literal check arguments.\n§ fact 2026-10-15 source\nPrefer native APIs.\n"
    );
    // The running session keeps its prompt; a new session sees both entries.
    let still_old =
        gears::batteries::snapshot::initialize(&event(Some(old["state"].clone())), &context.state)?;
    assert!(
        !still_old["prompt_fragments"]
            .to_string()
            .contains("Prefer native APIs.")
    );
    let fresh = gears::batteries::snapshot::initialize(&event(None), &context.state)?;
    let fragments = fresh["prompt_fragments"].to_string();
    assert!(fragments.contains("[old] Use literal check arguments."));
    assert!(fragments.contains("[fact] Prefer native APIs."));
    assert!(!fragments.contains("you may offer"));
    // A declined change is named in the offer instruction once offers are on.
    let remove = Change {
        version: 2,
        target: Target::Global,
        action: Action::Remove,
        before: Some(entry("old", "1970-01-01", "Use literal check arguments.")),
        after: None,
    };
    memory::log(&context, &remove, false)?;
    context.state.replace_file(
        Path::new("batteries.toml"),
        b"version = 1\n[memory]\noffer_lessons = true\n",
    )?;
    let offered = gears::batteries::snapshot::initialize(&event(None), &context.state)?;
    let fragments = offered["prompt_fragments"].to_string();
    assert!(fragments.contains("you may offer at most one thing"));
    assert!(fragments.contains("do not offer them again:\\n- Use literal check arguments."));
    // Workspace memory from a clone is used as it is, like the clone's AGENTS.md.
    let root = gears::state::StateRoot::new(workspace.clone())?;
    root.replace_file(
        Target::Workspace.relative(),
        "# Gears memory v2\n§ w1\nWorkspace facts use relative paths.\n".as_bytes(),
    )?;
    let imported = gears::batteries::initialize_at(&event(None), &context.state);
    assert!(imported.get("question").is_none());
    assert!(
        imported["prompt_fragments"]
            .to_string()
            .contains("Workspace memory:\\n[w1] Workspace facts use relative paths.")
    );
    let history: Value = serde_json::from_str(&cli(&["history", "--limit", "1"])?).unwrap();
    assert_eq!(history["total"], 2);
    assert_eq!(history["next_offset"], 1);
    assert_eq!(history["records"][0]["decision"], "yes");
    let status: Value = serde_json::from_str(&cli(&["status"])?).unwrap();
    assert_eq!(status["offer_lessons"], true);
    assert_eq!(
        status["entries"],
        json!({"user": 0, "global": 2, "workspace": 1})
    );
    assert_eq!(
        status["decisions"],
        json!({"yes": 1, "no": 1, "unreadable": 0})
    );
    assert!(cli(&["pending"]).is_err());
    println!("gears batteries memory ALL PASS");
    Ok(())
}
