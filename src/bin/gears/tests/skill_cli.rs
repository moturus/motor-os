use gears::batteries::paths::ToolContext;
use gears::batteries::skill_format::Content;
use gears::batteries::skill_pending::Proposal;
use serde_json::json;
use std::process::{Command, Stdio};

#[test]
fn pending_reviews_complete_skill_and_notes_versions_and_preserves_unavailable_files() {
    let path = std::env::temp_dir().join(format!("batteries-skill-cli-{}", std::process::id()));
    std::fs::create_dir_all(path.join("workspace")).unwrap();
    let context = ToolContext::new(
        path.join("workspace"),
        path.join("state"),
        "source".into(),
        None,
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_gears-batteries"))
            .args(args)
            .arg("--root")
            .arg(context.state.path())
            .arg("--workspace")
            .arg(&context.workspace)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let content = Content { skill_md: "---\nname: checks\ndescription: Run checks.\n---\n## When it applies\nRust.\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n".into(), notes_md: Some("A platform quirk.\n".into()) };
    let proposal = Proposal {
        version: 1,
        kind: "skill".into(),
        cleanup: None,
        name: "checks".into(),
        before: None,
        after: Some(content.clone()),
        source: serde_json::from_value(json!({"session": "source", "entries": ["evidence"]}))
            .unwrap(),
        date_ms: 1,
    };
    let id = gears::batteries::skill_pending::propose(&context, &proposal)
        .unwrap()
        .unwrap();
    let postponed = run(&["pending"]);
    assert!(postponed.status.success());
    assert!(
        String::from_utf8(postponed.stdout)
            .unwrap()
            .contains("postpone")
    );
    let listing = run(&["pending", "--list"]);
    assert!(listing.status.success());
    let text = String::from_utf8(listing.stdout).unwrap();
    for expected in ["A platform quirk.", "evidence", "skill"] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(
        gears::batteries::skill_store::current(&context, "checks")
            .unwrap()
            .is_none()
    );
    assert!(run(&["pending", "--approve", &id]).status.success());
    assert_eq!(
        gears::batteries::skill_store::current(&context, "checks")
            .unwrap()
            .unwrap(),
        content
    );
    let status: serde_json::Value = serde_json::from_slice(&run(&["status"]).stdout).unwrap();
    assert_eq!(status["pending_global"]["count"], 0);
    let mut edit = content;
    edit.notes_md = None;
    gears::batteries::skill_store::write(&context, "checks", Some(&edit)).unwrap();
    let hash = edit.hash();
    assert!(
        String::from_utf8(run(&["pending", "--list"]).stdout)
            .unwrap()
            .contains(&hash)
    );
    assert!(run(&["pending", "--approve", &hash]).status.success());
    assert!(gears::batteries::skill_store::approved(&context, "checks", &hash).unwrap());
    edit.skill_md = "broken skill".into();
    gears::batteries::skill_store::write(&context, "checks", Some(&edit)).unwrap();
    let output = run(&["pending"]);
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("unavailable")
    );
    assert_eq!(
        gears::batteries::skill_store::current(&context, "checks")
            .unwrap()
            .unwrap(),
        edit
    );
    std::fs::remove_dir_all(path).unwrap();
}
