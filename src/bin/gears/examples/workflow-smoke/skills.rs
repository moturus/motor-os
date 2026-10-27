//! A user-written skill is listed in the prompt and loaded by name through the real hook.

use std::path::Path;
use std::sync::Arc;

use gears::batteries::paths::ToolContext;
use gears::batteries::skill_format::Content;
use gears::batteries::skill_store;
use gears::runtime::{Event, Runtime};
use gears::session::Store;
use serde_json::json;

use super::scenario::{Approvals, Scripted, answer, call};
use super::support::Fixture;

pub fn run(binary: &Path, compiler: &str) -> Result<(), String> {
    let fixture = Fixture::new(binary, compiler)?;
    let name = format!("skill-{}", fixture.label);
    let context = ToolContext::new(
        fixture.workspace.clone(),
        fixture.state.clone(),
        "writer".into(),
        None,
    )?;
    let content = Content {
        skill_md: format!(
            "---\nname: {name}\ndescription: >-\n  Compile the fixture assertion.\nmetadata: {{platforms: motor linux}}\n---\n## When it applies\nFixture only.\n## Steps\nKeep the assertion.\n## How to check\nRun the declared check.\n## Pitfalls\nDo not remove the assertion.\n"
        ),
        notes_md: Some("Fixture note.".into()),
    };
    skill_store::write(&context, &name, Some(&content))?;
    let provider = Arc::new(Scripted::from_responses(vec![
        call("skill_view", json!({})),
        call("skill_view", json!({"name": name})),
        answer("loaded"),
    ]));
    let store = Store::with_root(&fixture.workspace, fixture.state.clone())?;
    let session = store.create(false, None)?;
    let group = session.path().unwrap().parent().unwrap().to_path_buf();
    let mut runtime = Runtime::new(
        provider.clone(),
        store,
        session,
        &fixture.config,
        "fixture/model".into(),
    )?;
    let sessions = vec![runtime.session().id().to_string()];
    let mut approvals = Approvals::default();
    let mut observer = |event| {
        if let Event::Notice(text) = event {
            fixture.observe_notice(&text)?;
        }
        Ok(())
    };
    runtime.turn(
        "list and load the skill".into(),
        &mut approvals,
        &mut observer,
    )?;
    let state = runtime.session().hook_state(&fixture.hook).unwrap();
    let snapshots = vec![state["prompt_snapshot"].as_str().unwrap().to_string()];
    assert_eq!(state["skills_loaded"], json!([name]));
    // Listing and loading never ask the user.
    assert!(approvals.0.is_empty());
    let requests = provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| {
        request
            .system
            .iter()
            .any(|text| text.starts_with("Skills:") && text.contains(&name))
    }));
    assert!(requests[1].messages.iter().any(|message| {
        message
            .text_content()
            .contains("Compile the fixture assertion.")
    }));
    assert!(
        requests[2]
            .messages
            .iter()
            .any(|message| message.text_content().contains("Fixture note."))
    );
    drop(requests);
    drop(runtime);
    skill_store::write(&context, &name, None)?;
    let directory = skill_store::relative(&name, "SKILL.md")?
        .parent()
        .unwrap()
        .to_path_buf();
    if let Some(path) = context.state.existing_directory(&directory)? {
        std::fs::remove_dir(path).map_err(|error| error.to_string())?;
    }
    fixture.cleanup(&group, &sessions, &snapshots)?;
    println!("gears batteries skills ALL PASS");
    Ok(())
}
