//! Review limits span memory, skills, decisions and restarted ephemeral runs.

use std::path::Path;

use gears::batteries::{
    Event, Session,
    memory_format::{Source, Target},
    paths::ToolContext,
    pending::Decision,
    review_config::Model,
    review_marks::{self, Disposition, Reason},
};
use gears::{
    provider::{Message, ToolCall},
    session::Store,
};
use serde_json::{Value, json};

fn execute(
    event: &mut Event,
    context: &ToolContext,
    name: &str,
    arguments: Value,
) -> Result<Value, String> {
    event.payload =
        json!({"tool_call": ToolCall::new(format!("cap-{name}"), name, arguments.to_string())});
    match name {
        "memory" => gears::batteries::memory_tool::execute(event, context),
        "skill_manage" => gears::batteries::skill_manage::execute(event, context),
        _ => unreachable!(),
    }
}

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let store = Store::with_root(workspace, root.join("sessions"))?;
    let mut parent = store.create(false, None)?;
    let evidence = parent.append_message(&Message::user("Prefer Rust for this project"))?;
    let entry = parent.append_message(&Message::assistant("A completed task"))?;
    let owner = ToolContext::new(
        workspace.into(),
        root.into(),
        parent.id().into(),
        parent.path(),
    )?;
    let executor = Model {
        provider: "local".into(),
        model: "executor".into(),
    };
    let mark = review_marks::create(&owner, &entry, Reason::Command, "", &executor)?;
    let other = review_marks::create(
        &owner,
        &entry,
        Reason::Command,
        "A different focus",
        &executor,
    )?;
    let later = parent.append_message(&Message::user("A later task"))?;
    owner.state.replace_file(Path::new("batteries.toml"), b"version=1\n[reviews]\nenabled=true\nmax_proposals=2\n[reviews.executor]\nprovider='local'\nmodel='executor'\n[reviews.reviewer]\nprovider='local'\nmodel='reviewer'\n")?;
    let before = std::fs::read(parent.path().unwrap()).map_err(|error| error.to_string())?;
    let context = ToolContext::new(workspace.into(), root.into(), "review-child".into(), None)?;
    let mut event = Event {
        protocol_version: 1,
        event: "tool_execute".into(),
        workspace: workspace.into(),
        session: Session {
            id: context.session.clone(),
            path: None,
            state: Some(json!({
            "run_kind": "review", "review_run": {"session": parent.id(), "path": parent.path(), "mark": mark},
            "turn_record": {"last_entry_id": "ephemeral-call"}})),
        },
        payload: json!({}),
    };
    let memory = json!({"action": "add", "target": "user", "text": "Prefer Rust.", "source_entries": [evidence]});
    let response = execute(&mut event, &context, "memory", memory.clone())?;
    let result: Value =
        serde_json::from_str(response["tool_result"]["content"].as_str().unwrap()).unwrap();
    let memory_id = result["proposal_id"].as_str().unwrap();
    let proposal = gears::batteries::pending::load(&context, Target::User, memory_id)?;
    assert_eq!(proposal.source.session, parent.id());
    assert_eq!(proposal.source.entries, [entry.clone(), evidence]);
    assert_eq!(proposal.source.review.as_deref(), Some(mark.as_str()));
    let mut invalid = memory.clone();
    invalid["source_entries"] = json!([later]);
    assert!(
        execute(&mut event, &context, "memory", invalid)
            .unwrap_err()
            .contains("outside")
    );
    let skill = "---\nname: review-checks\ndescription: Run checks.\nmetadata: {platforms: motor linux}\n---\n## When it applies\nRust.\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n";
    execute(
        &mut event,
        &context,
        "skill_manage",
        json!({"action": "add", "name": "review-checks", "skill_md": skill}),
    )?;
    let skills = gears::batteries::skill_pending::list(&context)?;
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].1.source.review.as_deref(), Some(mark.as_str()));
    let mut extra = memory.clone();
    extra["text"] = json!("Another proposal.");
    assert!(
        execute(&mut event, &context, "memory", extra.clone())
            .unwrap_err()
            .contains("limit (2)")
    );
    gears::batteries::memory::decide(&context, Target::User, memory_id, Decision::Deny)?;
    gears::batteries::skill_pending::decide(&context, &skills[0].0, Decision::Deny)?;
    assert!(gears::batteries::pending::list(&context, Target::User)?.is_empty());
    assert!(gears::batteries::skill_pending::list(&context)?.is_empty());
    let restarted = ToolContext::new(
        workspace.into(),
        root.into(),
        "review-restarted".into(),
        None,
    )?;
    event.session.id = restarted.session.clone();
    assert!(
        execute(&mut event, &restarted, "memory", extra.clone())
            .unwrap_err()
            .contains("limit (2)")
    );
    review_marks::finish(&owner, &mark, Disposition::Completed)?;
    assert!(
        execute(&mut event, &restarted, "memory", extra.clone())
            .unwrap_err()
            .contains("no longer due")
    );
    event.session.state.as_mut().unwrap()["review_run"]["mark"] = json!(other);
    execute(&mut event, &restarted, "memory", extra)?;
    let pending = gears::batteries::pending::list(&restarted, Target::User)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.source.review.as_deref(), Some(other.as_str()));
    assert!(
        gears::batteries::memory::load(&context, Target::User)?
            .entries
            .is_empty()
    );
    assert!(gears::batteries::skill_store::current(&context, "review-checks")?.is_none());
    let old = json!({"session": "old", "entries": ["e1"]});
    let source: Source = serde_json::from_value(old.clone()).unwrap();
    assert!(source.review.is_none());
    assert_eq!(serde_json::to_value(source).unwrap(), old);
    let mut malformed = pending[0].1.clone();
    malformed.source.review = Some("bad".into());
    assert!(malformed.validate().is_err());
    assert_eq!(
        std::fs::read(parent.path().unwrap()).map_err(|error| error.to_string())?,
        before
    );
    println!("gears batteries review proposal limit ALL PASS");
    Ok(())
}
