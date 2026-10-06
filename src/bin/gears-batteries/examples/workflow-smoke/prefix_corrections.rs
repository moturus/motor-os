//! Withdrawals follow the frozen prefix, including after compaction removes old notes.

use gears_batteries::pending::Decision;
use gears_batteries::skill_format::Content;
use gears_batteries::{
    Event, Session,
    memory_format::{Document, Entry, Target},
    paths::ToolContext,
};
use serde_json::{Value, json};
use std::path::Path;

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    std::fs::create_dir(workspace).map_err(|error| error.to_string())?;
    let context = ToolContext::new(workspace.into(), root.into(), "prefix-reader".into(), None)?;
    std::fs::write(
        workspace.join("AGENTS.md"),
        "Original project instructions.",
    )
    .map_err(|e| e.to_string())?;
    let entry: Entry = serde_json::from_value(json!({"metadata": {"id":"withdrawn-fact", "kind":"user",
        "scope":"global", "source":{"session":"source", "entries":["e1"]}, "date_ms":1}, "text":"Original fact."})).unwrap();
    context.state.replace_file(
        Target::User.relative(),
        Document {
            entries: vec![entry],
        }
        .encode(Target::User, 1375)?
        .as_bytes(),
    )?;
    let content = Content { skill_md: "---\nname: checks\ndescription: Run checks.\nmetadata: {platforms: motor linux}\n---\nInstructions.\n".into(), notes_md: None };
    gears_batteries::skill_store::write(&context, "checks", Some(&content))?;
    gears_batteries::skill_store::admit(&context, "checks", &content.hash(), Decision::Approve)?;
    let mut event = Event {
        protocol_version: 1,
        event: "initialize".into(),
        workspace: workspace.into(),
        session: Session {
            id: context.session.clone(),
            path: None,
            state: None,
        },
        payload: json!({"reason":"startup", "subscribed_events":["command"]}),
    };
    let initial = gears_batteries::initialize_at(&event, &context.state);
    assert!(
        initial["prompt_fragments"]
            .to_string()
            .contains("Original fact.")
    );
    assert!(initial["prompt_fragments"].to_string().contains("checks"));
    let frozen = initial["prompt_fragments"].clone();
    event.session.state = Some(initial["state"].clone());
    context.state.replace_file(
        Target::User.relative(),
        Document::default().encode(Target::User, 1375)?.as_bytes(),
    )?;
    gears_batteries::skill_store::write(&context, "checks", None)?;
    std::fs::write(workspace.join("AGENTS.md"), "Current project instructions.")
        .map_err(|e| e.to_string())?;
    event.payload["preserve_prefix"] = json!(true);
    for reason in ["startup", "compaction"] {
        event.event = "initialize".into();
        event.payload["reason"] = json!(reason);
        let initialized = gears_batteries::initialize_at(&event, &context.state);
        assert_eq!(initialized["prompt_fragments"], frozen);
        assert!(
            initialized["context"]
                .to_string()
                .contains("Current project instructions.")
        );
        assert!(initialized.get("notice").is_none(), "{initialized}");
        event.session.state = Some(
            initialized
                .get("state")
                .cloned()
                .unwrap_or_else(|| event.session.state.clone().unwrap()),
        );
        event.event = "context".into();
        let observed = gears_batteries::context_at(
            Event {
                protocol_version: 1,
                event: event.event.clone(),
                workspace: workspace.into(),
                session: Session {
                    id: context.session.clone(),
                    path: None,
                    state: event.session.state.clone(),
                },
                payload: Value::Null,
            },
            &context,
        );
        assert!(
            observed["context"]
                .to_string()
                .contains("Withdraw User memory entry withdrawn-fact"),
            "{observed}"
        );
        assert!(
            observed["context"]
                .to_string()
                .contains("Withdraw skill checks"),
            "{observed}"
        );
        event.session.state = Some(observed["state"].clone());
        assert!(
            gears_batteries::memory_context::observe(&event, &context)?
                .get("context")
                .is_none()
        );
        assert!(
            gears_batteries::skill_context::observe(&event, &context)?
                .get("context")
                .is_none()
        );
    }
    println!("gears batteries frozen-prefix corrections ALL PASS");
    Ok(())
}
