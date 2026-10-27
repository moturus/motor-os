//! Portable end-to-end batteries fixture. No external provider is contacted.

#[path = "workflow-smoke/support.rs"]
mod support;

use std::sync::Arc;

use gears::provider::{Message, Role};
use gears::runtime::{Event, Runtime};
use gears::session::Store;

#[path = "workflow-smoke/scenario.rs"]
mod scenario;

#[path = "workflow-smoke/memory.rs"]
mod memory;

#[path = "workflow-smoke/skills.rs"]
mod skills;

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let binary =
        std::path::PathBuf::from(args.next().ok_or("usage: workflow-smoke BATTERIES RUSTC")?);
    let compiler = args.next().ok_or("missing check compiler")?;
    let fixture = support::Fixture::new(&binary, &compiler)?;
    let store = Store::with_root(&fixture.workspace, fixture.state.clone())?;
    let session = store.create(false, None)?;
    let group = session.path().unwrap().parent().unwrap().to_path_buf();
    let mut sessions = vec![session.id().to_string()];
    let provider = Arc::new(scenario::Scripted::new(&fixture.label));
    let mut runtime = Runtime::new(
        provider.clone(),
        store,
        session,
        &fixture.config,
        "fixture/model".into(),
    )?;
    eprintln!(
        "batteries workflow workspace: {}",
        fixture.workspace.display()
    );
    let mut approvals = scenario::Approvals::default();
    let mut memory_notices = 0;
    let mut observer = |event| {
        if let Event::Notice(text) = event {
            fixture.observe_notice(&text)?;
            let proposed = format!(
                "hook {}: Proposed workspace memory entry:\nThe fixture uses a compile-time assertion.",
                fixture.hook
            );
            let declined = format!("hook {}: Memory change declined.", fixture.hook);
            if text == proposed || text == declined {
                memory_notices += 1;
            }
        }
        Ok(())
    };
    runtime.turn(fixture.label.clone(), &mut approvals, &mut observer)?;
    let state = runtime
        .session()
        .hook_state(&fixture.hook)
        .ok_or("missing batteries state")?;
    let snapshots = vec![
        state["prompt_snapshot"]
            .as_str()
            .ok_or("missing prompt snapshot")?
            .to_string(),
    ];
    assert_eq!(state["last_check"]["current"], true);
    assert_eq!(state["last_check"]["receipt"]["passed"], true);
    assert!(fixture.workspace.join("checked.rmeta").is_file());
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("notes/a file*")).unwrap(),
        "literal fixture\n"
    );
    assert!(
        approvals
            .0
            .iter()
            .find(|permission| permission.tool == "check")
            .unwrap()
            .detail
            .contains(&compiler)
    );
    let context = gears::batteries::paths::ToolContext::new(
        fixture.workspace.clone(),
        fixture.state.clone(),
        runtime.session().id().into(),
        runtime.session().path(),
    )?;
    runtime.turn("update task list".into(), &mut approvals, &mut observer)?;
    assert_eq!(memory_notices, 2);
    let selected = runtime
        .session()
        .entries()
        .iter()
        .find(|entry| {
            entry.kind == "message"
                && serde_json::from_value::<Message>(entry.data.clone()).is_ok_and(|message| {
                    message.role == Role::User && message.text_content() == "update task list"
                })
        })
        .unwrap()
        .id
        .clone();
    assert_eq!(
        runtime.session().hook_state(&fixture.hook).unwrap()["tasks"]["items"][0]["status"],
        "completed"
    );
    runtime.fork_at(&selected)?;
    sessions.push(runtime.session().id().to_string());
    assert_eq!(
        runtime.session().hook_state(&fixture.hook).unwrap()["tasks"]["items"][0]["status"],
        "pending"
    );
    runtime.new_session(false, None)?;
    sessions.push(runtime.session().id().to_string());
    let mut notices = 0;
    let mut reminder_observer = |event| {
        if let Event::Notice(text) = event {
            fixture.observe_notice(&text)?;
            if text
                == "before_stop: The workspace changed and no current passing check exists. Run the declared check before finishing; checks provide development evidence, not task acceptance."
            {
                notices += 1;
            }
        }
        Ok(())
    };
    runtime.turn(
        "exercise missing check reminders".into(),
        &mut approvals,
        &mut reminder_observer,
    )?;
    assert_eq!(notices, 3);
    assert_eq!(
        runtime.session().hook_state(&fixture.hook).unwrap()["check_reminders"],
        3
    );
    // Every scripted reply was used; an extra request would already have failed.
    assert_eq!(provider.remaining(), 0);
    let requests = provider.requests.lock().unwrap();
    // The scripted approver declined the proposed entry: logged, never written.
    let history = gears::batteries::memory_history::history(&context, 0, 10)?;
    assert_eq!(history["total"], 1);
    assert_eq!(history["records"][0]["decision"], "no");
    assert_eq!(history["records"][0]["session"], sessions[0]);
    assert!(!fixture.workspace.join(".gears/MEMORY.md").exists());
    assert!(requests.iter().any(|request| {
        request
            .messages
            .iter()
            .any(|message| message.text_content().contains("Memory change declined."))
    }));
    let reminders = requests
        .last()
        .unwrap()
        .messages
        .iter()
        .filter(|message| {
            message
                .text_content()
                .starts_with("The workspace changed and no current passing check exists.")
        })
        .count();
    assert_eq!(reminders, 3);
    // The hook allows reading, searching, todo and memory; the two writes, check and
    // the second patch were asked.
    assert_eq!(approvals.0.len(), 4);
    let asked = requests.len();
    drop(requests);
    // The user's own words go to memory at once, without a question or a request.
    let mut remembered = Vec::new();
    runtime.hook_command("remember", "Run the fixture check offline.", &mut |event| {
        if let Event::Notice(text) = event {
            fixture.observe_notice(&text)?;
            remembered.push(text);
        }
        Ok(())
    })?;
    assert!(
        remembered.iter().any(|text| text.contains("Remembered [")),
        "{remembered:?}"
    );
    assert!(
        std::fs::read_to_string(fixture.workspace.join(".gears/MEMORY.md"))
            .unwrap()
            .contains("Run the fixture check offline.")
    );
    assert_eq!(provider.requests.lock().unwrap().len(), asked);
    assert_eq!(approvals.0.len(), 4);
    drop(runtime);
    memory::run(&binary, &fixture.root)?;
    fixture.cleanup(&group, &sessions, &snapshots)?;
    skills::run(&binary, &compiler)?;
    println!("gears batteries workflow ALL PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("batteries workflow fixture failed: {error}");
        std::process::exit(1);
    }
}
