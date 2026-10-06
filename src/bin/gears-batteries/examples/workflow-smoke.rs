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

#[path = "workflow-smoke/acceptance.rs"]
mod acceptance;

#[path = "workflow-smoke/skills.rs"]
mod skills;

#[path = "workflow-smoke/skill_retention.rs"]
mod skill_retention;

#[path = "workflow-smoke/cleanup_candidates.rs"]
mod cleanup_candidates;

#[path = "workflow-smoke/cleanup_usage.rs"]
mod cleanup_usage;

#[path = "workflow-smoke/cleanup_proposals.rs"]
mod cleanup_proposals;

#[path = "workflow-smoke/cleanup_cli.rs"]
mod cleanup_cli;

#[path = "workflow-smoke/eval_directory.rs"]
mod eval_directory;

#[path = "workflow-smoke/eval_actor.rs"]
mod eval_actor;

#[path = "workflow-smoke/eval_command.rs"]
mod eval_command;

#[path = "workflow-smoke/eval_config.rs"]
mod eval_config;

#[path = "workflow-smoke/eval_copies.rs"]
mod eval_copies;

#[path = "workflow-smoke/eval_install.rs"]
mod eval_install;

#[path = "workflow-smoke/eval_policy.rs"]
mod eval_policy;

#[path = "workflow-smoke/eval_prepare.rs"]
mod eval_prepare;

#[path = "workflow-smoke/eval_report.rs"]
mod eval_report;

#[path = "workflow-smoke/eval_states.rs"]
mod eval_states;

#[path = "workflow-smoke/eval_tasks.rs"]
mod eval_tasks;

#[path = "workflow-smoke/review_marks.rs"]
mod review_marks;

#[path = "workflow-smoke/review_anchor.rs"]
mod review_anchor;

#[path = "workflow-smoke/review_policy.rs"]
mod review_policy;

#[path = "workflow-smoke/review_triggers.rs"]
mod review_triggers;

#[path = "workflow-smoke/review_resume.rs"]
mod review_resume;

#[path = "workflow-smoke/review_proposals.rs"]
mod review_proposals;

#[path = "workflow-smoke/prefix_corrections.rs"]
mod prefix_corrections;

#[path = "workflow-smoke/review_launch.rs"]
mod review_launch;

#[path = "workflow-smoke/review_instructions.rs"]
mod review_instructions;

#[path = "workflow-smoke/review_runner.rs"]
mod review_runner;

#[path = "workflow-smoke/review_cli.rs"]
mod review_cli;

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let binary = std::path::PathBuf::from(
        args.next()
            .ok_or("usage: workflow-smoke BATTERIES RUSTC GEARS")?,
    );
    let compiler = args.next().ok_or("missing check compiler")?;
    let gears = std::path::PathBuf::from(args.next().ok_or("missing Gears binary")?);
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
            let prefix = format!("hook {}: Memory proposal ", fixture.hook);
            if text.starts_with(&prefix) && (text.contains("\"text\": \"The fixture uses a compile-time assertion.\"")
                || text.ends_with("postponed; still pending. Approval admits future use and does not prove usefulness.")) {
                memory_notices += 1;
            } else { return Err(format!("unexpected workflow notice: {text}")); }
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
    let context = gears_batteries::paths::ToolContext::new(
        fixture.workspace.clone(),
        fixture.state.clone(),
        runtime.session().id().into(),
        runtime.session().path(),
    )?;
    let journal = std::fs::read_to_string(context.data_file("turns.jsonl")?)
        .map_err(|error| error.to_string())?;
    let recorded: gears_batteries::turns::Turn = serde_json::from_str(journal.trim_end()).unwrap();
    assert_eq!(
        (
            recorded.tool_calls,
            recorded.execution_errors,
            recorded.checks.len()
        ),
        (8, 0, 1)
    );
    assert_eq!(recorded.checks[0]["passed"], true);
    assert!(
        recorded
            .files_written
            .contains(std::path::Path::new("src/lib.rs"))
    );
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
            if text
                != "before_stop: The workspace changed and no current passing check exists. Run the declared check before finishing; checks provide development evidence, not task acceptance."
            {
                return Err(format!("unexpected workflow notice: {text}"));
            }
            notices += 1;
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
    let requests = provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 17);
    let pending = gears_batteries::pending::list(
        &context,
        gears_batteries::memory_format::Target::Workspace,
    )?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1.source.session, sessions[0]);
    assert!(pending[0].1.source.entries.iter().all(|id| {
        gears::session::read_snapshot(&group.join(format!("{}.jsonl", sessions[0])))
            .unwrap()
            .entries()
            .iter()
            .any(|entry| entry.id == *id)
    }));
    assert!(!fixture.workspace.join(".gears/MEMORY.md").exists());
    assert!(requests.iter().any(|request| {
        request
            .messages
            .iter()
            .any(|message| message.text_content().contains("postponed; still pending"))
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
    assert_eq!(approvals.0.len(), 4);
    drop(runtime);
    memory::run(&binary, &fixture.root)?;
    review_cli::run(&binary, &gears, &fixture.root)?;
    review_marks::run(&fixture.workspace, &fixture.root.join("review-state"))?;
    review_launch::run(&fixture.workspace, &fixture.root.join("review-launch"))?;
    review_instructions::run(
        &fixture.workspace,
        &fixture.root.join("review-instructions"),
    )?;
    review_anchor::run(&fixture.workspace, &fixture.root.join("review-anchor"))?;
    review_policy::run(&fixture.workspace, &fixture.root.join("review-policy"))?;
    review_runner::run(&fixture.workspace, &fixture.root.join("review-runner"))?;
    review_triggers::run(&fixture.workspace, &fixture.root.join("review-triggers"))?;
    review_proposals::run(&fixture.workspace, &fixture.root.join("review-proposals"))?;
    prefix_corrections::run(
        &fixture.root.join("prefix-workspace"),
        &fixture.root.join("prefix-state"),
    )?;
    eval_actor::run_fixture(&fixture.root.join("eval-actor"), &binary, &gears, &compiler)?;
    eval_command::run_fixture(&fixture.root.join("eval-command"), &compiler)?;
    eval_config::run_fixture(&fixture.root.join("eval-config"), &binary)?;
    eval_copies::run_fixture(&fixture.root.join("eval-copies"), &compiler)?;
    eval_install::run_fixture(&fixture.root.join("eval-install"))?;
    eval_policy::run_fixture(&fixture.root.join("eval-policy"))?;
    eval_prepare::run_fixture(&fixture.root.join("eval-prepare"), &binary)?;
    eval_report::run_fixture(&fixture.root.join("eval-report"))?;
    eval_states::run_fixture(&fixture.root.join("eval-states"))?;
    eval_tasks::run_fixture(&fixture.workspace, &fixture.root.join("eval-tasks"))?;
    eval_directory::run_fixture(
        &binary,
        &gears,
        &fixture.workspace,
        &fixture.root.join("eval-directory"),
    )?;
    cleanup_cli::run(
        &binary,
        &fixture.workspace,
        &fixture.root.join("cleanup-cli"),
    )?;
    cleanup_proposals::run(&fixture.workspace, &fixture.root.join("cleanup-proposals"))?;
    cleanup_usage::run(&fixture.workspace, &fixture.root.join("cleanup-usage"))?;
    cleanup_candidates::run(&fixture.workspace, &fixture.root.join("cleanup-candidates"))?;
    skill_retention::run(&fixture.workspace, &fixture.root.join("skill-retention"))?;
    fixture.cleanup(&group, &sessions, &snapshots)?;
    skills::run(&binary, &compiler)?;
    acceptance::run(&binary, &compiler)?;
    review_resume::run(&binary, &compiler)?;
    println!("gears batteries workflow ALL PASS");
    Ok(())
}

fn main() {
    if std::env::args_os().next().is_some_and(|name| {
        std::path::Path::new(&name)
            .file_name()
            .is_some_and(|name| name == "review-child")
    }) {
        review_runner::child();
        return;
    }
    if let Err(error) = run() {
        eprintln!("batteries workflow fixture failed: {error}");
        std::process::exit(1);
    }
}
