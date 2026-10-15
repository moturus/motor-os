//! Real hook processes exercise approval, loading and exact-version corrections.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use gears::batteries::paths::ToolContext;
use gears::batteries::{skill_pending, skill_sources, skill_store};
use gears::runtime::{Event, Runtime};
use gears::session::Store;
use serde_json::json;

use super::scenario::{Approvals, Scripted, answer, call};
use super::support::Fixture;

pub fn run(binary: &Path, compiler: &str) -> Result<(), String> {
    let fixture = Fixture::new(binary, compiler)?;
    std::fs::write(
        fixture.workspace.join("src/lib.rs"),
        "const _: () = assert!(1 + 1 == 2);\n",
    )
    .map_err(|error| error.to_string())?;
    let name = format!("skill-{}", fixture.label);
    let skill_md = format!(
        "---\nname: {name}\ndescription: >-\n  Compile the fixture assertion.\nlicense: MIT\nmetadata: {{platforms: motor linux}}\n---\n## When it applies\nFixture only.\n## Steps\nKeep the assertion.\n## How to check\nRun the declared check.\n## Pitfalls\nDo not remove the assertion.\n"
    );
    let provider = Arc::new(Scripted::from_responses(vec![
        call(
            "skill_manage",
            json!({"action": "add", "name": name, "skill_md": skill_md, "notes_md": "Original fixture note."}),
        ),
        call("skill_view", json!({})),
        answer("proposal staged"),
        call("skill_view", json!({"name": name})),
        call("check", json!({})),
        call(
            "skill_manage",
            json!({"action": "replace", "name": name, "notes_md": "Corrected fixture note."}),
        ),
        answer("loaded and checked"),
        answer("correction received"),
        answer("unapproved version withdrawn"),
        answer("withdrawal unchanged"),
        answer("resumed without withdrawn skill"),
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
    let mut sessions = vec![runtime.session().id().to_string()];
    let mut snapshots = Vec::new();
    let mut approvals = Approvals::default();
    let mut observer = |event| {
        if let Event::Notice(text) = event {
            return Err(format!("unexpected skill workflow notice: {text}"));
        }
        Ok(())
    };
    let cli = |context: &ToolContext, id: &str| -> Result<(), String> {
        let output = Command::new(binary)
            .args(["pending", "--approve", id])
            .arg("--root")
            .arg(context.state.path())
            .arg("--workspace")
            .arg(&fixture.workspace)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into());
        }
        Ok(())
    };
    let context = |runtime: &Runtime| {
        ToolContext::new(
            fixture.workspace.clone(),
            fixture.state.clone(),
            runtime.session().id().into(),
            runtime.session().path(),
        )
    };
    let pending = |context: &ToolContext| -> Result<_, String> {
        skill_pending::list(context)?
            .into_iter()
            .find(|(_, proposal)| proposal.name == name)
            .ok_or("missing fixture skill proposal".into())
    };
    runtime.turn(
        "propose the fixture skill".into(),
        &mut approvals,
        &mut observer,
    )?;
    snapshots.push(
        runtime.session().hook_state(&fixture.hook).unwrap()["prompt_snapshot"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    assert!(skill_store::current(&context(&runtime)?, &name)?.is_none());
    assert!(provider.requests.lock().unwrap().iter().all(|request| {
        request
            .system
            .iter()
            .all(|text| !text.starts_with("Approved skills:") || !text.contains(&name))
    }));
    cli(&context(&runtime)?, &pending(&context(&runtime)?)?.0)?;
    runtime.new_session(false, None)?;
    sessions.push(runtime.session().id().to_string());
    runtime.turn(
        "load the approved skill and run its check".into(),
        &mut approvals,
        &mut observer,
    )?;
    let ctx = context(&runtime)?;
    let state = runtime.session().hook_state(&fixture.hook).unwrap();
    snapshots.push(state["prompt_snapshot"].as_str().unwrap().to_string());
    assert_eq!(state["last_check"]["current"], true);
    let journal = std::fs::read_to_string(ctx.data_file("turns.jsonl")?)
        .map_err(|error| error.to_string())?;
    let turn: gears::batteries::turns::Turn =
        serde_json::from_str(journal.trim_end()).map_err(|error| error.to_string())?;
    assert_eq!(
        (
            turn.tool_calls,
            turn.execution_errors,
            turn.checks.len(),
            turn.skill_observations.len()
        ),
        (3, 0, 1, 1)
    );
    let fact = &turn.skill_observations[0];
    assert_eq!(fact["name"], name);
    assert_eq!(fact["causal_claim"], false);
    assert_eq!(fact["user_accepted"], false);
    for id in [
        fact["load_source"]["entries"][0].as_str().unwrap(),
        fact["check_source"]["entry"].as_str().unwrap(),
    ] {
        assert!(
            runtime
                .session()
                .entries()
                .iter()
                .any(|entry| entry.id == id)
        );
    }
    let (id, proposal) = pending(&ctx)?;
    let evidence = skill_sources::describe(&ctx, &proposal)?;
    assert_eq!(
        evidence["sessions_with_old_snapshot"],
        json!([runtime.session().id()])
    );
    assert!(
        evidence["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .all(|source| source["available"] == true)
    );
    cli(&ctx, &id)?;
    runtime.turn(
        "receive the approved correction".into(),
        &mut approvals,
        &mut observer,
    )?;
    let mut edited = skill_store::current(&ctx, &name)?.unwrap();
    edited.notes_md = Some("Unapproved fixture note.".into());
    skill_store::write(&ctx, &name, Some(&edited))?;
    runtime.turn(
        "withdraw the unapproved version".into(),
        &mut approvals,
        &mut observer,
    )?;
    runtime.turn(
        "confirm withdrawal is not repeated".into(),
        &mut approvals,
        &mut observer,
    )?;
    runtime.resume(runtime.session().id().to_string().as_str())?;
    runtime.turn(
        "check the resumed catalog".into(),
        &mut approvals,
        &mut observer,
    )?;
    let requests = provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 11);
    assert!(
        requests[3]
            .system
            .iter()
            .any(|text| text.starts_with("Approved skills:") && text.contains(&name))
    );
    assert!(
        requests[4]
            .messages
            .iter()
            .any(|message| message.text_content().contains("Original fixture note."))
    );
    assert_eq!(requests[6].system, requests[7].system);
    assert!(requests[7].messages.iter().any(|message| {
        message.text_content().contains("Correct loaded skill")
            && message.text_content().contains("Corrected fixture note.")
    }));
    let withdrawal = |request: &gears::provider::Request| {
        request
            .messages
            .iter()
            .filter(|message| message.text_content().contains("Withdraw loaded skill"))
            .count()
    };
    assert_eq!((withdrawal(&requests[8]), withdrawal(&requests[9])), (1, 1));
    assert!(requests.iter().all(|request| {
        request
            .messages
            .iter()
            .all(|message| !message.text_content().contains("Unapproved fixture note."))
    }));
    assert!(
        requests[10]
            .system
            .iter()
            .all(|text| !text.starts_with("Approved skills:") || !text.contains(&name))
    );
    drop(requests);
    drop(runtime);
    skill_store::write(&ctx, &name, None)?;
    let directory = skill_store::relative(&name, "SKILL.md")?
        .parent()
        .unwrap()
        .to_path_buf();
    if let Some(path) = ctx.state.existing_directory(&directory)? {
        std::fs::remove_dir(path).map_err(|error| error.to_string())?;
    }
    fixture.cleanup(&group, &sessions, &snapshots)?;
    Ok(())
}
