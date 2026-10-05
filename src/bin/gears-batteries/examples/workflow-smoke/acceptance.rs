//! The real hook records acceptance without a provider request or workspace check.

use std::path::Path;
use std::sync::Arc;

use gears::provider::{Message, Role};
use gears::runtime::{Event, Runtime};
use gears::session::Store;
use gears_batteries::acceptance::ACCEPTED_CONTEXT;

use super::scenario::{Approvals, Scripted, answer};
use super::support::Fixture;

fn accepted(runtime: &Runtime) -> Result<usize, String> {
    Ok(runtime
        .session()
        .context_messages()?
        .iter()
        .filter(|message| message.text_content() == ACCEPTED_CONTEXT)
        .count())
}

pub fn run(binary: &Path, compiler: &str) -> Result<(), String> {
    let fixture = Fixture::new(binary, compiler)?;
    let store = Store::with_root(&fixture.workspace, fixture.state.clone())?;
    let session = store.create(false, None)?;
    let group = session.path().unwrap().parent().unwrap().to_path_buf();
    let id = session.id().to_string();
    let mut sessions = vec![id.clone()];
    let provider = Arc::new(Scripted::from_responses(vec![answer("Acknowledged.")]));
    let mut runtime = Runtime::new(
        provider.clone(),
        store,
        session,
        &fixture.config,
        "fixture/model".into(),
    )?;
    let snapshot = runtime.session().hook_state(&fixture.hook).unwrap()["prompt_snapshot"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        runtime
            .hook_commands()
            .iter()
            .any(|command| command.name == "accept")
    );
    assert!(!fixture.workspace.join(".git").exists());
    runtime.turn(
        "yes, I accept this".into(),
        &mut Approvals::default(),
        &mut |_| Ok(()),
    )?;
    assert_eq!(accepted(&runtime)?, 0);
    let before = runtime
        .session()
        .entries()
        .iter()
        .find(|entry| {
            entry.kind == "message"
                && serde_json::from_value::<Message>(entry.data.clone()).is_ok_and(|message| {
                    message.role == Role::User && message.text_content() == "yes, I accept this"
                })
        })
        .unwrap()
        .id
        .clone();
    let state = runtime.session().hook_state(&fixture.hook);
    let mut notices = Vec::new();
    let mut observer = |event| {
        if let Event::Notice(text) = event {
            notices.push(text);
        }
        Ok(())
    };
    assert!(
        runtime
            .hook_command("accept", "extra", &mut observer)
            .is_err()
    );
    assert_eq!(accepted(&runtime)?, 0);
    runtime.hook_command("accept", "", &mut observer)?;
    assert_eq!(runtime.session().id(), id);
    assert_eq!(accepted(&runtime)?, 1);
    assert_eq!(runtime.session().hook_state(&fixture.hook), state);
    let acceptance_id = runtime.session().active_leaf().unwrap().to_string();
    let path = runtime.session().path().unwrap().to_path_buf();
    runtime.resume(&id)?;
    assert_eq!(accepted(&runtime)?, 1);
    assert!(
        runtime
            .session()
            .active_entries()?
            .iter()
            .any(|entry| entry.id == acceptance_id)
    );
    runtime.hook_command("accept", "", &mut observer)?;
    assert_eq!(accepted(&runtime)?, 2);
    runtime.fork_at(&before)?;
    sessions.push(runtime.session().id().to_string());
    assert_eq!(accepted(&runtime)?, 0);
    runtime.hook_command("accept", "", &mut observer)?;
    assert_eq!(accepted(&runtime)?, 1);
    let mut expected = vec![format!(
        "hook {}: gears-batteries: /accept takes no arguments",
        fixture.hook
    )];
    expected.extend(vec![format!("hook {}: Task accepted.", fixture.hook); 3]);
    assert_eq!(notices, expected);
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
    assert!(!fixture.workspace.join("checked.rmeta").exists());
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("src/lib.rs"))
            .map_err(|error| error.to_string())?,
        "const _: () = assert!(1 + 1 == 3);\n"
    );
    let saved = gears::session::read_snapshot(&path)?;
    assert!(
        saved
            .active_entries()?
            .iter()
            .any(|entry| entry.id == acceptance_id)
    );
    drop(runtime);
    fixture.cleanup(&group, &sessions, &[snapshot])?;
    println!("explicit task acceptance ALL PASS");
    Ok(())
}
