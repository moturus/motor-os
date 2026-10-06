//! The real hook asks on resume and never calls a provider to answer it.

use std::path::Path;
use std::sync::Arc;

use gears::provider::Message;
use gears::runtime::{Approval, Approver, Permission, Runtime};
use gears::session::Store;
use gears_batteries::{paths::ToolContext, review_config::Model, review_marks};

use super::{scenario::Scripted, support::Fixture};

struct Answers {
    review: Option<String>,
    asked: usize,
}
impl Approver for Answers {
    fn approve(&mut self, _: &Permission) -> Approval {
        panic!("resuming reviews must not run tools");
    }
    fn answer(&mut self, question: &gears::hooks::Question) -> Result<Option<String>, String> {
        self.asked += 1;
        let choices: Vec<_> = question
            .choices
            .iter()
            .map(|choice| choice.value.as_str())
            .collect();
        match choices.as_slice() {
            ["approve", "deny", "postpone"] => Ok(Some("postpone".into())),
            ["run", "drop"] => Ok(self.review.clone()),
            _ => Err("unexpected resume question".into()),
        }
    }
}

pub fn run(binary: &Path, compiler: &str) -> Result<(), String> {
    let fixture = Fixture::new(binary, compiler)?;
    let store = Store::with_root(&fixture.workspace, fixture.state.clone())?;
    let mut session = store.create(false, None)?;
    let id = session.id().to_string();
    let group = session.path().unwrap().parent().unwrap().to_path_buf();
    let entry = session.append_message(&Message::assistant("Completed earlier task"))?;
    let context = ToolContext::new(
        fixture.workspace.clone(),
        fixture.state.clone(),
        id.clone(),
        session.path(),
    )?;
    let executor = Model {
        provider: "local".into(),
        model: "executor".into(),
    };
    let mark = review_marks::create(
        &context,
        &entry,
        review_marks::Reason::Command,
        "",
        &executor,
    )?;
    let memory = fixture.workspace.join(".gears/MEMORY.md");
    let document = gears_batteries::memory_format::Document::default()
        .encode(gears_batteries::memory_format::Target::Workspace, 1024)?;
    std::fs::write(&memory, document).map_err(|error| error.to_string())?;
    let provider = Arc::new(Scripted::from_responses(Vec::new()));
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
    assert!(runtime.pending_hook_questions());
    assert_eq!(
        runtime.session().hook_state(&fixture.hook).unwrap()["reviews_paused"],
        true
    );
    let mut unanswered = Answers {
        review: None,
        asked: 0,
    };
    runtime.resolve_hook_questions(&mut unanswered, &mut |_| Ok(()))?;
    assert_eq!(
        unanswered.asked, 2,
        "workspace admission must precede the review question"
    );
    assert_eq!(review_marks::due(&context)?.len(), 1);
    assert_eq!(
        runtime.session().hook_state(&fixture.hook).unwrap()["reviews_paused"],
        true
    );
    // Workspace admission adds its own context; review answers must preserve it.
    let messages = runtime.session().context_messages()?;
    std::fs::remove_file(memory).map_err(|error| error.to_string())?;
    runtime.resume(&id)?;
    let mut run = Answers {
        review: Some("run".into()),
        asked: 0,
    };
    runtime.resolve_hook_questions(&mut run, &mut |_| Ok(()))?;
    assert_eq!(run.asked, 1);
    assert_eq!(review_marks::due(&context)?.len(), 1);
    assert_eq!(
        runtime.session().hook_state(&fixture.hook).unwrap()["reviews_paused"],
        false
    );
    runtime.resume(&id)?;
    let later = review_marks::create(
        &context,
        &entry,
        review_marks::Reason::Command,
        "Later focus",
        &executor,
    )?;
    let mut dismiss = Answers {
        review: Some("drop".into()),
        asked: 0,
    };
    runtime.resolve_hook_questions(&mut dismiss, &mut |_| Ok(()))?;
    assert_eq!(
        review_marks::load(&context, &mark)?.unwrap().disposition,
        review_marks::Disposition::Dropped
    );
    assert_eq!(
        review_marks::due(&context)?.len(),
        1,
        "only displayed marks may be dismissed"
    );
    assert_eq!(runtime.session().context_messages()?, messages);
    runtime.new_session(false, None)?;
    let new = runtime.session().id().to_string();
    assert!(!runtime.pending_hook_questions());
    let other = ToolContext::new(
        fixture.workspace.clone(),
        fixture.state.clone(),
        new.clone(),
        runtime.session().path(),
    )?;
    assert!(review_marks::due(&other)?.is_empty());
    assert_eq!(review_marks::due(&context)?.len(), 1);
    runtime.resume(&id)?;
    runtime.resolve_hook_questions(&mut dismiss, &mut |_| Ok(()))?;
    assert_eq!(
        review_marks::load(&context, &later)?.unwrap().disposition,
        review_marks::Disposition::Dropped
    );
    runtime.resume(&id)?;
    assert!(!runtime.pending_hook_questions());
    assert!(provider.requests.lock().unwrap().is_empty());
    assert!(!fixture.workspace.join("checked.rmeta").exists());
    drop(runtime);
    fixture.cleanup(&group, &[id, new], &[snapshot])?;
    println!("gears batteries review resume ALL PASS");
    Ok(())
}
