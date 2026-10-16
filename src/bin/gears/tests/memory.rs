#![cfg(unix)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use gears::batteries::memory_format::Target;
use gears::batteries::paths::ToolContext;
use gears::config::{Config, HookConfig};
use gears::provider::{
    Completion, EventSink, FinishReason, Provider, ProviderError, Request, ToolCall,
};
use gears::runtime::{Approval, Approver, Event, Permission, Runtime};
use gears::session::Store;
use serde_json::json;

#[derive(Default)]
struct Scripted {
    requests: Mutex<Vec<Request>>,
}

impl Provider for Scripted {
    fn complete(
        &self,
        request: &Request,
        _: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(request.clone());
        assert!(request.tools.iter().any(|tool| tool.name == "memory"));
        Ok(if requests.len() == 1 {
            Completion { tool_calls: vec![ToolCall::new("memory-call", "memory",
                json!({"action": "add", "target": "user", "text": "Prefer small Rust patches.", "id": "preference"}).to_string())],
                finish_reason: Some(FinishReason::ToolCalls), ..Completion::default() }
        } else {
            Completion {
                content: "done".into(),
                finish_reason: Some(FinishReason::Stop),
                ..Completion::default()
            }
        })
    }
}

struct Answers {
    choice: Option<&'static str>,
    asked: usize,
}

impl Approver for Answers {
    fn approve(&mut self, _: &Permission) -> Approval {
        panic!("the memory tool must use its own question, not a permission prompt");
    }
    fn attended(&self) -> bool {
        self.choice.is_some()
    }
    fn answer(&mut self, question: &gears::hooks::Question) -> Result<Option<String>, String> {
        let choice = self.choice.expect("an unattended run must never ask");
        assert_eq!(
            question
                .choices
                .iter()
                .map(|choice| choice.value.as_str())
                .collect::<Vec<_>>(),
            ["yes", "no"]
        );
        assert_eq!(question.text, "Remember this?");
        self.asked += 1;
        Ok(Some(choice.into()))
    }
}

#[test]
fn the_real_hook_writes_memory_only_on_yes_and_never_asks_unattended() {
    for choice in [Some("yes"), Some("no"), None] {
        let label = choice.unwrap_or("unattended");
        let path = std::env::temp_dir().join(format!(
            "batteries-memory-runtime-{label}-{}",
            std::process::id()
        ));
        let workspace = path.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let home = path.join("home");
        let state = home.join(".gears");
        let config = Config {
            hooks: vec![HookConfig {
                name: "batteries".into(),
                command: vec![
                    "/usr/bin/env".into(),
                    format!("HOME={}", home.display()),
                    env!("CARGO_BIN_EXE_gears-batteries").into(),
                    "hook".into(),
                ],
                events: None,
                timeout: std::time::Duration::from_secs(30),
                max_output_bytes: 1024 * 1024,
            }],
            ..Config::default()
        };
        let store = Store::with_root(&workspace, state.clone()).unwrap();
        let session = store.create(false, None).unwrap();
        let context = ToolContext::new(
            workspace.clone(),
            state,
            session.id().into(),
            session.path(),
        )
        .unwrap();
        let provider = Arc::new(Scripted::default());
        let mut runtime = Runtime::new(
            provider.clone(),
            store,
            session,
            &config,
            "fixture/model".into(),
        )
        .unwrap();
        let original_id = runtime.session().id().to_string();
        let mut answers = Answers { choice, asked: 0 };
        let mut notices = Vec::new();
        runtime
            .turn(
                "Remember my preference.".into(),
                &mut answers,
                &mut |event| {
                    if let Event::Notice(text) = event {
                        notices.push(text);
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(answers.asked, usize::from(choice.is_some()));
        assert_eq!(notices.len(), 2, "{notices:?}");
        assert!(notices[0].contains("Prefer small Rust patches."));
        let outcome = match choice {
            Some("yes") => "remembered in user memory",
            Some("no") => "declined",
            _ => "nobody answered",
        };
        assert!(notices[1].contains(outcome), "{notices:?}");
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[1]
                .messages
                .iter()
                .any(|message| message.text_content().contains(outcome))
        );
        assert!(
            !requests[1]
                .system
                .iter()
                .any(|text| text.contains("Prefer small Rust patches."))
        );
        drop(requests);
        runtime.new_session(false, None).unwrap();
        runtime
            .turn("Start another session.".into(), &mut answers, &mut |_| {
                Ok(())
            })
            .unwrap();
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[2]
                .system
                .iter()
                .any(|text| text.contains("[preference] Prefer small Rust patches.")),
            choice == Some("yes")
        );
        drop(requests);
        let live = gears::batteries::memory::load(&context, Target::User).unwrap();
        assert_eq!(live.entries.len(), usize::from(choice == Some("yes")));
        if let Some(entry) = live.entries.first() {
            assert_eq!(entry.session, original_id);
            assert_eq!(entry.date.len(), 10);
        }
        let mut decisions = Vec::new();
        gears::batteries::journal::visit(
            &context.state,
            Path::new("batteries/changes.jsonl"),
            |value| {
                decisions.push(value);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(decisions.len(), usize::from(choice.is_some()));
        if let Some(record) = decisions.first() {
            assert_eq!(record["decision"], choice.unwrap());
            assert_eq!(record["text"], "Prefer small Rust patches.");
            assert_eq!(record["session"], original_id);
        }
        if choice == Some("yes") {
            // A hand edit shows up in the next session, not in the running one.
            let hash =
                runtime.session().hook_state("batteries").unwrap()["prompt_snapshot"].clone();
            context
                .state
                .replace_file(Target::User.relative(), b"# Gears memory v2\n")
                .unwrap();
            runtime
                .turn("Use the current memory.".into(), &mut answers, &mut |_| {
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                runtime.session().hook_state("batteries").unwrap()["prompt_snapshot"],
                hash
            );
            runtime.new_session(false, None).unwrap();
            runtime
                .turn("Check it again.".into(), &mut answers, &mut |_| Ok(()))
                .unwrap();
            let requests = provider.requests.lock().unwrap();
            assert_eq!(requests.len(), 5);
            assert!(
                requests[3]
                    .system
                    .iter()
                    .any(|text| text.contains("Prefer small Rust patches."))
            );
            assert!(
                !requests[4]
                    .system
                    .iter()
                    .any(|text| text.contains("Prefer small Rust patches."))
            );
        }
        drop(runtime);
        std::fs::remove_dir_all(path).unwrap();
    }
}
