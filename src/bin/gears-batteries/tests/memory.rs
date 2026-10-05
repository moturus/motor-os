#![cfg(unix)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use gears::config::{Config, HookConfig};
use gears::provider::{
    Completion, EventSink, FinishReason, Provider, ProviderError, Request, ToolCall,
};
use gears::runtime::{Approval, Approver, Event, Permission, Runtime};
use gears::session::Store;
use gears_batteries::memory_format::Target;
use gears_batteries::paths::ToolContext;
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
        panic!("memory tool authority must use its admission question");
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
            ["approve", "deny", "postpone"]
        );
        self.asked += 1;
        Ok(Some(choice.into()))
    }
}

#[test]
fn the_real_hook_delivers_all_admission_answers_without_asking_in_unattended_runs() {
    for choice in [Some("approve"), Some("deny"), Some("postpone"), None] {
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
            Some("approve") => "approved",
            Some("deny") => "denied",
            _ => "postponed; still pending",
        };
        assert!(notices[1].contains(outcome));
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
        let live = gears_batteries::memory::load(&context, Target::User).unwrap();
        assert_eq!(live.entries.len(), usize::from(choice == Some("approve")));
        let pending = gears_batteries::pending::list(&context, Target::User).unwrap();
        assert_eq!(
            pending.len(),
            usize::from(matches!(choice, Some("postpone") | None))
        );
        let mut decisions = 0;
        gears_batteries::journal::visit(
            &context.state,
            Path::new("batteries/changes.jsonl"),
            |value| {
                assert_eq!(value["decision"], choice.unwrap());
                decisions += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            decisions,
            usize::from(matches!(choice, Some("approve" | "deny")))
        );
        let entries = runtime.session().entries();
        let source = live
            .entries
            .first()
            .map(|entry| &entry.metadata.source)
            .or_else(|| pending.first().map(|(_, proposal)| &proposal.source));
        if let Some(source) = source {
            assert_eq!(source.session, runtime.session().id());
            assert!(
                source
                    .entries
                    .iter()
                    .all(|id| entries.iter().any(|entry| entry.id == *id))
            );
        }
        drop(runtime);
        std::fs::remove_dir_all(path).unwrap();
    }
}
