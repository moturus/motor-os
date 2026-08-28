#![cfg(unix)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gears::config::{Config, ContextConfig, HookConfig};
use gears::provider::{
    Completion, EventSink, FinishReason, Provider, ProviderError, Request, StreamEvent, ToolCall,
};
use gears::runtime::{Approver, Event, Permission, Runtime};
use gears::session::Store;

struct Scripted {
    responses: Mutex<VecDeque<Result<Completion, ProviderError>>>,
    requests: Mutex<Vec<Request>>,
}

impl Scripted {
    fn new(responses: Vec<Result<Completion, ProviderError>>) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        })
    }
}

impl Provider for Scripted {
    fn complete(
        &self,
        request: &Request,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted response");
        if let Ok(completion) = &response {
            if !completion.reasoning.is_empty() {
                sink.on_event(StreamEvent::Reasoning(completion.reasoning.clone()))
                    .map_err(|error| ProviderError::Aborted(error.to_string()))?;
            }
            if !completion.content.is_empty() {
                sink.on_event(StreamEvent::Text(completion.content.clone()))
                    .map_err(|error| ProviderError::Aborted(error.to_string()))?;
            }
        }
        response
    }
}

struct FixedApproval(bool);

impl Approver for FixedApproval {
    fn approve(&mut self, _request: &Permission) -> bool {
        self.0
    }
}

struct UnexpectedApproval;

impl Approver for UnexpectedApproval {
    fn approve(&mut self, _request: &Permission) -> bool {
        panic!("permission hook should have allowed the call")
    }
}

fn answer(text: &str) -> Result<Completion, ProviderError> {
    Ok(Completion {
        content: text.to_string(),
        finish_reason: Some(FinishReason::Stop),
        ..Completion::default()
    })
}

fn priced_answer(text: &str) -> Result<Completion, ProviderError> {
    Ok(Completion {
        content: text.to_string(),
        finish_reason: Some(FinishReason::Stop),
        usage: gears::provider::Usage {
            prompt_tokens: 10,
            completion_tokens: 2,
            ..gears::provider::Usage::default()
        },
        ..Completion::default()
    })
}

fn tool(name: &str, arguments: &str) -> Result<Completion, ProviderError> {
    Ok(Completion {
        tool_calls: vec![ToolCall::new("call_1", name, arguments)],
        finish_reason: Some(FinishReason::ToolCalls),
        ..Completion::default()
    })
}

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("gears-runtime-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        Self { root, workspace }
    }

    fn runtime(&self, provider: Arc<dyn Provider>, config: &Config) -> Runtime {
        let store = Store::with_root(&self.workspace, self.root.join("state")).unwrap();
        let session = store.create(false, None).unwrap();
        Runtime::new(provider, store, session, config, "test/model".to_string()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn text_only_turn_streams_and_is_durable() {
    let fixture = Fixture::new("text");
    let provider = Scripted::new(vec![answer("hello")]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    let mut events = Vec::new();
    runtime
        .turn(
            "question".to_string(),
            &mut FixedApproval(false),
            &mut |event| {
                events.push(event);
                Ok(())
            },
        )
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Text(text) if text == "hello"))
    );
    let messages = runtime.session().context_messages().unwrap();
    assert_eq!(messages[0].text_content(), "question");
    assert_eq!(messages[1].text_content(), "hello");
}

#[test]
fn a_denied_sh_call_is_returned_to_the_model() {
    let fixture = Fixture::new("deny");
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch must-not-exist"}"#),
        answer("understood"),
    ]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    runtime
        .turn("do it".to_string(), &mut FixedApproval(false), &mut |_| {
            Ok(())
        })
        .unwrap();
    assert!(!fixture.workspace.join("must-not-exist").exists());
    let messages = runtime.session().context_messages().unwrap();
    assert!(
        messages
            .iter()
            .any(|message| message.text_content().contains("denied"))
    );
}

#[test]
fn an_approved_sh_call_runs_in_the_workspace() {
    let fixture = Fixture::new("sh");
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"printf made > result.txt"}"#),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    runtime
        .turn("make it".to_string(), &mut FixedApproval(true), &mut |_| {
            Ok(())
        })
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("result.txt")).unwrap(),
        "made"
    );
}

#[test]
fn a_hook_can_register_authorize_and_execute_a_tool() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new("hook");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(
        &hook,
        r#"#!/bin/sh
test -z "$OPENROUTER_API_KEY" || exit 9
event=$(cat)
case "$event" in
  *'"event":"initialize"'*)
    printf '%s' '{"tools":[{"name":"echo_hook","description":"fixture","parameters":{"type":"object"}}],"state":{"ready":true}}'
    ;;
  *'"event":"permission"'*)
    printf '%s' '{"decision":"allow"}'
    ;;
  *'"event":"tool_execute"'*)
    printf '%s' '{"tool_result":{"content":"hook executed","is_error":false}}'
    ;;
  *)
    printf '%s' '{}'
    ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = Config::default();
    config.hooks.push(HookConfig {
        name: "fixture".to_string(),
        command: vec![hook.display().to_string()],
        timeout: Duration::from_secs(2),
        max_output_bytes: 64 * 1024,
    });
    let provider = Scripted::new(vec![tool("echo_hook", "{}"), answer("done")]);
    let mut runtime = fixture.runtime(provider, &config);
    runtime
        .turn("use hook".to_string(), &mut UnexpectedApproval, &mut |_| {
            Ok(())
        })
        .unwrap();
    assert!(
        runtime
            .session()
            .context_messages()
            .unwrap()
            .iter()
            .any(|message| message.text_content() == "hook executed")
    );
    assert_eq!(
        runtime.session().hook_state("fixture").unwrap()["ready"],
        true
    );
}

#[test]
fn manual_compaction_appends_a_checkpoint_without_deleting_history() {
    let fixture = Fixture::new("compact");
    let provider = Scripted::new(vec![
        answer(&"a".repeat(300)),
        answer(&"b".repeat(300)),
        answer(&"c".repeat(300)),
        answer("summary of prior work"),
    ]);
    let config = Config {
        context: ContextConfig {
            window_tokens: 10_000,
            output_reserve_tokens: 2_000,
            recent_tail_tokens: 50,
        },
        ..Config::default()
    };
    let mut runtime = fixture.runtime(provider.clone(), &config);
    for prompt in ["one", "two", "three"] {
        runtime
            .turn(prompt.to_string(), &mut FixedApproval(false), &mut |_| {
                Ok(())
            })
            .unwrap();
    }
    let entries_before = runtime.session().entries().len();
    runtime.compact(None, &mut |_| Ok(())).unwrap();
    assert!(runtime.session().entries().len() > entries_before);
    assert!(
        runtime.session().context_messages().unwrap()[0]
            .text_content()
            .contains("summary of prior work")
    );
    let requests = provider.requests.lock().unwrap();
    assert!(requests.last().unwrap().tools.is_empty());
}

#[test]
fn provider_failures_are_recorded() {
    let fixture = Fixture::new("error");
    let provider = Scripted::new(vec![Err(ProviderError::Unavailable(
        "scripted".to_string(),
    ))]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    assert!(
        runtime
            .turn(
                "question".to_string(),
                &mut FixedApproval(false),
                &mut |_| Ok(()),
            )
            .is_err()
    );
    assert!(
        runtime
            .session()
            .entries()
            .iter()
            .any(|entry| entry.kind == "turn_error")
    );
}

#[test]
fn resume_restores_context_model_and_cumulative_usage() {
    let fixture = Fixture::new("resume");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let first = Scripted::new(vec![priced_answer("first answer")]);
    let mut runtime = Runtime::new(
        first,
        store.clone(),
        session,
        &Config::default(),
        "test/one".to_string(),
    )
    .unwrap();
    runtime
        .turn(
            "first question".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap();
    let id = runtime.summary().id;
    drop(runtime);

    let session = store.open(&id).unwrap();
    let resumed_model = session.model().unwrap();
    let second = Scripted::new(vec![answer("second answer")]);
    let mut resumed = Runtime::new(
        second.clone(),
        store,
        session,
        &Config::default(),
        resumed_model,
    )
    .unwrap();
    assert_eq!(resumed.model(), "test/one");
    assert_eq!(resumed.usage().total_tokens(), 12);
    resumed
        .turn(
            "follow up".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap();
    let requests = second.requests.lock().unwrap();
    assert!(
        requests[0]
            .messages
            .iter()
            .any(|message| message.text_content() == "first answer")
    );
}

struct UntilCancelled;

impl Provider for UntilCancelled {
    fn complete(
        &self,
        _request: &Request,
        sink: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        loop {
            sink.on_event(StreamEvent::Text(".".to_string()))
                .map_err(|error| ProviderError::Aborted(error.to_string()))?;
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn cancellation_stops_a_streaming_turn_and_records_it() {
    let fixture = Fixture::new("cancel");
    let mut runtime = fixture.runtime(Arc::new(UntilCancelled), &Config::default());
    let cancellation = runtime.cancellation();
    let cancel = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        cancellation.cancel();
    });
    let error = runtime
        .turn(
            "keep going".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap_err();
    cancel.join().unwrap();
    assert!(error.contains("cancelled"));
    assert!(
        runtime
            .session()
            .entries()
            .iter()
            .any(|entry| { entry.kind == "turn_error" && entry.data["cancelled"] == true })
    );
}

#[test]
fn automatic_compaction_runs_before_an_oversized_follow_up() {
    let fixture = Fixture::new("automatic-compact");
    let provider = Scripted::new(vec![
        answer(&"large ".repeat(1_000)),
        answer("summary"),
        answer("after compaction"),
    ]);
    let config = Config {
        context: ContextConfig {
            window_tokens: 800,
            output_reserve_tokens: 200,
            recent_tail_tokens: 50,
        },
        ..Config::default()
    };
    let mut runtime = fixture.runtime(provider.clone(), &config);
    runtime
        .turn("first".to_string(), &mut FixedApproval(false), &mut |_| {
            Ok(())
        })
        .unwrap();
    runtime
        .turn(
            "follow up".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap();
    assert!(
        runtime
            .session()
            .entries()
            .iter()
            .any(|entry| entry.kind == "compaction")
    );
    assert_eq!(provider.requests.lock().unwrap().len(), 3);
}

#[test]
fn changed_hook_manifest_is_noticed_on_resume() {
    let fixture = Fixture::new("identity");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let runtime = Runtime::new(
        Scripted::new(Vec::new()),
        store.clone(),
        session,
        &Config::default(),
        "test/model".to_string(),
    )
    .unwrap();
    let id = runtime.summary().id;
    drop(runtime);

    let mut config = Config::default();
    config.hooks.push(HookConfig {
        name: "new_hook".to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "cat >/dev/null; printf '%s' '{}'".to_string(),
        ],
        timeout: Duration::from_secs(2),
        max_output_bytes: 4096,
    });
    let session = store.open(&id).unwrap();
    let mut resumed = Runtime::new(
        Scripted::new(Vec::new()),
        store,
        session,
        &config,
        "test/model".to_string(),
    )
    .unwrap();
    assert!(
        resumed
            .take_startup_notices()
            .iter()
            .any(|notice| notice.contains("resources changed"))
    );
}
