#![cfg(unix)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gears::config::{Config, ContextConfig, HookConfig, ToolDirectory};
use gears::mock::{MockServer, Script, sse_response};
use gears::net::EgressPolicy;
use gears::net::host_curl::HostCurl;
use gears::permissions::{Grant, Grants};
use gears::provider::{
    Completion, ContentBlock, Endpoint, EventSink, FinishReason, Message, OpenAiCompat, Provider,
    ProviderError, Quirks, Request, StreamEvent, ToolCall, ToolOutcome,
};
use gears::runtime::{Approval, Approver, Event, Options, Permission, Runtime};
use gears::session::{PermissionGrant, Store, ToolState};
use gears::tools::Registry;

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
    fn approve(&mut self, _request: &Permission) -> Approval {
        if self.0 {
            Approval::Once
        } else {
            Approval::Deny
        }
    }
}

/// Gives one fixed answer and counts how often the user was asked.
struct CountingApproval {
    answer: Approval,
    asked: usize,
}

impl Approver for CountingApproval {
    fn approve(&mut self, _request: &Permission) -> Approval {
        self.asked += 1;
        self.answer
    }
}

struct UnexpectedApproval;

impl Approver for UnexpectedApproval {
    fn approve(&mut self, _request: &Permission) -> Approval {
        panic!("permission hook should have allowed the call")
    }
}

struct UnattendedApproval;

impl Approver for UnattendedApproval {
    fn approve(&mut self, _request: &Permission) -> Approval {
        panic!("unattended run must not ask for approval")
    }

    fn attended(&self) -> bool {
        false
    }
}

struct QuestionApproval {
    answer: Option<String>,
    attended: bool,
    asked: usize,
}

impl Approver for QuestionApproval {
    fn attended(&self) -> bool {
        self.attended
    }
    fn approve(&mut self, _: &Permission) -> Approval {
        Approval::Deny
    }
    fn answer(&mut self, _: &gears::hooks::Question) -> Result<Option<String>, String> {
        assert!(self.attended, "unattended run asked a question");
        self.asked += 1;
        Ok(self.answer.clone())
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

#[test]
fn runtime_events_pair_tool_ids_and_report_numeric_usage() {
    let fixture = Fixture::new("structured-events");
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"printf forbidden"}"#),
        priced_answer("denied"),
    ]);
    let mut runtime = fixture.runtime(provider, &config);
    let mut events = Vec::new();
    runtime
        .turn("work".into(), &mut FixedApproval(false), &mut |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
    let started = events
        .iter()
        .find_map(|event| match event {
            Event::ToolStart { call_id, .. } => Some(call_id),
            _ => None,
        })
        .unwrap();
    assert_eq!(started, "call_1");
    let ended = events
        .iter()
        .find_map(|event| match event {
            Event::ToolEnd {
                call_id,
                outcome,
                is_error,
                ..
            } => Some((call_id, outcome, is_error)),
            _ => None,
        })
        .unwrap();
    assert_eq!(ended, (started, &ToolOutcome::NotStarted, &true));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Event::ToolOutput { .. }))
    );
    let usage = events
        .iter()
        .filter_map(|event| match event {
            Event::Usage { request, total } => Some((request, total)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(usage.len(), 2);
    assert_eq!(usage[1].0.total(), 12);
    assert_eq!(usage[1].1.completions, 2);
    assert_eq!(usage[1].1.total_tokens(), 12);
}

#[test]
fn compaction_reports_its_usage_as_a_numeric_event() {
    let fixture = Fixture::new("compaction-usage-event");
    let config = Config {
        context: ContextConfig {
            window_tokens: 10_000,
            output_reserve_tokens: 2_000,
            recent_tail_tokens: 50,
        },
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        priced_answer(&"a".repeat(300)),
        priced_answer(&"b".repeat(300)),
        priced_answer("summary"),
    ]);
    let mut runtime = fixture.runtime(provider, &config);
    for prompt in ["one", "two"] {
        runtime
            .turn(prompt.into(), &mut UnexpectedApproval, &mut |_| Ok(()))
            .unwrap();
    }
    let mut reported = Vec::new();
    runtime
        .compact(None, &mut |event| {
            if let Event::Usage { request, total } = event {
                reported.push((request, total));
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(reported.len(), 1);
    assert_eq!(reported[0].0.total(), 12);
    assert_eq!(reported[0].1.completions, 3);
    assert_eq!(reported[0].1.total_tokens(), 36);
}

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
}

#[test]
fn endlessly_repeated_hook_questions_are_reported_and_bounded() {
    let fixture = Fixture::new("question-bound");
    let log = fixture.root.join("answers.jsonl");
    let question = serde_json::json!({"question": {"id": "q", "text": "Again?", "choices": [
        {"value": "yes", "label": "Yes"}, {"value": "no", "label": "No"}]}});
    let config = Config {
        hooks: vec![HookConfig {
            name: "repeated".into(),
            events: Some(vec!["initialize".into(), "answer".into()]),
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    "event=$(cat); case \"$event\" in *'\"event\":\"answer\"'*) printf '%s\\n' \"$event\" >> \"$1\" ;; esac; printf '%s' '{question}'"
                ),
                "repeated".into(),
                log.display().to_string(),
            ],
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![answer("done")]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    let mut approver = QuestionApproval {
        answer: Some("yes".into()),
        attended: true,
        asked: 0,
    };
    let mut notices = Vec::new();
    runtime
        .turn("work".into(), &mut approver, &mut |event| {
            if let Event::Notice(text) = event {
                notices.push(text);
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(approver.asked, 16);
    assert_eq!(std::fs::read_to_string(log).unwrap().lines().count(), 16);
    assert!(
        notices
            .iter()
            .any(|text| text.contains("operation limit (16)"))
    );
    assert!(!runtime.pending_hook_questions());
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
}

#[test]
fn hook_questions_are_answered_before_requests_and_unattended_questions_are_skipped() {
    for (case, value, attended) in [
        ("answered", Some("yes"), true),
        ("unattended", None, false),
        ("skipped", None, true),
        ("invalid", Some("other"), true),
    ] {
        let fixture = Fixture::new(&format!("question-{case}"));
        let log = fixture.root.join("answer.json");
        let question = serde_json::json!({"question": {"id": "q1", "text": "Publish?",
            "choices": [{"value": "yes", "label": "Publish"}, {"value": "no", "label": "Discard"}]}});
        let response = serde_json::json!({"state": {"answered": true}, "context": Message::user("decision context")});
        let script = format!(
            "event=$(cat); case \"$event\" in *'\"event\":\"initialize\"'*) printf '%s' '{question}' ;; *) printf '%s' \"$event\" > \"$1\"; printf '%s' '{response}' ;; esac"
        );
        let config = Config {
            hooks: vec![HookConfig {
                name: "question".into(),
                events: Some(vec!["initialize".into(), "answer".into()]),
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    script,
                    "question".into(),
                    log.display().to_string(),
                ],
                timeout: Duration::from_secs(2),
                max_output_bytes: 4096,
            }],
            ..Config::default()
        };
        let provider = Scripted::new(vec![answer("done")]);
        let mut runtime = fixture.runtime(provider.clone(), &config);
        let mut approver = QuestionApproval {
            answer: value.map(str::to_string),
            attended,
            asked: 0,
        };
        let mut notices = Vec::new();
        runtime
            .turn("work".into(), &mut approver, &mut |event| {
                if let Event::Notice(text) = event {
                    notices.push(text);
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(approver.asked, usize::from(attended));
        let event: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(log).unwrap()).unwrap();
        assert_eq!(event["payload"]["attended"], attended);
        assert_eq!(
            event["payload"]["answer"],
            serde_json::json!(value.filter(|v| *v != "other"))
        );
        assert!(!runtime.pending_hook_questions());
        assert!(
            provider.requests.lock().unwrap()[0]
                .messages
                .iter()
                .any(|message| message.text_content() == "decision context")
        );
        assert_eq!(
            runtime.session().hook_state("question").unwrap()["answered"],
            true
        );
        if case == "invalid" {
            assert!(notices.iter().any(|text| text.contains("invalid choice")));
        }
    }
}

#[test]
fn hook_hints_follow_setup_turn_end_and_command_responses() {
    let fixture = Fixture::new("hook-hints");
    let config = Config {
        hooks: vec![HookConfig {
            name: "hint".into(),
            events: Some(vec!["initialize".into(), "turn_end".into(), "command".into()]),
            command: vec!["/bin/sh".into(), "-c".into(),
                "event=$(cat); case \"$event\" in *'\"event\":\"initialize\"'*) printf '{\"hint\":\"Ready\",\"commands\":[{\"name\":\"clear-hint\",\"help\":\"Clear hint\"}]}' ;; *'\"event\":\"turn_end\"'*) printf '{\"hint\":\"Review pending\"}' ;; *) printf '{\"hint\":\"\"}' ;; esac".into()],
            timeout: Duration::from_secs(2), max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let mut runtime = fixture.runtime(Scripted::new(vec![answer("done")]), &config);
    assert_eq!(runtime.hint(), Some("Ready"));
    let mut hints = Vec::new();
    let mut observer = |event| {
        if let Event::Hint(hint) = event {
            hints.push(hint);
        }
        Ok(())
    };
    runtime
        .turn("work".into(), &mut FixedApproval(false), &mut observer)
        .unwrap();
    assert_eq!(runtime.hint(), Some("Review pending"));
    runtime
        .hook_command("clear-hint", "", &mut observer)
        .unwrap();
    assert_eq!(runtime.hint(), None);
    assert_eq!(hints, [Some("Review pending".into()), None]);
    runtime.new_session(false, None).unwrap();
    runtime.take_startup_notices();
    assert_eq!(runtime.hint(), Some("Ready"));
}

#[test]
fn hook_commands_dispatch_to_the_owner_without_a_model_turn() {
    let fixture = Fixture::new("hook-command");
    let log = fixture.root.join("command.json");
    let config = Config {
        hooks: vec![HookConfig {
            name: "owner".into(), events: Some(vec!["initialize".into(), "command".into()]),
            command: vec!["/bin/sh".into(), "-c".into(),
                "event=$(cat); case \"$event\" in *'\"event\":\"initialize\"'*) printf '{\"commands\":[{\"name\":\"tasks\",\"help\":\"Show the task list\"}]}' ;; *) printf '%s' \"$event\" > \"$1\"; printf '{\"notice\":\"handled\",\"state\":{\"handled\":true}}' ;; esac".into(),
                "owner".into(), log.display().to_string()],
            timeout: Duration::from_secs(2), max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    assert_eq!(runtime.hook_commands()[0].name, "tasks");
    assert_eq!(runtime.hook_commands()[0].help, "Show the task list");
    runtime.set_interactive(true).unwrap();
    let argument = "literal 'focus' $HOME\nsecond line";
    let mut notices = Vec::new();
    runtime
        .hook_command("tasks", argument, &mut |event| {
            if let Event::Notice(text) = event {
                notices.push(text);
            }
            Ok(())
        })
        .unwrap();
    let event: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(log).unwrap()).unwrap();
    assert_eq!(event["event"], "command");
    assert_eq!(event["payload"]["name"], "tasks");
    assert_eq!(event["payload"]["argument"], argument);
    assert_eq!(
        runtime.session().hook_state("owner").unwrap()["handled"],
        true
    );
    assert!(notices.iter().any(|text| text.contains("handled")));
    runtime.new_session(false, None).unwrap();
    assert_eq!(runtime.hook_commands().len(), 1);
    assert!(
        runtime
            .hook_command("missing", "", &mut |_: Event| Ok(()))
            .unwrap_err()
            .contains("unknown command")
    );
    assert!(provider.requests.lock().unwrap().is_empty());
    assert!(runtime.session().context_messages().unwrap().is_empty());
}

#[test]
fn turn_end_metadata_counts_rounds_and_identifies_the_last_entry_on_all_exits() {
    for (case, responses, status, rounds, limit) in [
        ("chat", vec![answer("done")], "completed", 0, 32),
        (
            "tools",
            vec![
                Ok(Completion {
                    tool_calls: vec![
                        ToolCall::new("one", "sh", r#"{"command":"printf one"}"#),
                        ToolCall::new("two", "sh", r#"{"command":"printf two"}"#),
                    ],
                    ..Completion::default()
                }),
                answer("done"),
            ],
            "completed",
            1,
            32,
        ),
        (
            "error",
            vec![Err(ProviderError::Protocol("broken".into()))],
            "error",
            0,
            32,
        ),
        (
            "cancel",
            vec![Err(ProviderError::Aborted("cancelled".into()))],
            "cancelled",
            0,
            32,
        ),
        (
            "limit",
            vec![tool("sh", r#"{"command":"printf limited"}"#)],
            "error",
            1,
            1,
        ),
    ] {
        let fixture = Fixture::new(&format!("turn-end-{case}"));
        let log = fixture.root.join("event.json");
        let config = Config {
            hooks: vec![HookConfig {
                name: "end".into(),
                events: Some(vec!["turn_end".into()]),
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("cat > '{}'; printf '{{}}'", log.display()),
                ],
                timeout: Duration::from_secs(2),
                max_output_bytes: 4096,
            }],
            max_tool_rounds: limit,
            ..Config::default()
        };
        let mut runtime = fixture.runtime(Scripted::new(responses), &config);
        let mut end = None;
        let result = runtime.turn("work".into(), &mut FixedApproval(false), &mut |event| {
            if let Event::TurnEnd {
                status,
                tool_rounds,
                last_entry_id,
            } = event
            {
                end = Some((status, tool_rounds, last_entry_id));
            }
            Ok(())
        });
        assert_eq!(result.is_ok(), status == "completed", "{case}: {result:?}");
        let id = runtime.session().active_leaf().unwrap();
        assert_eq!(end, Some((status, rounds, Some(id.to_string()))));
        let event: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(log).unwrap()).unwrap();
        assert_eq!(event["payload"]["status"], status);
        assert_eq!(event["payload"]["tool_rounds"], rounds);
        assert_eq!(event["payload"]["last_entry_id"], id);
        assert!(runtime.session().entry(id).is_some());
    }
}

#[test]
fn entry_hooks_identify_saved_outcomes_and_read_only_tools_even_when_not_started() {
    for allow in [false, true] {
        let fixture = Fixture::new(&format!("tool-entry-{allow}"));
        let log = fixture.root.join("events.jsonl");
        std::fs::write(fixture.workspace.join("source"), "fixture text").unwrap();
        let config = Config {
            tools: ["sh", "cat"]
                .into_iter()
                .map(|name| ToolDirectory {
                    directory: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("tools")
                        .join(name),
                    enabled: true,
                })
                .collect(),
            hooks: vec![HookConfig {
                name: "record".into(),
                events: Some(vec!["entry".into(), "permission".into()]),
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!(
                        "cat >> '{}'; printf '\\n' >> '{}'; printf '{{}}'",
                        log.display(),
                        log.display()
                    ),
                ],
                timeout: Duration::from_secs(2),
                max_output_bytes: 4096,
            }],
            ..Config::default()
        };
        let calls = vec![
            ToolCall::new("write", "sh", r#"{"command":"printf output"}"#),
            ToolCall::new("read", "cat", r#"{"path":"source"}"#),
            ToolCall::new("unknown", "missing", "{}"),
        ];
        let provider = Scripted::new(vec![
            Ok(Completion {
                tool_calls: calls.clone(),
                ..Completion::default()
            }),
            answer("done"),
        ]);
        let mut runtime = fixture.runtime(provider, &config);
        runtime
            .turn("work".into(), &mut FixedApproval(allow), &mut |_| Ok(()))
            .unwrap();
        let events: Vec<serde_json::Value> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let permissions: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "permission")
            .collect();
        assert_eq!(permissions.len(), 2);
        assert_eq!(permissions[0]["payload"]["tool"]["read_only"], false);
        assert_eq!(permissions[1]["payload"]["tool"]["read_only"], true);
        let shell = PathBuf::from(
            permissions[0]["payload"]["tool"]["shell_state_directory"]
                .as_str()
                .unwrap(),
        );
        assert_eq!(
            shell,
            runtime.session().path().unwrap().with_extension("sh-state")
        );
        assert!(permissions[1]["payload"]["tool"]["shell_state_directory"].is_null());
        if allow {
            assert_eq!(
                std::fs::read_to_string(shell.join("cwd"))
                    .unwrap()
                    .trim_end(),
                fixture.workspace.to_str().unwrap()
            );
        } else {
            assert!(
                !shell.exists(),
                "permission metadata must not create shell state"
            );
        }
        let entries: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "entry" && event["payload"]["role"] == "tool")
            .collect();
        assert_eq!(entries.len(), calls.len());
        for (index, event) in entries.iter().enumerate() {
            let payload = &event["payload"];
            assert_eq!(
                payload["tool_call"],
                serde_json::to_value(&calls[index]).unwrap()
            );
            assert_eq!(payload["tool"]["read_only"], index == 1);
            assert_eq!(
                payload["outcome"],
                if allow && index < 2 {
                    "completed"
                } else {
                    "not_started"
                }
            );
            let entry = runtime
                .session()
                .entry(payload["id"].as_str().unwrap())
                .unwrap();
            let message: Message = serde_json::from_value(entry.data.clone()).unwrap();
            assert_eq!(payload["tool_result"]["content"], message.text_content());
            assert_eq!(payload["tool_result_truncated"], false);
        }
    }
}

#[test]
fn entry_hooks_bound_unicode_text_without_truncating_the_saved_result() {
    let fixture = Fixture::new("bounded-tool-entry");
    let log = fixture.root.join("event.json");
    let result = fixture.root.join("result.json");
    let text = format!("x{}", "🦀".repeat(20_000));
    std::fs::write(
        &result,
        serde_json::json!({"tool_result": {
            "content": text, "is_error": false,
        }})
        .to_string(),
    )
    .unwrap();
    let config = Config {
        hooks: vec![HookConfig {
            name: "record".into(),
            events: Some(vec![
                "initialize".into(),
                "tool_execute".into(),
                "entry".into(),
            ]),
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    r#"body=$(cat)
case "$body" in
  *'"event":"initialize"'*) printf '%s' '{{"tools":[{{"name":"large","description":"fixture","parameters":{{"type":"object"}}}}]}}';;
  *'"event":"tool_execute"'*) cat '{}';;
  *'"role":"tool"'*) printf '%s' "$body" > '{}'; printf '{{}}';;
  *) printf '{{}}';;
esac"#,
                    result.display(),
                    log.display()
                ),
            ],
            timeout: Duration::from_secs(2),
            max_output_bytes: 128 * 1024,
        }],
        ..Config::default()
    };
    let mut runtime = fixture.runtime(
        Scripted::new(vec![tool("large", "{}"), answer("done")]),
        &config,
    );
    runtime
        .turn("work".into(), &mut FixedApproval(true), &mut |_| Ok(()))
        .unwrap();
    let event: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(log).unwrap()).unwrap();
    let payload = &event["payload"];
    let clipped = payload["tool_result"]["content"].as_str().unwrap();
    assert!(clipped.len() <= 64 * 1024);
    assert_eq!(payload["tool_result_truncated"], true);
    assert!(text.starts_with(clipped));
    let entry = runtime
        .session()
        .entry(payload["id"].as_str().unwrap())
        .unwrap();
    let saved: Message = serde_json::from_value(entry.data.clone()).unwrap();
    assert_eq!(saved.text_content(), text);
}

#[test]
fn hook_details_reach_the_permission_prompt_and_invalid_details_deny_the_call() {
    struct Capture(Vec<String>);
    impl Approver for Capture {
        fn approve(&mut self, permission: &Permission) -> Approval {
            self.0.push(permission.detail.clone());
            Approval::Once
        }
    }
    for (case, detail, valid) in [
        (
            "valid",
            "declared check: [\"/bin/check\",\"a file*\"]".into(),
            true,
        ),
        ("empty", String::new(), false),
        ("large", "x".repeat(16385), false),
    ] {
        let fixture = Fixture::new(&format!("permission-detail-{case}"));
        let response = fixture.root.join("response.json");
        std::fs::write(
            &response,
            serde_json::json!({"decision": "confirm", "permission_detail": detail}).to_string(),
        )
        .unwrap();
        let config = Config {
            hooks: vec![HookConfig {
                name: "policy".into(),
                events: Some(vec!["permission".into()]),
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("cat > /dev/null; cat '{}'", response.display()),
                ],
                timeout: Duration::from_secs(2),
                max_output_bytes: 32 * 1024,
            }],
            ..Config::default()
        };
        let mut runtime = fixture.runtime(
            Scripted::new(vec![
                tool("sh", r#"{"command":"printf result"}"#),
                answer("done"),
            ]),
            &config,
        );
        let mut approver = Capture(Vec::new());
        let mut shown = Vec::new();
        let mut outcome = None;
        runtime
            .turn("work".into(), &mut approver, &mut |event| {
                match event {
                    Event::Permission(permission) => shown.push(permission.detail),
                    Event::ToolEnd {
                        outcome: recorded, ..
                    } => outcome = Some(recorded),
                    _ => {}
                }
                Ok(())
            })
            .unwrap();
        if valid {
            assert_eq!(approver.0, shown);
            assert!(shown[0].contains(&format!("policy: {detail}")));
            assert_eq!(outcome, Some(ToolOutcome::Completed));
        } else {
            assert!(approver.0.is_empty());
            assert_eq!(outcome, Some(ToolOutcome::NotStarted));
        }
    }
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
        let mut config = config.clone();
        if config.tools.is_empty() {
            config.tools.push(ToolDirectory {
                directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
                enabled: true,
            });
        }
        Runtime::new(provider, store, session, &config, "test/model".to_string()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn reset_removes_what_the_user_added_and_continues_with_the_configured_tools() {
    let fixture = Fixture::new("reset");
    let global = fixture.root.join("global");
    let store = Store::with_root(&fixture.workspace, global.join("sessions")).unwrap();
    let session = store.create(false, None).unwrap();
    let old = session.path().unwrap().to_path_buf();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: false,
        }],
        ..Config::default()
    };
    let mut runtime = Runtime::with_options(
        Scripted::new(vec![]),
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(Registry::load_config(&config).unwrap()),
            tool_state_directory: Some(global.clone()),
        },
    )
    .unwrap();
    runtime
        .set_tool_state("sh", ToolState::Enabled, true)
        .unwrap();
    assert!(runtime.tool_statuses().unwrap()[0].enabled);
    std::fs::write(global.join("gears.toml"), "version = 1\n").unwrap();
    std::fs::write(global.join("local.key"), "key").unwrap();
    std::fs::create_dir_all(fixture.workspace.join(".gears")).unwrap();
    std::fs::write(fixture.workspace.join(".gears/MEMORY.md"), "fact").unwrap();
    runtime.reset().unwrap();
    assert!(global.join("gears.toml").is_file());
    assert!(!global.join("local.key").exists());
    assert!(!global.join("tools.toml").exists());
    assert!(!old.exists());
    assert!(!fixture.workspace.join(".gears").exists());
    assert!(runtime.session().path().unwrap().is_file());
    assert!(!runtime.tool_statuses().unwrap()[0].enabled);
}

#[test]
fn tool_toggles_update_the_next_request_and_preserve_scope_precedence() {
    let fixture = Fixture::new("tool-toggles");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let registry = Registry::load_config(&config).unwrap();
    let provider = Scripted::new(vec![answer("one"), answer("two"), answer("three")]);
    let mut runtime = Runtime::with_options(
        provider.clone(),
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(registry),
            tool_state_directory: Some(fixture.root.join("global")),
        },
    )
    .unwrap();
    runtime
        .turn("first".into(), &mut FixedApproval(false), &mut |_| Ok(()))
        .unwrap();
    let enabled_identity = runtime.session().latest_runtime_identity().unwrap();
    runtime
        .set_tool_state("sh", ToolState::Disabled, false)
        .unwrap();
    runtime
        .turn("second".into(), &mut FixedApproval(false), &mut |_| Ok(()))
        .unwrap();
    let disabled_identity = runtime.session().latest_runtime_identity().unwrap();
    runtime
        .set_tool_state("sh", ToolState::Enabled, true)
        .unwrap();
    assert_eq!(runtime.tool_statuses().unwrap()[0].source, "session");
    assert!(!runtime.tool_statuses().unwrap()[0].enabled);
    runtime
        .set_tool_state("sh", ToolState::Inherit, false)
        .unwrap();
    assert_eq!(runtime.tool_statuses().unwrap()[0].source, "global");
    runtime
        .turn("third".into(), &mut FixedApproval(false), &mut |_| Ok(()))
        .unwrap();
    let requests = provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].tools.iter().any(|spec| spec.name == "sh"));
    assert!(!requests[1].tools.iter().any(|spec| spec.name == "sh"));
    assert!(requests[2].tools.iter().any(|spec| spec.name == "sh"));
    assert_ne!(
        enabled_identity.manifest_hash,
        disabled_identity.manifest_hash
    );
    assert_eq!(
        enabled_identity.manifest_hash,
        runtime
            .session()
            .latest_runtime_identity()
            .unwrap()
            .manifest_hash
    );
}

#[test]
fn permission_listing_marks_stale_grants_and_revoke_clears_each_scope() {
    let fixture = Fixture::new("permission-listing");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let mut session = store.create(false, None).unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let registry = Registry::load_config(&config).unwrap();
    let identity = registry.tools()[0].approval_identity().unwrap();
    session
        .append_permission_grant(&PermissionGrant {
            name: "sh".into(),
            identity: identity.clone(),
            allow: Some(false),
            ..PermissionGrant::default()
        })
        .unwrap();
    let global_dir = fixture.root.join("global");
    let mut global = Grants::default();
    global.by_identity.insert(
        "a".repeat(64),
        Grant {
            name: "sh".into(),
            allow: true,
            ..Grant::default()
        },
    );
    global.save(&global_dir).unwrap();
    let mut runtime = Runtime::with_options(
        Scripted::new(Vec::new()),
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(registry),
            tool_state_directory: Some(global_dir),
        },
    )
    .unwrap();
    let listed = runtime.permission_statuses().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(
        listed
            .iter()
            .any(|grant| grant.scope == "session" && grant.current && !grant.allow)
    );
    assert!(
        listed
            .iter()
            .any(|grant| grant.scope == "global" && !grant.current && grant.allow)
    );
    runtime.revoke_permission("sh", false).unwrap();
    assert_eq!(runtime.permission_statuses().unwrap().len(), 1);
    runtime.revoke_permission("sh", true).unwrap();
    assert!(runtime.permission_statuses().unwrap().is_empty());
}

#[test]
fn a_missing_executable_does_not_prevent_listing_or_revoking_grants() {
    let fixture = Fixture::new("missing-grant-executable");
    let directory = fixture.root.join("package");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("parameters.json"), r#"{"type":"object"}"#).unwrap();
    std::fs::write(directory.join("run"), "#!/bin/sh\nprintf original\n").unwrap();
    std::fs::write(
        directory.join("tool.toml"),
        r#"
version = 1
kind = "process"
name = "package"
description = "Fixture"
parameters = "parameters.json"
[process.command]
common = ["./run"]
"#,
    )
    .unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: directory.clone(),
            enabled: true,
        }],
        ..Config::default()
    };
    let registry = Registry::load_config(&config).unwrap();
    let identity = registry.tools()[0].approval_identity().unwrap();
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let mut session = store.create(false, None).unwrap();
    session
        .append_permission_grant(&PermissionGrant {
            name: "package".into(),
            identity,
            allow: Some(true),
            ..PermissionGrant::default()
        })
        .unwrap();
    let mut runtime = Runtime::with_options(
        Scripted::new(Vec::new()),
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(registry),
            tool_state_directory: Some(fixture.root.join("global")),
        },
    )
    .unwrap();
    std::fs::remove_file(directory.join("run")).unwrap();
    let listed = runtime.permission_statuses().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].current);
    assert!(
        listed[0]
            .identity_error
            .as_ref()
            .unwrap()
            .contains("executable disappeared")
    );
    runtime.revoke_permission("package", false).unwrap();
    assert!(runtime.permission_statuses().unwrap().is_empty());
}

#[test]
fn global_allow_survives_new_sessions_but_not_unattended_calls() {
    let fixture = Fixture::new("global-allow-unattended");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let registry = Registry::load_config(&config).unwrap();
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch first"}"#),
        answer("done"),
        tool("sh", r#"{"command":"touch unattended"}"#),
        answer("done"),
        tool("sh", r#"{"command":"touch third"}"#),
        answer("done"),
    ]);
    let mut runtime = Runtime::with_options(
        provider,
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(registry),
            tool_state_directory: Some(fixture.root.join("global")),
        },
    )
    .unwrap();
    let mut grant = CountingApproval {
        answer: Approval::Global,
        asked: 0,
    };
    runtime
        .turn("first".into(), &mut grant, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(grant.asked, 1);
    let saved = Grants::load(&fixture.root.join("global")).unwrap();
    let saved = saved.by_identity.values().next().unwrap();
    assert_eq!(saved.kind, "process");
    assert!(saved.owner.ends_with("tools/sh"));
    assert!(saved.created_ms > 0);
    runtime.new_session(false, None).unwrap();
    runtime
        .turn("second".into(), &mut UnattendedApproval, &mut |_| Ok(()))
        .unwrap();
    let mut deny = CountingApproval {
        answer: Approval::Deny,
        asked: 0,
    };
    runtime
        .turn("third".into(), &mut deny, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(deny.asked, 0);
    assert!(fixture.workspace.join("first").exists());
    assert!(!fixture.workspace.join("unattended").exists());
    assert!(fixture.workspace.join("third").exists());
}

#[test]
fn failed_global_grant_write_keeps_the_pending_tool_unapproved() {
    struct BreakGrantFile(PathBuf);
    impl Approver for BreakGrantFile {
        fn approve(&mut self, _request: &Permission) -> Approval {
            std::fs::create_dir(self.0.join("permissions.toml")).unwrap();
            Approval::Global
        }
    }

    let fixture = Fixture::new("grant-write-failure");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let registry = Registry::load_config(&config).unwrap();
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch forbidden"}"#),
        answer("done"),
    ]);
    let global_dir = fixture.root.join("global");
    std::fs::create_dir(&global_dir).unwrap();
    let mut runtime = Runtime::with_options(
        provider,
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(registry),
            tool_state_directory: Some(global_dir.clone()),
        },
    )
    .unwrap();
    runtime
        .turn("try".into(), &mut BreakGrantFile(global_dir), &mut |_| {
            Ok(())
        })
        .unwrap();
    assert!(!fixture.workspace.join("forbidden").exists());
    assert!(
        runtime
            .session()
            .context_messages()
            .unwrap()
            .iter()
            .any(|message| message.text_content().contains("unsafe state entry"))
    );
}

#[test]
fn session_answers_override_global_answers_in_both_directions() {
    for session_allow in [true, false] {
        let fixture = Fixture::new(if session_allow {
            "session-allow"
        } else {
            "session-deny"
        });
        let config = Config {
            tools: vec![ToolDirectory {
                directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
                enabled: true,
            }],
            ..Config::default()
        };
        let registry = Registry::load_config(&config).unwrap();
        let identity = registry.tools()[0].approval_identity().unwrap();
        let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
        let mut session = store.create(false, None).unwrap();
        session
            .append_permission_grant(&PermissionGrant {
                name: "sh".into(),
                identity: identity.clone(),
                allow: Some(session_allow),
                ..PermissionGrant::default()
            })
            .unwrap();
        let global_dir = fixture.root.join("global");
        let mut global = Grants::default();
        global.by_identity.insert(
            identity,
            Grant {
                name: "sh".into(),
                allow: !session_allow,
                ..Grant::default()
            },
        );
        global.save(&global_dir).unwrap();
        let provider = Scripted::new(vec![
            tool("sh", r#"{"command":"printf made > result"}"#),
            answer("done"),
        ]);
        let mut runtime = Runtime::with_options(
            provider,
            store,
            session,
            &config,
            "test/model".into(),
            Options {
                tools: Some(registry),
                tool_state_directory: Some(global_dir),
            },
        )
        .unwrap();
        runtime
            .turn("go".into(), &mut UnexpectedApproval, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(fixture.workspace.join("result").exists(), session_allow);
    }
}

#[test]
fn an_executable_change_invalidates_a_session_allow_before_the_next_call() {
    // Parallel spawns can inherit a writable copy of the fixture executable until
    // exec, making its own exec fail with ETXTBSY. Run alone in a child process.
    const CHILD: &str = "GEARS_EXECUTABLE_CHANGE_FIXTURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .args([
                "--exact",
                "an_executable_change_invalidates_a_session_allow_before_the_next_call",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new("executable-grant-change");
    let directory = fixture.root.join("package");
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("run");
    std::fs::write(&executable, "#!/bin/sh\nprintf original\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(directory.join("parameters.json"), r#"{"type":"object"}"#).unwrap();
    std::fs::write(
        directory.join("tool.toml"),
        r#"
version = 1
kind = "process"
name = "package"
description = "Fixture"
parameters = "parameters.json"
[process.command]
common = ["./run"]
"#,
    )
    .unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory,
            enabled: true,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool("package", "{}"),
        tool("package", "{}"),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider, &config);
    let mut asked = 0;
    let mut approver = |_: &Permission| {
        asked += 1;
        if asked == 1 {
            Approval::Session
        } else {
            Approval::Deny
        }
    };
    let mut output = String::new();
    let mut completed = 0;
    runtime
        .turn("go".into(), &mut approver, &mut |event| {
            if let Event::ToolOutput { ref text, .. } = event {
                output.push_str(text);
            }
            if let Event::ToolEnd {
                is_error: false, ..
            } = event
            {
                completed += 1;
                std::fs::write(&executable, "#!/bin/sh\nprintf changed\n").unwrap();
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(asked, 2);
    assert_eq!(completed, 1);
    assert_eq!(output, "original");
    assert!(!runtime.permission_statuses().unwrap()[0].current);
}

#[test]
fn global_denial_persists_and_refuses_later_attended_calls() {
    let fixture = Fixture::new("global-denial");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let registry = Registry::load_config(&config).unwrap();
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch first"}"#),
        answer("done"),
        tool("sh", r#"{"command":"touch second"}"#),
        answer("done"),
    ]);
    let global_dir = fixture.root.join("global");
    let mut runtime = Runtime::with_options(
        provider,
        store,
        session,
        &config,
        "test/model".into(),
        Options {
            tools: Some(registry),
            tool_state_directory: Some(global_dir.clone()),
        },
    )
    .unwrap();
    let mut deny = CountingApproval {
        answer: Approval::DenyGlobal,
        asked: 0,
    };
    runtime
        .turn("first".into(), &mut deny, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(deny.asked, 1);
    assert!(
        !Grants::load(&global_dir)
            .unwrap()
            .by_identity
            .values()
            .next()
            .unwrap()
            .allow
    );
    runtime.new_session(false, None).unwrap();
    let mut allow = CountingApproval {
        answer: Approval::Once,
        asked: 0,
    };
    runtime
        .turn("second".into(), &mut allow, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(allow.asked, 0);
    assert!(!fixture.workspace.join("first").exists());
    assert!(!fixture.workspace.join("second").exists());
}

#[test]
fn empty_tool_configuration_is_chat_only() {
    let fixture = Fixture::new("chat-only");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.create(false, None).unwrap();
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch must-not-exist"}"#),
        answer("done"),
    ]);
    let mut runtime = Runtime::new(
        provider.clone(),
        store,
        session,
        &Config::default(),
        "test/model".to_string(),
    )
    .unwrap();
    runtime
        .turn(
            "hello".to_string(),
            &mut UnexpectedApproval,
            &mut |_| Ok(()),
        )
        .unwrap();
    let requests = provider.requests.lock().unwrap();
    assert!(requests[0].tools.is_empty());
    assert!(
        requests[1]
            .messages
            .iter()
            .any(|message| message.text_content().contains("unknown or disabled tool"))
    );
    assert!(!fixture.workspace.join("must-not-exist").exists());
}

#[test]
fn configured_directory_tool_is_advertised_and_executed() {
    let fixture = Fixture::new("directory-tool");
    let directory = fixture.root.join("print-tool");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("parameters.json"),
        r#"{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}"#,
    )
    .unwrap();
    std::fs::write(
        directory.join("tool.toml"),
        r#"
version = 1
kind = "process"
name = "print"
description = "Print one string"
parameters = "parameters.json"
display = "{text}"
read_only = true
[process]
output = "stdout"
[process.command]
common = ["/usr/bin/printf", "%s"]
[process.arguments]
after_double_dash = ["text"]
[process.arguments.text]
type = "string"
"#,
    )
    .unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: directory.clone(),
            enabled: true,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool("print", r#"{"text":"two words"}"#),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    let mut output = String::new();
    let mut detail = String::new();
    runtime
        .turn(
            "print".to_string(),
            &mut FixedApproval(true),
            &mut |event| {
                match event {
                    Event::ToolOutput { name, text, .. } => {
                        assert_eq!(name, "print");
                        output.push_str(&text);
                    }
                    Event::Permission(permission) => detail = permission.detail,
                    _ => {}
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(output, "two words");
    assert_eq!(detail, "\"two words\"");
    let requests = provider.requests.lock().unwrap();
    assert!(requests[0].tools.iter().any(|spec| spec.name == "print"));
    assert!(
        requests[1]
            .messages
            .iter()
            .any(|message| message.text_content() == "two words")
    );
    drop(requests);

    let provider = Scripted::new(vec![tool("print", "{}"), answer("done")]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    runtime
        .turn(
            "print".to_string(),
            &mut UnexpectedApproval,
            &mut |_| Ok(()),
        )
        .unwrap();
    assert!(
        provider.requests.lock().unwrap()[1]
            .messages
            .iter()
            .any(|message| message.text_content().contains("display needs argument"))
    );

    let mut disabled = config;
    disabled.tools[0].enabled = false;
    let provider = Scripted::new(vec![tool("print", r#"{"text":"not run"}"#), answer("done")]);
    let mut runtime = fixture.runtime(provider.clone(), &disabled);
    runtime
        .turn(
            "print".to_string(),
            &mut UnexpectedApproval,
            &mut |_| Ok(()),
        )
        .unwrap();
    let requests = provider.requests.lock().unwrap();
    assert!(!requests[0].tools.iter().any(|spec| spec.name == "print"));
    assert!(
        requests[1]
            .messages
            .iter()
            .any(|message| message.text_content().contains("unknown or disabled tool"))
    );
}

#[test]
fn shipped_sh_tool_runs_from_its_directory() {
    let fixture = Fixture::new("shipped-sh");
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool(
            "sh",
            r#"{"command":"test -d \"$GEARS_SH_STATE_DIR\" && printf made > result.txt"}"#,
        ),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    runtime
        .turn("make it".to_string(), &mut FixedApproval(true), &mut |_| {
            Ok(())
        })
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("result.txt")).unwrap(),
        "made"
    );
    assert!(
        runtime
            .session()
            .path()
            .unwrap()
            .with_extension("sh-state")
            .is_dir()
    );
    let requests = provider.requests.lock().unwrap();
    assert_eq!(
        requests[0]
            .tools
            .iter()
            .filter(|spec| spec.name == "sh")
            .count(),
        1
    );
}

#[test]
fn shipped_sh_restores_directory_and_exports_after_resume() {
    let fixture = Fixture::new("sh-state-resume");
    std::fs::create_dir(fixture.workspace.join("nested")).unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool(
            "sh",
            r#"{"command":"cd nested && export SH_TEST_VALUE='two words'"}"#,
        ),
        tool(
            "sh",
            r#"{"command":"printf '%s' \"$SH_TEST_VALUE\" > first.txt"}"#,
        ),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider, &config);
    runtime
        .turn(
            "set state".to_string(),
            &mut FixedApproval(true),
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("nested/first.txt")).unwrap(),
        "two words"
    );
    let path = runtime.session().path().unwrap().to_path_buf();
    let state = path.with_extension("sh-state");
    let exports = std::fs::read_to_string(state.join("env.sh")).unwrap();
    assert!(!exports.lines().any(|line| line.contains(" GEARS_")));
    assert!(!exports.lines().any(|line| line.contains(" PATH=")));
    drop(runtime);

    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let session = store.open_path(&path).unwrap();
    let provider = Scripted::new(vec![
        tool(
            "sh",
            r#"{"command":"printf '%s' \"$SH_TEST_VALUE\" > resumed.txt"}"#,
        ),
        answer("done"),
    ]);
    let mut resumed =
        Runtime::new(provider, store, session, &config, "test/model".to_string()).unwrap();
    resumed
        .turn(
            "use state".to_string(),
            &mut FixedApproval(true),
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("nested/resumed.txt")).unwrap(),
        "two words"
    );
}

#[test]
fn shipped_sh_uses_a_bounded_per_call_timeout() {
    let fixture = Fixture::new("sh-call-timeout");
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"export SH_TEST_VALUE=kept"}"#),
        tool(
            "sh",
            r#"{"command":"printf bad > unstarted.txt","timeout":121}"#,
        ),
        tool(
            "sh",
            r#"{"command":"export SH_TEST_VALUE=lost; sleep 5","timeout":1}"#,
        ),
        tool(
            "sh",
            r#"{"command":"printf '%s' \"$SH_TEST_VALUE\" > state.txt"}"#,
        ),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider, &config);
    runtime
        .turn("run".to_string(), &mut FixedApproval(true), &mut |_| Ok(()))
        .unwrap();
    assert!(!fixture.workspace.join("unstarted.txt").exists());
    assert_eq!(
        std::fs::read_to_string(fixture.workspace.join("state.txt")).unwrap(),
        "kept"
    );
    let results = runtime
        .session()
        .context_messages()
        .unwrap()
        .into_iter()
        .flat_map(|message| message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult { content, .. } => Some(content),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        results
            .iter()
            .any(|result| result.contains("between 1 and 120 seconds"))
    );
    assert!(
        results
            .iter()
            .any(|result| result.contains("timed out after 1s"))
    );
}

/// Run shipped tool `name` once per argument object in one turn, collecting its output.
fn run_shipped(fixture: &Fixture, name: &str, calls: &[&str]) -> (String, Runtime) {
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tools")
                .join(name),
            enabled: true,
        }],
        ..Config::default()
    };
    let mut script: Vec<_> = calls.iter().map(|call| tool(name, call)).collect();
    script.push(answer("done"));
    let mut runtime = fixture.runtime(Scripted::new(script), &config);
    let mut output = String::new();
    runtime
        .turn("use it".into(), &mut FixedApproval(true), &mut |event| {
            if let Event::ToolOutput { text, .. } = event {
                output.push_str(&text);
            }
            Ok(())
        })
        .unwrap();
    (output, runtime)
}

#[test]
fn shipped_read_tools_pass_spaces_globs_and_leading_dashes_literally() {
    // Tool, workspace files, argument objects, and what the output must show.
    type Case<'a> = (
        &'a str,
        &'a [(&'a str, &'a str)],
        &'a [&'a str],
        fn(&str) -> bool,
    );
    let lines = [("-input [glob].txt", "first\nsecond\nthird\n")];
    let limited = [r#"{"lines":2,"path":"-input [glob].txt"}"#];
    let cases: [Case; 6] = [
        (
            "ls",
            &[
                ("dir with spaces/literal[?].txt", "data"),
                ("-lh/marker.txt", "data"),
            ],
            &[r#"{"path":"dir with spaces"}"#, r#"{"path":"-lh"}"#],
            |out| out.contains("literal[?].txt") && out.contains("marker.txt"),
        ),
        ("head", &lines, &limited, |out| out == "first\nsecond\n"),
        ("tail", &lines, &limited, |out| out == "second\nthird\n"),
        (
            "wc",
            &[("-count [glob].txt", "one\ntwo\n")],
            &[r#"{"mode":"lines","path":"-count [glob].txt"}"#],
            |out| out.trim_start().starts_with("2 ") && out.contains("-count [glob].txt"),
        ),
        (
            "cat",
            &[("-read [glob].txt", "literal contents\n")],
            &[r#"{"path":"-read [glob].txt"}"#],
            |out| out == "literal contents\n",
        ),
        (
            "find",
            &[
                ("dir [glob]/wanted file.txt", "yes"),
                ("dir [glob]/other.txt", "no"),
            ],
            &[r#"{"path":"dir [glob]","name":"wanted*","type":"file"}"#],
            |out| out.contains("dir [glob]/wanted file.txt") && !out.contains("other.txt"),
        ),
    ];
    for (name, files, calls, check) in cases {
        let fixture = Fixture::new(&format!("shipped-{name}"));
        for (path, text) in files {
            let path = fixture.workspace.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let (output, _) = run_shipped(&fixture, name, calls);
        assert!(check(&output), "{name}: {output}");
    }
}

#[test]
fn shipped_curl_returns_headers_without_following_redirects() {
    let server = MockServer::start(vec![
        Script::new().write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"),
        Script::new().write(b"HTTP/1.1 302 Found\r\nLocation: /destination\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    ])
    .unwrap();
    let fixture = Fixture::new("shipped-curl");
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/curl"),
            enabled: true,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool(
            "curl",
            &serde_json::json!({"url": server.url("/ok")}).to_string(),
        ),
        tool(
            "curl",
            &serde_json::json!({"url": server.url("/redirect")}).to_string(),
        ),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider, &config);
    let mut output = String::new();
    runtime
        .turn(
            "fetch".to_string(),
            &mut FixedApproval(true),
            &mut |event| {
                if let Event::ToolOutput { name, text, .. } = event {
                    assert_eq!(name, "curl");
                    output.push_str(&text);
                }
                Ok(())
            },
        )
        .unwrap();
    assert!(
        output.contains("HTTP/1.1 200 OK") && output.contains("hello"),
        "{output}"
    );
    assert!(
        output.contains("HTTP/1.1 302 Found") && output.contains("Location: /destination"),
        "{output}"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, "/ok");
    assert_eq!(requests[1].target, "/redirect");
}

#[test]
fn shipped_diff_treats_differences_as_a_normal_result() {
    let fixture = Fixture::new("shipped-diff");
    std::fs::write(fixture.workspace.join("old [file].txt"), "old\n").unwrap();
    std::fs::write(fixture.workspace.join("new [file].txt"), "new\n").unwrap();
    let (_, runtime) = run_shipped(
        &fixture,
        "diff",
        &[
            r#"{"left":"old [file].txt","right":"new [file].txt"}"#,
            r#"{"left":"old [file].txt","right":"missing"}"#,
        ],
    );
    let results = runtime
        .session()
        .context_messages()
        .unwrap()
        .into_iter()
        .flat_map(|message| message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult {
                tool_name,
                content,
                is_error,
                ..
            } if tool_name == "diff" => Some((content, is_error)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 2);
    assert!(!results[0].1, "{}", results[0].0);
    assert!(results[0].0.contains("old") && results[0].0.contains("new"));
    assert!(results[1].1);
    assert!(results[1].0.contains("exit status 2"), "{}", results[1].0);
}

#[test]
fn shipped_sed_maps_script_and_literal_path_without_a_shell() {
    let fixture = Fixture::new("shipped-sed");
    let path = fixture.workspace.join("a * b.txt");
    std::fs::write(&path, "first line\n").unwrap();
    let (output, _) = run_shipped(
        &fixture,
        "sed",
        &[r#"{"script":"s/first/second/","path":"a * b.txt"}"#],
    );
    assert!(output.contains("second line"), "{output}");
    assert_eq!(std::fs::read_to_string(path).unwrap(), "first line\n");
}

#[cfg(unix)]
#[test]
fn shipped_lorry_is_listed_but_unavailable_on_linux() {
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/lorry"),
            enabled: true,
        }],
        ..Config::default()
    };
    let registry = Registry::load_config(&config).unwrap();
    assert_eq!(registry.tools()[0].name, "lorry");
    assert!(!registry.tools()[0].read_only);
    assert!(registry.enabled("lorry").is_none());
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
fn reasoning_only_reply_is_an_error_without_an_empty_assistant_message() {
    let fixture = Fixture::new("empty-reply");
    let provider = Scripted::new(vec![Ok(Completion {
        reasoning: "thinking".to_string(),
        finish_reason: Some(FinishReason::Stop),
        ..Completion::default()
    })]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    let error = runtime
        .turn(
            "question".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap_err();
    assert!(error.contains("empty reply"), "{error}");
    let messages = runtime.session().context_messages().unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].text_content(), "question");
}

#[test]
fn zero_tool_round_budget_reports_an_error_instead_of_panicking() {
    let fixture = Fixture::new("zero-rounds");
    let config = Config {
        max_tool_rounds: 0,
        ..Config::default()
    };
    let provider = Scripted::new(Vec::new());
    let mut runtime = fixture.runtime(provider.clone(), &config);
    let error = runtime
        .turn(
            "question".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap_err();
    assert!(error.contains("tool round limit (0) reached"), "{error}");
    assert!(provider.requests.lock().unwrap().is_empty());
    assert!(
        runtime
            .session()
            .entries()
            .iter()
            .any(|entry| entry.kind == "turn_error")
    );
}

#[test]
fn tool_round_limit_stops_after_the_last_result() {
    let fixture = Fixture::new("round-limit");
    let config = Config {
        max_tool_rounds: 1,
        ..Config::default()
    };
    let provider = Scripted::new(vec![tool("sh", r#"{"command":"touch no-file"}"#)]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    let error = runtime
        .turn(
            "question".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap_err();
    assert!(error.contains("tool round limit (1) reached"), "{error}");
    assert_eq!(provider.requests.lock().unwrap().len(), 1);
    let messages = runtime.session().context_messages().unwrap();
    assert_eq!(messages.len(), 4);
    assert!(messages[2].text_content().contains("denied"));
    assert!(messages[3].text_content().contains("ended early"));
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
fn session_allow_survives_resume_but_not_a_new_session() {
    let fixture = Fixture::new("always");
    let touch = |name: &str| tool("sh", &format!(r#"{{"command":"touch {name}"}}"#));
    let provider = Scripted::new(vec![
        touch("one"),
        touch("two"),
        answer("done"),
        touch("three"),
        answer("done"),
        touch("four"),
        answer("done"),
        touch("five"),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    let first = runtime.summary().id;
    let mut always = CountingApproval {
        answer: Approval::Session,
        asked: 0,
    };
    // One answer covers the rest of the turn and the following turns.
    for prompt in ["first", "second"] {
        runtime
            .turn(prompt.to_string(), &mut always, &mut |_| Ok(()))
            .unwrap();
    }
    assert_eq!(always.asked, 1);
    for name in ["one", "two", "three"] {
        assert!(fixture.workspace.join(name).exists(), "{name}");
    }

    let mut deny = CountingApproval {
        answer: Approval::Deny,
        asked: 0,
    };
    runtime.new_session(false, None).unwrap();
    runtime
        .turn("third".to_string(), &mut deny, &mut |_| Ok(()))
        .unwrap();
    // The original session retains its own grant after returning to it.
    runtime.resume(&first).unwrap();
    runtime
        .turn("fourth".to_string(), &mut deny, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(deny.asked, 1);
    assert!(!fixture.workspace.join("four").exists());
    assert!(fixture.workspace.join("five").exists());
}

#[test]
fn session_allow_is_stored_with_the_session() {
    let fixture = Fixture::new("always-restart");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let open = |session, script| {
        let provider = Scripted::new(script);
        let config = Config {
            tools: vec![ToolDirectory {
                directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
                enabled: true,
            }],
            ..Config::default()
        };
        Runtime::new(
            provider,
            store.clone(),
            session,
            &config,
            "test/model".to_string(),
        )
        .unwrap()
    };
    let mut runtime = open(
        store.create(false, None).unwrap(),
        vec![tool("sh", r#"{"command":"touch before"}"#), answer("done")],
    );
    let mut always = CountingApproval {
        answer: Approval::Session,
        asked: 0,
    };
    runtime
        .turn("first".to_string(), &mut always, &mut |_| Ok(()))
        .unwrap();
    let saved = runtime.session().permission_grants().unwrap();
    let saved = saved.values().next().unwrap();
    assert_eq!(saved.kind, "process");
    assert!(saved.owner.ends_with("tools/sh"));
    assert!(saved.created_ms > 0);
    let id = runtime.summary().id;
    drop(runtime);

    // A restarted binary resuming the same session uses its saved grant.
    let mut resumed = open(
        store.open(&id).unwrap(),
        vec![tool("sh", r#"{"command":"touch after"}"#), answer("done")],
    );
    let mut deny = CountingApproval {
        answer: Approval::Deny,
        asked: 0,
    };
    resumed
        .turn("second".to_string(), &mut deny, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(deny.asked, 0);
    assert!(fixture.workspace.join("before").exists());
    assert!(fixture.workspace.join("after").exists());
}

#[test]
fn saved_denial_prevents_a_permission_hook_from_allowing_the_call() {
    let fixture = Fixture::new("saved-denial-before-hook");
    let hook = fixture.root.join("hook.sh");
    let checks = fixture.root.join("checks");
    std::fs::write(
        &hook,
        format!(
            "event=$(cat)\ncase \"$event\" in\n  *'\"event\":\"permission\"'*) printf x >> '{}' ; printf '%s' '{{\"decision\":\"allow\"}}' ;;\n  *) printf '%s' '{{}}' ;;\nesac\n",
            checks.display()
        ),
    )
    .unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        hooks: vec![HookConfig {
            events: None,
            name: "fixture".into(),
            command: vec!["sh".into(), hook.display().to_string()],
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let mut session = store.create(false, None).unwrap();
    let identity = Registry::load_config(&config).unwrap().tools()[0]
        .approval_identity()
        .unwrap();
    session
        .append_permission_grant(&PermissionGrant {
            name: "sh".into(),
            identity,
            allow: Some(false),
            ..PermissionGrant::default()
        })
        .unwrap();
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch denied"}"#),
        answer("done"),
    ]);
    let mut runtime = Runtime::new(provider, store, session, &config, "test/model".into()).unwrap();
    runtime
        .turn("try".into(), &mut UnexpectedApproval, &mut |_| Ok(()))
        .unwrap();
    assert!(!fixture.workspace.join("denied").exists());
    assert!(!checks.exists());
}

#[test]
fn hook_confirm_asks_even_after_a_saved_allowance() {
    let fixture = Fixture::new("confirm-after-grant");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(
        &hook,
        "event=$(cat)\ncase \"$event\" in\n  *'\"event\":\"permission\"'*) printf '%s' '{\"decision\":\"confirm\"}' ;;\n  *) printf '%s' '{}' ;;\nesac\n",
    )
    .unwrap();
    let config = Config {
        tools: vec![ToolDirectory {
            directory: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
            enabled: true,
        }],
        hooks: vec![HookConfig {
            events: None,
            name: "fixture".into(),
            command: vec!["sh".into(), hook.display().to_string()],
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let mut session = store.create(false, None).unwrap();
    let identity = Registry::load_config(&config).unwrap().tools()[0]
        .approval_identity()
        .unwrap();
    session
        .append_permission_grant(&PermissionGrant {
            name: "sh".into(),
            identity,
            allow: Some(true),
            ..PermissionGrant::default()
        })
        .unwrap();
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch unconfirmed"}"#),
        answer("done"),
    ]);
    let mut runtime = Runtime::new(provider, store, session, &config, "test/model".into()).unwrap();
    let mut deny = CountingApproval {
        answer: Approval::Deny,
        asked: 0,
    };
    runtime
        .turn("try".into(), &mut deny, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(deny.asked, 1);
    assert!(!fixture.workspace.join("unconfirmed").exists());
}

#[test]
fn a_hook_denial_wins_over_always_allow() {
    let fixture = Fixture::new("always-deny");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(
        &hook,
        r#"#!/bin/sh
event=$(cat)
case "$event" in
  *'"event":"permission"'*forbidden*) printf '%s' '{"decision":"deny"}' ;;
  *) printf '%s' '{}' ;;
esac
"#,
    )
    .unwrap();
    let mut config = Config::default();
    config.hooks.push(HookConfig {
        events: None,
        name: "fixture".to_string(),
        // A parallel spawn can briefly inherit the script's writable fd.
        // Let sh read it without executing that inode (ETXTBSY on Linux).
        command: vec!["sh".to_string(), hook.display().to_string()],
        timeout: Duration::from_secs(2),
        max_output_bytes: 64 * 1024,
    });
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"touch fine"}"#),
        tool("sh", r#"{"command":"touch forbidden"}"#),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider, &config);
    let mut always = CountingApproval {
        answer: Approval::Session,
        asked: 0,
    };
    runtime
        .turn("go".to_string(), &mut always, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(always.asked, 1);
    assert!(fixture.workspace.join("fine").exists());
    assert!(!fixture.workspace.join("forbidden").exists());
}

#[test]
fn a_hook_can_register_authorize_and_execute_a_tool() {
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
    let mut config = Config::default();
    config.hooks.push(HookConfig {
        events: None,
        name: "fixture".to_string(),
        command: vec!["sh".to_string(), hook.display().to_string()],
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
fn failed_tool_notice_keeps_the_executed_hook_result() {
    let fixture = Fixture::new("hook-notice-error");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(
        &hook,
        r#"#!/bin/sh
event=$(cat)
case "$event" in
  *'"event":"initialize"'*)
    printf '%s' '{"tools":[{"name":"echo_hook","description":"fixture","parameters":{"type":"object"}}]}'
    ;;
  *'"event":"permission"'*)
    printf '%s' '{"decision":"allow"}'
    ;;
  *'"event":"tool_execute"'*)
    printf '%s' '{"tool_result":{"content":"executed once","is_error":false},"notice":"finished"}'
    ;;
  *) printf '%s' '{}';;
esac
"#,
    )
    .unwrap();
    let mut config = Config::default();
    config.hooks.push(HookConfig {
        events: None,
        name: "fixture".to_string(),
        command: vec!["sh".to_string(), hook.display().to_string()],
        timeout: Duration::from_secs(2),
        max_output_bytes: 4096,
    });
    let mut runtime = fixture.runtime(Scripted::new(vec![tool("echo_hook", "{}")]), &config);
    let error = runtime
        .turn("go".to_string(), &mut UnexpectedApproval, &mut |event| {
            if matches!(event, Event::Notice(ref message) if message.contains("finished")) {
                Err("notice display failed".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert!(error.contains("notice display failed"));
    let context = runtime.session().context_messages().unwrap();
    assert!(
        context
            .iter()
            .any(|message| message.text_content() == "executed once")
    );
    assert_eq!(
        context
            .iter()
            .filter(|message| message.role == gears::provider::Role::Tool)
            .count(),
        1
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
fn compaction_bounds_a_large_tool_result_sent_to_the_summarizer() {
    let fixture = Fixture::new("large-compaction-input");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let mut session = store.create(false, None).unwrap();
    session.append_message(&Message::user("start")).unwrap();
    session
        .append_message(&Message::assistant_response(
            String::new(),
            vec![ToolCall::new("one", "sh", "{}")],
        ))
        .unwrap();
    session
        .append_message(&Message::tool_result(
            "one",
            "sh",
            "large output ".repeat(20_000),
            false,
        ))
        .unwrap();
    session.append_message(&Message::assistant("done")).unwrap();
    session.append_message(&Message::user("continue")).unwrap();
    let provider = Scripted::new(vec![answer("summary")]);
    let config = Config {
        context: ContextConfig {
            window_tokens: 800,
            output_reserve_tokens: 200,
            recent_tail_tokens: 50,
        },
        ..Config::default()
    };
    let mut runtime = Runtime::new(
        provider.clone(),
        store,
        session,
        &config,
        "test/model".to_string(),
    )
    .unwrap();
    runtime.compact(None, &mut |_| Ok(())).unwrap();
    let requests = provider.requests.lock().unwrap();
    let request = requests.last().unwrap();
    let bytes = serde_json::to_vec(&(&request.system, &request.messages)).unwrap();
    assert!(bytes.len() < 800 * 4, "summarizer input is too large");
    assert!(request.messages[0].text_content().contains("[truncated]"));
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
fn an_oversized_first_turn_records_its_error() {
    let fixture = Fixture::new("oversized-first-turn");
    let config = Config {
        context: ContextConfig {
            window_tokens: 800,
            output_reserve_tokens: 200,
            recent_tail_tokens: 50,
        },
        ..Config::default()
    };
    let mut runtime = fixture.runtime(Scripted::new(Vec::new()), &config);
    let error = runtime
        .turn(
            "large input ".repeat(10_000),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap_err();
    assert!(error.contains("limit"), "{error}");
    assert!(runtime.session().entries().iter().any(|entry| {
        entry.kind == "turn_error" && entry.data["detail"].as_str() == Some(error.as_str())
    }));
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

#[test]
fn resume_reports_discarded_crash_tail_and_completes_a_new_turn() {
    let fixture = Fixture::new("crash-recovery");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let mut session = store.create(false, None).unwrap();
    session.append_message(&Message::user("before")).unwrap();
    session
        .append_message(&Message::assistant_response(
            String::new(),
            vec![
                ToolCall::new("one", "sh", "{}"),
                ToolCall::new("two", "sh", "{}"),
            ],
        ))
        .unwrap();
    session
        .append_message(&Message::tool_result("one", "sh", "done", false))
        .unwrap();
    let id = session.id().to_string();
    drop(session);

    let mut runtime = Runtime::new(
        Scripted::new(vec![answer("recovered")]),
        store.clone(),
        store.open(&id).unwrap(),
        &Config::default(),
        "test/model".to_string(),
    )
    .unwrap();
    assert!(
        runtime
            .take_startup_notices()
            .iter()
            .any(|notice| notice.contains("discarded 2 incomplete session records"))
    );
    runtime
        .turn("next".to_string(), &mut FixedApproval(false), &mut |_| {
            Ok(())
        })
        .unwrap();
    assert_eq!(runtime.session().context_messages().unwrap().len(), 3);
}

#[test]
fn a_provider_switch_is_recorded_and_used_on_the_next_turn() {
    let fixture = Fixture::new("provider-switch");
    let first = Scripted::new(vec![answer("first answer")]);
    let second = Scripted::new(vec![answer("second answer")]);
    let mut runtime = fixture.runtime(first.clone(), &Config::default());
    let next = second.clone();
    runtime.install_provider_factory(Arc::new(move |name| {
        if name == "second" {
            Ok(next.clone() as Arc<dyn Provider>)
        } else {
            Err(format!("unknown provider {name}"))
        }
    }));
    runtime
        .turn(
            "one".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap();
    runtime.set_provider("second", &mut |_| Ok(())).unwrap();
    assert_eq!(runtime.provider_name(), "second");
    assert_eq!(runtime.session().provider().as_deref(), Some("second"));
    runtime
        .turn(
            "two".to_string(),
            &mut FixedApproval(false),
            &mut |_| Ok(()),
        )
        .unwrap();
    assert_eq!(first.requests.lock().unwrap().len(), 1);
    assert_eq!(second.requests.lock().unwrap().len(), 1);
    assert!(
        runtime
            .session()
            .context_messages()
            .unwrap()
            .iter()
            .any(|message| message.text_content() == "second answer")
    );
}

#[test]
fn switched_provider_sees_reasoning_cache_markers_and_retry_notice() {
    let fixture = Fixture::new("provider-phase-two");
    let first = MockServer::start_one(sse_response(&[
        r#"{"choices":[{"index":0,"delta":{"reasoning":"considered"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"first answer"},"finish_reason":"stop"}]}"#,
    ]))
    .unwrap();
    let rate_limit = Script::new()
        .write("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\n\r\n");
    let second = MockServer::start(vec![
        rate_limit,
        sse_response(&[r#"{"choices":[{"index":0,"delta":{"content":"second answer"},"finish_reason":"stop"}]}"#]),
    ])
    .unwrap();
    let make_provider = |url: &str, name: &str| -> Arc<dyn Provider> {
        let policy = EgressPolicy::new(&["127.0.0.1".into()])
            .with_plain_http_allowlist(&["127.0.0.1".into()]);
        let endpoint = Endpoint::new(url)
            .unwrap()
            .with_quirks(Quirks::for_host("openrouter.ai"));
        Arc::new(
            OpenAiCompat::new(HostCurl::new(policy).unwrap(), endpoint)
                .without_key()
                .with_cache_identity(name),
        )
    };
    let mut runtime = fixture.runtime(
        make_provider(&first.url("/v1"), "default"),
        &Config::default(),
    );
    let second_url = second.url("/v1");
    runtime.install_provider_factory(Arc::new(move |name| {
        if name == "second" {
            Ok(make_provider(&second_url, name))
        } else {
            Err(format!("unknown provider {name}"))
        }
    }));
    runtime
        .turn("one".into(), &mut FixedApproval(false), &mut |_| Ok(()))
        .unwrap();
    runtime.set_provider("second", &mut |_| Ok(())).unwrap();
    let mut events = Vec::new();
    runtime
        .turn("two".into(), &mut FixedApproval(false), &mut |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Notice(text) if text.contains("retrying")))
    );
    assert_eq!(second.requests().len(), 2);
    let request: serde_json::Value = serde_json::from_slice(&second.requests()[1].body).unwrap();
    assert_eq!(
        request["messages"][0]["content"][0]["cache_control"]["type"],
        "ephemeral"
    );
    assert_eq!(request["messages"][2]["reasoning"], "considered");
    assert_eq!(
        request["messages"][2]["content"][0]["cache_control"]["type"],
        "ephemeral"
    );
    assert_eq!(
        request["messages"][3]["content"][0]["cache_control"]["type"],
        "ephemeral"
    );
    assert!(
        request["prompt_cache_key"]
            .as_str()
            .unwrap()
            .starts_with("gears-")
    );
    assert_eq!(first.requests().len(), 1);
    let first_request: serde_json::Value =
        serde_json::from_slice(&first.requests()[0].body).unwrap();
    assert_ne!(
        request["prompt_cache_key"],
        first_request["prompt_cache_key"]
    );
}

#[test]
fn resuming_another_session_restores_its_provider() {
    let fixture = Fixture::new("provider-session-switch");
    let store = Store::with_root(&fixture.workspace, fixture.root.join("state")).unwrap();
    let first_session = store.create(false, None).unwrap();
    let mut second_session = store.create(false, None).unwrap();
    second_session.set_provider("second").unwrap();
    let second_id = second_session.id().to_string();
    drop(second_session);

    let first = Scripted::new(Vec::new());
    let second = Scripted::new(vec![answer("from second")]);
    let mut runtime = Runtime::new(
        first.clone(),
        store,
        first_session,
        &Config::default(),
        "test/model".to_string(),
    )
    .unwrap();
    let next = second.clone();
    runtime.install_provider_factory(Arc::new(move |name| {
        if name == "second" {
            Ok(next.clone() as Arc<dyn Provider>)
        } else {
            Err(format!("unknown provider {name}"))
        }
    }));
    runtime.resume(&second_id).unwrap();
    assert_eq!(runtime.provider_name(), "second");
    runtime
        .turn("hello".to_string(), &mut FixedApproval(false), &mut |_| {
            Ok(())
        })
        .unwrap();
    assert!(first.requests.lock().unwrap().is_empty());
    assert_eq!(second.requests.lock().unwrap().len(), 1);
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
    let mut saw_text = false;
    let error = runtime
        .turn(
            "keep going".to_string(),
            &mut FixedApproval(false),
            &mut |event| {
                if matches!(event, Event::Text(_)) {
                    saw_text = true;
                    cancellation.cancel();
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert!(saw_text);
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
fn lifecycle_hooks_run_after_a_cancelled_turn() {
    let fixture = Fixture::new("cancel-hooks");
    let log = fixture.root.join("events.jsonl");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\ncat >> '{}'\nprintf '\\n' >> '{}'\nprintf '{{}}'\n",
            log.display(),
            log.display()
        ),
    )
    .unwrap();
    let mut config = Config::default();
    config.hooks.push(HookConfig {
        events: None,
        name: "log".to_string(),
        command: vec!["sh".to_string(), hook.display().to_string()],
        timeout: Duration::from_secs(2),
        max_output_bytes: 4096,
    });
    let mut runtime = fixture.runtime(Arc::new(UntilCancelled), &config);
    let cancellation = runtime.cancellation();
    let mut saw_text = false;
    let error = runtime
        .turn(
            "interrupt".to_string(),
            &mut FixedApproval(false),
            &mut |event| {
                if matches!(event, Event::Text(_)) {
                    saw_text = true;
                    cancellation.cancel();
                }
                Ok(())
            },
        )
        .unwrap_err();
    assert!(saw_text);
    assert!(error.contains("cancelled"), "{error}");
    runtime.new_session(false, None).unwrap();
    runtime.close();
    let events = std::fs::read_to_string(log).unwrap();
    assert!(events.contains("\"event\":\"turn_end\""), "{events}");
    assert!(events.contains("\"status\":\"cancelled\""), "{events}");
    assert!(events.contains("\"type\":\"turn_error\""), "{events}");
    assert_eq!(events.matches("\"event\":\"session_start\"").count(), 2);
    assert_eq!(events.matches("\"event\":\"session_end\"").count(), 2);
}

#[test]
fn cancellation_pairs_every_call_in_a_tool_round() {
    let fixture = Fixture::new("cancel-round");
    let provider = Scripted::new(vec![Ok(Completion {
        tool_calls: vec![
            ToolCall::new("call_1", "sh", r#"{"command":"printf started; sleep 2"}"#),
            ToolCall::new("call_2", "sh", r#"{"command":"touch never"}"#),
        ],
        finish_reason: Some(FinishReason::ToolCalls),
        ..Completion::default()
    })]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    let cancellation = runtime.cancellation();
    let mut saw_output = false;
    let error = runtime
        .turn("go".to_string(), &mut FixedApproval(true), &mut |event| {
            if matches!(event, Event::ToolOutput { .. }) {
                saw_output = true;
                cancellation.cancel();
            }
            Ok(())
        })
        .unwrap_err();
    assert!(saw_output);
    assert!(error.contains("cancelled"), "{error}");
    assert!(!fixture.workspace.join("never").exists());
    let outcomes = runtime
        .session()
        .context_messages()
        .unwrap()
        .into_iter()
        .flat_map(|message| message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult {
                call_id, outcome, ..
            } => Some((call_id, outcome)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes,
        [
            ("call_1".to_string(), ToolOutcome::InterruptedUnknown),
            ("call_2".to_string(), ToolOutcome::NotStarted),
        ]
    );
}

#[test]
fn before_stop_reminders_are_saved_as_user_notes_and_bounded_per_turn() {
    let fixture = Fixture::new("before-stop");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(
        &hook,
        "#!/bin/sh\ncat >/dev/null\nprintf '%s' '{\"message\":\"Run the declared check.\"}'\n",
    )
    .unwrap();
    let config = Config {
        hooks: vec![HookConfig {
            name: "check".into(),
            command: vec!["sh".into(), hook.display().to_string()],
            events: Some(vec!["before_stop".into()]),
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"printf checked"}"#),
        answer("one"),
        answer("two"),
        answer("three"),
        answer("four"),
        answer("chat only"),
    ]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    let mut reminders = 0;
    runtime
        .turn("work".into(), &mut FixedApproval(true), &mut |event| {
            if matches!(event, Event::Notice(ref text) if text.starts_with("before_stop:")) {
                reminders += 1;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(reminders, 3);
    let context = runtime.session().context_messages().unwrap();
    let notes = context
        .iter()
        .filter(|message| {
            message.role == gears::provider::Role::User
                && message.text_content() == "Run the declared check."
        })
        .count();
    assert_eq!(notes, 3);
    assert_eq!(context.last().unwrap().text_content(), "four");
    let requests = provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests[2].messages.last().unwrap().text_content(),
        "Run the declared check."
    );
    drop(requests);
    runtime
        .turn("hello".into(), &mut UnexpectedApproval, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(provider.requests.lock().unwrap().len(), 6);
}

#[test]
fn hook_setup_receives_startup_provider_model_and_subscriptions() {
    let fixture = Fixture::new("setup-payload");
    let log = fixture.root.join("setup.json");
    let config = Config {
        hooks: vec![HookConfig {
            name: "setup".into(),
            events: Some(vec!["initialize".into()]),
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("cat > '{}'; printf '{{}}'", log.display()),
            ],
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let runtime = fixture.runtime(Scripted::new(Vec::new()), &config);
    let event: serde_json::Value = serde_json::from_slice(&std::fs::read(log).unwrap()).unwrap();
    assert_eq!(
        event["payload"],
        serde_json::json!({"reason":"startup","provider":"default","model":"test/model",
            "subscribed_events": ["initialize"]})
    );
    assert_eq!(event["session"]["id"], runtime.session().id());
}

#[test]
fn session_changes_repeat_setup_and_replace_prompt_fragments() {
    let fixture = Fixture::new("session-setup");
    let log = fixture.root.join("setups.jsonl");
    let response = fixture.root.join("response.json");
    std::fs::write(&response, r#"{"prompt_fragments":["setup prompt one"]}"#).unwrap();
    let config = Config {
        hooks: vec![HookConfig {
            name: "setup".into(),
            events: Some(vec!["initialize".into()]),
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    "cat >> '{}'; printf '\\n' >> '{}'; cat '{}'",
                    log.display(),
                    log.display(),
                    response.display()
                ),
            ],
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![answer("new answer"), answer("still usable")]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    let original = runtime.session().id().to_string();
    std::fs::write(&response, r#"{"prompt_fragments":["setup prompt two"]}"#).unwrap();
    runtime.new_session(false, None).unwrap();
    runtime
        .turn("hello".into(), &mut UnexpectedApproval, &mut |_| Ok(()))
        .unwrap();
    runtime.clone_session().unwrap();
    let user = runtime
        .session()
        .entries()
        .iter()
        .find(|entry| entry.kind == "message" && entry.data["role"] == "user")
        .unwrap()
        .id
        .clone();
    runtime.fork_at(&user).unwrap();
    runtime.resume(&original).unwrap();
    runtime.resume(&original).unwrap();
    let events = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .map(|event| event["payload"]["reason"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["startup", "new", "clone", "fork", "resume", "resume"]
    );
    assert!(
        events
            .iter()
            .all(|event| event["payload"]["model"] == "test/model"
                && event["payload"]["provider"] == "default")
    );
    let requests = provider.requests.lock().unwrap();
    assert!(
        requests[0]
            .system
            .iter()
            .any(|text| text.contains("setup prompt two"))
    );
    assert!(
        !requests[0]
            .system
            .iter()
            .any(|text| text.contains("setup prompt one"))
    );
    drop(requests);
    std::fs::write(&response, "invalid").unwrap();
    assert!(runtime.new_session(false, None).is_err());
    assert_eq!(runtime.session().id(), original);
    runtime
        .turn(
            "after failed setup".into(),
            &mut UnexpectedApproval,
            &mut |_| Ok(()),
        )
        .unwrap();
    assert!(
        provider.requests.lock().unwrap()[1]
            .system
            .iter()
            .any(|text| text.contains("setup prompt two"))
    );
}

#[test]
fn selection_changes_and_compaction_repeat_setup_with_current_metadata() {
    let fixture = Fixture::new("selection-setup");
    let log = fixture.root.join("setups.jsonl");
    let response = fixture.root.join("response.json");
    std::fs::write(&response, r#"{"prompt_fragments":["setup original"]}"#).unwrap();
    let config = Config {
        hooks: vec![HookConfig {
            name: "setup".into(),
            events: Some(vec!["initialize".into()]),
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    "cat >> '{}'; printf '\\n' >> '{}'; cat '{}'",
                    log.display(),
                    log.display(),
                    response.display()
                ),
            ],
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        context: ContextConfig {
            window_tokens: 10_000,
            output_reserve_tokens: 2_000,
            recent_tail_tokens: 50,
        },
        ..Config::default()
    };
    let remote = Scripted::new(vec![
        answer(&"a".repeat(300)),
        answer(&"b".repeat(300)),
        answer("compact summary"),
        answer("after compact"),
    ]);
    let mut runtime = fixture.runtime(Scripted::new(Vec::new()), &config);
    let next = remote.clone();
    runtime.install_provider_factory(Arc::new(move |_| Ok(next.clone() as Arc<dyn Provider>)));
    std::fs::write(&response, r#"{"prompt_fragments":["setup selected"]}"#).unwrap();
    runtime
        .set_model("test/next".into(), &mut |_| Ok(()))
        .unwrap();
    runtime.set_provider("remote", &mut |_| Ok(())).unwrap();
    for prompt in ["one", "two"] {
        runtime
            .turn(prompt.into(), &mut UnexpectedApproval, &mut |_| Ok(()))
            .unwrap();
    }
    std::fs::write(&response, r#"{"prompt_fragments":["setup compacted"]}"#).unwrap();
    runtime.compact(None, &mut |_| Ok(())).unwrap();
    runtime
        .turn("three".into(), &mut UnexpectedApproval, &mut |_| Ok(()))
        .unwrap();
    let events = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        events
            .iter()
            .map(|event| event["payload"]["reason"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["startup", "model_change", "provider_change", "compaction"]
    );
    assert_eq!(events[1]["payload"]["provider"], "default");
    assert_eq!(events[1]["payload"]["model"], "test/next");
    for event in &events[2..] {
        assert_eq!(event["payload"]["provider"], "remote");
        assert_eq!(event["payload"]["model"], "test/next");
    }
    let requests = remote.requests.lock().unwrap();
    assert!(
        requests[3]
            .system
            .iter()
            .any(|text| text.contains("setup compacted"))
    );
    assert!(
        !requests[3]
            .system
            .iter()
            .any(|text| text.contains("setup selected"))
    );
    drop(requests);
    std::fs::write(&response, "invalid").unwrap();
    assert!(
        runtime
            .set_model("test/failing".into(), &mut |_| Ok(()))
            .is_err()
    );
    assert_eq!(runtime.model(), "test/next");
    assert!(runtime.set_provider("other", &mut |_| Ok(())).is_err());
    assert_eq!(runtime.provider_name(), "remote");
}

#[test]
fn a_failed_before_stop_hook_is_reported_without_repeating_the_answer() {
    let fixture = Fixture::new("before-stop-failure");
    let config = Config {
        hooks: vec![HookConfig {
            name: "broken".into(),
            command: vec!["/bin/sh".into(), "-c".into(), "printf invalid".into()],
            events: Some(vec!["before_stop".into()]),
            timeout: Duration::from_secs(2),
            max_output_bytes: 4096,
        }],
        ..Config::default()
    };
    let provider = Scripted::new(vec![
        tool("sh", r#"{"command":"printf checked"}"#),
        answer("done"),
    ]);
    let mut runtime = fixture.runtime(provider.clone(), &config);
    let mut notices = Vec::new();
    runtime
        .turn("work".into(), &mut FixedApproval(true), &mut |event| {
            if let Event::Notice(text) = event {
                notices.push(text);
            }
            Ok(())
        })
        .unwrap();
    assert!(
        notices
            .iter()
            .any(|text| text.contains("before_stop hook broken failed"))
    );
    assert_eq!(provider.requests.lock().unwrap().len(), 2);
    assert_eq!(
        runtime
            .session()
            .context_messages()
            .unwrap()
            .last()
            .unwrap()
            .text_content(),
        "done"
    );
}

#[test]
fn cancellation_keeps_the_tool_result_when_a_result_hook_cannot_run() {
    let fixture = Fixture::new("cancel-result-hook");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(&hook, "#!/bin/sh\ncat >/dev/null\nprintf '{}'\n").unwrap();
    let mut config = Config::default();
    config.hooks.push(HookConfig {
        events: None,
        name: "fixture".to_string(),
        command: vec!["sh".to_string(), hook.display().to_string()],
        timeout: Duration::from_secs(2),
        max_output_bytes: 4096,
    });
    let provider = Scripted::new(vec![Ok(Completion {
        tool_calls: vec![
            ToolCall::new("call_1", "sh", r#"{"command":"printf started; sleep 2"}"#),
            ToolCall::new("call_2", "sh", r#"{"command":"touch never"}"#),
        ],
        finish_reason: Some(FinishReason::ToolCalls),
        ..Completion::default()
    })]);
    let mut runtime = fixture.runtime(provider, &config);
    let cancellation = runtime.cancellation();
    let mut saw_output = false;
    let error = runtime
        .turn("go".to_string(), &mut FixedApproval(true), &mut |event| {
            if matches!(event, Event::ToolOutput { .. }) {
                saw_output = true;
                cancellation.cancel();
            }
            Ok(())
        })
        .unwrap_err();
    assert!(saw_output);
    assert!(error.contains("cancelled"), "{error}");
    let results = runtime
        .session()
        .context_messages()
        .unwrap()
        .into_iter()
        .flat_map(|message| message.content)
        .filter(|block| matches!(block, ContentBlock::ToolResult { .. }))
        .count();
    assert_eq!(results, 2);
    assert!(!fixture.workspace.join("never").exists());
}

#[test]
fn an_observer_error_pairs_calls_that_never_started() {
    let fixture = Fixture::new("observer-before-tools");
    let provider = Scripted::new(vec![Ok(Completion {
        tool_calls: vec![
            ToolCall::new("call_1", "sh", r#"{"command":"touch never-one"}"#),
            ToolCall::new("call_2", "sh", r#"{"command":"touch never-two"}"#),
        ],
        finish_reason: Some(FinishReason::ToolCalls),
        ..Completion::default()
    })]);
    let mut runtime = fixture.runtime(provider, &Config::default());
    let error = runtime
        .turn("go".to_string(), &mut FixedApproval(true), &mut |event| {
            if matches!(event, Event::Permission(_)) {
                Err("observer refused permission event".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert!(error.contains("observer refused"), "{error}");
    for name in ["never-one", "never-two"] {
        assert!(!fixture.workspace.join(name).exists());
    }
    let outcomes = runtime
        .session()
        .context_messages()
        .unwrap()
        .into_iter()
        .flat_map(|message| message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(outcomes, [ToolOutcome::NotStarted, ToolOutcome::NotStarted]);
    assert!(
        runtime
            .session()
            .entries()
            .iter()
            .any(|entry| entry.kind == "turn_error")
    );
}

#[test]
fn a_failed_result_hook_preserves_the_completed_call() {
    let fixture = Fixture::new("result-hook-error");
    let hook = fixture.root.join("hook.sh");
    std::fs::write(
        &hook,
        "#!/bin/sh\nevent=$(cat)\ncase \"$event\" in\n  *'\"event\":\"tool_result\"'*) exit 7 ;;\n  *) printf '{}' ;;\nesac\n",
    )
    .unwrap();
    let mut config = Config::default();
    config.hooks.push(HookConfig {
        events: None,
        name: "fixture".to_string(),
        command: vec!["sh".to_string(), hook.display().to_string()],
        timeout: Duration::from_secs(2),
        max_output_bytes: 4096,
    });
    let provider = Scripted::new(vec![Ok(Completion {
        tool_calls: vec![
            ToolCall::new("call_1", "sh", r#"{"command":"touch done"}"#),
            ToolCall::new("call_2", "sh", r#"{"command":"touch never"}"#),
        ],
        finish_reason: Some(FinishReason::ToolCalls),
        ..Completion::default()
    })]);
    let mut runtime = fixture.runtime(provider, &config);
    let error = runtime
        .turn("go".to_string(), &mut FixedApproval(true), &mut |_| Ok(()))
        .unwrap_err();
    assert!(error.contains("exited unsuccessfully"), "{error}");
    assert!(fixture.workspace.join("done").exists());
    assert!(!fixture.workspace.join("never").exists());
    let outcomes = runtime
        .session()
        .context_messages()
        .unwrap()
        .into_iter()
        .flat_map(|message| message.content)
        .filter_map(|block| match block {
            ContentBlock::ToolResult { outcome, .. } => Some(outcome),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(outcomes, [ToolOutcome::Completed, ToolOutcome::NotStarted]);
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
        events: None,
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
