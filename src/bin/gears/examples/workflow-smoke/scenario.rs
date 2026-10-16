//! A scripted provider drives real tools and compiler checks, without a network.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use gears::provider::{
    Completion, EventSink, FinishReason, Provider, ProviderError, Request, ToolCall,
};
use gears::runtime::{Approval, Approver, Permission};
use serde_json::{Value, json};

static NEXT_CALL: AtomicU32 = AtomicU32::new(0);

pub struct Scripted {
    pub requests: Mutex<Vec<Request>>,
    responses: Mutex<VecDeque<Completion>>,
}

impl Scripted {
    /// Scripted replies not yet requested.
    pub fn remaining(&self) -> usize {
        self.responses.lock().unwrap().len()
    }

    pub fn from_responses(responses: Vec<Completion>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        }
    }

    pub fn new(label: &str) -> Self {
        Self { requests: Mutex::new(Vec::new()), responses: Mutex::new(vec![
            call("todo", json!({"items": [{"id": "compile", "text": "Repair and compile the crate", "status": "pending"}]})),
            call("read_file", json!({"path": "src/lib.rs"})),
            call("search_files", json!({"pattern": "assert", "path": "src"})),
            call("session_search", json!({"query": label})),
            call("write_file", json!({"path": "notes/a file*", "content": "literal fixture\n"})),
            call("patch", json!({"path": "src/lib.rs", "old_text": "== 3", "new_text": "== 2"})),
            call("memory", json!({"action": "add", "target": "workspace", "text": "The fixture uses a compile-time assertion."})),
            call("check", json!({})), answer("repaired and checked"),
            call("todo", json!({"items": [{"id": "compile", "text": "Repair and compile the crate", "status": "completed"}]})),
            answer("task list updated"),
            call("read_file", json!({"path": "src/lib.rs"})),
            call("patch", json!({"path": "src/lib.rs", "old_text": "== 2", "new_text": "== 3"})),
            answer("finished without check"), answer("still finished"),
            answer("finished again"), answer("final fixture reply"),
        ].into()) }
    }
}

impl Provider for Scripted {
    fn complete(
        &self,
        request: &Request,
        _: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        assert!(request.tools.iter().any(|tool| tool.name == "todo"));
        assert!(
            request
                .system
                .iter()
                .any(|text| text.contains("Fixture instructions:"))
        );
        self.requests.lock().unwrap().push(request.clone());
        self.responses.lock().unwrap().pop_front().ok_or_else(|| {
            ProviderError::Protocol("unexpected extra request in workflow fixture".into())
        })
    }
}

pub fn call(name: &str, arguments: Value) -> Completion {
    Completion {
        tool_calls: vec![ToolCall::new(
            format!("fixture-{}", NEXT_CALL.fetch_add(1, Ordering::Relaxed)),
            name,
            arguments.to_string(),
        )],
        finish_reason: Some(FinishReason::ToolCalls),
        ..Completion::default()
    }
}

pub fn answer(text: &str) -> Completion {
    Completion {
        content: text.into(),
        finish_reason: Some(FinishReason::Stop),
        ..Completion::default()
    }
}

#[derive(Default)]
pub struct Approvals(pub Vec<Permission>);
impl Approver for Approvals {
    fn answer(&mut self, question: &gears::hooks::Question) -> Result<Option<String>, String> {
        if question
            .choices
            .iter()
            .map(|choice| choice.value.as_str())
            .collect::<Vec<_>>()
            != ["yes", "no"]
        {
            return Err("unexpected workflow question".into());
        }
        Ok(Some("no".into()))
    }

    fn approve(&mut self, permission: &Permission) -> Approval {
        self.0.push(permission.clone());
        Approval::Once
    }
}
