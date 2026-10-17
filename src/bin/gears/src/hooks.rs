//! Versioned command-hook protocol and ordered composition.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::HookConfig;
use crate::process::{Cancellation, Request as ProcessRequest, run};
use crate::provider::{Message, ToolCall, ToolSpec};
use crate::session::{HookState, Session};

pub const PROTOCOL_VERSION: u32 = 1;
pub const EVENTS: &[&str] = &[
    "initialize",
    "session_start",
    "session_end",
    "entry",
    "turn_start",
    "input",
    "context",
    "permission",
    "tool_execute",
    "tool_result",
    "before_stop",
    "turn_end",
    "before_compact",
    "after_compact",
    "model_change",
    "provider_change",
    "command",
    "answer",
];

#[derive(Serialize)]
struct Event<'a> {
    protocol_version: u32,
    event: &'a str,
    hook: &'a str,
    workspace: &'a Path,
    session: SessionView<'a>,
    payload: Value,
}

#[derive(Serialize)]
struct SessionView<'a> {
    id: &'a str,
    path: Option<&'a Path>,
    state: Option<Value>,
}

#[derive(Deserialize, Default)]
struct Response {
    protocol_version: Option<u32>,
    #[serde(default)]
    prompt_fragments: Vec<String>,
    #[serde(default)]
    tools: Vec<ToolSpec>,
    #[serde(default)]
    commands: Vec<CommandSpec>,
    input: Option<String>,
    messages: Option<Vec<Message>>,
    decision: Option<Decision>,
    permission_detail: Option<String>,
    tool_result: Option<ToolResult>,
    compaction: Option<CompactionAdvice>,
    state: Option<Value>,
    context: Option<Message>,
    notice: Option<String>,
    message: Option<String>,
    question: Option<Question>,
    hint: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Ask,
    Confirm,
}

pub struct PermissionReview {
    pub decision: Decision,
    pub details: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub content: String,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct CompactionAdvice {
    #[serde(default)]
    pub cancel: bool,
    pub focus: Option<String>,
    pub output_reserve_tokens: Option<u64>,
    pub recent_tail_tokens: Option<u64>,
    pub summary: Option<String>,
    pub retained_tail: Option<Vec<Message>>,
}

pub struct Initialize {
    pub prompt_fragments: Vec<String>,
    pub tools: Vec<ToolSpec>,
    pub commands: Vec<CommandSpec>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: String,
    pub help: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: String,
    pub text: String,
    pub choices: Vec<Choice>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub value: String,
    pub label: String,
}

pub struct PendingQuestion {
    owner: usize,
    pub hook: String,
    pub question: Question,
}

#[derive(Default)]
struct Feedback {
    questions: VecDeque<PendingQuestion>,
    hint: Option<Option<String>>,
}

struct Hook {
    config: HookConfig,
}

pub struct Manager {
    workspace: PathBuf,
    hooks: Vec<Hook>,
    tool_owner: HashMap<String, usize>,
    prompt_fragments: Vec<String>,
    tools: Vec<ToolSpec>,
    commands: Vec<CommandSpec>,
    command_owner: HashMap<String, usize>,
    feedback: Mutex<Feedback>,
}

impl Manager {
    pub fn initialize(
        configs: Vec<HookConfig>,
        workspace: PathBuf,
        reserved_names: &[String],
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<Self, String> {
        let hooks = configs
            .into_iter()
            .map(|config| Hook { config })
            .collect::<Vec<_>>();
        let mut manager = Self {
            workspace,
            hooks,
            tool_owner: HashMap::new(),
            prompt_fragments: Vec::new(),
            tools: Vec::new(),
            commands: Vec::new(),
            command_owner: HashMap::new(),
            feedback: Mutex::new(Feedback::default()),
        };
        let mut names = HashSet::new();
        names.extend(reserved_names.iter().cloned());
        for index in 0..manager.hooks.len() {
            let response = manager.invoke(
                index,
                "initialize",
                payload.clone(),
                session,
                cancellation,
                notice,
            )?;
            for fragment in response.prompt_fragments {
                if !fragment.trim().is_empty() {
                    manager.prompt_fragments.push(fragment);
                }
            }
            for tool in response.tools {
                validate_tool(&tool)?;
                if !names.insert(tool.name.clone()) {
                    return Err(format!("duplicate tool name {:?}", tool.name));
                }
                manager.tool_owner.insert(tool.name.clone(), index);
                manager.tools.push(tool);
            }
            for command in response.commands {
                validate_command(&command)?;
                if crate::cli::COMMAND_NAMES.contains(&command.name.as_str())
                    || manager.command_owner.contains_key(&command.name)
                {
                    return Err(format!("duplicate command name {:?}", command.name));
                }
                if manager.hooks[index]
                    .config
                    .events
                    .as_ref()
                    .is_some_and(|events| !events.iter().any(|event| event == "command"))
                {
                    return Err(format!(
                        "hook {} registers commands but does not subscribe to command",
                        manager.hooks[index].config.name
                    ));
                }
                manager.command_owner.insert(command.name.clone(), index);
                manager.commands.push(command);
            }
        }
        Ok(manager)
    }

    /// Build fresh registrations without replacing a working manager on failure.
    pub fn setup_again(
        &self,
        reserved_names: &[String],
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<Self, String> {
        Self::initialize(
            self.hooks.iter().map(|hook| hook.config.clone()).collect(),
            self.workspace.clone(),
            reserved_names,
            payload,
            session,
            cancellation,
            notice,
        )
    }

    pub fn initialized(&self) -> Initialize {
        Initialize {
            prompt_fragments: self.prompt_fragments.clone(),
            tools: self.tools.clone(),
            commands: self.commands.clone(),
        }
    }

    pub fn manifest(&self) -> Value {
        serde_json::json!({
            "hooks": self.hooks.iter().map(|hook| &hook.config.name).collect::<Vec<_>>(),
            "tools": self.tools,
            "commands": self.commands,
        })
    }

    pub fn commands(&self) -> &[CommandSpec] {
        &self.commands
    }

    pub fn take_question(&self) -> Option<PendingQuestion> {
        self.feedback.lock().unwrap().questions.pop_front()
    }

    pub fn has_questions(&self) -> bool {
        !self.feedback.lock().unwrap().questions.is_empty()
    }

    pub fn take_hint(&self) -> Option<Option<String>> {
        self.feedback.lock().unwrap().hint.take()
    }

    pub fn discard_questions(&self) {
        self.feedback.lock().unwrap().questions.clear();
    }

    pub fn answer(
        &self,
        pending: &PendingQuestion,
        answer: Option<&str>,
        attended: bool,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<(), String> {
        if self
            .hooks
            .get(pending.owner)
            .is_none_or(|hook| hook.config.name != pending.hook)
        {
            return Err("question does not belong to this hook manager".into());
        }
        if answer.is_some() && (!attended || cancellation.cancelled()) {
            return Err("unattended or cancelled questions cannot have an answer".into());
        }
        if answer.is_some_and(|value| {
            !pending
                .question
                .choices
                .iter()
                .any(|choice| choice.value == value)
        }) {
            return Err("answer is not one of the hook's choices".into());
        }
        let cancelled = cancellation.cancelled();
        let lifecycle = Cancellation::new();
        let interrupted = cancelled && crate::platform::take_interrupt();
        let token = if cancelled { &lifecycle } else { cancellation };
        let result = self
            .invoke(
                pending.owner,
                "answer",
                serde_json::json!({
                    "id": pending.question.id, "answer": answer, "attended": attended,
                    "cancelled": cancelled,
                }),
                session,
                token,
                notice,
            )
            .map(|_| ());
        if interrupted {
            crate::platform::note_interrupt();
        }
        result
    }

    pub fn command(
        &self,
        name: &str,
        argument: &str,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<(), String> {
        let index = self
            .command_owner
            .get(name)
            .copied()
            .ok_or_else(|| format!("unknown command /{name}"))?;
        self.invoke(
            index,
            "command",
            serde_json::json!({"name": name, "argument": argument}),
            session,
            cancellation,
            notice,
        )
        .map(|_| ())
    }

    pub fn transform_input(
        &self,
        mut input: String,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<String, String> {
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "input",
                serde_json::json!({"input": input}),
                session,
                cancellation,
                notice,
            )?;
            if let Some(transformed) = response.input {
                input = transformed;
            }
        }
        Ok(input)
    }

    pub fn transform_context(
        &self,
        mut messages: Vec<Message>,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<Vec<Message>, String> {
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "context",
                serde_json::json!({"messages": messages}),
                session,
                cancellation,
                notice,
            )?;
            if let Some(transformed) = response.messages {
                messages = transformed;
            }
            if let Some(context) = response.context {
                messages.push(context);
            }
        }
        Ok(messages)
    }

    pub fn permission_review(
        &self,
        call: &ToolCall,
        metadata: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> PermissionReview {
        let mut result = Decision::Ask;
        let mut details = Vec::new();
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "permission",
                serde_json::json!({"tool_call": call, "tool": metadata}),
                session,
                cancellation,
                notice,
            );
            let decision = match response {
                Ok(response) => {
                    if let Some(detail) = response.permission_detail {
                        let total = details.iter().map(String::len).sum::<usize>()
                            + detail.len()
                            + self.hooks[index].config.name.len()
                            + 2;
                        if detail.trim().is_empty() || total > 16 * 1024 || detail.contains('\0') {
                            notice(format!(
                                "permission hook {} returned invalid permission_detail; denying call",
                                self.hooks[index].config.name
                            ));
                            result = Decision::Deny;
                            continue;
                        }
                        details.push(format!("{}: {detail}", self.hooks[index].config.name));
                    }
                    response.decision.unwrap_or(Decision::Ask)
                }
                Err(error) => {
                    notice(format!(
                        "permission hook {} failed; denying call: {error}",
                        self.hooks[index].config.name
                    ));
                    Decision::Deny
                }
            };
            result = match (result, decision) {
                (_, Decision::Deny) => Decision::Deny,
                (Decision::Deny, _) => Decision::Deny,
                (_, Decision::Confirm) => Decision::Confirm,
                (Decision::Confirm, _) => Decision::Confirm,
                (_, Decision::Allow) => Decision::Allow,
                (current, Decision::Ask) => current,
            };
        }
        PermissionReview {
            decision: result,
            details,
        }
    }

    pub fn owns_tool(&self, name: &str) -> bool {
        self.tool_owner.contains_key(name)
    }

    pub fn tool_owner(&self, name: &str) -> Option<&str> {
        let index = *self.tool_owner.get(name)?;
        Some(&self.hooks[index].config.name)
    }

    pub fn approval_identity(&self, name: &str) -> Option<String> {
        let index = *self.tool_owner.get(name)?;
        let spec = self.tools.iter().find(|tool| tool.name == name)?;
        let config = &self.hooks[index].config;
        let identity = serde_json::json!({
            "name": name,
            "kind": "hook",
            "owner": config.name,
            "command": config.command,
            "events": config.events,
            "timeout_ms": config.timeout.as_millis(),
            "max_output_bytes": config.max_output_bytes,
            "spec": spec,
        });
        let bytes = serde_json::to_vec(&identity).ok()?;
        let digest = Sha256::digest(bytes);
        Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn execute_tool(
        &self,
        call: &ToolCall,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<ToolResult, String> {
        let index = self
            .tool_owner
            .get(&call.name)
            .copied()
            .ok_or_else(|| format!("no hook owns tool {:?}", call.name))?;
        let response = self.invoke(
            index,
            "tool_execute",
            serde_json::json!({"tool_call": call}),
            session,
            cancellation,
            notice,
        )?;
        response
            .tool_result
            .ok_or_else(|| format!("hook returned no result for tool {:?}", call.name))
    }

    pub fn transform_tool_result(
        &self,
        call: &ToolCall,
        mut result: ToolResult,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<ToolResult, String> {
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "tool_result",
                serde_json::json!({"tool_call": call, "tool_result": result}),
                session,
                cancellation,
                notice,
            )?;
            if let Some(transformed) = response.tool_result {
                result = transformed;
            }
        }
        Ok(result)
    }

    pub fn before_stop(
        &self,
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Option<String> {
        let mut messages = Vec::new();
        let mut bytes = 0;
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "before_stop",
                payload.clone(),
                session,
                cancellation,
                notice,
            );
            match response {
                Ok(response) => {
                    if let Some(message) = response.message.filter(|text| !text.trim().is_empty()) {
                        let added = message.len() + usize::from(!messages.is_empty());
                        if bytes + added > 4096 {
                            notice(format!(
                                "hook {}: before_stop messages exceed 4096 bytes; skipped",
                                self.hooks[index].config.name
                            ));
                        } else {
                            bytes += added;
                            messages.push(message);
                        }
                    }
                }
                Err(error) => notice(format!(
                    "before_stop hook {} failed: {error}",
                    self.hooks[index].config.name
                )),
            }
        }
        (!messages.is_empty()).then(|| messages.join("\n"))
    }

    pub fn before_compact(
        &self,
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<CompactionAdvice, String> {
        let mut combined = CompactionAdvice::default();
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "before_compact",
                payload.clone(),
                session,
                cancellation,
                notice,
            )?;
            if let Some(advice) = response.compaction {
                if advice.cancel {
                    combined.cancel = true;
                }
                if advice.focus.is_some() {
                    combined.focus = advice.focus;
                }
                if advice.output_reserve_tokens.is_some() {
                    combined.output_reserve_tokens = advice.output_reserve_tokens;
                }
                if advice.recent_tail_tokens.is_some() {
                    combined.recent_tail_tokens = advice.recent_tail_tokens;
                }
                if advice.summary.is_some() {
                    combined.summary = advice.summary;
                    combined.retained_tail = advice.retained_tail;
                }
            }
        }
        Ok(combined)
    }

    pub fn notify(
        &self,
        event: &str,
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) {
        for index in 0..self.hooks.len() {
            if let Err(error) =
                self.invoke(index, event, payload.clone(), session, cancellation, notice)
            {
                notice(format!(
                    "hook {} failed during {event}: {error}",
                    self.hooks[index].config.name
                ));
            }
        }
    }

    fn invoke(
        &self,
        index: usize,
        event_name: &str,
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<Response, String> {
        let hook = &self.hooks[index];
        if hook
            .config
            .events
            .as_ref()
            .is_some_and(|events| !events.iter().any(|event| event == event_name))
        {
            return Ok(Response::default());
        }
        let mut payload = payload;
        if event_name == "initialize"
            && let Some(fields) = payload.as_object_mut()
        {
            fields.insert(
                "subscribed_events".into(),
                serde_json::json!(hook.config.events),
            );
        }
        let event = Event {
            protocol_version: PROTOCOL_VERSION,
            event: event_name,
            hook: &hook.config.name,
            workspace: &self.workspace,
            session: SessionView {
                id: session.id(),
                path: session.path(),
                state: session.hook_state(&hook.config.name),
            },
            payload,
        };
        let stdin = serde_json::to_vec(&event)
            .map_err(|error| format!("cannot serialize hook event: {error}"))?;
        let output = run(
            &ProcessRequest {
                program: hook.config.command[0].clone(),
                args: hook.config.command[1..].to_vec(),
                cwd: self.workspace.clone(),
                stdin: Some(stdin),
                timeout: hook.config.timeout,
                max_output_bytes: hook.config.max_output_bytes,
                env: Vec::new(),
                remove_env: vec![crate::provider::KEY_ENV.to_string()],
            },
            cancellation,
            &mut |_, _| {},
        )
        .map_err(|error| error.to_string())?;
        if !output.stderr.trim().is_empty() {
            notice(format!(
                "hook {}: {}",
                hook.config.name,
                output.stderr.trim()
            ));
        }
        if output.cancelled {
            return Err("cancelled".to_string());
        }
        if output.timed_out {
            return Err(format!(
                "timed out after {}s",
                hook.config.timeout.as_secs()
            ));
        }
        if output.code != Some(0) {
            return Err(format!("exited unsuccessfully: {}", output.status));
        }
        if output.stdout_dropped > 0 {
            return Err(format!(
                "stdout exceeded {} bytes",
                hook.config.max_output_bytes
            ));
        }
        let raw: Value = serde_json::from_str(output.stdout.trim())
            .map_err(|error| format!("invalid JSON result: {error}"))?;
        validate_result_fields(event_name, &raw)?;
        let response: Response = serde_json::from_value(raw)
            .map_err(|error| format!("invalid result shape: {error}"))?;
        if response.protocol_version.unwrap_or(PROTOCOL_VERSION) != PROTOCOL_VERSION {
            return Err("hook returned an incompatible protocol_version".to_string());
        }
        if let Some(question) = &response.question {
            validate_question(question)?;
            if hook
                .config
                .events
                .as_ref()
                .is_some_and(|events| !events.iter().any(|event| event == "answer"))
            {
                return Err("hook asks a question but does not subscribe to answer".into());
            }
            if self.feedback.lock().unwrap().questions.len() >= 16 {
                return Err("hook questions exceed the pending limit (16)".into());
            }
        }
        if let Some(hint) = &response.hint
            && (hint.len() > 256 || hint.chars().any(char::is_control))
        {
            return Err("hook hint must be one line of at most 256 bytes".into());
        }
        if let Some(message) = response.notice.as_deref() {
            notice(format!("hook {}: {message}", hook.config.name));
        }
        if response.state.is_some() || response.context.is_some() {
            session.append_hook_state(&HookState {
                hook: hook.config.name.clone(),
                state: response
                    .state
                    .clone()
                    .or_else(|| session.hook_state(&hook.config.name))
                    .unwrap_or(Value::Null),
                context: response.context.clone(),
            })?;
        }
        let mut feedback = self.feedback.lock().unwrap();
        if let Some(question) = response.question.clone() {
            feedback.questions.push_back(PendingQuestion {
                owner: index,
                hook: hook.config.name.clone(),
                question,
            });
        }
        if let Some(hint) = &response.hint {
            feedback.hint = Some((!hint.is_empty()).then(|| hint.clone()));
        }
        Ok(response)
    }
}

fn validate_tool(tool: &ToolSpec) -> Result<(), String> {
    if tool.name.is_empty()
        || !tool
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!("invalid hook tool name {:?}", tool.name));
    }
    if !tool.parameters.is_object() {
        return Err(format!(
            "tool {:?} parameters must be a JSON object",
            tool.name
        ));
    }
    Ok(())
}

fn validate_command(command: &CommandSpec) -> Result<(), String> {
    if command.name.is_empty()
        || command.name.len() > 64
        || !command
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        || command.help.trim().is_empty()
        || command.help.len() > 256
        || command.help.chars().any(char::is_control)
    {
        return Err(format!(
            "invalid hook command {:?}: expected a name and one-line help",
            command.name
        ));
    }
    Ok(())
}

fn validate_question(question: &Question) -> Result<(), String> {
    let line = |text: &str, max| {
        !text.trim().is_empty() && text.len() <= max && !text.chars().any(char::is_control)
    };
    let mut values = HashSet::new();
    if !line(&question.id, 64)
        || !line(&question.text, 1024)
        || !(2..=6).contains(&question.choices.len())
        || question.choices.iter().any(|choice| {
            !line(&choice.value, 64) || !line(&choice.label, 256) || !values.insert(&choice.value)
        })
    {
        return Err("hook question needs an id, text and 2–6 distinct labeled choices".into());
    }
    Ok(())
}

fn validate_result_fields(event: &str, value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("hook result must be a JSON object")?;
    let mut allowed = HashSet::from([
        "protocol_version",
        "state",
        "context",
        "notice",
        "question",
        "hint",
    ]);
    match event {
        "initialize" => allowed.extend(["prompt_fragments", "tools", "commands"]),
        "input" => {
            allowed.insert("input");
        }
        "context" => {
            allowed.insert("messages");
        }
        "permission" => {
            allowed.insert("decision");
            allowed.insert("permission_detail");
        }
        "tool_execute" | "tool_result" => {
            allowed.insert("tool_result");
        }
        "before_compact" => {
            allowed.insert("compaction");
        }
        "before_stop" => {
            allowed.insert("message");
        }
        _ => {}
    }
    for field in object.keys() {
        if !allowed.contains(field.as_str()) {
            return Err(format!("field {field:?} is not valid for event {event:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Removes a test's fixture directory when the test ends.
    #[cfg(unix)]
    struct Root(PathBuf);

    #[cfg(unix)]
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn fixture(name: &str) -> (Root, PathBuf, Session) {
        let root = std::env::temp_dir().join(format!("gears-hooks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let store = crate::session::Store::with_root(&workspace, root.join("state")).unwrap();
        let session = store.create(true, None).unwrap();
        (Root(root), workspace, session)
    }

    #[cfg(unix)]
    fn hook(name: &str, script: &str, timeout: std::time::Duration) -> HookConfig {
        HookConfig {
            name: name.to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            events: None,
            timeout,
            max_output_bytes: 4096,
        }
    }

    #[test]
    fn event_fields_are_event_specific() {
        assert!(
            validate_result_fields(
                "permission",
                &serde_json::json!({"decision": "allow", "state": {"n": 1}})
            )
            .is_ok()
        );
        assert!(
            validate_result_fields(
                "permission",
                &serde_json::json!({"input": "not allowed here"})
            )
            .is_err()
        );
    }

    #[test]
    fn question_bounds_and_values_are_checked() {
        let question = Question {
            id: "publish".into(),
            text: "Publish?".into(),
            choices: vec![
                Choice {
                    value: "yes".into(),
                    label: "Publish".into(),
                },
                Choice {
                    value: "no".into(),
                    label: "Discard".into(),
                },
            ],
        };
        validate_question(&question).unwrap();
        let mut invalid = question.clone();
        invalid.choices[1].value = "yes".into();
        assert!(validate_question(&invalid).is_err());
        invalid = question.clone();
        invalid.text = "x".repeat(1025);
        assert!(validate_question(&invalid).is_err());
        invalid = question.clone();
        invalid.choices.truncate(1);
        assert!(validate_question(&invalid).is_err());
        invalid = question;
        invalid.choices[0].label = "two\nlines".into();
        assert!(validate_question(&invalid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn questions_route_answers_and_hints_without_accepting_unknown_values() {
        let (_root, workspace, mut session) = fixture("question-answer");
        let log = workspace.join("answer.json");
        let config = HookConfig {
            name: "owner".into(), events: Some(vec!["initialize".into(), "answer".into()]),
            command: vec!["/bin/sh".into(), "-c".into(),
                "event=$(cat); case \"$event\" in *'\"event\":\"initialize\"'*) printf '{\"hint\":\"Pending proposal\",\"question\":{\"id\":\"q1\",\"text\":\"Publish?\",\"choices\":[{\"value\":\"yes\",\"label\":\"Publish\"},{\"value\":\"no\",\"label\":\"Discard\"}]}}' ;; *) printf '%s' \"$event\" > \"$1\"; printf '{\"hint\":\"\",\"state\":{\"answered\":true}}' ;; esac".into(),
                "owner".into(), log.display().to_string()],
            timeout: std::time::Duration::from_secs(2), max_output_bytes: 4096,
        };
        let cancellation = Cancellation::new();
        let manager = Manager::initialize(
            vec![config.clone()],
            workspace.clone(),
            &[],
            Value::Object(Default::default()),
            &mut session,
            &cancellation,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(manager.take_hint(), Some(Some("Pending proposal".into())));
        assert_eq!(manager.take_hint(), None);
        let pending = manager.take_question().unwrap();
        assert_eq!(pending.hook, "owner");
        assert!(manager.take_question().is_none());
        assert!(
            manager
                .answer(
                    &pending,
                    Some("unknown"),
                    true,
                    &mut session,
                    &cancellation,
                    &mut |_| {}
                )
                .is_err()
        );
        assert!(!log.exists());
        assert!(
            manager
                .answer(
                    &pending,
                    Some("yes"),
                    false,
                    &mut session,
                    &cancellation,
                    &mut |_| {}
                )
                .is_err()
        );
        for (value, attended, cancelled) in [
            (Some("yes"), true, false),
            (None, false, false),
            (None, true, true),
        ] {
            if cancelled {
                cancellation.cancel();
                assert!(
                    manager
                        .answer(
                            &pending,
                            Some("yes"),
                            true,
                            &mut session,
                            &cancellation,
                            &mut |_| {}
                        )
                        .is_err()
                );
            }
            manager
                .answer(
                    &pending,
                    value,
                    attended,
                    &mut session,
                    &cancellation,
                    &mut |_| {},
                )
                .unwrap();
            let event: Value =
                serde_json::from_str(&std::fs::read_to_string(&log).unwrap()).unwrap();
            assert_eq!(event["event"], "answer");
            assert_eq!(event["payload"]["id"], "q1");
            assert_eq!(event["payload"]["answer"], serde_json::json!(value));
            assert_eq!(event["payload"]["attended"], attended);
            assert_eq!(event["payload"]["cancelled"], cancelled);
        }
        assert_eq!(manager.take_hint(), Some(None));
        assert_eq!(session.hook_state("owner").unwrap()["answered"], true);
        let mut unsubscribed = config;
        unsubscribed.events = Some(vec!["initialize".into()]);
        assert!(
            Manager::initialize(
                vec![unsubscribed],
                workspace.clone(),
                &[],
                Value::Object(Default::default()),
                &mut session,
                &Cancellation::new(),
                &mut |_| {}
            )
            .is_err()
        );
        std::fs::remove_dir_all(workspace.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn commands_reject_collisions_invalid_help_and_missing_subscriptions() {
        for (case, commands, events, expected) in [
            (
                "builtin",
                r#"[{"name":"help","help":"replacement"}]"#,
                None,
                "duplicate",
            ),
            (
                "duplicate",
                r#"[{"name":"review","help":"one"},{"name":"review","help":"two"}]"#,
                None,
                "duplicate",
            ),
            (
                "name",
                r#"[{"name":"/review","help":"one"}]"#,
                None,
                "invalid",
            ),
            (
                "help",
                r#"[{"name":"review","help":"two\nlines"}]"#,
                None,
                "invalid",
            ),
            (
                "subscription",
                r#"[{"name":"review","help":"one"}]"#,
                Some(vec!["initialize".into()]),
                "subscribe",
            ),
        ] {
            let (_root, workspace, mut session) = fixture(&format!("commands-{case}"));
            let mut config = hook(
                "fixture",
                &format!("cat >/dev/null; printf '%s' '{{\"commands\":{commands}}}'"),
                std::time::Duration::from_secs(2),
            );
            config.events = events;
            let result = Manager::initialize(
                vec![config],
                workspace.clone(),
                &[],
                Value::Object(Default::default()),
                &mut session,
                &Cancellation::new(),
                &mut |_| {},
            );
            assert!(
                matches!(result, Err(ref error) if error.contains(expected)),
                "{case}"
            );
            std::fs::remove_dir_all(workspace.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn tool_names_and_schemas_are_checked() {
        assert!(
            validate_tool(&ToolSpec::new(
                "valid_tool",
                "test",
                serde_json::json!({"type": "object"})
            ))
            .is_ok()
        );
        assert!(
            validate_tool(&ToolSpec::new(
                "bad tool",
                "test",
                serde_json::json!({"type": "object"})
            ))
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn transforms_are_ordered_and_state_is_durable() {
        let (_root, workspace, mut session) = fixture("ordered");
        let first = hook(
            "first",
            r#"event=$(cat)
case "$event" in
  *'"event":"initialize"'*) printf '%s' '{"state":{"ready":true}}' ;;
  *'"event":"input"'*) printf '%s' '{"input":"first"}' ;;
  *) printf '%s' '{}' ;;
esac"#,
            std::time::Duration::from_secs(2),
        );
        let second = hook(
            "second",
            r#"event=$(cat)
case "$event" in
  *'"event":"initialize"'*) printf '%s' '{}' ;;
  *'"event":"input"'*'"input":"first"'*) printf '%s' '{"input":"second"}' ;;
  *'"event":"input"'*) exit 7 ;;
  *) printf '%s' '{}' ;;
esac"#,
            std::time::Duration::from_secs(2),
        );
        let cancellation = Cancellation::new();
        let mut notices = Vec::new();
        let manager = Manager::initialize(
            vec![first, second],
            workspace,
            &[],
            Value::Object(Default::default()),
            &mut session,
            &cancellation,
            &mut |notice| notices.push(notice),
        )
        .unwrap();
        assert_eq!(
            manager
                .transform_input(
                    "original".to_string(),
                    &mut session,
                    &cancellation,
                    &mut |notice| notices.push(notice),
                )
                .unwrap(),
            "second"
        );
        assert_eq!(session.hook_state("first").unwrap()["ready"], true);
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_registered_tools_are_rejected() {
        let (_root, workspace, mut session) = fixture("duplicate-tool");
        let script = r#"cat >/dev/null
printf '%s' '{"tools":[{"name":"same","description":"test","parameters":{"type":"object"}}]}'"#;
        let result = Manager::initialize(
            vec![
                hook("one", script, std::time::Duration::from_secs(2)),
                hook("two", script, std::time::Duration::from_secs(2)),
            ],
            workspace,
            &[],
            Value::Object(Default::default()),
            &mut session,
            &Cancellation::new(),
            &mut |_| {},
        );
        assert!(matches!(result, Err(error) if error.contains("duplicate tool name")));
        let (_root, workspace, mut session) = fixture("reserved-tool");
        let result = Manager::initialize(
            vec![hook("one", script, std::time::Duration::from_secs(2))],
            workspace,
            &["same".to_string()],
            Value::Object(Default::default()),
            &mut session,
            &Cancellation::new(),
            &mut |_| {},
        );
        assert!(matches!(result, Err(error) if error.contains("duplicate tool name")));
    }

    #[cfg(unix)]
    #[test]
    fn permission_denial_wins_over_allow() {
        let (_root, workspace, mut session) = fixture("permission-order");
        let permission_hook = |name, decision| {
            hook(
                name,
                &format!(
                    r#"event=$(cat)
case "$event" in
  *'"event":"permission"'*) printf '%s' '{{"decision":"{decision}"}}' ;;
  *) printf '%s' '{{}}' ;;
esac"#
                ),
                std::time::Duration::from_secs(2),
            )
        };
        let cancellation = Cancellation::new();
        let manager = Manager::initialize(
            vec![
                permission_hook("allow", "allow"),
                permission_hook("deny", "deny"),
            ],
            workspace,
            &[],
            Value::Object(Default::default()),
            &mut session,
            &cancellation,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(
            manager
                .permission_review(
                    &ToolCall::new("c1", "sh", r#"{"command":"true"}"#),
                    Value::Null,
                    &mut session,
                    &cancellation,
                    &mut |_| {},
                )
                .decision,
            Decision::Deny
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_timeout_and_cancellation_deny_permission() {
        for (name, permission, cancellation) in [
            ("malformed", "printf '%s' not-json", Cancellation::new()),
            ("timeout", "sleep 1; printf '%s' '{}'", Cancellation::new()),
            ("cancel", "sleep 1; printf '%s' '{}'", {
                let cancellation = Cancellation::new();
                cancellation.cancel();
                cancellation
            }),
        ] {
            let (_root, workspace, mut session) = fixture(name);
            let script = format!(
                r#"event=$(cat)
case "$event" in
  *'"event":"permission"'*) {permission} ;;
  *) printf '%s' '{{}}' ;;
esac"#
            );
            let mut manager = Manager::initialize(
                vec![hook(name, &script, std::time::Duration::from_secs(2))],
                workspace,
                &[],
                Value::Object(Default::default()),
                &mut session,
                &Cancellation::new(),
                &mut |_| {},
            )
            .unwrap();
            if name == "timeout" {
                // The short deadline tests permission, not setup process scheduling.
                manager.hooks[0].config.timeout = std::time::Duration::from_millis(20);
            }
            let mut notices = Vec::new();
            assert_eq!(
                manager
                    .permission_review(
                        &ToolCall::new("c1", "sh", r#"{"command":"true"}"#),
                        Value::Null,
                        &mut session,
                        &cancellation,
                        &mut |notice| notices.push(notice),
                    )
                    .decision,
                Decision::Deny,
                "{name}"
            );
            assert!(notices.iter().any(|notice| notice.contains("denying")));
        }
    }

    #[cfg(unix)]
    #[test]
    fn only_subscribed_events_start_the_hook() {
        let (_root, workspace, mut session) = fixture("event-filter");
        let log = workspace.join("events");
        let script = format!(
            "cat >> '{}'; printf '\\n' >> '{}'; printf '{{\"decision\":\"allow\"}}'",
            log.display(),
            log.display()
        );
        let mut config = hook("policy", &script, std::time::Duration::from_secs(2));
        config.events = Some(vec!["permission".into()]);
        let manager = Manager::initialize(
            vec![config],
            workspace.clone(),
            &[],
            Value::Object(Default::default()),
            &mut session,
            &Cancellation::new(),
            &mut |_| {},
        )
        .unwrap();
        assert!(!log.exists());
        manager
            .transform_input(
                "unchanged".into(),
                &mut session,
                &Cancellation::new(),
                &mut |_| {},
            )
            .unwrap();
        assert!(!log.exists());
        assert_eq!(
            manager
                .permission_review(
                    &ToolCall::new("c1", "sh", "{}"),
                    Value::Null,
                    &mut session,
                    &Cancellation::new(),
                    &mut |_| {}
                )
                .decision,
            Decision::Allow
        );
        let events = std::fs::read_to_string(&log).unwrap();
        assert_eq!(events.lines().count(), 1);
        assert!(events.contains("\"event\":\"permission\""));
        let mut config = hook("disabled", "exit 1", std::time::Duration::from_secs(2));
        config.events = Some(Vec::new());
        let manager = Manager::initialize(
            vec![config],
            workspace,
            &[],
            Value::Object(Default::default()),
            &mut session,
            &Cancellation::new(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(
            manager
                .permission_review(
                    &ToolCall::new("c2", "sh", "{}"),
                    Value::Null,
                    &mut session,
                    &Cancellation::new(),
                    &mut |_| {}
                )
                .decision,
            Decision::Ask
        );
    }

    #[cfg(unix)]
    #[test]
    fn before_stop_messages_are_bounded_without_truncation() {
        for bytes in [4096, 4097] {
            let (_root, workspace, mut session) = fixture(&format!("stop-note-{bytes}"));
            let message = "x".repeat(bytes);
            let response = serde_json::json!({"message": message}).to_string();
            let mut config = hook(
                "check",
                &format!("cat >/dev/null; printf '%s' '{response}'"),
                std::time::Duration::from_secs(2),
            );
            config.events = Some(vec!["before_stop".into()]);
            config.max_output_bytes = 8192;
            let manager = Manager::initialize(
                vec![config],
                workspace,
                &[],
                Value::Object(Default::default()),
                &mut session,
                &Cancellation::new(),
                &mut |_| {},
            )
            .unwrap();
            let mut notices = Vec::new();
            let result = manager.before_stop(
                serde_json::json!({}),
                &mut session,
                &Cancellation::new(),
                &mut |notice| notices.push(notice),
            );
            if bytes == 4096 {
                assert_eq!(result.as_deref(), Some(message.as_str()));
                assert!(notices.is_empty());
            } else {
                assert!(result.is_none());
                assert!(
                    notices
                        .iter()
                        .any(|notice| notice.contains("exceed 4096 bytes"))
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn repeated_setup_replaces_registrations_and_preserves_the_previous_manager_on_failure() {
        let (_root, workspace, mut session) = fixture("setup-again");
        let response = workspace.join("response.json");
        std::fs::write(&response, r#"{"prompt_fragments":["first"]}"#).unwrap();
        let script = format!("cat >/dev/null; cat '{}'", response.display());
        let manager = Manager::initialize(
            vec![hook("setup", &script, std::time::Duration::from_secs(2))],
            workspace.clone(),
            &[],
            Value::Object(Default::default()),
            &mut session,
            &Cancellation::new(),
            &mut |_| {},
        )
        .unwrap();
        std::fs::write(&response, r#"{"prompt_fragments":["second"],"tools":[{"name":"registered","description":"fixture","parameters":{"type":"object"}}]}"#).unwrap();
        let next = manager
            .setup_again(
                &[],
                serde_json::json!({"reason":"new","provider":"local","model":"test/model"}),
                &mut session,
                &Cancellation::new(),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(next.initialized().prompt_fragments, ["second"]);
        assert!(next.owns_tool("registered"));
        assert_eq!(manager.initialized().prompt_fragments, ["first"]);
        assert!(!manager.owns_tool("registered"));
        assert!(
            next.setup_again(
                &["registered".into()],
                serde_json::json!({}),
                &mut session,
                &Cancellation::new(),
                &mut |_| {}
            )
            .is_err()
        );
        std::fs::write(&response, "invalid").unwrap();
        assert!(
            next.setup_again(
                &[],
                serde_json::json!({}),
                &mut session,
                &Cancellation::new(),
                &mut |_| {}
            )
            .is_err()
        );
        assert!(next.owns_tool("registered"));
        std::fs::write(&response, "{}").unwrap();
        let cleared = next
            .setup_again(
                &[],
                serde_json::json!({}),
                &mut session,
                &Cancellation::new(),
                &mut |_| {},
            )
            .unwrap();
        assert!(cleared.initialized().prompt_fragments.is_empty());
        assert!(!cleared.owns_tool("registered"));
    }
}
