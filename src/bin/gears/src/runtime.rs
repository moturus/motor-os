//! One provider loop with sessions, hooks, authorization, and compaction.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;

use crate::config::{Config, ContextConfig};
use crate::hooks::{Decision, Manager as Hooks, ToolResult};
use crate::process::{Cancellation, Stream};
use crate::prompt::Effective;
use crate::provider::{
    EventSink, Message, Provider, ProviderError, Request, StreamEvent, ToolCall, ToolSpec,
    UsageMeter,
};
use crate::session::{Compaction, Session, SessionInfo, Store, TreeItem};

const PROCESS_OUTPUT_BYTES: usize = 1024 * 1024;
const MODEL_STREAM_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub enum Event {
    Text(String),
    Reasoning(String),
    ToolStart {
        name: String,
        detail: String,
    },
    ToolOutput {
        name: String,
        stream: Stream,
        text: String,
    },
    ToolEnd {
        name: String,
        content: String,
        is_error: bool,
    },
    Permission(Permission),
    Notice(String),
    Usage(String),
    ModelChanged(String),
    SessionChanged(SessionSummary),
    TurnEnd,
}

#[derive(Debug, Clone)]
pub struct Permission {
    pub tool: String,
    pub detail: String,
    pub workspace: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub path: Option<PathBuf>,
    pub name: Option<String>,
    pub entries: usize,
    pub ephemeral: bool,
}

pub trait Observer {
    fn event(&mut self, event: Event) -> Result<(), String>;
}

impl<F> Observer for F
where
    F: FnMut(Event) -> Result<(), String>,
{
    fn event(&mut self, event: Event) -> Result<(), String> {
        self(event)
    }
}

pub trait Approver {
    fn approve(&mut self, request: &Permission) -> bool;
}

impl<F> Approver for F
where
    F: FnMut(&Permission) -> bool,
{
    fn approve(&mut self, request: &Permission) -> bool {
        self(request)
    }
}

pub struct Runtime {
    provider: Arc<dyn Provider>,
    store: Store,
    session: Session,
    hooks: Hooks,
    prompt: Effective,
    model: String,
    sh_timeout: std::time::Duration,
    max_tool_rounds: usize,
    context: ContextConfig,
    cancellation: Cancellation,
    usage: UsageMeter,
    startup_notices: Vec<String>,
}

impl Runtime {
    pub fn new(
        provider: Arc<dyn Provider>,
        store: Store,
        mut session: Session,
        config: &Config,
        model: String,
    ) -> Result<Self, String> {
        let cancellation = Cancellation::new();
        let previous_identity = session.latest_runtime_identity();
        let mut startup_notices = Vec::new();
        let hooks = Hooks::initialize(
            config.hooks.clone(),
            store.workspace().to_path_buf(),
            &mut session,
            &cancellation,
            &mut |notice| startup_notices.push(notice),
        )?;
        let initialized = hooks.initialized();
        let manifest = serde_json::json!({
            "builtin_tools": [sh_spec()],
            "hooks": hooks.manifest(),
        });
        let prompt = Effective::new(store.workspace(), initialized.prompt_fragments, &manifest);
        let identity = prompt.identity();
        if previous_identity
            .as_ref()
            .is_some_and(|previous| previous != &identity)
        {
            startup_notices.push(
                "prompt or hook/tool resources changed since this session was last opened"
                    .to_string(),
            );
        }
        session.append_runtime_identity(&identity)?;
        if session.model().as_deref() != Some(model.as_str()) {
            session.set_model(&model)?;
        }
        hooks.notify(
            "session_start",
            serde_json::json!({"session_id": session.id()}),
            &mut session,
            &cancellation,
            &mut |notice| startup_notices.push(notice),
        );
        let usage = session.usage();
        Ok(Self {
            provider,
            store,
            session,
            hooks,
            prompt,
            model,
            sh_timeout: config.sh_timeout,
            max_tool_rounds: config.max_tool_rounds,
            context: config.context,
            cancellation,
            usage,
            startup_notices,
        })
    }

    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }

    pub fn take_startup_notices(&mut self) -> Vec<String> {
        std::mem::take(&mut self.startup_notices)
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn usage(&self) -> &UsageMeter {
        &self.usage
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            id: self.session.id().to_string(),
            path: self.session.path().map(PathBuf::from),
            name: self.session.name(),
            entries: self.session.entries().len(),
            ephemeral: self.session.is_ephemeral(),
        }
    }

    pub fn turn(
        &mut self,
        input: String,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        self.cancellation.reset();
        let mut notices = Vec::new();
        let input = self.hooks.transform_input(
            input,
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        )?;
        emit_notices(observer, notices)?;
        if input.trim().is_empty() {
            return Err("prompt must not be empty".to_string());
        }
        let entry = self.session.append_message(&Message::user(input.clone()))?;
        self.notify(
            "entry",
            serde_json::json!({"id": entry, "type": "message", "role": "user"}),
            observer,
        )?;
        self.notify("turn_start", serde_json::json!({"input": input}), observer)?;

        let result = self.run_turn(approver, observer);
        let payload = match &result {
            Ok(()) => serde_json::json!({"status": "completed"}),
            Err(error) => serde_json::json!({
                "status": if self.cancellation.cancelled() { "cancelled" } else { "error" },
                "error": error,
            }),
        };
        let end_result = self
            .notify("turn_end", payload, observer)
            .and_then(|()| observer.event(Event::TurnEnd));
        match result {
            Ok(()) => end_result,
            Err(error) => {
                let _ = end_result;
                Err(error)
            }
        }
    }

    fn run_turn(
        &mut self,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        for round in 0..self.max_tool_rounds {
            self.maybe_compact(false, None, observer)?;
            let mut messages = self.session.context_messages()?;
            let mut notices = Vec::new();
            messages = self.hooks.transform_context(
                messages,
                &mut self.session,
                &self.cancellation,
                &mut |notice| notices.push(notice),
            )?;
            emit_notices(observer, notices)?;
            self.ensure_fits(&messages)?;
            let request = self.request(messages, true);
            let completion = {
                let mut sink = RuntimeSink {
                    cancellation: &self.cancellation,
                    observer,
                };
                self.provider.complete(&request, &mut sink)
            };
            let completion = match completion {
                Ok(completion) => completion,
                Err(error) => {
                    let cancelled =
                        matches!(error, ProviderError::Aborted(_)) || self.cancellation.cancelled();
                    let entry = self.session.append_error(&error.to_string(), cancelled)?;
                    self.notify(
                        "entry",
                        serde_json::json!({"id": entry, "type": "turn_error"}),
                        observer,
                    )?;
                    return Err(error.to_string());
                }
            };
            self.usage.add(&completion.usage);
            let assistant = completion.message();
            let entry = self.session.append_message(&assistant)?;
            self.notify(
                "entry",
                serde_json::json!({"id": entry, "type": "message", "role": "assistant"}),
                observer,
            )?;
            self.session.append_usage(&completion.usage)?;
            observer.event(Event::Usage(self.usage.summary()))?;
            if completion.tool_calls.is_empty() {
                return Ok(());
            }
            for call in completion.tool_calls {
                self.execute_call(call, approver, observer)?;
                if self.cancellation.cancelled() {
                    let entry = self.session.append_error("turn cancelled", true)?;
                    self.notify(
                        "entry",
                        serde_json::json!({"id": entry, "type": "turn_error"}),
                        observer,
                    )?;
                    return Err("turn cancelled".to_string());
                }
            }
            if round + 1 == self.max_tool_rounds {
                let error = format!("tool round limit ({}) reached", self.max_tool_rounds);
                let entry = self.session.append_error(&error, false)?;
                self.notify(
                    "entry",
                    serde_json::json!({"id": entry, "type": "turn_error"}),
                    observer,
                )?;
                return Err(error);
            }
        }
        unreachable!("the bounded loop returns on its last round")
    }

    pub fn compact(
        &mut self,
        focus: Option<String>,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        self.cancellation.reset();
        if self.maybe_compact(true, focus, observer)? {
            Ok(())
        } else {
            Err("there is not enough history to compact".to_string())
        }
    }

    pub fn set_model(&mut self, model: String, observer: &mut dyn Observer) -> Result<(), String> {
        if model.trim().is_empty() {
            return Err("model id must not be empty".to_string());
        }
        self.model = model.clone();
        let entry = self.session.set_model(&model)?;
        self.notify(
            "model_change",
            serde_json::json!({"id": entry, "model": model}),
            observer,
        )?;
        observer.event(Event::ModelChanged(model))
    }

    pub fn set_name(&mut self, name: &str) -> Result<(), String> {
        self.session.set_name(name)?;
        Ok(())
    }

    pub fn set_label(&mut self, entry_id: &str, label: Option<&str>) -> Result<(), String> {
        self.session.set_label(entry_id, label)?;
        Ok(())
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionInfo>, String> {
        self.store.list()
    }

    pub fn tree(&self) -> Vec<TreeItem> {
        self.session.tree()
    }

    pub fn select_entry(&mut self, id: &str) -> Result<Option<String>, String> {
        self.session.select(id)
    }

    pub fn new_session(&mut self, ephemeral: bool, name: Option<&str>) -> Result<(), String> {
        let session = self.store.create(ephemeral, name)?;
        self.install_session(session)
    }

    pub fn resume(&mut self, selector: &str) -> Result<(), String> {
        if self.session.id() == selector {
            return Ok(());
        }
        let session = self.store.open(selector)?;
        self.install_session(session)
    }

    pub fn clone_session(&mut self) -> Result<(), String> {
        let session = self.store.clone_active(&self.session)?;
        self.install_session(session)
    }

    pub fn fork_at(&mut self, entry_id: &str) -> Result<String, String> {
        let (session, draft) = self.store.fork_at_user(&self.session, entry_id)?;
        self.install_session(session)?;
        Ok(draft)
    }

    pub fn close(&mut self) -> Vec<String> {
        let mut notices = Vec::new();
        self.hooks.notify(
            "session_end",
            serde_json::json!({"session_id": self.session.id()}),
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        );
        notices
    }

    fn install_session(&mut self, mut session: Session) -> Result<(), String> {
        self.hooks.notify(
            "session_end",
            serde_json::json!({"session_id": self.session.id()}),
            &mut self.session,
            &self.cancellation,
            &mut |notice| self.startup_notices.push(notice),
        );
        let identity = self.prompt.identity();
        if session
            .latest_runtime_identity()
            .as_ref()
            .is_some_and(|previous| previous != &identity)
        {
            self.startup_notices.push(
                "prompt or hook/tool resources changed since this session was last opened"
                    .to_string(),
            );
        }
        session.append_runtime_identity(&identity)?;
        if let Some(model) = session.model() {
            self.model = model;
        } else {
            session.set_model(&self.model)?;
        }
        self.session = session;
        self.usage = self.session.usage();
        self.hooks.notify(
            "session_start",
            serde_json::json!({"session_id": self.session.id()}),
            &mut self.session,
            &self.cancellation,
            &mut |notice| self.startup_notices.push(notice),
        );
        Ok(())
    }

    fn execute_call(
        &mut self,
        call: ToolCall,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        let detail = call_detail(&call);
        let permission = Permission {
            tool: call.name.clone(),
            detail: detail.clone(),
            workspace: self.store.workspace().to_path_buf(),
        };
        observer.event(Event::Permission(permission.clone()))?;
        let mut notices = Vec::new();
        let decision = self.hooks.permission(
            &call,
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        );
        emit_notices(observer, notices)?;
        let allowed = match decision {
            Decision::Deny => false,
            Decision::Allow => true,
            Decision::Ask => approver.approve(&permission),
        };
        observer.event(Event::ToolStart {
            name: call.name.clone(),
            detail,
        })?;
        let result = if !allowed {
            ToolResult {
                content: "tool call denied".to_string(),
                is_error: true,
            }
        } else if call.name == "sh" {
            self.execute_sh(&call, observer)
        } else if self.hooks.owns_tool(&call.name) {
            let mut notices = Vec::new();
            let result = self.hooks.execute_tool(
                &call,
                &mut self.session,
                &self.cancellation,
                &mut |notice| notices.push(notice),
            );
            emit_notices(observer, notices)?;
            result.unwrap_or_else(|error| ToolResult {
                content: error,
                is_error: true,
            })
        } else {
            ToolResult {
                content: format!("unknown tool {:?}", call.name),
                is_error: true,
            }
        };
        let mut notices = Vec::new();
        let result = self.hooks.transform_tool_result(
            &call,
            result,
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        )?;
        emit_notices(observer, notices)?;
        let entry = self.session.append_message(&Message::tool_result(
            &call.id,
            &call.name,
            &result.content,
            result.is_error,
        ))?;
        self.notify(
            "entry",
            serde_json::json!({"id": entry, "type": "message", "role": "tool"}),
            observer,
        )?;
        observer.event(Event::ToolEnd {
            name: call.name,
            content: result.content,
            is_error: result.is_error,
        })
    }

    fn execute_sh(&self, call: &ToolCall, observer: &mut dyn Observer) -> ToolResult {
        let arguments: Value = match serde_json::from_str(&call.arguments) {
            Ok(arguments) => arguments,
            Err(error) => {
                return ToolResult {
                    content: format!("invalid sh arguments: {error}"),
                    is_error: true,
                };
            }
        };
        let Some(command) = arguments.get("command").and_then(Value::as_str) else {
            return ToolResult {
                content: "sh requires a string field named command".to_string(),
                is_error: true,
            };
        };
        let mut observer_error = None;
        let output = crate::process::sh(
            self.store.workspace().to_path_buf(),
            command,
            self.sh_timeout,
            PROCESS_OUTPUT_BYTES,
            &self.cancellation,
            &mut |stream, text| {
                if let Err(error) = observer.event(Event::ToolOutput {
                    name: "sh".to_string(),
                    stream,
                    text: text.to_string(),
                }) {
                    observer_error = Some(error);
                    self.cancellation.cancel();
                }
            },
        );
        if let Some(error) = observer_error {
            return ToolResult {
                content: error,
                is_error: true,
            };
        }
        match output {
            Ok(output) => ToolResult {
                content: output.model_text(MODEL_STREAM_BYTES),
                is_error: !output.success(),
            },
            Err(error) => ToolResult {
                content: error,
                is_error: true,
            },
        }
    }

    fn request(&self, messages: Vec<Message>, tools: bool) -> Request {
        let request = Request::new(&self.model, messages)
            .with_system(self.prompt.fragments().to_vec())
            .with_cancellation(self.cancellation.clone());
        if tools {
            let mut specs = vec![sh_spec()];
            specs.extend(self.hooks.initialized().tools);
            request.with_tools(specs)
        } else {
            request
        }
    }

    fn maybe_compact(
        &mut self,
        force: bool,
        focus: Option<String>,
        observer: &mut dyn Observer,
    ) -> Result<bool, String> {
        let messages = self.session.context_messages()?;
        let tokens_before = estimate_request_tokens(
            self.prompt.fragments(),
            &messages,
            &self.request(Vec::new(), true).tools,
        );
        let threshold = self
            .context
            .window_tokens
            .saturating_sub(self.context.output_reserve_tokens);
        if !force && tokens_before <= threshold {
            return Ok(false);
        }
        let mut notices = Vec::new();
        let advice = self.hooks.before_compact(
            serde_json::json!({
                "automatic": !force,
                "focus": focus,
                "tokens_before": tokens_before,
                "window_tokens": self.context.window_tokens,
                "output_reserve_tokens": self.context.output_reserve_tokens,
                "recent_tail_tokens": self.context.recent_tail_tokens,
            }),
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        )?;
        emit_notices(observer, notices)?;
        if advice.cancel {
            observer.event(Event::Notice("compaction cancelled by hook".to_string()))?;
            return Ok(false);
        }
        let reserve = advice
            .output_reserve_tokens
            .unwrap_or(self.context.output_reserve_tokens);
        let tail_tokens = advice
            .recent_tail_tokens
            .unwrap_or(self.context.recent_tail_tokens);
        validate_compaction_limits(self.context.window_tokens, reserve, tail_tokens)?;
        let (older, retained_tail) = split_tail(&messages, tail_tokens);
        if older.is_empty() {
            return Ok(false);
        }
        let focus = advice.focus.or(focus);
        let (summary, retained_tail) = match advice.summary {
            Some(summary) => {
                let retained = advice
                    .retained_tail
                    .ok_or("before_compact supplied a summary without a complete retained_tail")?;
                (summary, retained)
            }
            None => {
                let mut system = vec![crate::prompt::COMPACTION.trim().to_string()];
                if let Some(focus) = focus.as_deref() {
                    system.push(format!("Additional focus: {focus}"));
                }
                let request = Request::new(&self.model, older)
                    .with_system(system)
                    .with_cancellation(self.cancellation.clone());
                let mut sink = CancellationSink {
                    cancellation: &self.cancellation,
                };
                let completion = self
                    .provider
                    .complete(&request, &mut sink)
                    .map_err(|error| format!("compaction failed: {error}"))?;
                self.usage.add(&completion.usage);
                self.session.append_usage(&completion.usage)?;
                if completion.content.trim().is_empty() {
                    return Err("compaction returned an empty summary".to_string());
                }
                (completion.content, retained_tail)
            }
        };
        let compact_context = {
            let mut context = vec![Message::user(format!("[Conversation summary]\n{summary}"))];
            context.extend(retained_tail.clone());
            context
        };
        let hard_limit = self.context.window_tokens.saturating_sub(reserve);
        if estimate_request_tokens(
            self.prompt.fragments(),
            &compact_context,
            &self.request(Vec::new(), true).tools,
        ) > hard_limit
        {
            return Err("compacted context still exceeds the model limit".to_string());
        }
        let entry = Compaction {
            summary,
            retained_tail,
            tokens_before,
        };
        let entry_id = self.session.append_compaction(&entry)?;
        self.notify(
            "entry",
            serde_json::json!({"id": entry_id, "type": "compaction"}),
            observer,
        )?;
        self.notify(
            "after_compact",
            serde_json::to_value(&entry).expect("compaction serializes"),
            observer,
        )?;
        observer.event(Event::Notice("context compacted".to_string()))?;
        Ok(true)
    }

    fn ensure_fits(&self, messages: &[Message]) -> Result<(), String> {
        let limit = self
            .context
            .window_tokens
            .saturating_sub(self.context.output_reserve_tokens);
        let tokens = estimate_request_tokens(
            self.prompt.fragments(),
            messages,
            &self.request(Vec::new(), true).tools,
        );
        if tokens > limit {
            Err(format!(
                "hook-transformed context is approximately {tokens} tokens; limit is {limit}"
            ))
        } else {
            Ok(())
        }
    }

    fn notify(
        &mut self,
        event: &str,
        payload: Value,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        let mut notices = Vec::new();
        self.hooks.notify(
            event,
            payload,
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        );
        emit_notices(observer, notices)
    }
}

fn sh_spec() -> ToolSpec {
    ToolSpec::new(
        "sh",
        "Run a shell command in the current working directory. The command is not sandboxed.",
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute."
                }
            },
            "required": ["command"],
            "additionalProperties": false
        }),
    )
}

fn call_detail(call: &ToolCall) -> String {
    if call.name == "sh"
        && let Ok(arguments) = serde_json::from_str::<Value>(&call.arguments)
        && let Some(command) = arguments.get("command").and_then(Value::as_str)
    {
        return command.to_string();
    }
    format!("{} {}", call.name, call.arguments)
}

fn emit_notices(observer: &mut dyn Observer, notices: Vec<String>) -> Result<(), String> {
    for notice in notices {
        observer.event(Event::Notice(notice))?;
    }
    Ok(())
}

struct RuntimeSink<'a> {
    cancellation: &'a Cancellation,
    observer: &'a mut dyn Observer,
}

impl EventSink for RuntimeSink<'_> {
    fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()> {
        if self.cancellation.cancelled() {
            return Err(std::io::Error::other("turn cancelled"));
        }
        let event = match event {
            StreamEvent::Text(text) => Event::Text(text),
            StreamEvent::Reasoning(text) => Event::Reasoning(text),
        };
        self.observer.event(event).map_err(std::io::Error::other)
    }
}

struct CancellationSink<'a> {
    cancellation: &'a Cancellation,
}

impl EventSink for CancellationSink<'_> {
    fn on_event(&mut self, _event: StreamEvent) -> std::io::Result<()> {
        if self.cancellation.cancelled() {
            Err(std::io::Error::other("turn cancelled"))
        } else {
            Ok(())
        }
    }
}

fn estimate_request_tokens(prompt: &[String], messages: &[Message], tools: &[ToolSpec]) -> u64 {
    let bytes = serde_json::to_vec(&(prompt, messages, tools))
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    u64::try_from(bytes.saturating_add(3) / 4)
        .unwrap_or(u64::MAX)
        .saturating_add(32)
}

fn estimate_messages(messages: &[Message]) -> u64 {
    let bytes = serde_json::to_vec(messages)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX);
    u64::try_from(bytes.saturating_add(3) / 4).unwrap_or(u64::MAX)
}

fn split_tail(messages: &[Message], tail_tokens: u64) -> (Vec<Message>, Vec<Message>) {
    let mut start = messages.len();
    while start > 0 {
        let candidate = start - 1;
        if estimate_messages(&messages[candidate..]) > tail_tokens && start < messages.len() {
            break;
        }
        start = candidate;
    }
    while start > 0 && messages[start].role == crate::provider::Role::Tool {
        start -= 1;
    }
    (messages[..start].to_vec(), messages[start..].to_vec())
}

fn validate_compaction_limits(window: u64, reserve: u64, tail: u64) -> Result<(), String> {
    if reserve >= window || tail >= window.saturating_sub(reserve) {
        return Err("hook returned invalid compaction thresholds".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_does_not_begin_with_a_tool_result() {
        let messages = vec![
            Message::user("old"),
            Message::assistant_response(String::new(), vec![ToolCall::new("one", "sh", "{}")]),
            Message::tool_result("one", "sh", "result", false),
            Message::assistant("done"),
        ];
        let (older, tail) = split_tail(&messages, 20);
        assert!(!older.is_empty());
        assert_ne!(tail.first().unwrap().role, crate::provider::Role::Tool);
    }

    #[test]
    fn sh_permission_displays_the_exact_command() {
        let call = ToolCall::new("one", "sh", r#"{"command":"printf '%s' hello"}"#);
        assert_eq!(call_detail(&call), "printf '%s' hello");
    }

    #[test]
    fn bad_compaction_thresholds_are_rejected() {
        assert!(validate_compaction_limits(100, 100, 1).is_err());
        assert!(validate_compaction_limits(100, 20, 80).is_err());
        assert!(validate_compaction_limits(100, 20, 10).is_ok());
    }
}
