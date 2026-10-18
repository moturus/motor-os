//! One provider loop with sessions, hooks, authorization, and compaction.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;

use crate::config::{Config, ContextConfig};
use crate::hooks::{Decision, Manager as Hooks, ToolResult};
use crate::permissions::{Grant, Grants};
use crate::process::{Cancellation, Stream};
use crate::prompt::Effective;
use crate::provider::{
    ContentBlock, EventSink, Message, Provider, ProviderError, Request, StreamEvent, ToolCall,
    ToolOutcome, ToolSpec, Usage, UsageMeter,
};
use crate::session::{
    Compaction, PermissionGrant, Session, SessionInfo, Store, ToolState, TreeItem,
};
use crate::tool_state::Overrides;
use crate::tools::{ExecutionContext, Registry};

const MODEL_STREAM_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub enum Event {
    Text(String),
    Reasoning(String),
    ToolStart {
        call_id: String,
        name: String,
        detail: String,
    },
    ToolOutput {
        name: String,
        stream: Stream,
        text: String,
    },
    ToolEnd {
        call_id: String,
        name: String,
        content: String,
        is_error: bool,
        outcome: ToolOutcome,
    },
    Permission(Permission),
    Notice(String),
    Hint(Option<String>),
    Usage {
        request: Usage,
        total: UsageMeter,
    },
    ModelChanged(String),
    SessionChanged(SessionSummary),
    TurnEnd {
        status: &'static str,
        tool_rounds: usize,
        last_entry_id: Option<String>,
    },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolStatus {
    pub name: String,
    pub enabled: bool,
    pub available: bool,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionStatus {
    pub name: String,
    pub identity: String,
    pub allow: bool,
    pub scope: &'static str,
    pub current: bool,
    pub identity_error: Option<String>,
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

/// The user's answer to one permission prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    Deny,
    Once,
    Session,
    Global,
    DenySession,
    DenyGlobal,
}

pub trait Approver {
    fn approve(&mut self, request: &Permission) -> Approval;

    fn answer(&mut self, _question: &crate::hooks::Question) -> Result<Option<String>, String> {
        Ok(None)
    }

    fn attended(&self) -> bool {
        true
    }
}

impl<F> Approver for F
where
    F: FnMut(&Permission) -> Approval,
{
    fn approve(&mut self, request: &Permission) -> Approval {
        self(request)
    }
}

pub type ProviderFactory = Arc<dyn Fn(&str) -> Result<Arc<dyn Provider>, String> + Send + Sync>;

/// Answers every question with a denial, for runs nobody is watching.
pub struct Unattended;

impl Approver for Unattended {
    fn approve(&mut self, _: &Permission) -> Approval {
        Approval::Deny
    }
    fn attended(&self) -> bool {
        false
    }
}

pub struct Runtime {
    provider: Arc<dyn Provider>,
    provider_name: String,
    provider_factory: Option<ProviderFactory>,
    store: Store,
    session: Session,
    hooks: Hooks,
    tools: Registry,
    /// The tools as configured, before saved enablement; `/reset` returns to them.
    configured_tools: Registry,
    tool_state_directory: PathBuf,
    prompt: Effective,
    model: String,
    max_tool_rounds: usize,
    context: ContextConfig,
    cancellation: Cancellation,
    usage: UsageMeter,
    startup_notices: Vec<String>,
    interactive: bool,
    hint: Option<String>,
    questions_answered: usize,
}

/// Choices beyond the configuration; the defaults suit an ordinary run.
#[derive(Default)]
pub struct Options {
    /// Tools to use instead of the configured ones.
    pub tools: Option<Registry>,
    /// Where tool enablement is saved, instead of the Gears directory.
    pub tool_state_directory: Option<PathBuf>,
}

impl Runtime {
    pub fn new(
        provider: Arc<dyn Provider>,
        store: Store,
        session: Session,
        config: &Config,
        model: String,
    ) -> Result<Self, String> {
        Self::with_options(provider, store, session, config, model, Options::default())
    }

    pub fn with_options(
        provider: Arc<dyn Provider>,
        store: Store,
        mut session: Session,
        config: &Config,
        model: String,
        options: Options,
    ) -> Result<Self, String> {
        let Options {
            tools,
            tool_state_directory,
        } = options;
        let mut tools = match tools {
            Some(tools) => tools,
            None => Registry::load_config(config)?,
        };
        let configured_tools = tools.clone();
        let tool_state_directory = match tool_state_directory {
            Some(directory) => directory,
            None => crate::directory::default_root()?,
        };
        crate::process::ensure_cleanup()?;
        let cancellation = Cancellation::new();
        let previous_identity = session.latest_runtime_identity();
        let mut startup_notices = Vec::new();
        startup_notices.extend(apply_tool_states(
            &mut tools,
            &Overrides::load(&tool_state_directory)?,
            &session,
        )?);
        if session.recovered_entries() > 0 {
            startup_notices.push(format!(
                "discarded {} incomplete session records after a crash",
                session.recovered_entries()
            ));
        }
        let reserved_names = tools
            .tools()
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        let provider_name = session.provider().unwrap_or_else(|| "default".to_string());
        let payload =
            serde_json::json!({"reason": "startup", "provider": provider_name, "model": model});
        let hooks = Hooks::initialize(
            config.hooks.clone(),
            store.workspace().to_path_buf(),
            &reserved_names,
            payload,
            &mut session,
            &cancellation,
            &mut |notice| startup_notices.push(notice),
        )?;
        let prompt = effective_prompt(store.workspace(), &tools, &hooks);
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
        let hint = hooks.take_hint().flatten();
        Ok(Self {
            provider,
            provider_name,
            provider_factory: None,
            store,
            session,
            hooks,
            tools,
            configured_tools,
            tool_state_directory,
            prompt,
            model,
            max_tool_rounds: config.max_tool_rounds,
            context: config.context,
            cancellation,
            usage,
            startup_notices,
            interactive: false,
            hint,
            questions_answered: 0,
        })
    }

    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }

    pub fn tools(&self) -> &Registry {
        &self.tools
    }

    pub fn tool_statuses(&self) -> Result<Vec<ToolStatus>, String> {
        let global = Overrides::load(&self.tool_state_directory)?;
        let session = self.session.tool_states()?;
        Ok(self
            .tools
            .tools()
            .iter()
            .map(|tool| {
                let source = if session.contains_key(&tool.name) {
                    "session"
                } else if global.tools.contains_key(&tool.name) {
                    "global"
                } else {
                    "config"
                };
                ToolStatus {
                    name: tool.name.clone(),
                    enabled: tool.enabled,
                    available: tool.process.command.is_some(),
                    source,
                }
            })
            .collect())
    }

    pub fn permission_statuses(&self) -> Result<Vec<PermissionStatus>, String> {
        let current = self.current_permission_identities()?;
        let mut statuses = Vec::new();
        for (identity, grant) in self.session.permission_grants()? {
            statuses.push(PermissionStatus {
                current: current
                    .get(&grant.name)
                    .and_then(|result| result.as_ref().ok())
                    == Some(&identity),
                identity_error: current
                    .get(&grant.name)
                    .and_then(|result| result.as_ref().err())
                    .cloned(),
                name: grant.name,
                identity,
                allow: grant
                    .allow
                    .expect("effective session grants have an answer"),
                scope: "session",
            });
        }
        for (identity, grant) in Grants::load(&self.tool_state_directory)?.by_identity {
            statuses.push(PermissionStatus {
                current: current
                    .get(&grant.name)
                    .and_then(|result| result.as_ref().ok())
                    == Some(&identity),
                identity_error: current
                    .get(&grant.name)
                    .and_then(|result| result.as_ref().err())
                    .cloned(),
                name: grant.name,
                identity,
                allow: grant.allow,
                scope: "global",
            });
        }
        statuses.sort_by(|left, right| {
            (&left.name, left.scope, &left.identity).cmp(&(
                &right.name,
                right.scope,
                &right.identity,
            ))
        });
        Ok(statuses)
    }

    pub fn revoke_permission(&mut self, name: &str, global_scope: bool) -> Result<(), String> {
        self.prepare_write()?;
        if global_scope {
            let mut grants = Grants::load(&self.tool_state_directory)?;
            let before = grants.by_identity.len();
            grants.by_identity.retain(|_, grant| grant.name != name);
            if grants.by_identity.len() == before {
                return Err(format!("no global grant for {name:?}"));
            }
            grants.save(&self.tool_state_directory)
        } else {
            let matching = self
                .session
                .permission_grants()?
                .into_iter()
                .filter(|(_, grant)| grant.name == name)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                return Err(format!("no session grant for {name:?}"));
            }
            for (_, grant) in matching {
                self.session.append_permission_grant(&PermissionGrant {
                    allow: None,
                    created_ms: crate::session::now_ms(),
                    ..grant
                })?;
            }
            Ok(())
        }
    }

    fn current_permission_identities(
        &self,
    ) -> Result<std::collections::BTreeMap<String, Result<String, String>>, String> {
        let mut identities = std::collections::BTreeMap::new();
        for tool in self.tools.tools() {
            identities.insert(tool.name.clone(), tool.approval_identity());
        }
        for tool in self.hooks.initialized().tools {
            let identity = self
                .hooks
                .approval_identity(&tool.name)
                .ok_or_else(|| format!("no approval identity for {:?}", tool.name))?;
            identities.insert(tool.name, Ok(identity));
        }
        Ok(identities)
    }

    pub fn set_tool_state(
        &mut self,
        name: &str,
        state: ToolState,
        global_scope: bool,
    ) -> Result<(), String> {
        self.prepare_write()?;
        if !self.tools.tools().iter().any(|tool| tool.name == name) {
            return Err(format!("unknown directory tool {name:?}"));
        }
        let mut global = Overrides::load(&self.tool_state_directory)?;
        if global_scope {
            match state {
                ToolState::Enabled => {
                    global.tools.insert(name.to_string(), true);
                }
                ToolState::Disabled => {
                    global.tools.insert(name.to_string(), false);
                }
                ToolState::Inherit => {
                    global.tools.remove(name);
                }
            }
            global.save(&self.tool_state_directory)?;
        } else {
            self.session.set_tool_state(name, state)?;
        }
        self.refresh_tools(&global)
    }

    fn refresh_tools(&mut self, global: &Overrides) -> Result<(), String> {
        let mut tools = self.tools.clone();
        let notices = apply_tool_states(&mut tools, global, &self.session)?;
        let prompt = effective_prompt(self.store.workspace(), &tools, &self.hooks);
        self.session.append_runtime_identity(&prompt.identity())?;
        self.tools = tools;
        self.prompt = prompt;
        self.startup_notices.extend(notices);
        Ok(())
    }

    fn save_approval(
        &mut self,
        name: &str,
        identity: &str,
        answer: Approval,
    ) -> Result<(), String> {
        let allow = match answer {
            Approval::Session | Approval::Global => Some(true),
            Approval::DenySession | Approval::DenyGlobal => Some(false),
            Approval::Once | Approval::Deny => None,
        };
        let Some(allow) = allow else {
            return Ok(());
        };
        let (kind, owner) = if let Some(tool) = self.tools.enabled(name) {
            ("process", tool.directory.display().to_string())
        } else {
            (
                "hook",
                self.hooks
                    .tool_owner(name)
                    .ok_or_else(|| format!("unknown tool {name:?}"))?
                    .to_string(),
            )
        };
        let created_ms = crate::session::now_ms();
        if matches!(answer, Approval::Global | Approval::DenyGlobal) {
            let mut grants = Grants::load(&self.tool_state_directory)?;
            grants.by_identity.insert(
                identity.to_string(),
                Grant {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    owner,
                    created_ms,
                    allow,
                },
            );
            grants.save(&self.tool_state_directory)
        } else {
            self.session.append_permission_grant(&PermissionGrant {
                name: name.to_string(),
                identity: identity.to_string(),
                kind: kind.to_string(),
                owner,
                created_ms,
                allow: Some(allow),
            })?;
            Ok(())
        }
    }

    pub fn take_startup_notices(&mut self) -> Vec<String> {
        if let Some(hint) = self.hooks.take_hint() {
            self.hint = hint;
        }
        std::mem::take(&mut self.startup_notices)
    }

    pub fn hook_commands(&self) -> &[crate::hooks::CommandSpec] {
        self.hooks.commands()
    }

    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    fn emit_hook_hint(&mut self, observer: &mut dyn Observer) -> Result<(), String> {
        if let Some(hint) = self.hooks.take_hint() {
            self.hint = hint.clone();
            observer.event(Event::Hint(hint))?;
        }
        Ok(())
    }

    pub fn hook_command(
        &mut self,
        name: &str,
        argument: &str,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        self.hook_command_with_approver(name, argument, &mut Unattended, observer)
    }

    pub fn hook_command_with_approver(
        &mut self,
        name: &str,
        argument: &str,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        self.prepare_write()?;
        self.cancellation.reset();
        self.questions_answered = 0;
        self.handle_hook_questions(approver, observer)?;
        emit_notices(observer, self.take_startup_notices())?;
        let mut notices = Vec::new();
        let result = self.hooks.command(
            name,
            argument,
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        );
        emit_notices(observer, notices)?;
        self.emit_hook_hint(observer)?;
        result?;
        self.handle_hook_questions(approver, observer)?;
        if self.cancellation.cancelled() {
            return Err("command cancelled".into());
        }
        Ok(())
    }

    pub fn pending_hook_questions(&self) -> bool {
        self.hooks.has_questions()
    }

    pub fn resolve_hook_questions(
        &mut self,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        self.prepare_write()?;
        self.questions_answered = 0;
        self.handle_hook_questions(approver, observer).map(|_| ())
    }

    fn handle_hook_questions(
        &mut self,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
    ) -> Result<bool, String> {
        let mut handled = false;
        while let Some(pending) = self.hooks.take_question() {
            handled = true;
            if self.questions_answered >= 16 {
                self.hooks.discard_questions();
                observer.event(Event::Notice(
                    "hook questions exceed the operation limit (16); skipped".into(),
                ))?;
                break;
            }
            self.questions_answered += 1;
            let attended = approver.attended();
            let mut answer = if attended && !self.cancellation.cancelled() {
                match approver.answer(&pending.question) {
                    Ok(answer) => answer,
                    Err(error) => {
                        observer.event(Event::Notice(format!(
                            "hook {} question failed: {error}",
                            pending.hook
                        )))?;
                        None
                    }
                }
            } else {
                None
            };
            if self.cancellation.cancelled() {
                answer = None;
            }
            if answer.as_ref().is_some_and(|value| {
                !pending
                    .question
                    .choices
                    .iter()
                    .any(|choice| &choice.value == value)
            }) {
                observer.event(Event::Notice(format!(
                    "hook {} question received an invalid choice; skipped",
                    pending.hook
                )))?;
                answer = None;
            }
            let mut notices = Vec::new();
            if let Err(error) = self.hooks.answer(
                &pending,
                answer.as_deref(),
                attended,
                &mut self.session,
                &self.cancellation,
                &mut |notice| notices.push(notice),
            ) {
                notices.push(format!("hook {} answer failed: {error}", pending.hook));
            }
            emit_notices(observer, notices)?;
            self.emit_hook_hint(observer)?;
            crate::process::ensure_cleanup()?;
        }
        Ok(handled)
    }

    /// Interfaces opt in explicitly; library and one-shot runs are unattended.
    pub fn set_interactive(&mut self, interactive: bool) -> Result<(), String> {
        self.prepare_write()?;
        self.interactive = interactive;
        Ok(())
    }

    fn prepare_write(&mut self) -> Result<(), String> {
        crate::process::ensure_cleanup()
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn provider_name(&self) -> &str {
        &self.provider_name
    }

    pub fn install_provider_factory(&mut self, factory: ProviderFactory) {
        self.provider_factory = Some(factory);
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
        self.prepare_write()?;
        emit_notices(observer, self.take_startup_notices())?;
        self.cancellation.reset();
        self.questions_answered = 0;
        self.handle_hook_questions(approver, observer)?;
        let mut notices = Vec::new();
        let input = self.hooks.transform_input(
            input,
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        )?;
        emit_notices(observer, notices)?;
        self.handle_hook_questions(approver, observer)?;
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

        let entries_before = self.session.entries().len();
        let mut tool_rounds = 0;
        let result = self
            .run_turn(approver, observer, &mut tool_rounds)
            .or_else(|error| {
                let recorded = self.session.entries()[entries_before..]
                    .iter()
                    .any(|entry| entry.kind == "turn_error");
                if recorded {
                    Err(error)
                } else {
                    self.fail_turn(error, self.cancellation.cancelled(), observer)
                }
            });
        let status = match &result {
            Ok(()) => "completed",
            Err(_) if self.cancellation.cancelled() => "cancelled",
            Err(_) => "error",
        };
        let last_entry_id = self.session.active_leaf().map(str::to_string);
        let payload = serde_json::json!({
            "status": status, "error": result.as_ref().err(),
            "tool_rounds": tool_rounds, "last_entry_id": last_entry_id,
        });
        let end_result = self
            .after_cancellation(status == "cancelled", |runtime| {
                runtime.notify("turn_end", payload, observer)
            })
            .and_then(|()| self.handle_hook_questions(approver, observer).map(|_| ()))
            .and_then(|()| {
                observer.event(Event::TurnEnd {
                    status,
                    tool_rounds,
                    last_entry_id,
                })
            });
        result.and(end_result)
    }

    fn run_turn(
        &mut self,
        approver: &mut dyn Approver,
        observer: &mut dyn Observer,
        tool_rounds: &mut usize,
    ) -> Result<(), String> {
        let mut stop_reminders = 0;
        for _ in 0..self.max_tool_rounds {
            self.maybe_compact(false, None, observer)?;
            let messages = loop {
                self.handle_hook_questions(approver, observer)?;
                let messages = self.session.context_messages()?;
                let mut notices = Vec::new();
                let messages = self.hooks.transform_context(
                    messages,
                    &mut self.session,
                    &self.cancellation,
                    &mut |notice| notices.push(notice),
                )?;
                emit_notices(observer, notices)?;
                let changed = self.handle_hook_questions(approver, observer)?;
                if !changed || self.questions_answered >= 16 {
                    break messages;
                }
            };
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
                    return self.fail_turn(error.to_string(), cancelled, observer);
                }
            };
            self.usage.add(&completion.usage);
            if completion.tool_calls.is_empty() && completion.content.trim().is_empty() {
                self.session.append_usage(&completion.usage)?;
                observer.event(Event::Usage {
                    request: completion.usage,
                    total: self.usage,
                })?;
                return self.fail_turn(
                    "model returned an empty reply".to_string(),
                    false,
                    observer,
                );
            }
            let assistant = completion.message();
            let entry = self.session.append_message(&assistant)?;
            self.notify(
                "entry",
                serde_json::json!({"id": entry, "type": "message", "role": "assistant"}),
                observer,
            )?;
            self.session.append_usage(&completion.usage)?;
            observer.event(Event::Usage {
                request: completion.usage,
                total: self.usage,
            })?;
            if completion.tool_calls.is_empty() {
                if *tool_rounds > 0 && stop_reminders < 3 {
                    let mut notices = Vec::new();
                    let reminder = self.hooks.before_stop(
                        serde_json::json!({"tool_rounds": tool_rounds, "last_entry_id": entry}),
                        &mut self.session,
                        &self.cancellation,
                        &mut |notice| notices.push(notice),
                    );
                    emit_notices(observer, notices)?;
                    if self.cancellation.cancelled() {
                        return self.fail_turn("turn cancelled".into(), true, observer);
                    }
                    if let Some(reminder) = reminder {
                        stop_reminders += 1;
                        let note = self
                            .session
                            .append_message(&Message::user(reminder.clone()))?;
                        self.notify("entry", serde_json::json!({"id": note, "type": "message", "role": "user", "source": "before_stop"}), observer)?;
                        observer.event(Event::Notice(format!("before_stop: {reminder}")))?;
                        continue;
                    }
                }
                return Ok(());
            }
            *tool_rounds += 1;
            let calls = completion.tool_calls;
            for (index, call) in calls.iter().cloned().enumerate() {
                if let Err(error) = self.execute_call(call, approver, observer) {
                    self.record_unstarted_calls(
                        &calls[index + 1..],
                        "an earlier call ended the round",
                        observer,
                    )?;
                    return self.fail_turn(error, self.cancellation.cancelled(), observer);
                }
                if self.cancellation.cancelled() {
                    self.record_unstarted_calls(&calls[index + 1..], "turn cancelled", observer)?;
                    return self.fail_turn("turn cancelled".to_string(), true, observer);
                }
            }
        }
        let error = format!("tool round limit ({}) reached", self.max_tool_rounds);
        self.fail_turn(error, false, observer)
    }

    /// Lifecycle hooks still observe a cancelled turn: they run with a fresh
    /// token, and the cancellation is restored for whatever follows.
    fn after_cancellation<T>(&mut self, cancelled: bool, run: impl FnOnce(&mut Self) -> T) -> T {
        if !cancelled {
            return run(self);
        }
        self.cancellation.reset();
        let result = run(self);
        self.cancellation.cancel();
        result
    }

    fn fail_turn(
        &mut self,
        error: String,
        cancelled: bool,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        let cancelled = cancelled || self.cancellation.cancelled();
        let entry = self.session.append_error(&error, cancelled)?;
        let notification = self.after_cancellation(cancelled, |runtime| {
            runtime.notify(
                "entry",
                serde_json::json!({"id": entry, "type": "turn_error"}),
                observer,
            )
        });
        // An observer failure must not replace the recorded turn error.
        let _ = notification;
        Err(error)
    }

    pub fn compact(
        &mut self,
        focus: Option<String>,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        self.prepare_write()?;
        self.cancellation.reset();
        if self.maybe_compact(true, focus, observer)? {
            Ok(())
        } else {
            Err("there is not enough history to compact".to_string())
        }
    }

    pub fn set_model(&mut self, model: String, observer: &mut dyn Observer) -> Result<(), String> {
        self.prepare_write()?;
        if model.trim().is_empty() {
            return Err("model id must not be empty".to_string());
        }
        self.cancellation.reset();
        let prepared = self.prepare_hook_setup("model_change", &self.provider_name.clone(), &model);
        emit_notices(observer, self.take_startup_notices())?;
        let (hooks, prompt) = prepared?;
        let entry = self.session.set_model(&model)?;
        self.session.append_runtime_identity(&prompt.identity())?;
        self.model = model.clone();
        self.hooks = hooks;
        self.prompt = prompt;
        self.notify(
            "model_change",
            serde_json::json!({"id": entry, "model": model}),
            observer,
        )?;
        observer.event(Event::ModelChanged(model))
    }

    pub fn set_provider(&mut self, name: &str, observer: &mut dyn Observer) -> Result<(), String> {
        self.prepare_write()?;
        if name == self.provider_name {
            return Ok(());
        }
        let factory = self
            .provider_factory
            .as_ref()
            .ok_or("provider switching is not configured")?;
        let provider = factory(name)?;
        self.cancellation.reset();
        let prepared = self.prepare_hook_setup("provider_change", name, &self.model.clone());
        emit_notices(observer, self.take_startup_notices())?;
        let (hooks, prompt) = prepared?;
        let entry = self.session.set_provider(name)?;
        self.session.append_runtime_identity(&prompt.identity())?;
        self.provider = provider;
        self.provider_name = name.to_string();
        self.hooks = hooks;
        self.prompt = prompt;
        self.notify(
            "provider_change",
            serde_json::json!({"id": entry, "provider": name}),
            observer,
        )?;
        observer.event(Event::Notice(format!("provider: {name}")))
    }

    /// Use what `/setup` chose. The same provider is reconnected too, since
    /// its address or key may have changed.
    pub fn apply_setup(
        &mut self,
        provider: &str,
        model: String,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        self.prepare_write()?;
        if provider == self.provider_name {
            let factory = self
                .provider_factory
                .as_ref()
                .ok_or("provider switching is not configured")?;
            self.provider = factory(provider)?;
        } else {
            self.set_provider(provider, observer)?;
        }
        self.set_model(model, observer)
    }

    pub fn save_default_selection(&mut self) -> Result<(), String> {
        self.prepare_write()?;
        crate::provider_choice::ProviderChoice::save_selection(&self.provider_name, &self.model)
    }

    pub fn set_name(&mut self, name: &str) -> Result<(), String> {
        self.prepare_write()?;
        self.session.set_name(name)?;
        Ok(())
    }

    pub fn set_label(&mut self, entry_id: &str, label: Option<&str>) -> Result<(), String> {
        self.prepare_write()?;
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
        self.prepare_write()?;
        let draft = self.session.select(id)?;
        self.refresh_tools(&Overrides::load(&self.tool_state_directory)?)?;
        Ok(draft)
    }

    pub fn new_session(&mut self, ephemeral: bool, name: Option<&str>) -> Result<(), String> {
        self.prepare_write()?;
        let session = self.store.create(ephemeral, name)?;
        self.install_session(session, "new")
    }

    /// Removes what the user and Gears added (see `crate::reset`) and continues
    /// in a new session. The provider, model and key of this run stay loaded.
    pub fn reset(&mut self) -> Result<usize, String> {
        // Leave the saved session first, so nothing writes into removed files.
        self.new_session(true, None)?;
        let removed = crate::reset::reset(&self.tool_state_directory, self.store.workspace())?;
        self.tools = self.configured_tools.clone();
        self.new_session(false, None)?;
        Ok(removed)
    }

    pub fn resume(&mut self, selector: &str) -> Result<(), String> {
        self.prepare_write()?;
        self.cancellation.reset();
        if self.session.id() == selector {
            return self.refresh_hooks("resume");
        }
        let session = self.store.open(selector)?;
        self.install_session(session, "resume")
    }

    pub fn clone_session(&mut self) -> Result<(), String> {
        self.prepare_write()?;
        let session = self.store.clone_active(&self.session)?;
        self.install_session(session, "clone")
    }

    pub fn fork_at(&mut self, entry_id: &str) -> Result<String, String> {
        self.prepare_write()?;
        let (session, draft) = self.store.fork_at_user(&self.session, entry_id)?;
        self.install_session(session, "fork")?;
        Ok(draft)
    }

    pub fn close(&mut self) -> Vec<String> {
        if let Err(error) = self.prepare_write() {
            self.startup_notices.push(error);
            return std::mem::take(&mut self.startup_notices);
        }
        let mut notices = self.take_startup_notices();
        self.cancellation.reset();
        self.hooks.notify(
            "session_end",
            serde_json::json!({"session_id": self.session.id()}),
            &mut self.session,
            &self.cancellation,
            &mut |notice| notices.push(notice),
        );
        self.questions_answered = 0;
        if let Err(error) = self.handle_hook_questions(&mut Unattended, &mut |event| {
            if let Event::Notice(text) = event {
                notices.push(text);
            }
            Ok(())
        }) {
            notices.push(error);
        }
        notices
    }

    fn refresh_hooks(&mut self, reason: &str) -> Result<(), String> {
        let (hooks, prompt) =
            self.prepare_hook_setup(reason, &self.provider_name.clone(), &self.model.clone())?;
        self.session.append_runtime_identity(&prompt.identity())?;
        self.hooks = hooks;
        self.prompt = prompt;
        Ok(())
    }

    fn prepare_hook_setup(
        &mut self,
        reason: &str,
        provider: &str,
        model: &str,
    ) -> Result<(Hooks, Effective), String> {
        let reserved = self
            .tools
            .tools()
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        let payload = serde_json::json!({"reason": reason, "provider": provider, "model": model});
        let hooks = self.hooks.setup_again(
            &reserved,
            payload,
            &mut self.session,
            &self.cancellation,
            &mut |notice| self.startup_notices.push(notice),
        )?;
        let prompt = effective_prompt(self.store.workspace(), &self.tools, &hooks);
        Ok((hooks, prompt))
    }

    fn install_session(&mut self, mut session: Session, reason: &str) -> Result<(), String> {
        self.cancellation.reset();
        let provider_name = session
            .provider()
            .unwrap_or_else(|| self.provider_name.clone());
        let provider = if provider_name != self.provider_name {
            let factory = self
                .provider_factory
                .as_ref()
                .ok_or("provider switching is not configured")?;
            Some(factory(&provider_name)?)
        } else {
            None
        };
        if session.provider().is_none() {
            session.set_provider(&provider_name)?;
        }
        if session.recovered_entries() > 0 {
            self.startup_notices.push(format!(
                "discarded {} incomplete session records after a crash",
                session.recovered_entries()
            ));
        }
        let mut tools = self.tools.clone();
        self.startup_notices.extend(apply_tool_states(
            &mut tools,
            &Overrides::load(&self.tool_state_directory)?,
            &session,
        )?);
        let model = session.model().unwrap_or_else(|| self.model.clone());
        if session.model().is_none() {
            session.set_model(&model)?;
        }
        let reserved = tools
            .tools()
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        let hooks = self.hooks.setup_again(
            &reserved,
            serde_json::json!({"reason": reason, "provider": provider_name, "model": model}),
            &mut session,
            &self.cancellation,
            &mut |notice| self.startup_notices.push(notice),
        )?;
        let prompt = effective_prompt(self.store.workspace(), &tools, &hooks);
        let identity = prompt.identity();
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
        self.hooks.notify(
            "session_end",
            serde_json::json!({"session_id": self.session.id()}),
            &mut self.session,
            &self.cancellation,
            &mut |notice| self.startup_notices.push(notice),
        );
        if let Some(provider) = provider {
            self.provider = provider;
            self.provider_name = provider_name;
        }
        self.session = session;
        self.model = model;
        self.tools = tools;
        self.hooks = hooks;
        self.prompt = prompt;
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
        if self.tools.enabled(&call.name).is_none() && !self.hooks.owns_tool(&call.name) {
            let reason = format!("unknown or disabled tool {:?}", call.name);
            return self.record_unstarted_calls(std::slice::from_ref(&call), &reason, observer);
        }
        let detail = if let Some(tool) = self.tools.enabled(&call.name) {
            match tool.display_detail(&call.arguments) {
                Ok(Some(detail)) => detail,
                Ok(None) => call_detail(&call),
                Err(error) => {
                    return self.record_unstarted_calls(
                        std::slice::from_ref(&call),
                        &error,
                        observer,
                    );
                }
            }
        } else {
            call_detail(&call)
        };
        let identity = if let Some(tool) = self.tools.enabled(&call.name) {
            tool.approval_identity()
        } else {
            self.hooks
                .approval_identity(&call.name)
                .ok_or_else(|| format!("no approval identity for {:?}", call.name))
        };
        let identity = match identity {
            Ok(identity) => identity,
            Err(error) => {
                return self.record_unstarted_calls(std::slice::from_ref(&call), &error, observer);
            }
        };
        let saved_answer = (|| {
            let session = self.session.permission_grants()?;
            let global = Grants::load(&self.tool_state_directory)?;
            Ok::<_, String>(
                session
                    .get(&identity)
                    .and_then(|grant| grant.allow)
                    .or_else(|| global.by_identity.get(&identity).map(|grant| grant.allow)),
            )
        })();
        let saved_answer = match saved_answer {
            Ok(answer) => answer,
            Err(error) => {
                return self.record_unstarted_calls(std::slice::from_ref(&call), &error, observer);
            }
        };
        let mut notices = Vec::new();
        let review = if saved_answer == Some(false) {
            crate::hooks::PermissionReview {
                decision: Decision::Deny,
                details: Vec::new(),
            }
        } else {
            self.hooks.permission_review(
                &call,
                self.tool_metadata(&call.name),
                &mut self.session,
                &self.cancellation,
                &mut |notice| notices.push(notice),
            )
        };
        let mut detail = detail;
        for additional in review.details {
            detail.push('\n');
            detail.push_str(&additional);
        }
        let permission = Permission {
            tool: call.name.clone(),
            detail: detail.clone(),
            workspace: self.store.workspace().to_path_buf(),
        };
        if let Err(error) = observer.event(Event::Permission(permission.clone())) {
            self.record_unstarted_calls(
                std::slice::from_ref(&call),
                "permission event failed",
                observer,
            )?;
            return Err(error);
        }
        if let Err(error) = emit_notices(observer, notices) {
            self.record_unstarted_calls(
                std::slice::from_ref(&call),
                "permission notice failed",
                observer,
            )?;
            return Err(error);
        }
        if let Err(error) = self.handle_hook_questions(approver, observer) {
            self.record_unstarted_calls(std::slice::from_ref(&call), &error, observer)?;
            return Err(error);
        }
        let allowed = match review.decision {
            Decision::Deny => false,
            Decision::Allow => true,
            Decision::Ask if saved_answer == Some(true) && approver.attended() => true,
            Decision::Ask | Decision::Confirm if approver.attended() => {
                let answer = approver.approve(&permission);
                if let Err(error) = self.save_approval(&call.name, &identity, answer) {
                    return self.record_unstarted_calls(
                        std::slice::from_ref(&call),
                        &error,
                        observer,
                    );
                }
                matches!(
                    answer,
                    Approval::Once | Approval::Session | Approval::Global
                )
            }
            Decision::Ask | Decision::Confirm => false,
        };
        if let Err(error) = observer.event(Event::ToolStart {
            call_id: call.id.clone(),
            name: call.name.clone(),
            detail,
        }) {
            self.record_unstarted_calls(
                std::slice::from_ref(&call),
                "tool start event failed",
                observer,
            )?;
            return Err(error);
        }
        if self.cancellation.cancelled() {
            self.record_unstarted_calls(std::slice::from_ref(&call), "turn cancelled", observer)?;
            return Err("turn cancelled".into());
        }
        let mut post_error = None;
        let (result, outcome) = if !allowed {
            (
                ToolResult {
                    content: "tool call denied".to_string(),
                    is_error: true,
                },
                ToolOutcome::NotStarted,
            )
        } else if let Some(tool) = self.tools.enabled(&call.name) {
            let shell_state = tool
                .process
                .shell_state
                .then(|| self.session.shell_state_directory())
                .transpose();
            match shell_state {
                Ok(path) => self.execute_directory_tool(tool, &call, path.as_deref(), observer),
                Err(error) => (
                    ToolResult {
                        content: error,
                        is_error: true,
                    },
                    ToolOutcome::NotStarted,
                ),
            }
        } else if self.hooks.owns_tool(&call.name) {
            let mut notices = Vec::new();
            let result = self.hooks.execute_tool(
                &call,
                &mut self.session,
                &self.cancellation,
                &mut |notice| notices.push(notice),
            );
            if let Err(error) = emit_notices(observer, notices) {
                post_error.get_or_insert(error);
            }
            let outcome = if self.cancellation.cancelled() {
                ToolOutcome::InterruptedUnknown
            } else {
                ToolOutcome::Completed
            };
            (
                result.unwrap_or_else(|error| ToolResult {
                    content: error,
                    is_error: true,
                }),
                outcome,
            )
        } else {
            (
                ToolResult {
                    content: format!("unknown tool {:?}", call.name),
                    is_error: true,
                },
                ToolOutcome::NotStarted,
            )
        };
        let result = if self.cancellation.cancelled() {
            result
        } else {
            let mut notices = Vec::new();
            let transformed = self.hooks.transform_tool_result(
                &call,
                result.clone(),
                &mut self.session,
                &self.cancellation,
                &mut |notice| notices.push(notice),
            );
            if let Err(error) = emit_notices(observer, notices) {
                post_error.get_or_insert(error);
            }
            match transformed {
                Ok(transformed) => transformed,
                Err(error) => {
                    post_error.get_or_insert(error);
                    result
                }
            }
        };
        let entry = self
            .session
            .append_message(&Message::tool_result_with_outcome(
                &call.id,
                &call.name,
                &result.content,
                result.is_error,
                outcome,
            ))?;
        let notification = self.notify(
            "entry",
            self.tool_entry(&entry, &call, &result, outcome),
            observer,
        );
        let end = observer.event(Event::ToolEnd {
            call_id: call.id,
            name: call.name,
            content: result.content,
            is_error: result.is_error,
            outcome,
        });
        if let Err(error) = self.handle_hook_questions(approver, observer) {
            post_error.get_or_insert(error);
        }
        match post_error
            .or_else(|| crate::process::ensure_cleanup().err())
            .or(notification.err())
            .or(end.err())
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn record_unstarted_calls(
        &mut self,
        calls: &[ToolCall],
        reason: &str,
        observer: &mut dyn Observer,
    ) -> Result<(), String> {
        let cancelled = self.cancellation.cancelled();
        for call in calls {
            let content = format!("tool call not started: {reason}");
            let entry = self
                .session
                .append_message(&Message::tool_result_with_outcome(
                    &call.id,
                    &call.name,
                    &content,
                    true,
                    ToolOutcome::NotStarted,
                ))?;
            let notification = self.after_cancellation(cancelled, |runtime| {
                let payload = runtime.tool_entry(
                    &entry,
                    call,
                    &ToolResult {
                        content: content.clone(),
                        is_error: true,
                    },
                    ToolOutcome::NotStarted,
                );
                runtime.notify("entry", payload, observer)
            });
            let _ = notification;
            let _ = observer.event(Event::ToolEnd {
                call_id: call.id.clone(),
                name: call.name.clone(),
                content,
                is_error: true,
                outcome: ToolOutcome::NotStarted,
            });
        }
        Ok(())
    }

    fn tool_metadata(&self, name: &str) -> serde_json::Value {
        let tool = self.tools.enabled(name);
        let shell_state = tool
            .is_some_and(|tool| tool.process.shell_state)
            .then(|| self.session.shell_state_path())
            .flatten();
        serde_json::json!({"read_only": tool.is_some_and(|tool| tool.read_only),
            "shell_state_directory": shell_state})
    }

    fn tool_entry(
        &self,
        id: &str,
        call: &ToolCall,
        result: &ToolResult,
        outcome: ToolOutcome,
    ) -> serde_json::Value {
        let mut end = result.content.len().min(64 * 1024);
        while !result.content.is_char_boundary(end) {
            end -= 1;
        }
        serde_json::json!({"id": id, "type": "message", "role": "tool",
            "tool_call": call, "tool": self.tool_metadata(&call.name), "outcome": outcome,
            "tool_result": {"content": &result.content[..end], "is_error": result.is_error},
            "tool_result_truncated": end < result.content.len()})
    }

    fn execute_directory_tool(
        &self,
        tool: &crate::tools::Tool,
        call: &ToolCall,
        shell_state: Option<&std::path::Path>,
        observer: &mut dyn Observer,
    ) -> (ToolResult, ToolOutcome) {
        let mut observer_error = None;
        let context = ExecutionContext {
            workspace: self.store.workspace(),
            session_id: self.session.id(),
            session_path: self.session.path(),
            shell_state,
        };
        let output = tool.execute(
            &call.arguments,
            &context,
            &self.cancellation,
            &mut |stream, text| {
                if let Err(error) = observer.event(Event::ToolOutput {
                    name: call.name.clone(),
                    stream,
                    text: text.to_string(),
                }) {
                    observer_error = Some(error);
                    self.cancellation.cancel();
                }
            },
        );
        if let Some(error) = observer_error {
            return (
                ToolResult {
                    content: error,
                    is_error: true,
                },
                ToolOutcome::InterruptedUnknown,
            );
        }
        match output {
            Ok(output) => {
                let interrupted = output.cancelled || output.timed_out;
                let failed = interrupted
                    || !output
                        .code
                        .is_some_and(|code| tool.process.normal_exit_statuses.contains(&code));
                let content = if tool.process.stdout_only && !failed {
                    output.model_stdout(MODEL_STREAM_BYTES)
                } else {
                    output.model_text(MODEL_STREAM_BYTES)
                };
                (
                    ToolResult {
                        content,
                        is_error: failed,
                    },
                    if interrupted {
                        ToolOutcome::InterruptedUnknown
                    } else {
                        ToolOutcome::Completed
                    },
                )
            }
            Err(error) => (
                ToolResult {
                    content: error.to_string(),
                    is_error: true,
                },
                if error.started {
                    ToolOutcome::InterruptedUnknown
                } else {
                    ToolOutcome::NotStarted
                },
            ),
        }
    }

    fn request(&self, messages: Vec<Message>, tools: bool) -> Request {
        let request = Request::new(&self.model, messages)
            .with_system(self.prompt.fragments().to_vec())
            .with_cancellation(self.cancellation.clone());
        if tools {
            let mut specs = Vec::new();
            specs.extend(self.tools.enabled_tools().map(crate::tools::Tool::spec));
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
        let prefix = self.request(Vec::new(), true);
        let tokens_before = estimate_request_tokens(&prefix.system, &messages, &prefix.tools);
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
                    system.push(format!(
                        "Additional focus: {}",
                        clipped_text(focus, self.context.window_tokens as usize / 2)
                    ));
                }
                let input = compaction_input(&older, self.context.window_tokens);
                let request = Request::new(&self.model, input)
                    .with_system(system)
                    .with_cancellation(self.cancellation.clone());
                if estimate_request_tokens(&request.system, &request.messages, &[])
                    >= self.context.window_tokens
                {
                    return Err("compaction instructions exceed the model limit".to_string());
                }
                let mut sink = CancellationSink {
                    cancellation: &self.cancellation,
                };
                let completion = self
                    .provider
                    .complete(&request, &mut sink)
                    .map_err(|error| format!("compaction failed: {error}"))?;
                self.usage.add(&completion.usage);
                self.session.append_usage(&completion.usage)?;
                observer.event(Event::Usage {
                    request: completion.usage,
                    total: self.usage,
                })?;
                if completion.content.trim().is_empty() {
                    return Err("compaction returned an empty summary".to_string());
                }
                (completion.content, retained_tail)
            }
        };
        let retained_tail = cap_tool_results(retained_tail, self.context.window_tokens);
        let compact_context = {
            let mut context = vec![Message::user(format!("[Conversation summary]\n{summary}"))];
            context.extend(retained_tail.clone());
            context
        };
        let hard_limit = self.context.window_tokens.saturating_sub(reserve);
        if estimate_request_tokens(&prefix.system, &compact_context, &prefix.tools) > hard_limit {
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
        let refreshed = self.refresh_hooks("compaction");
        emit_notices(observer, self.take_startup_notices())?;
        refreshed?;
        observer.event(Event::Notice("context compacted".to_string()))?;
        Ok(true)
    }

    fn ensure_fits(&self, messages: &[Message]) -> Result<(), String> {
        let limit = self
            .context
            .window_tokens
            .saturating_sub(self.context.output_reserve_tokens);
        let prefix = self.request(Vec::new(), true);
        let tokens = estimate_request_tokens(&prefix.system, messages, &prefix.tools);
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
        emit_notices(observer, notices)?;
        self.emit_hook_hint(observer)
    }
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
            StreamEvent::Notice(text) => Event::Notice(text),
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

fn apply_tool_states(
    tools: &mut Registry,
    global: &Overrides,
    session: &Session,
) -> Result<Vec<String>, String> {
    let session_states = session.tool_states()?;
    let mut notices = Vec::new();
    for name in global.tools.keys().chain(session_states.keys()) {
        if !tools.tools().iter().any(|tool| &tool.name == name) {
            notices.push(format!(
                "tool state refers to unconfigured directory tool {name:?}"
            ));
        }
    }
    notices.sort();
    notices.dedup();
    let states = tools
        .tools()
        .iter()
        .map(|tool| {
            let enabled = session_states
                .get(&tool.name)
                .map(|state| *state == ToolState::Enabled)
                .or_else(|| global.tools.get(&tool.name).copied())
                .unwrap_or(tool.enabled_by_default);
            (tool.name.clone(), enabled)
        })
        .collect::<Vec<_>>();
    for (name, enabled) in states {
        tools.set_enabled(&name, enabled)?;
    }
    Ok(notices)
}

fn effective_prompt(workspace: &std::path::Path, tools: &Registry, hooks: &Hooks) -> Effective {
    let manifest = serde_json::json!({
        "directory_tools": tools.enabled_tools().collect::<Vec<_>>(),
        "hooks": hooks.manifest(),
    });
    Effective::new(workspace, hooks.initialized().prompt_fragments, &manifest)
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

fn clipped_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let end = text.floor_char_boundary(max_bytes);
    format!("{} [truncated]", &text[..end])
}

fn cap_tool_results(mut messages: Vec<Message>, window_tokens: u64) -> Vec<Message> {
    let limit = window_tokens.saturating_div(8).saturating_mul(4) as usize;
    for message in &mut messages {
        for block in &mut message.content {
            if let ContentBlock::ToolResult { content, .. } = block
                && content.len() > limit
            {
                *content = clipped_text(content, limit);
            }
        }
    }
    messages
}

fn compaction_input(messages: &[Message], window_tokens: u64) -> Vec<Message> {
    let total_limit = window_tokens.saturating_div(2).saturating_mul(4) as usize;
    let item_limit = window_tokens.saturating_div(8).saturating_mul(4) as usize;
    let mut chunks = Vec::new();
    let mut used = 0;
    for message in messages.iter().rev() {
        let mut chunk = format!("{:?}:\n", message.role);
        for block in &message.content {
            match block {
                ContentBlock::Text { text } => chunk.push_str(&clipped_text(text, item_limit)),
                ContentBlock::ToolCall { call } => chunk.push_str(&format!(
                    "tool call {} {} {}",
                    call.id,
                    call.name,
                    clipped_text(&call.arguments, item_limit)
                )),
                ContentBlock::ToolResult {
                    tool_name,
                    content,
                    outcome,
                    ..
                } => chunk.push_str(&format!(
                    "tool result {tool_name} {outcome:?}: {}",
                    clipped_text(content, item_limit)
                )),
            }
            chunk.push('\n');
        }
        let remaining = total_limit.saturating_sub(used);
        if remaining == 0 {
            break;
        }
        let chunk = clipped_text(&chunk, remaining);
        used = used.saturating_add(chunk.len());
        chunks.push(chunk);
    }
    chunks.reverse();
    vec![Message::user(chunks.concat())]
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
    fn tool_state_precedence_and_stale_names() {
        let root =
            std::env::temp_dir().join(format!("gears-runtime-tool-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let store = Store::with_root(&root.join("workspace"), root.join("state")).unwrap();
        let mut session = store.create(true, None).unwrap();
        let mut registry = Registry::load(
            &[crate::config::ToolDirectory {
                directory: PathBuf::from("tools/sh"),
                enabled: true,
            }],
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        )
        .unwrap();
        let mut global = Overrides::default();
        global.tools.insert("sh".into(), false);
        global.tools.insert("removed".into(), true);
        let notices = apply_tool_states(&mut registry, &global, &session).unwrap();
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("removed"));
        assert!(registry.enabled("sh").is_none());
        session.set_tool_state("sh", ToolState::Enabled).unwrap();
        apply_tool_states(&mut registry, &global, &session).unwrap();
        assert!(registry.enabled("sh").is_some());
        session.set_tool_state("sh", ToolState::Inherit).unwrap();
        apply_tool_states(&mut registry, &global, &session).unwrap();
        assert!(registry.enabled("sh").is_none());
        drop(session);
        std::fs::remove_dir_all(root).unwrap();
    }

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
    fn retained_tool_result_is_capped_without_changing_history() {
        let original = vec![Message::tool_result("one", "sh", "x".repeat(10_000), false)];
        let retained = cap_tool_results(original.clone(), 800);
        assert!(retained[0].text_content().len() < 500);
        assert!(retained[0].text_content().contains("[truncated]"));
        assert_eq!(original[0].text_content().len(), 10_000);
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
