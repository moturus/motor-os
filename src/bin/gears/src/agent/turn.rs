//! The agent loop: send the conversation and the tool schemas, stream the
//! reply, and if the model asked for tools — gate them, run them in order,
//! append the results, go round again. When it asks for none, the turn ends.
//!
//! Two invariants hold however a turn ends, because the session file is
//! written as this goes and a malformed transcript cannot be resumed: an
//! assistant message carrying tool calls is *always* followed by exactly one
//! result per call, and a cancelled or failed turn leaves the conversation at
//! a point the model can be asked from again.

use crate::agent::bus::{Bus, Decision, Gone, PermissionRequest};
use crate::agent::context::{self, Context, Policy};
use crate::agent::task::{HandoffReason, ItemState, Mode, Task};
use crate::provider::{
    ChatMessage, ChatRequest, FinishReason, ModelProvider, ProviderError, ToolCall, Usage,
    UsageMeter,
};
use crate::tools::{Registry, ToolResult, clip, describe, parse_args, task as task_tool};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPhase {
    Prepared,
    Decision,
    Result,
}

/// One durable stage in a prepared mutation's audit trail.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MutationEvent {
    pub phase: MutationPhase,
    /// Monotonic workspace generation after a successfully applied result.
    /// Zero denotes a non-applying stage or a record from an older Gears.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub generation: u64,
    pub digest: String,
    pub tool: String,
    pub permission_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<crate::tools::mutation::Change>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_artifact: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_artifact: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Where a conversation is recorded as it grows, so that it can be resumed.
/// The session file is the real one (`session.rs`); a conversation with no
/// journal simply forgets.
pub trait Journal: Send {
    fn message(&mut self, message: &ChatMessage) -> std::io::Result<()>;

    fn task(&mut self, _task: &crate::agent::task::Task) -> std::io::Result<()> {
        Ok(())
    }

    fn usage(&mut self, _usage: &Usage) -> std::io::Result<()> {
        Ok(())
    }

    fn mutation(&mut self, _event: &MutationEvent) -> std::io::Result<()> {
        Ok(())
    }

    fn verification(
        &mut self,
        _evidence: &crate::agent::verification::Evidence,
    ) -> std::io::Result<()> {
        Ok(())
    }

    /// A checkpoint: the `replaced` messages from `head` are gone, and these
    /// exact messages stand where they were.
    fn compaction(
        &mut self,
        _head: usize,
        _replaced: usize,
        _replacement: &[ChatMessage],
    ) -> std::io::Result<()> {
        Ok(())
    }
}

/// What an agent's work is allowed to cost. Sub-agents always share one,
/// because nobody is watching those (`agent/registry.rs`); the agent the user
/// is talking to gets one only where the user asked for it, and then it is the
/// whole run's ([`Purse`]).
pub trait Budget: Send + Sync {
    /// Asked before every completion. `Err` is why there will not be one, in
    /// a typed form that also carries the words the model and user read.
    fn check(&self) -> Result<(), BudgetExhausted>;

    /// What one completion cost, as the endpoint reported it.
    fn spent(&self, usage: &Usage);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    Tokens,
    Spend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetExhausted {
    kind: BudgetKind,
    message: String,
}

impl BudgetExhausted {
    pub fn tokens(message: impl Into<String>) -> BudgetExhausted {
        BudgetExhausted {
            kind: BudgetKind::Tokens,
            message: message.into(),
        }
    }

    pub fn spend(message: impl Into<String>) -> BudgetExhausted {
        BudgetExhausted {
            kind: BudgetKind::Spend,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> BudgetKind {
        self.kind
    }
}

impl std::fmt::Display for BudgetExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BudgetExhausted {}

/// Whether there is anything left to spend. USD where the endpoint prices its
/// completions, tokens where it does not (plan decision 10) — a budget that
/// cannot be counted in money is still a budget. `whose` names the pocket, and
/// is read by whoever is told there is nothing in it.
pub fn affordable(
    usd: Option<f64>,
    tokens: Option<u64>,
    spent: &UsageMeter,
    whose: &str,
) -> Result<(), BudgetExhausted> {
    if let Some(limit) = usd
        && let Some(cost) = spent.cost_usd()
        && cost >= limit
    {
        return Err(BudgetExhausted::spend(format!(
            "the {whose} budget of ${limit:.2} is spent (${cost:.4} so far)"
        )));
    }
    if let Some(limit) = tokens
        && spent.total_tokens() >= limit
    {
        return Err(BudgetExhausted::tokens(format!(
            "the {whose} budget of {limit} tokens is spent ({} so far)",
            spent.total_tokens()
        )));
    }
    Ok(())
}

/// What one gears run may do. The step cap is per *turn* — it is the backstop
/// against a model that calls tools forever — while the budget is the whole
/// run's, because a quota is not restored by the user typing again.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RunLimits {
    pub max_steps: usize,
    pub budget_usd: Option<f64>,
    pub budget_tokens: Option<u64>,
}

impl Default for RunLimits {
    fn default() -> RunLimits {
        RunLimits {
            max_steps: DEFAULT_MAX_STEPS,
            budget_usd: None,
            budget_tokens: None,
        }
    }
}

/// The run's purse: what everything charged on the user's behalf has cost,
/// against what they said it might. Sub-agents charge it through their own
/// (`agent/registry.rs`), because a bill hides where nobody is watching.
pub struct Purse {
    limits: RunLimits,
    spent: std::sync::Mutex<UsageMeter>,
}

impl Purse {
    pub fn new(limits: RunLimits) -> Purse {
        Purse {
            limits,
            spent: std::sync::Mutex::new(UsageMeter::new()),
        }
    }

    /// Whether the user set a cap at all. Without one there is nothing to hand
    /// an agent: an unlimited budget is the absence of a budget.
    pub fn capped(&self) -> bool {
        self.limits.budget_usd.is_some() || self.limits.budget_tokens.is_some()
    }

    pub fn spending(&self) -> UsageMeter {
        *self.spent.lock().unwrap()
    }
}

impl Budget for Purse {
    fn check(&self) -> Result<(), BudgetExhausted> {
        affordable(
            self.limits.budget_usd,
            self.limits.budget_tokens,
            &self.spent.lock().unwrap(),
            "run",
        )
    }

    fn spent(&self, usage: &Usage) {
        self.spent.lock().unwrap().add(usage);
    }
}

/// One agent's memory: what has been said, and what it has cost.
pub struct Conversation {
    model: String,
    messages: Vec<ChatMessage>,
    usage: UsageMeter,
    journal: Option<Box<dyn Journal>>,
}

impl Conversation {
    pub fn new(model: impl Into<String>) -> Conversation {
        Conversation {
            model: model.into(),
            messages: Vec::new(),
            usage: UsageMeter::new(),
            journal: None,
        }
    }

    /// Restart from a transcript that was read back off disk.
    pub fn resumed(
        model: impl Into<String>,
        messages: Vec<ChatMessage>,
        usage: UsageMeter,
    ) -> Conversation {
        Conversation {
            model: model.into(),
            messages,
            usage,
            journal: None,
        }
    }

    pub fn with_journal(mut self, journal: Box<dyn Journal>) -> Conversation {
        self.journal = Some(journal);
        self
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn messages(&self) -> &[ChatMessage] {
        &self.messages
    }

    pub fn usage(&self) -> UsageMeter {
        self.usage
    }

    /// The model's last word, if it had one: a sub-agent's answer, as its
    /// parent receives it. Only the last message counts — an earlier one is
    /// how the answer was arrived at rather than the answer, and offering it
    /// as one would be putting words in the model's mouth.
    pub fn answer(&self) -> Option<&str> {
        let last = self.messages.last()?;
        match last.role == crate::provider::Role::Assistant {
            true => last
                .content
                .as_deref()
                .map(str::trim)
                .filter(|text| !text.is_empty()),
            false => None,
        }
    }

    /// Append a message and record it. A journal that fails is switched off
    /// and complained about *once*: losing the session file is bad, dropping
    /// the work in progress is worse, and a session half-written in silence
    /// is worst of all.
    pub fn push(&mut self, message: ChatMessage) -> Result<(), String> {
        let failure = self
            .journal
            .as_mut()
            .and_then(|journal| journal.message(&message).err());
        self.messages.push(message);
        self.complain(failure)
    }

    pub fn record_task(&mut self, task: &crate::agent::task::Task) -> Result<(), String> {
        let failure = self
            .journal
            .as_mut()
            .and_then(|journal| journal.task(task).err());
        self.complain(failure)
    }

    fn record_mutation(&mut self, event: &MutationEvent) -> Result<(), String> {
        let failure = self
            .journal
            .as_mut()
            .and_then(|journal| journal.mutation(event).err());
        self.complain(failure)
    }

    /// Append one validated check record before a task refers to its id.
    pub fn record_verification(
        &mut self,
        evidence: &crate::agent::verification::Evidence,
    ) -> Result<(), String> {
        let failure = self
            .journal
            .as_mut()
            .and_then(|journal| journal.verification(evidence).err());
        self.complain(failure)
    }

    /// Replace tool results with stubs, and say what that saved. Nothing is
    /// journaled: the session file records what really happened, and what
    /// really happened is that the model was sent less of it.
    pub fn evict(&mut self, indices: &[usize]) -> usize {
        let mut saved = 0;
        for index in indices {
            if let Some(message) = self.messages.get_mut(*index) {
                saved += context::stub(message);
            }
        }
        saved
    }

    /// Replace a stretch of the conversation with a summary of it, and record
    /// that this happened so a resumed session sees the same thing. A gears
    /// too old to know the record steps over it and resumes the whole
    /// transcript instead: bigger than it need be, but never wrong.
    pub fn compact(&mut self, range: std::ops::Range<usize>, summary: &str) -> Result<(), String> {
        let replacement = context::replacement(summary, &self.messages[range.clone()]);
        let failure = self.journal.as_mut().and_then(|journal| {
            journal
                .compaction(range.start, range.len(), &replacement)
                .err()
        });
        self.messages.splice(range, replacement).for_each(drop);
        self.complain(failure)
    }

    fn add_usage(&mut self, usage: &Usage) -> Result<(), String> {
        let failure = self
            .journal
            .as_mut()
            .and_then(|journal| journal.usage(usage).err());
        self.usage.add(usage);
        self.complain(failure)
    }

    fn complain(&mut self, failure: Option<std::io::Error>) -> Result<(), String> {
        match failure {
            None => Ok(()),
            Some(e) => {
                self.journal = None;
                Err(format!("the session is no longer being recorded: {e}"))
            }
        }
    }
}

/// Why a turn stopped. Whatever it says has already been reported on the bus;
/// the value is for the caller's control flow — and, when a sub-agent's turn
/// is what stopped, for the parent, which is told what went wrong in a tool
/// result rather than left to infer it from the screen.
#[derive(Debug, PartialEq, Eq)]
pub enum Turned {
    /// The model answered.
    Done,
    /// The model asked a question and durably handed control to the user.
    Waiting,
    /// A ^C ended it. The conversation is back at a resumable point.
    Cancelled,
    /// It went wrong. The user can say something else, or the same thing
    /// again — gears does not retry on its own (plan decision 7).
    Failed(String),
    /// The interface went away; there is nothing to go on for.
    Gone,
}

/// A model that keeps calling tools and never answers is stopped here.
pub const DEFAULT_MAX_STEPS: usize = 64;

pub struct Agent<P> {
    provider: P,
    tools: Registry,
    conversation: Conversation,
    max_steps: usize,
    budget: Option<std::sync::Arc<dyn Budget>>,
    context: Context,
    /// Set when a checkpoint could not be made, so that one turn does not keep
    /// paying a completion to find that out again. A new prompt clears it: the
    /// user asking for something else is a new decision to spend.
    no_summary: bool,
    task: Option<TaskState>,
    mutation_generation: std::sync::Arc<std::sync::Mutex<u64>>,
    verification: Vec<crate::agent::verification::Evidence>,
    next_mode: Option<Mode>,
    task_notice: Option<String>,
}

pub(crate) type TaskView = std::sync::Arc<std::sync::Mutex<Option<Task>>>;

struct TaskState {
    current: Option<Task>,
    view: TaskView,
    workspace: Option<std::sync::Arc<crate::tools::Workspace>>,
}

/// Whether the remaining tool calls of one round should really run.
enum Flow {
    Run,
    Waiting,
    Cancelled,
    Failed(String),
}

impl<P: ModelProvider> Agent<P> {
    pub fn new(provider: P, tools: Registry, conversation: Conversation) -> Agent<P> {
        Agent {
            provider,
            tools,
            conversation,
            max_steps: DEFAULT_MAX_STEPS,
            budget: None,
            context: Context::new(Policy::default()),
            no_summary: false,
            task: None,
            mutation_generation: std::sync::Arc::new(std::sync::Mutex::new(0)),
            verification: Vec::new(),
            next_mode: None,
            task_notice: None,
        }
    }

    pub(crate) fn with_task(mut self, current: Option<Task>, view: TaskView) -> Agent<P> {
        *view.lock().unwrap() = current.clone();
        self.task = Some(TaskState {
            current,
            view,
            workspace: None,
        });
        self
    }

    pub(crate) fn with_mutation_generation(
        mut self,
        generation: std::sync::Arc<std::sync::Mutex<u64>>,
    ) -> Agent<P> {
        self.mutation_generation = generation;
        self
    }

    pub(crate) fn with_verification(
        mut self,
        verification: Vec<crate::agent::verification::Evidence>,
    ) -> Agent<P> {
        self.verification = verification;
        self
    }

    pub(crate) fn with_task_workspace(
        mut self,
        workspace: std::sync::Arc<crate::tools::Workspace>,
    ) -> Agent<P> {
        self.task
            .as_mut()
            .expect("task state must be installed before its workspace")
            .workspace = Some(workspace);
        self
    }

    pub fn with_max_steps(mut self, steps: usize) -> Agent<P> {
        self.max_steps = steps.max(1);
        self
    }

    pub fn with_context(mut self, policy: Policy) -> Agent<P> {
        self.context = Context::new(policy);
        self
    }

    pub(crate) fn select_mode(&mut self, mode: Mode) -> Result<String, String> {
        if self.current_task().is_some_and(|task| {
            !task.complete() || task.handoff().is_some() || task.pending_mode().is_some()
        }) {
            return Err(
                "the current task is still active; transition its mode through task control"
                    .to_string(),
            );
        }
        self.next_mode = Some(mode);
        Ok(format!(
            "next task mode: {}",
            crate::agent::mode::profile(mode).name
        ))
    }

    /// Record and, when allowed, apply a prepared mutation initiated directly
    /// by the user interface while the agent is idle.
    pub(crate) fn user_mutation(
        &mut self,
        prepared: crate::tools::mutation::Prepared,
        decision: Decision,
    ) -> Result<String, String> {
        let preview = self
            .tools
            .mutation_preview(&prepared, "user", None)
            .map_err(|error| format!("cannot retain approval preview: {error}"))?;
        self.conversation.record_mutation(&MutationEvent {
            phase: MutationPhase::Prepared,
            generation: 0,
            digest: prepared.digest().to_string(),
            tool: prepared.tool().to_string(),
            permission_key: prepared.permission_key().to_string(),
            changes: prepared.changes(),
            preview: Some(preview.text),
            preview_artifact: preview.artifact,
            request_artifact: None,
            detail: None,
        })?;
        self.conversation.record_mutation(&mutation_stage(
            &prepared,
            MutationPhase::Decision,
            0,
            match decision {
                Decision::Allow => "allow",
                Decision::Deny => "deny",
                Decision::Always => "always",
            }
            .to_string(),
        ))?;
        if !decision.allowed() {
            return Ok("checkpoint was not restored".to_string());
        }
        let result = self.apply_and_record_mutation(&prepared)?;
        match result.is_error() {
            true => Err(result.content),
            false => Ok(result.content),
        }
    }

    /// What the endpoint counted for the last request a *resumed* session
    /// made, out of the transcript. Without it the first request after a
    /// resume is the one request nobody has measured — which, on the session
    /// this exists for, is also the largest one there has been.
    pub fn measured(&mut self, prompt_tokens: u64) {
        self.context
            .observed(prompt_tokens, self.conversation.messages());
    }

    pub fn with_budget(mut self, budget: std::sync::Arc<dyn Budget>) -> Agent<P> {
        self.budget = Some(budget);
        self
    }

    pub fn conversation(&self) -> &Conversation {
        &self.conversation
    }

    pub fn usage(&self) -> UsageMeter {
        self.conversation.usage()
    }

    /// Answer one prompt, streaming everything the user should see to `bus`.
    pub fn turn(&mut self, prompt: &str, bus: &mut Bus) -> Turned {
        self.no_summary = false;
        if let Err(error) = self.prepare_task(prompt) {
            return match bus.failed(error.clone()) {
                Ok(()) => Turned::Failed(error),
                Err(Gone) => Turned::Gone,
            };
        }
        if let Some(notice) = self.task_notice.take()
            && bus.notice(notice).is_err()
        {
            return Turned::Gone;
        }
        if let Err(e) = self.conversation.push(ChatMessage::user(prompt))
            && bus.failed(e).is_err()
        {
            return Turned::Gone;
        }
        self.work(bus)
    }

    fn work(&mut self, bus: &mut Bus) -> Turned {
        for _ in 0..self.max_steps {
            // Between rounds, before anything is sent: a ^C that arrived while
            // a tool was running means this turn is over.
            if let Some(turned) = self.at_boundary(bus) {
                return turned;
            }
            if let Some(budget) = &self.budget
                && let Err(exhausted) = budget.check()
            {
                let reason = match exhausted.kind() {
                    BudgetKind::Tokens => HandoffReason::TokenLimit,
                    BudgetKind::Spend => HandoffReason::SpendLimit,
                };
                return self.limit_handoff(reason, exhausted.to_string(), bus);
            }
            if self.trim(bus).is_err() {
                return Turned::Gone;
            }
            // Again, because trimming can itself have taken a completion and
            // a while: a ^C during the summary stops the turn here rather than
            // buying one more answer nobody is waiting for.
            if let Some(turned) = self.at_boundary(bus) {
                return turned;
            }
            let mut messages = self.conversation.messages.clone();
            if let Some(task) = self.task_message() {
                let after_system = messages
                    .iter()
                    .take_while(|message| message.role == crate::provider::Role::System)
                    .count();
                messages.insert(after_system, task);
            }
            let request = ChatRequest::new(self.conversation.model.clone(), messages)
                .with_tools(self.tools.specs_for(self.mode_allows_mutations()));

            let completion = match self.provider.complete(&request, bus) {
                Ok(completion) => completion,
                Err(e) => return self.stopped(e, bus),
            };
            // Cancellation can land after the final streamed delta but before
            // the provider's end marker. Do not accept or journal that answer,
            // and do not let the request leak into the next turn.
            if let Some(turned) = self.interrupted(bus) {
                return turned;
            }
            // What the endpoint counted, and what it counted: the only honest
            // measure of how full the window is (`agent/context.rs`).
            self.context
                .observed(completion.usage.prompt_tokens, &request.messages);
            if let Some(budget) = &self.budget {
                budget.spent(&completion.usage);
            }
            if let Err(e) = self.conversation.add_usage(&completion.usage)
                && bus.failed(e).is_err()
            {
                return Turned::Gone;
            }
            if let Err(e) = self.conversation.push(completion.message())
                && bus.failed(e).is_err()
            {
                return Turned::Gone;
            }
            if completion.finish_reason == Some(FinishReason::Length)
                && bus
                    .notice("the model reached its output limit; the answer is cut short")
                    .is_err()
            {
                return Turned::Gone;
            }
            if !completion.wants_tools() {
                return Turned::Done;
            }
            match self.run_calls(&completion.tool_calls, bus) {
                Ok(Flow::Run) => {}
                Ok(Flow::Waiting) => return Turned::Waiting,
                Ok(Flow::Cancelled) => return Turned::Cancelled,
                Ok(Flow::Failed(error)) => return Turned::Failed(error),
                Err(Gone) => return Turned::Gone,
            }
        }
        let text = format!(
            "the model called tools {} times without answering; stopping",
            self.max_steps
        );
        self.limit_handoff(HandoffReason::StepLimit, text, bus)
    }

    fn prepare_task(&mut self, prompt: &str) -> Result<(), String> {
        if self.task.is_none() {
            return Ok(());
        }
        if let Some(mut current) = self.current_task().cloned() {
            if let Some(pending) = current.pending_mode().copied() {
                current.resolve_mode(pending.from(), pending.to(), false)?;
                self.save_task(current.clone())?;
                self.task_notice = Some(format!(
                    "cancelled pending mode transition {} -> {} before resuming",
                    crate::agent::mode::profile(pending.from()).name,
                    crate::agent::mode::profile(pending.to()).name
                ));
            }
            match current.handoff() {
                Some(handoff) if handoff.reason() != HandoffReason::Paused => {
                    let mut task = current.clone();
                    task.resume(handoff.reason())?;
                    return self.save_task(task);
                }
                Some(_) => return Ok(()),
                None => {}
            }
            if current.complete() {
                let mode = self.next_mode.take().unwrap_or(Mode::Code);
                let mut task = current;
                task.begin_next(prompt.to_string(), mode)?;
                self.save_task(task.clone())?;
                task.transition(1, ItemState::Pending, ItemState::Active, None)?;
                return self.save_task(task);
            }
            return Ok(());
        }
        let mode = self.next_mode.take().unwrap_or(Mode::Code);
        let mut task = Task::new(prompt.to_string(), vec![prompt.to_string()], mode)?;
        self.save_task(task.clone())?;
        task.transition(1, ItemState::Pending, ItemState::Active, None)?;
        self.save_task(task)
    }

    fn save_task(&mut self, task: Task) -> Result<(), String> {
        self.conversation.record_task(&task)?;
        let state = self.task.as_mut().expect("task state disappeared");
        state.current = Some(task.clone());
        *state.view.lock().unwrap() = Some(task);
        Ok(())
    }

    fn current_task(&self) -> Option<&Task> {
        self.task.as_ref()?.current.as_ref()
    }

    fn task_message(&self) -> Option<ChatMessage> {
        self.current_task().map(|task| {
            let profile = crate::agent::mode::profile(task.mode());
            let tools = self.tools.names_for(profile.tools.allows_mutation());
            ChatMessage::system(format!(
                "Active mode profile v{}:\n{}\nTools available in this mode (contract v{}): {}\n\
                 This inventory is authoritative; ignore tool names in older messages.\n\n\
                 Current task state (authoritative; do not infer state from older prose):\n{}",
                profile.version,
                profile.prompt,
                crate::tools::SPEC_VERSION,
                match tools.is_empty() {
                    true => "none".to_string(),
                    false => tools.join(", "),
                },
                task.compact()
            ))
        })
    }

    fn mode_profile(&self) -> &'static crate::agent::mode::Profile {
        crate::agent::mode::profile(self.current_task().map(Task::mode).unwrap_or(Mode::Code))
    }

    fn mode_allows_mutations(&self) -> bool {
        self.mode_profile().tools.allows_mutation()
    }

    /// Cut the conversation back to something the window will take, before the
    /// request goes out rather than after the endpoint has refused it.
    fn trim(&mut self, bus: &Bus) -> Result<(), Gone> {
        let task = self.task_message();
        let plan = self
            .context
            .plan_with_extra(self.conversation.messages(), task.as_slice());
        if !plan.evict.is_empty() {
            let saved = self.conversation.evict(&plan.evict);
            bus.notice(format!(
                "context: dropped {} old tool result{} ({saved} bytes) to make room",
                plan.evict.len(),
                match plan.evict.len() {
                    1 => "",
                    _ => "s",
                }
            ))?;
        }
        match plan.compact {
            Some(range) if !self.no_summary => self.checkpoint(range, bus),
            _ => Ok(()),
        }
    }

    /// Have the model summarize the oldest part of the conversation, and put
    /// the summary where that part was. It costs a completion, which is why it
    /// comes only once there is nothing left to stub.
    fn checkpoint(&mut self, range: std::ops::Range<usize>, bus: &Bus) -> Result<(), Gone> {
        bus.notice(format!(
            "context: summarizing {} messages to make room",
            range.len()
        ))?;
        let request = context::summary_request(
            self.conversation.model(),
            &self.conversation.messages()[..range.end],
        );
        let completion = match self.provider.complete(&request, &mut Quiet(bus)) {
            Ok(completion) => completion,
            // Not a failure of the turn. The request that follows may still
            // fit; if it does not, the endpoint says so in its own words, and
            // the conversation is exactly as it was.
            Err(e) => {
                self.no_summary = true;
                return bus.notice(format!("context: could not summarize: {e}"));
            }
        };
        if let Some(budget) = &self.budget {
            budget.spent(&completion.usage);
        }
        if let Err(e) = self.conversation.add_usage(&completion.usage) {
            bus.failed(e)?;
        }
        let summary = completion.content.trim().to_string();
        if summary.is_empty() {
            self.no_summary = true;
            return bus.notice("context: the summary came back empty; nothing was dropped");
        }
        if let Err(e) = self.conversation.compact(range, &summary) {
            bus.failed(e)?;
        }
        Ok(())
    }

    /// A ^C between rounds ends the turn: asking the model what to do next
    /// would be spending the user's money on an answer they have just said
    /// they do not want.
    fn interrupted(&self, bus: &Bus) -> Option<Turned> {
        if !bus.cancelled() {
            return None;
        }
        bus.take_cancel();
        Some(match bus.notice("cancelled") {
            Ok(()) => Turned::Cancelled,
            Err(Gone) => Turned::Gone,
        })
    }

    /// Stop scheduling at an atomic boundary until the UI resumes us.
    fn at_boundary(&mut self, bus: &Bus) -> Option<Turned> {
        if let Some(turned) = self.interrupted(bus) {
            return Some(turned);
        }
        if bus.paused()
            && let Err(error) = self.stop_task_for_pause()
        {
            return Some(match bus.failed(error.clone()) {
                Ok(()) => Turned::Failed(error),
                Err(Gone) => Turned::Gone,
            });
        }
        bus.wait_if_paused();
        if let Some(turned) = self.interrupted(bus) {
            return Some(turned);
        }
        if let Err(error) = self.resume_task_from_pause() {
            return Some(match bus.failed(error.clone()) {
                Ok(()) => Turned::Failed(error),
                Err(Gone) => Turned::Gone,
            });
        }
        None
    }

    fn stop_task_for_pause(&mut self) -> Result<(), String> {
        let Some(task) = self.current_task().cloned() else {
            return Ok(());
        };
        if task.handoff().is_some() {
            return Ok(());
        }
        let mut stopped = task;
        stopped.stop(HandoffReason::Paused, None)?;
        self.save_task(stopped)
    }

    fn resume_task_from_pause(&mut self) -> Result<(), String> {
        let Some(task) = self.current_task().cloned() else {
            return Ok(());
        };
        if task.handoff().map(|handoff| handoff.reason()) != Some(HandoffReason::Paused) {
            return Ok(());
        }
        let mut resumed = task;
        resumed.resume(HandoffReason::Paused)?;
        self.save_task(resumed)
    }

    fn limit_handoff(&mut self, reason: HandoffReason, text: String, bus: &Bus) -> Turned {
        if let Some(mut task) = self.current_task().cloned()
            && task.handoff().is_none()
            && let Err(error) = task.stop(reason, None).and_then(|()| self.save_task(task))
        {
            return match bus.failed(error.clone()) {
                Ok(()) => Turned::Failed(error),
                Err(Gone) => Turned::Gone,
            };
        }
        match bus.failed(text.clone()) {
            Ok(()) => Turned::Failed(text),
            Err(Gone) => Turned::Gone,
        }
    }

    /// Turn a failed completion into an outcome. A cancelled turn arrives here
    /// as an abort from the sink, and the cancel flag is what says whether the
    /// user asked for it or the interface simply went away.
    fn stopped(&mut self, e: ProviderError, bus: &Bus) -> Turned {
        if matches!(e, ProviderError::Aborted(_)) {
            if !bus.take_cancel() {
                return Turned::Gone;
            }
            return match bus.notice("cancelled") {
                Ok(()) => Turned::Cancelled,
                Err(Gone) => Turned::Gone,
            };
        }
        let text = e.to_string();
        match bus.failed(text.clone()) {
            Ok(()) => Turned::Failed(text),
            Err(Gone) => Turned::Gone,
        }
    }

    fn run_calls(&mut self, calls: &[ToolCall], bus: &mut Bus) -> Result<Flow, Gone> {
        let mut flow = Flow::Run;
        for call in calls {
            if matches!(&flow, Flow::Run)
                && let Some(turned) = self.at_boundary(bus)
            {
                flow = match turned {
                    Turned::Cancelled => Flow::Cancelled,
                    Turned::Failed(error) => Flow::Failed(error),
                    Turned::Gone => return Err(Gone),
                    Turned::Done | Turned::Waiting => unreachable!(),
                };
            }
            let result = match &flow {
                Flow::Run => self.call_tool(call, bus)?,
                // Every call is answered even when nothing ran: an assistant
                // message whose tool calls dangle cannot be sent again.
                Flow::Waiting => ToolResult::error("waiting for the user before this call can run"),
                Flow::Cancelled => ToolResult::error("cancelled before this call ran"),
                Flow::Failed(error) => {
                    ToolResult::error(format!("turn stopped before this call ran: {error}"))
                }
            };
            if let Err(e) = self.conversation.push(match result.retains_artifact() {
                true => {
                    ChatMessage::tool_result(call.id.clone(), result.content).retaining_artifact()
                }
                false => ChatMessage::tool_result(call.id.clone(), result.content),
            }) {
                bus.failed(e)?;
            }
            if matches!(&flow, Flow::Run) && self.waiting_for_user() {
                flow = Flow::Waiting;
            }
        }
        Ok(flow)
    }

    fn call_tool(&mut self, call: &ToolCall, bus: &Bus) -> Result<ToolResult, Gone> {
        let name = call.name();
        // Decoded twice — here to describe and to key the call, and again in
        // `dispatch`, which owns the one error path for arguments that are
        // nonsense. Cheap, and it keeps that error going to the model.
        let args = parse_args(call.arguments()).ok();
        bus.tool_start(describe(name, args.as_ref()))?;

        if !self.mode_allows_mutations()
            && self
                .tools
                .get(name)
                .is_some_and(crate::tools::Tool::mutates)
        {
            let result = ToolResult::error(crate::agent::mode::mutation_unavailable(
                name,
                self.mode_profile().mode,
            ));
            let (detail, full) = summarize(&result);
            bus.tool_end(result.outcome, detail, full)?;
            return Ok(result);
        }

        let mut verification_generation = self.mutation_generation();
        let mut result = match (self.tools.get(name), &args) {
            (Some(_), Some(args)) if name == task_tool::NAME => self.call_task(args, bus)?,
            (Some(tool), Some(args)) if tool.gated(args) => match tool.prepare_mutation(args) {
                Ok(Some(prepared)) => self.call_mutation(call, args, prepared, bus)?,
                Ok(None) => {
                    let request = PermissionRequest {
                        key: tool.permission_key(args),
                        detail: describe(name, Some(args)),
                        preview: None,
                    };
                    match bus.ask(request).allowed() {
                        true => {
                            let permission_key = tool.permission_key(args);
                            let mutates = tool.mutates();
                            tool.approved(args);
                            if mutates {
                                match self.call_opaque_mutation(
                                    call,
                                    permission_key,
                                    &bus.execution(),
                                ) {
                                    Ok((result, generation)) => {
                                        verification_generation = Ok(generation);
                                        result
                                    }
                                    Err(error) => {
                                        bus.failed(error.clone())?;
                                        ToolResult::error(error)
                                    }
                                }
                            } else {
                                self.tools.dispatch_call(
                                    name,
                                    call.arguments(),
                                    &call.id,
                                    &bus.execution(),
                                )
                            }
                        }
                        false => ToolResult::error(format!("the user did not allow {name} to run")),
                    }
                }
                Err(error) => ToolResult::error(format!("{name}: {error}")),
            },
            _ => self
                .tools
                .dispatch_call(name, call.arguments(), &call.id, &bus.execution()),
        };
        if result.verification.is_some()
            && let Err(error) = self.attach_verification(&mut result, verification_generation)
        {
            result.verification = None;
            result.outcome = crate::tools::ToolOutcome::ProtocolFailed;
            result.content = format!("{}\nverification: {error}", result.content);
        }
        let (detail, full) = summarize(&result);
        bus.tool_end(result.outcome, detail, full)?;
        Ok(result)
    }

    fn call_task(&mut self, args: &serde_json::Value, bus: &Bus) -> Result<ToolResult, Gone> {
        let operation = match task_tool::parse(args) {
            Ok(operation) => operation,
            Err(error) => return Ok(ToolResult::error(format!("task: {error}"))),
        };
        let Some(mut task) = self.current_task().cloned() else {
            return Ok(ToolResult::error("task state is unavailable"));
        };
        if let task_tool::Operation::Mode { from, to } = operation {
            return self.call_task_mode(task, from, to, bus);
        }
        let question = match operation {
            task_tool::Operation::Add { text } => task.add_item(text).map(|_| None),
            task_tool::Operation::Transition { id, from, to, text } => {
                task.transition(id, from, to, text).map(|()| None)
            }
            task_tool::Operation::Wait { question } => task
                .stop(HandoffReason::WaitingForUser, Some(question.clone()))
                .map(|()| Some(question)),
            task_tool::Operation::Mode { .. } => unreachable!(),
        };
        let question = match question {
            Ok(question) => question,
            Err(error) => return Ok(ToolResult::error(format!("task: {error}"))),
        };
        if let Err(error) = self.save_task(task.clone()) {
            bus.failed(error.clone())?;
            return Ok(ToolResult::error(error));
        }
        if let Some(question) = question {
            bus.notice(format!("waiting for user: {question}"))?;
        }
        Ok(ToolResult::ok(crate::trace::scrub(&task.compact())))
    }

    fn call_task_mode(
        &mut self,
        mut task: Task,
        from: Mode,
        to: Mode,
        bus: &Bus,
    ) -> Result<ToolResult, Gone> {
        if from == Mode::Plan
            && to == Mode::Code
            && let Err(error) = self.checkpoint_plan(&mut task)
        {
            return Ok(ToolResult::error(format!("task: {error}")));
        }
        if let Err(error) = task.request_mode(from, to) {
            return Ok(ToolResult::error(format!("task: {error}")));
        }
        if let Err(error) = self.save_task(task.clone()) {
            bus.failed(error.clone())?;
            return Ok(ToolResult::error(error));
        }

        let approved = if to == Mode::Code {
            let from_name = crate::agent::mode::profile(from).name;
            let checkpoint = task
                .checkpoint()
                .map_or_else(|| "none".to_string(), |id| id.to_string());
            bus.ask(PermissionRequest {
                key: format!(
                    "mode:{from_name}-to-code:task:{}:checkpoint:{checkpoint}",
                    task.generation()
                ),
                detail: format!("enter code mode from {from_name}"),
                preview: Some(crate::trace::scrub(&task.compact())),
            })
            .allowed()
        } else {
            true
        };
        if let Err(error) = task.resolve_mode(from, to, approved) {
            return Ok(ToolResult::error(format!("task: {error}")));
        }
        if let Err(error) = self.save_task(task.clone()) {
            bus.failed(error.clone())?;
            return Ok(ToolResult::error(error));
        }
        if !approved {
            return Ok(ToolResult::error(crate::agent::mode::code_denied()));
        }
        bus.notice(format!("mode: {}", crate::agent::mode::profile(to).name))?;
        Ok(ToolResult::ok(crate::trace::scrub(&task.compact())))
    }

    fn checkpoint_plan(&mut self, task: &mut Task) -> Result<(), String> {
        let workspace = self
            .task
            .as_ref()
            .and_then(|state| state.workspace.clone())
            .ok_or("plan checkpoint storage is unavailable")?;
        let metadata = workspace.create_checkpoint(
            &format!("plan at task generation {}", task.generation()),
            task.generation(),
            self.mutation_generation()?,
        )?;
        task.set_checkpoint(task.checkpoint(), Some(metadata.id))?;
        self.save_task(task.clone())
    }

    fn waiting_for_user(&self) -> bool {
        self.current_task()
            .and_then(Task::handoff)
            .is_some_and(|handoff| handoff.reason() == HandoffReason::WaitingForUser)
    }

    fn call_mutation(
        &mut self,
        call: &ToolCall,
        args: &serde_json::Value,
        prepared: crate::tools::mutation::Prepared,
        bus: &Bus,
    ) -> Result<ToolResult, Gone> {
        let preview = match self
            .tools
            .mutation_preview(&prepared, &call.id, Some(call.arguments()))
        {
            Ok(preview) => preview,
            Err(error) => {
                return Ok(ToolResult::error(format!(
                    "{}: cannot retain approval preview: {error}",
                    prepared.tool()
                )));
            }
        };
        let prepared_event = MutationEvent {
            phase: MutationPhase::Prepared,
            generation: 0,
            digest: prepared.digest().to_string(),
            tool: prepared.tool().to_string(),
            permission_key: prepared.permission_key().to_string(),
            changes: prepared.changes(),
            preview: Some(preview.text.clone()),
            preview_artifact: preview.artifact,
            request_artifact: preview.request_artifact,
            detail: None,
        };
        if let Err(error) = self.conversation.record_mutation(&prepared_event) {
            bus.failed(error.clone())?;
            return Ok(ToolResult::error(error));
        }

        let request = PermissionRequest {
            key: prepared.permission_key().to_string(),
            detail: describe(prepared.tool(), Some(args)),
            preview: Some(preview.text),
        };
        let decision = bus.ask(request);
        let decision_text = match decision {
            crate::agent::bus::Decision::Allow => "allow",
            crate::agent::bus::Decision::Deny => "deny",
            crate::agent::bus::Decision::Always => "always",
        };
        let decision_event = mutation_stage(
            &prepared,
            MutationPhase::Decision,
            0,
            decision_text.to_string(),
        );
        if let Err(error) = self.conversation.record_mutation(&decision_event) {
            bus.failed(error.clone())?;
            return Ok(ToolResult::error(error));
        }
        if !decision.allowed() {
            return Ok(ToolResult::error(format!(
                "the user did not allow {} to run",
                prepared.tool()
            )));
        }
        if bus.cancelled() {
            let event = mutation_stage(
                &prepared,
                MutationPhase::Result,
                0,
                "cancelled before apply".to_string(),
            );
            if let Err(error) = self.conversation.record_mutation(&event) {
                bus.failed(error)?;
            }
            return Ok(ToolResult::error(
                "cancelled before the mutation was applied",
            ));
        }

        if let Some(tool) = self.tools.get(prepared.tool()) {
            tool.approved(args);
        }
        match self.apply_and_record_mutation(&prepared) {
            Ok(result) => Ok(result),
            Err(error) => {
                bus.failed(error.clone())?;
                Ok(ToolResult::error(error))
            }
        }
    }

    fn mutation_generation(&self) -> Result<u64, String> {
        self.mutation_generation
            .lock()
            .map(|generation| *generation)
            .map_err(|_| "workspace mutation generation lock is poisoned".to_string())
    }

    fn apply_and_record_mutation(
        &mut self,
        prepared: &crate::tools::mutation::Prepared,
    ) -> Result<ToolResult, String> {
        // Keep generation assignment and journal order together across all
        // writable agents sharing this workspace.
        let generation = self.mutation_generation.clone();
        let mut current = generation
            .lock()
            .map_err(|_| "workspace mutation generation lock is poisoned".to_string())?;
        let next = current
            .checked_add(1)
            .ok_or_else(|| "workspace mutation generation is exhausted".to_string())?;
        let result = self.tools.apply_mutation(prepared);
        let applied_generation = if result.is_error() {
            0
        } else {
            *current = next;
            next
        };
        self.conversation.record_mutation(&mutation_stage(
            prepared,
            MutationPhase::Result,
            applied_generation,
            result.content.clone(),
        ))?;
        Ok(result)
    }

    fn call_opaque_mutation(
        &mut self,
        call: &ToolCall,
        permission_key: String,
        execution: &crate::tools::Execution,
    ) -> Result<(ToolResult, u64), String> {
        // Opaque commands may have changed the workspace even when they
        // report failure, so once dispatched they conservatively advance it.
        let clock = self.mutation_generation.clone();
        let mut current = clock
            .lock()
            .map_err(|_| "workspace mutation generation lock is poisoned".to_string())?;
        let next = current
            .checked_add(1)
            .ok_or_else(|| "workspace mutation generation is exhausted".to_string())?;
        let result = self
            .tools
            .dispatch_call(call.name(), call.arguments(), &call.id, execution);
        *current = next;
        self.conversation.record_mutation(&MutationEvent {
            phase: MutationPhase::Result,
            generation: next,
            digest: format!("provider-call:{}", crate::trace::scrub(&call.id)),
            tool: call.name().to_string(),
            permission_key,
            changes: Vec::new(),
            preview: None,
            preview_artifact: None,
            request_artifact: None,
            detail: Some(crate::trace::scrub(&result.content)),
        })?;
        Ok((result, next))
    }

    fn attach_verification(
        &mut self,
        result: &mut ToolResult,
        mutation_generation: Result<u64, String>,
    ) -> Result<(), String> {
        let Some(captured) = result.verification.take() else {
            return Ok(());
        };
        let Some(mut task) = self.current_task().cloned() else {
            return Ok(());
        };
        let mutation_generation = mutation_generation?;
        let ended_git_revision = captured.ended_git_revision.clone();
        let id = self
            .verification
            .last()
            .map(|evidence| evidence.id.checked_add(1))
            .unwrap_or(Some(1))
            .ok_or("verification evidence id space is exhausted")?;
        let evidence = crate::agent::verification::Evidence {
            version: crate::agent::verification::VERSION,
            id,
            candidate: captured.candidate,
            scope: crate::agent::verification::Scope {
                task_generation: task.generation(),
                checkpoint: task.checkpoint(),
                mutation_generation,
                git_revision: captured.git_revision,
            },
            started_unix_millis: Some(captured.started_unix_millis),
            ended_unix_millis: Some(captured.ended_unix_millis),
            end: Some(captured.end),
            output_artifact: captured.output_artifact,
            skip_reason: None,
            diagnostics: captured.diagnostics,
        };
        evidence.validate()?;
        task.add_verification_evidence(id)?;
        self.conversation.record_verification(&evidence)?;
        self.verification.push(evidence.clone());
        self.save_task(task)?;

        let current_generation = self.mutation_generation()?;
        let status = match evidence.status(current_generation, ended_git_revision.as_deref()) {
            crate::agent::verification::Status::Passed => "passed",
            crate::agent::verification::Status::Failed => "failed",
            crate::agent::verification::Status::Skipped => "skipped",
            crate::agent::verification::Status::Stale => "stale",
        };
        result.content.push_str(&format!(
            "\nverification evidence {id}: {status}; raw output artifact {}",
            evidence.output_artifact.unwrap()
        ));
        Ok(())
    }
}

fn mutation_stage(
    prepared: &crate::tools::mutation::Prepared,
    phase: MutationPhase,
    generation: u64,
    detail: String,
) -> MutationEvent {
    MutationEvent {
        phase,
        generation,
        digest: prepared.digest().to_string(),
        tool: prepared.tool().to_string(),
        permission_key: prepared.permission_key().to_string(),
        changes: Vec::new(),
        preview: None,
        preview_artifact: None,
        request_artifact: None,
        detail: Some(crate::trace::scrub(&detail)),
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Where a summary streams: nobody wants to read one, and a ^C during it
/// still has to be able to stop it.
struct Quiet<'a>(&'a Bus);

impl crate::provider::EventSink for Quiet<'_> {
    fn on_content(&mut self, _text: &str) -> std::io::Result<()> {
        match self.0.cancelled() {
            true => Err(std::io::Error::other("cancelled")),
            false => Ok(()),
        }
    }
}

/// How much of a result one line of terminal may carry.
const SHOWN: usize = 200;

/// What a finished call looks like on screen, and — when that is not the whole
/// of it — the result itself, for the UI to keep. A one-line result is worth
/// showing as it is (`wrote 6 bytes to notes.txt` says everything); a file or a
/// build log is reported by size, and an error by its first words, because the
/// screen is not where either belongs.
///
/// Eliding happens here and nowhere else. The renderer used to clip a long
/// line a second time, which is how a failed build came to read `2144 bytes`
/// with nothing saying it had failed: only this function knows whether there
/// is a full result behind the summary to point the user at.
fn summarize(result: &ToolResult) -> (String, Option<String>) {
    let content = result.content.trim_end();
    if content.len() <= SHOWN && !content.contains('\n') {
        return (content.to_string(), None);
    }
    let line = match result.is_error() {
        true => clip(&content.replace('\n', " "), SHOWN),
        false => format!("{} bytes", result.content.len()),
    };
    (line, Some(result.content.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::{Cancel, Decision, Event, ROOT, event_channel};
    use crate::provider::{Completion, EventSink, Role, ToolSpec};
    use crate::tools::{Tool, schema, string_arg};
    use serde_json::{Value, json};
    use std::sync::mpsc::Receiver;
    use std::sync::{Arc, Mutex};

    /// A provider that answers from a script and records what it was asked.
    struct Script {
        replies: Mutex<Vec<Result<Completion, ProviderError>>>,
        seen: Mutex<Vec<ChatRequest>>,
        /// Raised while streaming the reply at this index, standing in for a
        /// ^C that arrives mid-answer.
        cancel_at: Mutex<Option<(usize, Cancel)>>,
    }

    impl Script {
        fn new(replies: Vec<Result<Completion, ProviderError>>) -> Script {
            Script {
                replies: Mutex::new(replies.into_iter().rev().collect()),
                seen: Mutex::new(Vec::new()),
                cancel_at: Mutex::new(None),
            }
        }

        fn requests(&self) -> Vec<ChatRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl ModelProvider for Arc<Script> {
        fn complete(
            &self,
            req: &ChatRequest,
            sink: &mut dyn EventSink,
        ) -> Result<Completion, ProviderError> {
            let index = {
                let mut seen = self.seen.lock().unwrap();
                seen.push(req.clone());
                seen.len() - 1
            };
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop()
                .unwrap_or_else(|| panic!("the model was asked {} times", index + 1));
            if let Some((at, cancel)) = self.cancel_at.lock().unwrap().as_ref()
                && *at == index
            {
                cancel.raise();
            }
            let completion = reply?;
            // Streamed before returning, exactly as the real client does — so
            // a raised cancel flag stops the turn right here.
            if !completion.content.is_empty() {
                sink.on_content(&completion.content)
                    .map_err(|e| ProviderError::Aborted(e.to_string()))?;
            }
            Ok(completion)
        }
    }

    fn says(text: &str) -> Result<Completion, ProviderError> {
        Ok(Completion {
            content: text.to_string(),
            finish_reason: Some(FinishReason::Stop),
            usage: Usage {
                prompt_tokens: 5,
                completion_tokens: 3,
                ..Usage::default()
            },
            ..Completion::default()
        })
    }

    fn calls(id: &str, name: &str, arguments: &str) -> Result<Completion, ProviderError> {
        Ok(Completion {
            tool_calls: vec![ToolCall::new(id, name, arguments)],
            finish_reason: Some(FinishReason::ToolCalls),
            // A round that asks for a tool is a completion like any other, and
            // was paid for like one.
            usage: Usage {
                prompt_tokens: 5,
                completion_tokens: 3,
                ..Usage::default()
            },
            ..Completion::default()
        })
    }

    /// A tool that records what it did, so a test can see whether it ran.
    struct Note {
        written: Mutex<Vec<String>>,
    }

    impl Tool for Arc<Note> {
        fn name(&self) -> &'static str {
            "note"
        }

        fn spec(&self) -> ToolSpec {
            ToolSpec::new(
                "note",
                "Write a note.",
                schema(json!({"path": {"type": "string"}}), &["path"]),
            )
        }

        fn mutates(&self) -> bool {
            true
        }

        fn permission_key(&self, args: &Value) -> String {
            format!("note:{}", args["path"].as_str().unwrap_or("?"))
        }

        fn call(&self, args: &Value) -> Result<String, String> {
            let path = string_arg(args, "path")?;
            self.written.lock().unwrap().push(path.clone());
            Ok(format!("noted {path}"))
        }
    }

    struct Fixture {
        agent: Agent<Arc<Script>>,
        script: Arc<Script>,
        note: Arc<Note>,
        events: Receiver<Event>,
        bus: Bus,
    }

    fn fixture(replies: Vec<Result<Completion, ProviderError>>) -> Fixture {
        let script = Arc::new(Script::new(replies));
        let note = Arc::new(Note {
            written: Mutex::new(Vec::new()),
        });
        let mut tools = Registry::new();
        tools.register(Box::new(note.clone()));
        let (tx, events) = event_channel();
        Fixture {
            agent: Agent::new(script.clone(), tools, Conversation::new("test/model")),
            script,
            note,
            events,
            bus: Bus::new(ROOT, tx),
        }
    }

    /// Run a turn with a stand-in for the UI thread: it answers permission
    /// questions from a list and keeps everything else for the assertions.
    fn turn(fixture: &mut Fixture, prompt: &str, answers: &[Decision]) -> (Turned, Vec<Event>) {
        let (turned, events, _) = turn_collect(fixture, prompt, answers);
        (turned, events)
    }

    fn turn_collect(
        fixture: &mut Fixture,
        prompt: &str,
        answers: &[Decision],
    ) -> (Turned, Vec<Event>, Vec<PermissionRequest>) {
        let mut answers: Vec<Decision> = answers.iter().rev().copied().collect();
        std::thread::scope(|scope| {
            let agent = &mut fixture.agent;
            let bus = &mut fixture.bus;
            let running = scope.spawn(move || {
                let outcome = agent.turn(prompt, bus);
                // The end marker: without one, the loop below would sit on a
                // channel whose sender is still alive.
                let _ = bus.exit();
                outcome
            });
            let mut seen = Vec::new();
            let mut requests = Vec::new();
            while let Ok(event) = fixture.events.recv() {
                match event {
                    Event::Permission { request, reply, .. } => {
                        requests.push(request);
                        reply.send(answers.pop().unwrap_or(Decision::Deny))
                    }
                    Event::Exit { .. } => break,
                    other => seen.push(other),
                }
            }
            (running.join().unwrap(), seen, requests)
        })
    }

    /// An agent over the fixture's provider but a registry of the test's own,
    /// for the two tests that need something the shared fixture does not have.
    fn rebuilt(fixture: &Fixture, tools: Registry) -> Agent<Arc<Script>> {
        Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model"),
        )
    }

    fn roles(conversation: &Conversation) -> Vec<(Role, String)> {
        conversation
            .messages()
            .iter()
            .map(|m| (m.role, m.content.clone().unwrap_or_default()))
            .collect()
    }

    #[derive(Clone)]
    struct TaskJournal(Arc<Mutex<Vec<Task>>>);

    impl Journal for TaskJournal {
        fn message(&mut self, _message: &ChatMessage) -> std::io::Result<()> {
            Ok(())
        }

        fn task(&mut self, task: &Task) -> std::io::Result<()> {
            self.0.lock().unwrap().push(task.clone());
            Ok(())
        }
    }

    #[test]
    fn root_task_operations_are_journaled_and_wait_for_the_next_prompt() {
        let first = Ok(Completion {
            tool_calls: vec![
                ToolCall::new("task-add", "task", r#"{"action":"add","text":"verify"}"#),
                ToolCall::new(
                    "task-done",
                    "task",
                    r#"{"action":"transition","id":1,"from":"active","to":"completed"}"#,
                ),
                ToolCall::new(
                    "task-wait",
                    "task",
                    r#"{"action":"wait","question":"which parser?"}"#,
                ),
                ToolCall::new("too-late", "note", r#"{"path":"never.txt"}"#),
            ],
            finish_reason: Some(FinishReason::ToolCalls),
            ..Completion::default()
        });
        let mut fixture = fixture(vec![
            first,
            calls(
                "task-active",
                "task",
                r#"{"action":"transition","id":2,"from":"pending","to":"active"}"#,
            ),
            calls(
                "task-complete",
                "task",
                r#"{"action":"transition","id":2,"from":"active","to":"completed"}"#,
            ),
            says("done"),
            says("new answer"),
        ]);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let view = Arc::new(Mutex::new(None));
        let mut tools = Registry::new();
        tools.register(Box::new(fixture.note.clone()));
        tools.register(task_tool::tool());
        fixture.agent = Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model").with_journal(Box::new(TaskJournal(tasks.clone()))),
        )
        .with_task(None, view.clone());

        let (outcome, events) = turn(&mut fixture, "repair it", &[]);
        assert_eq!(outcome, Turned::Waiting);
        assert!(fixture.note.written.lock().unwrap().is_empty());
        assert!(events.iter().any(|event| matches!(event,
            Event::Notice { text, .. } if text == "waiting for user: which parser?"
        )));
        assert_eq!(fixture.script.requests().len(), 1);
        assert_eq!(
            view.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .handoff()
                .unwrap()
                .reason(),
            HandoffReason::WaitingForUser
        );

        assert_eq!(
            turn(&mut fixture, "the expression parser", &[]).0,
            Turned::Done
        );
        assert!(view.lock().unwrap().as_ref().unwrap().complete());
        assert_eq!(turn(&mut fixture, "now document it", &[]).0, Turned::Done);
        let current = view.lock().unwrap().clone().unwrap();
        assert_eq!(current.request(), "now document it");
        assert_eq!(current.items()[0].state(), ItemState::Active);
        assert_eq!(
            tasks
                .lock()
                .unwrap()
                .iter()
                .map(Task::generation)
                .collect::<Vec<_>>(),
            (1..=10).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_tool_call_runs_and_the_answer_follows_it() {
        let mut fixture = fixture(vec![
            calls("call_1", "note", r#"{"path":"a.txt"}"#),
            says("done"),
        ]);
        let (outcome, _) = turn(&mut fixture, "take a note", &[Decision::Allow]);

        assert_eq!(outcome, Turned::Done);
        assert_eq!(*fixture.note.written.lock().unwrap(), ["a.txt"]);

        let said = roles(fixture.agent.conversation());
        assert_eq!(said[0], (Role::User, "take a note".to_string()));
        assert_eq!(said[1].0, Role::Assistant);
        assert_eq!(said[2], (Role::Tool, "noted a.txt".to_string()));
        assert_eq!(said[3], (Role::Assistant, "done".to_string()));

        // The second request carried the whole exchange back, tools included.
        let requests = fixture.script.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].messages.len(), 3);
        assert_eq!(requests[1].tools[0].function.name, "note");
        assert_eq!(fixture.agent.usage().completions, 2);
    }

    #[test]
    fn read_only_modes_omit_and_refuse_mutating_tools() {
        for mode in [Mode::Ask, Mode::Plan, Mode::Review] {
            let mut fixture = fixture(vec![
                calls("forged", "note", r#"{"path":"never.txt"}"#),
                says("understood"),
            ]);
            let mut tools = Registry::new();
            tools.register(Box::new(fixture.note.clone()));
            let task = Task::new("inspect it".into(), vec!["inspect it".into()], mode).unwrap();
            fixture.agent = Agent::new(
                fixture.script.clone(),
                tools,
                Conversation::new("test/model"),
            )
            .with_task(Some(task), Arc::new(Mutex::new(None)));

            let (outcome, _, permissions) = turn_collect(&mut fixture, "go", &[]);
            assert_eq!(outcome, Turned::Done);
            assert!(permissions.is_empty(), "{mode:?} reached the gate");
            assert!(fixture.note.written.lock().unwrap().is_empty());
            let requests = fixture.script.requests();
            assert!(requests.iter().all(|request| {
                request
                    .tools
                    .iter()
                    .all(|spec| spec.function.name != "note")
            }));
            let mode_state = requests[0]
                .messages
                .iter()
                .find_map(|message| message.content.as_deref())
                .unwrap();
            assert!(
                mode_state.contains("Active mode profile v2"),
                "{mode_state}"
            );
            assert!(
                mode_state.contains("Tools available in this mode (contract v1): none"),
                "{mode_state}"
            );
            assert!(!mode_state.contains("note"), "{mode_state}");
            let said = roles(fixture.agent.conversation());
            assert!(
                said[2].1.contains(&format!(
                    "unavailable in {} mode",
                    crate::agent::mode::profile(mode).name
                )),
                "{mode:?}: {said:?}"
            );
        }
    }

    #[test]
    fn entering_code_is_approved_before_a_same_round_mutation() {
        let calls = Ok(Completion {
            tool_calls: vec![
                ToolCall::new(
                    "mode-code",
                    "task",
                    r#"{"action":"mode","from_mode":"ask","to_mode":"code"}"#,
                ),
                ToolCall::new("write", "note", r#"{"path":"allowed.txt"}"#),
            ],
            finish_reason: Some(FinishReason::ToolCalls),
            ..Completion::default()
        });
        let mut fixture = fixture(vec![calls, says("done")]);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let view = Arc::new(Mutex::new(None));
        let mut tools = Registry::new();
        tools.register(Box::new(fixture.note.clone()));
        tools.register(task_tool::tool());
        let task = Task::new("answer then fix".into(), vec!["inspect".into()], Mode::Ask).unwrap();
        fixture.agent = Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model").with_journal(Box::new(TaskJournal(tasks.clone()))),
        )
        .with_task(Some(task), view.clone());

        let (outcome, _, permissions) =
            turn_collect(&mut fixture, "fix it", &[Decision::Allow, Decision::Allow]);
        assert_eq!(outcome, Turned::Done);
        assert_eq!(*fixture.note.written.lock().unwrap(), ["allowed.txt"]);
        assert_eq!(permissions.len(), 2);
        assert!(permissions[0].detail.contains("enter code mode from ask"));
        assert!(
            permissions[0]
                .preview
                .as_deref()
                .unwrap()
                .contains("pending mode")
        );
        assert_eq!(view.lock().unwrap().as_ref().unwrap().mode(), Mode::Code);
        let tasks = tasks.lock().unwrap();
        assert!(tasks[0].pending_mode().is_some());
        assert_eq!(tasks[1].mode(), Mode::Code);
        assert!(tasks[1].pending_mode().is_none());
    }

    #[test]
    fn plan_approval_records_a_fresh_checkpoint_before_mutation() {
        let root = std::env::temp_dir().join(format!("gears-turn-plan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let checkpoints = Arc::new(
            crate::agent::checkpoint::LazyStore::new(
                root.clone(),
                "31-1".to_string(),
                100_000,
                200_000,
                false,
            )
            .unwrap(),
        );
        let workspace = Arc::new(
            crate::tools::Workspace::new(&root)
                .unwrap()
                .with_checkpoints(checkpoints),
        );
        let calls = Ok(Completion {
            tool_calls: vec![
                ToolCall::new(
                    "mode-code",
                    "task",
                    r#"{"action":"mode","from_mode":"plan","to_mode":"code"}"#,
                ),
                ToolCall::new("write", "note", r#"{"path":"after-plan.txt"}"#),
            ],
            finish_reason: Some(FinishReason::ToolCalls),
            ..Completion::default()
        });
        let mut fixture = fixture(vec![calls, says("done")]);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let view = Arc::new(Mutex::new(None));
        let mut tools = Registry::new();
        tools.register(Box::new(fixture.note.clone()));
        tools.register(task_tool::tool());
        let task = Task::new("implement the plan".into(), vec!["edit".into()], Mode::Plan).unwrap();
        fixture.agent = Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model").with_journal(Box::new(TaskJournal(tasks.clone()))),
        )
        .with_task(Some(task), view.clone())
        .with_task_workspace(workspace.clone());

        let (outcome, _, permissions) = turn_collect(
            &mut fixture,
            "implement",
            &[Decision::Allow, Decision::Allow],
        );
        assert_eq!(outcome, Turned::Done);
        assert_eq!(*fixture.note.written.lock().unwrap(), ["after-plan.txt"]);
        assert_eq!(permissions.len(), 2);
        let task = view.lock().unwrap().clone().unwrap();
        let checkpoint = task.checkpoint().unwrap();
        assert_eq!(task.mode(), Mode::Code);
        assert!(
            permissions[0]
                .key
                .ends_with(&format!("checkpoint:{checkpoint}"))
        );
        assert!(
            permissions[0]
                .preview
                .as_deref()
                .unwrap()
                .contains(&format!("checkpoint Some({checkpoint})"))
        );
        let tasks = tasks.lock().unwrap();
        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[0].mode(), Mode::Plan);
        assert!(tasks[0].pending_mode().is_none());
        assert!(tasks[1].pending_mode().is_some());
        assert_eq!(tasks[2].mode(), Mode::Code);
        let metadata = workspace
            .checkpoints()
            .unwrap()
            .into_iter()
            .find(|entry| entry.id == checkpoint)
            .unwrap();
        assert_eq!(metadata.task_generation, 1);
        assert!(metadata.name.starts_with("plan at task generation"));
        drop(tasks);
        drop(fixture);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn entering_review_immediately_removes_mutating_tools() {
        let calls = Ok(Completion {
            tool_calls: vec![
                ToolCall::new(
                    "mode-review",
                    "task",
                    r#"{"action":"mode","from_mode":"code","to_mode":"review"}"#,
                ),
                ToolCall::new("write", "note", r#"{"path":"never.txt"}"#),
            ],
            finish_reason: Some(FinishReason::ToolCalls),
            ..Completion::default()
        });
        let mut fixture = fixture(vec![calls, says("reviewed")]);
        let view = Arc::new(Mutex::new(None));
        let mut tools = Registry::new();
        tools.register(Box::new(fixture.note.clone()));
        tools.register(task_tool::tool());
        let task = Task::new("review it".into(), vec!["review".into()], Mode::Code).unwrap();
        fixture.agent = Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model"),
        )
        .with_task(Some(task), view.clone());

        let (outcome, _, permissions) = turn_collect(&mut fixture, "review", &[]);
        assert_eq!(outcome, Turned::Done);
        assert!(permissions.is_empty());
        assert!(fixture.note.written.lock().unwrap().is_empty());
        assert_eq!(view.lock().unwrap().as_ref().unwrap().mode(), Mode::Review);
        assert!(
            fixture.script.requests()[1]
                .tools
                .iter()
                .all(|spec| spec.function.name != "note")
        );
    }

    #[test]
    fn a_resumed_pending_mode_is_cancelled_before_the_next_prompt() {
        let mut fixture = fixture(vec![says("still planning")]);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let view = Arc::new(Mutex::new(None));
        let mut task = Task::new("plan it".into(), vec!["inspect".into()], Mode::Plan).unwrap();
        task.set_checkpoint(None, Some(9)).unwrap();
        task.request_mode(Mode::Plan, Mode::Code).unwrap();
        fixture.agent = Agent::new(
            fixture.script.clone(),
            Registry::new(),
            Conversation::new("test/model").with_journal(Box::new(TaskJournal(tasks.clone()))),
        )
        .with_task(Some(task), view.clone());

        let (outcome, events) = turn(&mut fixture, "continue safely", &[]);
        assert_eq!(outcome, Turned::Done);
        assert!(events.iter().any(|event| matches!(event,
            Event::Notice { text, .. } if text.contains("cancelled pending mode transition plan -> code")
        )));
        let task = view.lock().unwrap().clone().unwrap();
        assert_eq!(task.mode(), Mode::Plan);
        assert!(task.pending_mode().is_none());
        assert_eq!(tasks.lock().unwrap().len(), 1);
        let request = &fixture.script.requests()[0];
        assert!(request.messages.iter().any(|message| {
            message
                .content
                .as_deref()
                .is_some_and(|text| text.contains("Mode: plan"))
        }));
        assert!(request.tools.is_empty());
    }

    #[test]
    fn a_denied_call_is_answered_rather_than_run() {
        let mut fixture = fixture(vec![
            calls("call_1", "note", r#"{"path":"a.txt"}"#),
            says("understood"),
        ]);
        let (outcome, events) = turn(&mut fixture, "take a note", &[Decision::Deny]);

        assert_eq!(outcome, Turned::Done);
        assert!(fixture.note.written.lock().unwrap().is_empty());
        // The model is told, in the tool result, so it can do something else.
        let said = roles(fixture.agent.conversation());
        assert!(said[2].1.contains("did not allow"), "{said:?}");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::ToolEnd { outcome, .. } if outcome.is_error()))
        );
    }

    #[derive(Clone)]
    struct MutationJournal(Arc<Mutex<Vec<MutationEvent>>>);

    impl Journal for MutationJournal {
        fn message(&mut self, _message: &ChatMessage) -> std::io::Result<()> {
            Ok(())
        }

        fn mutation(&mut self, event: &MutationEvent) -> std::io::Result<()> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[test]
    fn file_mutations_are_previewed_approved_applied_and_audited() {
        let root = std::env::temp_dir().join(format!("gears-turn-mutation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let workspace = Arc::new(crate::tools::Workspace::new(&root).unwrap());
        let mut fixture = fixture(vec![
            calls(
                "write-1",
                "write_file",
                r#"{"path":"notes.txt","content":"hello\n"}"#,
            ),
            says("done"),
        ]);
        let mut tools = Registry::new();
        for tool in crate::tools::fs::tools(workspace) {
            tools.register(tool);
        }
        let audit = Arc::new(Mutex::new(Vec::new()));
        fixture.agent = Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model").with_journal(Box::new(MutationJournal(audit.clone()))),
        );

        let (outcome, _, requests) = turn_collect(&mut fixture, "write it", &[Decision::Allow]);
        assert_eq!(outcome, Turned::Done);
        assert_eq!(std::fs::read(root.join("notes.txt")).unwrap(), b"hello\n");
        assert_eq!(requests.len(), 1);
        let preview = requests[0].preview.as_deref().unwrap();
        assert!(preview.contains("--- /dev/null"), "{preview}");
        assert!(preview.contains("+hello"), "{preview}");

        let audit = audit.lock().unwrap();
        assert_eq!(audit.len(), 3, "{audit:?}");
        assert_eq!(audit[0].phase, MutationPhase::Prepared);
        assert_eq!(audit[1].phase, MutationPhase::Decision);
        assert_eq!(audit[1].detail.as_deref(), Some("allow"));
        assert_eq!(audit[2].phase, MutationPhase::Result);
        assert_eq!(audit[2].generation, 1);
        assert!(audit[..2].iter().all(|event| event.generation == 0));
        assert!(audit.iter().all(|event| event.digest == audit[0].digest));
        drop(audit);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_native_check_is_journaled_and_attached_to_the_current_task() {
        let root =
            std::env::temp_dir().join(format!("gears-turn-verification-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let workspace = Arc::new(crate::tools::Workspace::new(&root).unwrap());
        let artifacts = Arc::new(
            crate::agent::artifact::LazyStore::new(
                root.clone(),
                "1-2".to_string(),
                1_000_000,
                2_000_000,
            )
            .unwrap(),
        );
        let mut registry = Registry::new().with_artifacts(artifacts.clone());
        for tool in crate::tools::toolchain::tools(
            Arc::new(crate::tools::toolchain::LorryToolchain::new("echo")),
            workspace,
            std::time::Duration::from_secs(10),
            1_000_000,
        ) {
            registry.register(tool);
        }
        let mut fixture = fixture(vec![
            calls("check-1", "test", r#"{"args":["--lib"]}"#),
            calls("write-1", "note", r#"{"path":"after.rs"}"#),
            says("done"),
        ]);
        registry.register(Box::new(fixture.note.clone()));
        let task = Task::new("verify".into(), vec!["run checks".into()], Mode::Code).unwrap();
        let view = Arc::new(Mutex::new(None));
        fixture.agent = Agent::new(
            fixture.script.clone(),
            registry,
            Conversation::new("test/model"),
        )
        .with_task(Some(task), view.clone());

        let (outcome, _) = turn(
            &mut fixture,
            "verify it",
            &[Decision::Allow, Decision::Allow],
        );
        assert_eq!(outcome, Turned::Done);
        assert_eq!(
            view.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .verification_evidence(),
            [1]
        );
        let evidence = &fixture.agent.verification[0];
        assert_eq!(
            evidence.candidate.argv,
            ["echo", "--color", "never", "test", "--lib"]
        );
        assert_eq!(evidence.scope.mutation_generation, 1);
        assert_eq!(
            evidence.status(fixture.agent.mutation_generation().unwrap(), None),
            crate::agent::verification::Status::Stale
        );
        assert_eq!(
            artifacts.get().unwrap().read(1).unwrap(),
            b"--color never test --lib\n"
        );
        assert!(
            roles(fixture.agent.conversation())[2]
                .1
                .contains("verification evidence 1: passed; raw output artifact 1")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn denying_a_file_mutation_writes_neither_file_nor_undo_entry() {
        let root =
            std::env::temp_dir().join(format!("gears-turn-denied-mutation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let undo = Arc::new(crate::agent::undo::UndoLog::new(&root, "s1").unwrap());
        let workspace = Arc::new(
            crate::tools::Workspace::new(&root)
                .unwrap()
                .with_undo(undo.clone()),
        );
        let mut fixture = fixture(vec![
            calls(
                "write-denied",
                "write_file",
                r#"{"path":"notes.txt","content":"no\n"}"#,
            ),
            says("understood"),
        ]);
        let mut tools = Registry::new();
        for tool in crate::tools::fs::tools(workspace) {
            tools.register(tool);
        }
        let audit = Arc::new(Mutex::new(Vec::new()));
        fixture.agent = Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model").with_journal(Box::new(MutationJournal(audit.clone()))),
        );

        let (outcome, _, _) = turn_collect(&mut fixture, "write it", &[Decision::Deny]);
        assert_eq!(outcome, Turned::Done);
        assert!(!root.join("notes.txt").exists());
        assert!(undo.files().is_empty());
        let audit = audit.lock().unwrap();
        assert_eq!(audit.len(), 2, "{audit:?}");
        assert_eq!(audit[1].phase, MutationPhase::Decision);
        assert_eq!(audit[1].detail.as_deref(), Some("deny"));
        drop(audit);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_call_the_registry_refuses_comes_back_as_a_result() {
        let mut fixture = fixture(vec![
            calls("call_1", "note", "{"),
            calls("call_2", "nonesuch", "{}"),
            says("I see"),
        ]);
        let (outcome, _) = turn(&mut fixture, "go", &[]);

        assert_eq!(outcome, Turned::Done);
        let said = roles(fixture.agent.conversation());
        assert!(said[2].1.contains("not valid JSON"), "{said:?}");
        assert!(said[4].1.contains("no such tool"), "{said:?}");
        // Neither reached the permission gate, so neither could have run.
        assert!(fixture.note.written.lock().unwrap().is_empty());
    }

    #[test]
    fn every_call_of_a_round_is_answered() {
        let two = Ok(Completion {
            tool_calls: vec![
                ToolCall::new("call_1", "note", r#"{"path":"a.txt"}"#),
                ToolCall::new("call_2", "note", r#"{"path":"b.txt"}"#),
            ],
            finish_reason: Some(FinishReason::ToolCalls),
            ..Completion::default()
        });
        let mut fixture = fixture(vec![two, says("both done")]);
        let (outcome, _) = turn(
            &mut fixture,
            "two notes",
            &[Decision::Allow, Decision::Deny],
        );

        assert_eq!(outcome, Turned::Done);
        assert_eq!(*fixture.note.written.lock().unwrap(), ["a.txt"]);
        let said = roles(fixture.agent.conversation());
        assert_eq!(said[2].1, "noted a.txt");
        assert!(said[3].1.contains("did not allow"), "{said:?}");
    }

    #[test]
    fn a_cancelled_turn_leaves_the_conversation_resumable() {
        let mut fixture = fixture(vec![says("half a sen")]);
        let cancel = fixture.bus.canceller();
        *fixture.script.cancel_at.lock().unwrap() = Some((0, cancel));

        let (outcome, events) = turn(&mut fixture, "say something", &[]);
        assert_eq!(outcome, Turned::Cancelled);
        // The partial turn is dropped: the last thing said is the prompt, so
        // the conversation can be sent again as it stands.
        let said = roles(fixture.agent.conversation());
        assert_eq!(said.len(), 1);
        assert_eq!(said[0].1, "say something");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Notice { text, .. } if text == "cancelled"))
        );
        // And the flag was consumed, so the next turn starts clean.
        assert!(!fixture.bus.cancelled());
    }

    #[test]
    fn a_provider_failure_ends_the_turn_without_a_retry() {
        let mut fixture = fixture(vec![Err(ProviderError::Auth("bad key".to_string()))]);
        let (outcome, events) = turn(&mut fixture, "hello", &[]);

        // The reason travels with the outcome: a sub-agent's parent is told
        // what went wrong in a tool result, having seen none of this.
        assert_eq!(
            outcome,
            Turned::Failed("authentication failed: bad key".to_string())
        );
        assert_eq!(fixture.script.requests().len(), 1, "it tried again");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Failed { text, .. } if text.contains("bad key")))
        );
        // Still resumable: the prompt is the last thing in the transcript.
        assert_eq!(roles(fixture.agent.conversation()).len(), 1);
    }

    #[test]
    fn a_model_that_never_answers_is_stopped() {
        let replies = (0..5)
            .map(|n| calls(&format!("call_{n}"), "note", r#"{"path":"a.txt"}"#))
            .collect();
        let mut fixture = fixture(replies);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let view = Arc::new(Mutex::new(None));
        let mut tools = Registry::new();
        tools.register(Box::new(fixture.note.clone()));
        fixture.agent = Agent::new(
            fixture.script.clone(),
            tools,
            Conversation::new("test/model").with_journal(Box::new(TaskJournal(tasks.clone()))),
        )
        .with_task(None, view.clone())
        .with_max_steps(3);

        let (outcome, events) = turn(
            &mut fixture,
            "loop forever",
            &[Decision::Always, Decision::Always, Decision::Always],
        );
        assert!(
            matches!(&outcome, Turned::Failed(why) if why.contains("without answering")),
            "{outcome:?}"
        );
        assert_eq!(fixture.script.requests().len(), 3);
        assert_eq!(
            view.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .handoff()
                .unwrap()
                .reason(),
            HandoffReason::StepLimit
        );
        assert_eq!(tasks.lock().unwrap().last(), view.lock().unwrap().as_ref());
        assert!(
            events.iter().any(
                |e| matches!(e, Event::Failed { text, .. } if text.contains("without answering"))
            ),
            "{events:?}"
        );
    }

    /// A budget stops an agent *before* the next completion, not after it: the
    /// point is not to spend the money, so the check comes first and what a
    /// round cost is added when the endpoint says what that was.
    #[test]
    fn a_budget_ends_the_turn_before_the_next_completion() {
        struct Tally {
            spent: Mutex<u64>,
            kind: BudgetKind,
        }

        impl Budget for Tally {
            fn check(&self) -> Result<(), BudgetExhausted> {
                match *self.spent.lock().unwrap() >= 8 {
                    true if self.kind == BudgetKind::Tokens => {
                        Err(BudgetExhausted::tokens("the budget is used up"))
                    }
                    true => Err(BudgetExhausted::spend("the budget is used up")),
                    false => Ok(()),
                }
            }

            fn spent(&self, usage: &Usage) {
                *self.spent.lock().unwrap() += usage.prompt_tokens + usage.completion_tokens;
            }
        }

        for (kind, reason) in [
            (BudgetKind::Tokens, HandoffReason::TokenLimit),
            (BudgetKind::Spend, HandoffReason::SpendLimit),
        ] {
            let purse = Arc::new(Tally {
                spent: Mutex::new(0),
                kind,
            });
            let mut fixture = fixture(vec![
                calls("call_1", "note", r#"{"path":"a.txt"}"#),
                says("this is never asked for"),
            ]);
            let view = Arc::new(Mutex::new(None));
            let mut tools = Registry::new();
            tools.register(Box::new(fixture.note.clone()));
            fixture.agent = Agent::new(
                fixture.script.clone(),
                tools,
                Conversation::new("test/model"),
            )
            .with_task(None, view.clone())
            .with_budget(purse.clone());

            let (outcome, events) = turn(&mut fixture, "take a note", &[Decision::Allow]);
            // One round happened, at 8 tokens; the second was refused.
            assert!(
                matches!(&outcome, Turned::Failed(why) if why.contains("used up")),
                "{outcome:?}"
            );
            assert_eq!(fixture.script.requests().len(), 1);
            assert_eq!(*purse.spent.lock().unwrap(), 8);
            assert_eq!(
                view.lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .handoff()
                    .unwrap()
                    .reason(),
                reason
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, Event::Failed { text, .. } if text.contains("used up")))
            );
        }
    }

    /// The purse a run gets when the user caps it. Nothing here needs an
    /// agent: what an empty budget does to a turn is the test above.
    #[test]
    fn the_runs_purse_counts_in_whichever_currency_the_endpoint_reports() {
        let spend = |tokens: u64, cost: Option<f64>| Usage {
            prompt_tokens: tokens,
            completion_tokens: 0,
            total_tokens: tokens,
            cost,
        };

        // Uncapped is not the same as unspent: it counts, and always affords.
        let open = Purse::new(RunLimits::default());
        assert!(!open.capped());
        open.spent(&spend(1_000_000, Some(99.0)));
        assert!(open.check().is_ok());
        assert_eq!(open.spending().total_tokens(), 1_000_000);

        // Tokens, which every endpoint reports.
        let counted = Purse::new(RunLimits {
            budget_tokens: Some(100),
            ..RunLimits::default()
        });
        assert!(counted.capped());
        counted.spent(&spend(99, None));
        assert!(counted.check().is_ok());
        counted.spent(&spend(1, None));
        let why = counted.check().unwrap_err();
        assert_eq!(why.kind(), BudgetKind::Tokens);
        assert!(why.to_string().contains("the run budget of 100 tokens"));

        // Money, where there is a price to go by.
        let priced = Purse::new(RunLimits {
            budget_usd: Some(0.50),
            ..RunLimits::default()
        });
        priced.spent(&spend(1, Some(0.49)));
        assert!(priced.check().is_ok());
        priced.spent(&spend(1, Some(0.02)));
        let why = priced.check().unwrap_err();
        assert_eq!(why.kind(), BudgetKind::Spend);
        assert!(why.to_string().contains("the run budget of $0.50"));
        assert!(why.to_string().contains("$0.5100"));
    }

    /// A ^C that arrives while a tool is running ends the turn when the tool
    /// returns, rather than buying one more answer nobody wants.
    #[test]
    fn a_cancel_between_rounds_stops_before_the_model_is_asked_again() {
        /// A tool that presses ^C, so the flag is raised where a real one
        /// would be: after the round's calls were let through, during one.
        struct Trip(Cancel);

        impl Tool for Trip {
            fn name(&self) -> &'static str {
                "trip"
            }

            fn spec(&self) -> ToolSpec {
                ToolSpec::new("trip", "Trip the cancel flag.", schema(json!({}), &[]))
            }

            fn mutates(&self) -> bool {
                false
            }

            fn call(&self, _args: &Value) -> Result<String, String> {
                self.0.raise();
                Ok("tripped".to_string())
            }
        }

        let round = Ok(Completion {
            tool_calls: vec![
                ToolCall::new("call_1", "trip", "{}"),
                ToolCall::new("call_2", "note", r#"{"path":"never.txt"}"#),
            ],
            finish_reason: Some(FinishReason::ToolCalls),
            ..Completion::default()
        });
        let mut fixture = fixture(vec![round, says("never sent")]);
        let mut tools = Registry::new();
        tools.register(Box::new(Trip(fixture.bus.canceller())));
        tools.register(Box::new(fixture.note.clone()));
        fixture.agent = rebuilt(&fixture, tools);

        let (outcome, _) = turn(&mut fixture, "trip it", &[]);
        assert_eq!(outcome, Turned::Cancelled);
        assert_eq!(fixture.script.requests().len(), 1, "it asked again");
        // The call ran and was answered, so the transcript can be sent again.
        let said = roles(fixture.agent.conversation());
        assert_eq!(said.len(), 4);
        assert_eq!(said[2], (Role::Tool, "tripped".to_string()));
        assert!(
            said[3].1.contains("cancelled before this call ran"),
            "{said:?}"
        );
        assert!(fixture.note.written.lock().unwrap().is_empty());
        assert!(!fixture.bus.cancelled());
    }

    /// A provider that counts what it is sent the way an endpoint does —
    /// from the request itself — and keeps asking for tools until it has had
    /// `rounds` of them. Nothing else can say whether context management
    /// works: the numbers that drive it come back from the far side.
    struct Counter {
        rounds: usize,
        asked: Mutex<usize>,
        peak: Mutex<u64>,
    }

    impl ModelProvider for Arc<Counter> {
        fn complete(
            &self,
            req: &ChatRequest,
            _sink: &mut dyn EventSink,
        ) -> Result<Completion, ProviderError> {
            // Four bytes to the token, near enough to what an endpoint reports
            // for JSON and English alike.
            let tokens = (serde_json::to_string(req).unwrap().len() / 4) as u64;
            let mut peak = self.peak.lock().unwrap();
            *peak = (*peak).max(tokens);
            let mut asked = self.asked.lock().unwrap();
            *asked += 1;
            let usage = Usage {
                prompt_tokens: tokens,
                completion_tokens: 10,
                ..Usage::default()
            };
            Ok(match *asked > self.rounds {
                true => Completion {
                    content: "done".to_string(),
                    finish_reason: Some(FinishReason::Stop),
                    usage,
                    ..Completion::default()
                },
                false => Completion {
                    tool_calls: vec![ToolCall::new(format!("call_{asked}"), "loud", "{}")],
                    finish_reason: Some(FinishReason::ToolCalls),
                    usage,
                    ..Completion::default()
                },
            })
        }
    }

    /// A tool with a great deal to say, which is what fills a window: one
    /// `read_file` of a source file is this by a factor of two.
    struct Loud;

    impl Tool for Loud {
        fn name(&self) -> &'static str {
            "loud"
        }

        fn spec(&self) -> ToolSpec {
            ToolSpec::new("loud", "Say a great deal.", schema(json!({}), &[]))
        }

        fn mutates(&self) -> bool {
            false
        }

        fn call(&self, _args: &Value) -> Result<String, String> {
            Ok("lorem ipsum ".repeat(340))
        }
    }

    /// Run `rounds` of calls under `policy` and report what the largest
    /// request came to, in the endpoint's own tokens.
    fn long_run(rounds: usize, policy: Policy) -> (u64, Conversation) {
        let counter = Arc::new(Counter {
            rounds,
            asked: Mutex::new(0),
            peak: Mutex::new(0),
        });
        let mut tools = Registry::new();
        tools.register(Box::new(Loud));
        let (tx, _events) = event_channel();
        let mut bus = Bus::new(ROOT, tx);
        let mut agent = Agent::new(counter.clone(), tools, Conversation::new("test/model"))
            .with_max_steps(rounds + 2)
            .with_context(policy);

        assert_eq!(agent.turn("keep going", &mut bus), Turned::Done);
        let peak = *counter.peak.lock().unwrap();
        (peak, agent.conversation)
    }

    /// The step's whole point: fifty rounds of large results, and every
    /// request still inside the window the user declared — on stubbing alone,
    /// which is what a run full of tool results needs.
    #[test]
    fn a_long_run_stays_inside_the_window() {
        const BUDGET: u64 = 20_000;
        let stubbing = Policy {
            budget: BUDGET,
            summarize: false,
        };
        let (peak, conversation) = long_run(50, stubbing);
        assert!(peak <= BUDGET, "{peak} tokens against a budget of {BUDGET}");

        // The oldest results went and the newest stayed: the model can still
        // see what it has just been told.
        let results: Vec<&str> = conversation
            .messages()
            .iter()
            .filter(|m| m.role == Role::Tool)
            .map(|m| m.content.as_deref().unwrap_or_default())
            .collect();
        assert!(results[0].contains("dropped this result"), "{}", results[0]);
        assert!(results.last().unwrap().starts_with("lorem ipsum"));

        // And it is the managing that did it, not the size of the run: the
        // same fifty rounds unmanaged are far past the same budget.
        let unmanaged = Policy {
            budget: 0,
            summarize: false,
        };
        let (unmanaged, _) = long_run(50, unmanaged);
        assert!(unmanaged > BUDGET * 2, "{unmanaged} tokens unmanaged");
    }

    /// The second lever, once there is nothing left to stub: the model writes
    /// a summary of the oldest part of the conversation and it stands there in
    /// place of what it summarized.
    #[test]
    fn a_summary_takes_the_place_of_what_it_summarizes() {
        let mut fixture = fixture(vec![says("what went before"), says("carrying on")]);
        let mut conversation = Conversation::new("test/model");
        conversation
            .push(ChatMessage::system("you are gears"))
            .unwrap();
        for turn in 0..8 {
            let long = "ask ".repeat(200);
            conversation
                .push(ChatMessage::user(format!("{turn}: {long}")))
                .unwrap();
            conversation
                .push(ChatMessage::assistant("answer ".repeat(200)))
                .unwrap();
        }
        let before = conversation.messages().len();
        fixture.agent = Agent::new(fixture.script.clone(), Registry::new(), conversation)
            .with_context(Policy {
                budget: 4_000,
                summarize: true,
            });
        fixture.agent.measured(3_900);

        let (outcome, events) = turn(&mut fixture, "and now this", &[]);
        assert_eq!(outcome, Turned::Done);

        // Two completions: the summary, and then the turn itself.
        let requests = fixture.script.requests();
        assert_eq!(requests.len(), 2);
        let instruction = requests[0].messages.last().unwrap();
        assert!(
            instruction
                .content
                .as_deref()
                .unwrap()
                .contains("all you will have"),
            "{instruction:?}"
        );

        // And the turn was asked with the summary standing where the oldest
        // messages had been, those messages gone from what was sent.
        let sent = &requests[1].messages;
        assert!(sent.len() < before, "{} of {before} messages", sent.len());
        assert_eq!(sent[0].role, Role::System);
        assert!(
            !sent
                .iter()
                .any(|m| m.content.as_deref().is_some_and(|t| t.starts_with("0:"))),
            "the first exchange is still there"
        );

        let said = roles(fixture.agent.conversation());
        assert_eq!(said[0].0, Role::System);
        assert!(said[1].1.ends_with("what went before"), "{said:?}");
        assert_eq!(said.last().unwrap().1, "carrying on");
        // The summary was paid for like any other completion.
        assert_eq!(fixture.agent.usage().completions, 2);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Notice { text, .. } if text.contains("summarizing"))),
            "{events:?}"
        );
    }

    /// An endpoint that will not summarize leaves the conversation exactly as
    /// it was: the request that follows may still fit, and if it does not the
    /// endpoint says so in its own words. What it does not do is cost the same
    /// completion again at every round of the same turn.
    #[test]
    fn a_summary_that_fails_is_not_a_failed_turn_and_is_not_paid_for_twice() {
        let mut fixture = fixture(vec![
            Err(ProviderError::Unavailable("overloaded".to_string())),
            calls("call_1", "note", r#"{"path":"a.txt"}"#),
            says("answered anyway"),
        ]);
        let mut conversation = Conversation::new("test/model");
        conversation
            .push(ChatMessage::system("you are gears"))
            .unwrap();
        for turn in 0..8 {
            conversation
                .push(ChatMessage::user(format!("{turn}: {}", "ask ".repeat(200))))
                .unwrap();
            conversation
                .push(ChatMessage::assistant("answer ".repeat(200)))
                .unwrap();
        }
        let mut tools = Registry::new();
        tools.register(Box::new(fixture.note.clone()));
        fixture.agent =
            Agent::new(fixture.script.clone(), tools, conversation).with_context(Policy {
                budget: 4_000,
                summarize: true,
            });
        fixture.agent.measured(3_900);

        let (outcome, events) = turn(&mut fixture, "and now this", &[Decision::Allow]);
        assert_eq!(outcome, Turned::Done);
        // Three completions: the summary that failed, and the two rounds of
        // the turn itself. The second round did not try to summarize again.
        assert_eq!(fixture.script.requests().len(), 3);
        // And nothing was dropped on the strength of a summary there is not.
        let said = roles(fixture.agent.conversation());
        assert!(said[1].1.starts_with("0: ask"), "{:?}", said[1]);
        assert!(
            events.iter().any(
                |e| matches!(e, Event::Notice { text, .. } if text.contains("could not summarize"))
            ),
            "{events:?}"
        );
    }

    #[test]
    fn a_result_is_summarized_by_shape() {
        let shown = |result| {
            let (line, full) = summarize(&result);
            (line, full.is_some())
        };
        assert_eq!(
            shown(ToolResult::ok("wrote 6 bytes\n")),
            ("wrote 6 bytes".to_string(), false)
        );
        assert_eq!(
            shown(ToolResult::ok("a\nb\nc")),
            ("5 bytes".to_string(), true)
        );
        assert_eq!(
            shown(ToolResult::error("nope")),
            ("nope".to_string(), false)
        );
    }

    /// A summary that leaves something out has to hand it over, and an error
    /// too long for its line is summarized rather than silently cut.
    #[test]
    fn what_the_line_leaves_out_travels_with_it() {
        let log = format!(
            "exit status 101\n{}",
            "error: mismatched types\n".repeat(50)
        );
        let (line, full) = summarize(&ToolResult::ok(&log));
        assert_eq!(line, format!("{} bytes", log.len()));
        assert_eq!(full.unwrap(), log);

        let (line, full) = summarize(&ToolResult::error(format!("run: {}", "x".repeat(500))));
        assert!(line.ends_with('…'), "{line}");
        assert!(line.chars().count() <= SHOWN + 1, "{line}");
        assert_eq!(full.unwrap().len(), 505);

        // Newlines in an error are folded, so the summary stays one line.
        let (line, full) = summarize(&ToolResult::error("run: no\nsuch\nfile"));
        assert_eq!(line, "run: no such file");
        assert_eq!(full.unwrap(), "run: no\nsuch\nfile");
    }
}
