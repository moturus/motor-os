//! The agent loop: send the conversation and the tool schemas, stream the
//! reply, and if the model asked for tools — gate them, run them in order,
//! append the results, go round again. When it asks for none, the turn ends.
//!
//! Two invariants hold however a turn ends, because the session file is
//! written as this goes and a malformed transcript cannot be resumed: an
//! assistant message carrying tool calls is *always* followed by exactly one
//! result per call, and a cancelled or failed turn leaves the conversation at
//! a point the model can be asked from again.

use crate::agent::bus::{Bus, Gone, PermissionRequest};
use crate::agent::context::{self, Context, Policy};
use crate::provider::{
    ChatMessage, ChatRequest, FinishReason, ModelProvider, ProviderError, ToolCall, Usage,
    UsageMeter,
};
use crate::tools::{Registry, ToolResult, clip, describe, parse_args};

/// Where a conversation is recorded as it grows, so that it can be resumed.
/// The session file is the real one (`session.rs`); a conversation with no
/// journal simply forgets.
pub trait Journal: Send {
    fn message(&mut self, message: &ChatMessage) -> std::io::Result<()>;

    fn usage(&mut self, _usage: &Usage) -> std::io::Result<()> {
        Ok(())
    }

    /// A checkpoint: the `replaced` messages from `head` are gone, and this
    /// summary of them stands where they were.
    fn compaction(
        &mut self,
        _head: usize,
        _replaced: usize,
        _summary: &str,
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
    /// words the model and the user both read.
    fn check(&self) -> Result<(), String>;

    /// What one completion cost, as the endpoint reported it.
    fn spent(&self, usage: &Usage);
}

/// Whether there is anything left to spend. USD where the endpoint prices its
/// completions, tokens where it does not (plan decision 10) — a budget that
/// cannot be counted in money is still a budget. `whose` names the pocket, and
/// is read by whoever is told there is nothing in it.
pub fn affordable(
    usd: Option<f64>,
    tokens: Option<u64>,
    spent: &UsageMeter,
    whose: &str,
) -> Result<(), String> {
    if let Some(limit) = usd
        && let Some(cost) = spent.cost_usd()
        && cost >= limit
    {
        return Err(format!(
            "the {whose} budget of ${limit:.2} is spent (${cost:.4} so far)"
        ));
    }
    if let Some(limit) = tokens
        && spent.total_tokens() >= limit
    {
        return Err(format!(
            "the {whose} budget of {limit} tokens is spent ({} so far)",
            spent.total_tokens()
        ));
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
    fn check(&self) -> Result<(), String> {
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
        let failure = self
            .journal
            .as_mut()
            .and_then(|journal| journal.compaction(range.start, range.len(), summary).err());
        self.messages
            .splice(range, [context::checkpoint(summary)])
            .for_each(drop);
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
}

/// Whether the remaining tool calls of one round should really run.
enum Flow {
    Run,
    Cancelled,
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
        }
    }

    pub fn with_max_steps(mut self, steps: usize) -> Agent<P> {
        self.max_steps = steps.max(1);
        self
    }

    pub fn with_context(mut self, policy: Policy) -> Agent<P> {
        self.context = Context::new(policy);
        self
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
                && let Err(why) = budget.check()
            {
                return match bus.failed(why.clone()) {
                    Ok(()) => Turned::Failed(why),
                    Err(Gone) => Turned::Gone,
                };
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
            let request = ChatRequest::new(
                self.conversation.model.clone(),
                self.conversation.messages.clone(),
            )
            .with_tools(self.tools.specs());

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
                Ok(Flow::Cancelled) => return Turned::Cancelled,
                Err(Gone) => return Turned::Gone,
            }
        }
        let text = format!(
            "the model called tools {} times without answering; stopping",
            self.max_steps
        );
        match bus.failed(text.clone()) {
            Ok(()) => Turned::Failed(text),
            Err(Gone) => Turned::Gone,
        }
    }

    /// Cut the conversation back to something the window will take, before the
    /// request goes out rather than after the endpoint has refused it.
    fn trim(&mut self, bus: &Bus) -> Result<(), Gone> {
        let plan = self.context.plan(self.conversation.messages());
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
    fn at_boundary(&self, bus: &Bus) -> Option<Turned> {
        if let Some(turned) = self.interrupted(bus) {
            return Some(turned);
        }
        bus.wait_if_paused();
        self.interrupted(bus)
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
            if matches!(flow, Flow::Run) {
                bus.wait_if_paused();
                if bus.cancelled() {
                    bus.take_cancel();
                    bus.notice("cancelled")?;
                    flow = Flow::Cancelled;
                }
            }
            let result = match flow {
                Flow::Run => self.call_tool(call, bus)?,
                // Every call is answered even when nothing ran: an assistant
                // message whose tool calls dangle cannot be sent again.
                Flow::Cancelled => ToolResult::error("cancelled before this call ran"),
            };
            if let Err(e) = self
                .conversation
                .push(ChatMessage::tool_result(call.id.clone(), result.content))
            {
                bus.failed(e)?;
            }
        }
        Ok(flow)
    }

    fn call_tool(&self, call: &ToolCall, bus: &Bus) -> Result<ToolResult, Gone> {
        let name = call.name();
        // Decoded twice — here to describe and to key the call, and again in
        // `dispatch`, which owns the one error path for arguments that are
        // nonsense. Cheap, and it keeps that error going to the model.
        let args = parse_args(call.arguments()).ok();
        bus.tool_start(describe(name, args.as_ref()))?;

        let result = match (self.tools.get(name), &args) {
            (Some(tool), Some(args)) if tool.gated(args) => {
                let request = PermissionRequest {
                    key: tool.permission_key(args),
                    detail: describe(name, Some(args)),
                };
                match bus.ask(request).allowed() {
                    true => {
                        tool.approved(args);
                        self.tools
                            .dispatch(name, call.arguments(), &bus.execution())
                    }
                    false => ToolResult::error(format!("the user did not allow {name} to run")),
                }
            }
            _ => self
                .tools
                .dispatch(name, call.arguments(), &bus.execution()),
        };
        let (detail, full) = summarize(&result);
        bus.tool_end(result.outcome, detail, full)?;
        Ok(result)
    }
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
            while let Ok(event) = fixture.events.recv() {
                match event {
                    Event::Permission { reply, .. } => {
                        reply.send(answers.pop().unwrap_or(Decision::Deny))
                    }
                    Event::Exit { .. } => break,
                    other => seen.push(other),
                }
            }
            (running.join().unwrap(), seen)
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
        fixture.agent.max_steps = 3;

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
        struct Tally(Mutex<u64>);

        impl Budget for Tally {
            fn check(&self) -> Result<(), String> {
                match *self.0.lock().unwrap() >= 8 {
                    true => Err("the budget is used up".to_string()),
                    false => Ok(()),
                }
            }

            fn spent(&self, usage: &Usage) {
                *self.0.lock().unwrap() += usage.prompt_tokens + usage.completion_tokens;
            }
        }

        let purse = Arc::new(Tally(Mutex::new(0)));
        let mut fixture = fixture(vec![
            calls("call_1", "note", r#"{"path":"a.txt"}"#),
            says("this is never asked for"),
        ]);
        let mut tools = Registry::new();
        tools.register(Box::new(fixture.note.clone()));
        fixture.agent = rebuilt(&fixture, tools).with_budget(purse.clone());

        let (outcome, events) = turn(&mut fixture, "take a note", &[Decision::Allow]);
        // One round happened, at 8 tokens; the second was refused.
        assert!(
            matches!(&outcome, Turned::Failed(why) if why.contains("used up")),
            "{outcome:?}"
        );
        assert_eq!(fixture.script.requests().len(), 1);
        assert_eq!(*purse.0.lock().unwrap(), 8);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Failed { text, .. } if text.contains("used up")))
        );
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
        assert!(why.contains("the run budget of 100 tokens"), "{why}");

        // Money, where there is a price to go by.
        let priced = Purse::new(RunLimits {
            budget_usd: Some(0.50),
            ..RunLimits::default()
        });
        priced.spent(&spend(1, Some(0.49)));
        assert!(priced.check().is_ok());
        priced.spent(&spend(1, Some(0.02)));
        let why = priced.check().unwrap_err();
        assert!(why.contains("the run budget of $0.50"), "{why}");
        assert!(why.contains("$0.5100"), "{why}");
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
