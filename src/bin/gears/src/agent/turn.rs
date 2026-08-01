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
}

/// What an agent's work is allowed to cost. The agent the user is talking to
/// has none — they are watching it, and it is their money — while sub-agents
/// share one, because nobody is watching those (`agent/registry.rs`).
pub trait Budget: Send + Sync {
    /// Asked before every completion. `Err` is why there will not be one, in
    /// words the model and the user both read.
    fn check(&self) -> Result<(), String>;

    /// What one completion cost, as the endpoint reported it.
    fn spent(&self, usage: &Usage);
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
        }
    }

    pub fn with_max_steps(mut self, steps: usize) -> Agent<P> {
        self.max_steps = steps.max(1);
        self
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
            // a tool was running means this turn is over, and asking the model
            // what to do next would be spending the user's money on an answer
            // they have just said they do not want.
            if bus.cancelled() {
                bus.take_cancel();
                return match bus.notice("cancelled") {
                    Ok(()) => Turned::Cancelled,
                    Err(Gone) => Turned::Gone,
                };
            }
            if let Some(budget) = &self.budget
                && let Err(why) = budget.check()
            {
                return match bus.failed(why.clone()) {
                    Ok(()) => Turned::Failed(why),
                    Err(Gone) => Turned::Gone,
                };
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
            if matches!(flow, Flow::Run) && bus.cancelled() {
                bus.take_cancel();
                bus.notice("cancelled")?;
                flow = Flow::Cancelled;
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
                        self.tools.dispatch(name, call.arguments())
                    }
                    false => ToolResult::error(format!("the user did not allow {name} to run")),
                }
            }
            _ => self.tools.dispatch(name, call.arguments()),
        };
        let (detail, full) = summarize(&result);
        bus.tool_end(!result.is_error, detail, full)?;
        Ok(result)
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
    let line = match result.is_error {
        true => clip(&content.replace('\n', " "), SHOWN),
        false => format!("{} bytes", result.content.len()),
    };
    (line, Some(result.content.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::{Cancel, Decision, Event, ROOT};
    use crate::provider::{Completion, EventSink, Role, ToolSpec};
    use crate::tools::{Tool, schema, string_arg};
    use serde_json::{Value, json};
    use std::sync::mpsc::{Receiver, channel};
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
        let (tx, events) = channel();
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
                .any(|e| matches!(e, Event::ToolEnd { ok: false, .. }))
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
        struct Purse(Mutex<u64>);

        impl Budget for Purse {
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

        let purse = Arc::new(Purse(Mutex::new(0)));
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

        let mut fixture = fixture(vec![calls("call_1", "trip", "{}"), says("never sent")]);
        let mut tools = Registry::new();
        tools.register(Box::new(Trip(fixture.bus.canceller())));
        fixture.agent = rebuilt(&fixture, tools);

        let (outcome, _) = turn(&mut fixture, "trip it", &[]);
        assert_eq!(outcome, Turned::Cancelled);
        assert_eq!(fixture.script.requests().len(), 1, "it asked again");
        // The call ran and was answered, so the transcript can be sent again.
        let said = roles(fixture.agent.conversation());
        assert_eq!(said.len(), 3);
        assert_eq!(said[2], (Role::Tool, "tripped".to_string()));
        assert!(!fixture.bus.cancelled());
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
