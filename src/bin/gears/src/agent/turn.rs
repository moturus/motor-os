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
use crate::tools::{Registry, ToolResult, describe, parse_args};

/// Where a conversation is recorded as it grows, so that it can be resumed.
/// The session file is the real one (`session.rs`); a conversation with no
/// journal simply forgets.
pub trait Journal: Send {
    fn message(&mut self, message: &ChatMessage) -> std::io::Result<()>;

    fn usage(&mut self, _usage: &Usage) -> std::io::Result<()> {
        Ok(())
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
/// the value is for the caller's control flow, not for printing.
#[derive(Debug, PartialEq, Eq)]
pub enum Turned {
    /// The model answered.
    Done,
    /// A ^C ended it. The conversation is back at a resumable point.
    Cancelled,
    /// It went wrong. The user can say something else, or the same thing
    /// again — gears does not retry on its own (plan decision 7).
    Failed,
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
        }
    }

    pub fn with_max_steps(mut self, steps: usize) -> Agent<P> {
        self.max_steps = steps.max(1);
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
            let request = ChatRequest::new(
                self.conversation.model.clone(),
                self.conversation.messages.clone(),
            )
            .with_tools(self.tools.specs());

            let completion = match self.provider.complete(&request, bus) {
                Ok(completion) => completion,
                Err(e) => return self.stopped(e, bus),
            };
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
        match bus.failed(text) {
            Ok(()) => Turned::Failed,
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
        match bus.failed(e.to_string()) {
            Ok(()) => Turned::Failed,
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
            (Some(tool), Some(args)) if tool.mutates() => {
                let request = PermissionRequest {
                    key: tool.permission_key(args),
                    detail: describe(name, Some(args)),
                };
                match bus.ask(request).allowed() {
                    true => self.tools.dispatch(name, call.arguments()),
                    false => ToolResult::error(format!("the user did not allow {name} to run")),
                }
            }
            _ => self.tools.dispatch(name, call.arguments()),
        };
        bus.tool_end(!result.is_error, summarize(&result))?;
        Ok(result)
    }
}

/// What a finished call looks like in the transcript. A one-line result is
/// worth showing — `wrote 6 bytes to notes.txt` says everything — and a file
/// or a search hit list is not, so that one is reported by size.
fn summarize(result: &ToolResult) -> String {
    let content = result.content.trim_end();
    match result.is_error || (content.len() <= 120 && !content.contains('\n')) {
        true => content.to_string(),
        false => format!("{} bytes", result.content.len()),
    }
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

        assert_eq!(outcome, Turned::Failed);
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
        assert_eq!(outcome, Turned::Failed);
        assert_eq!(fixture.script.requests().len(), 3);
        assert!(
            events.iter().any(
                |e| matches!(e, Event::Failed { text, .. } if text.contains("without answering"))
            ),
            "{events:?}"
        );
    }

    #[test]
    fn a_result_is_summarized_by_shape() {
        assert_eq!(
            summarize(&ToolResult::ok("wrote 6 bytes\n")),
            "wrote 6 bytes"
        );
        assert_eq!(summarize(&ToolResult::ok("a\nb\nc")), "5 bytes");
        assert_eq!(summarize(&ToolResult::error("nope")), "nope");
    }
}
