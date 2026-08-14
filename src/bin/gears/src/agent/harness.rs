//! Assembly: one workspace, one session, one agent the user talks to, and
//! however many that one starts for itself.
//!
//! Everything the agent needs is put together here and then handed across a
//! thread boundary, so that the only things the UI keeps are the two ends of
//! the bus and the few objects that are honestly the user's rather than the
//! model's — the undo log and the session it belongs to.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use crate::agent::bus::{Bus, Cancel, Event, Pause, ROOT, event_channel};
use crate::agent::prompt;
use crate::agent::registry::{Agents, Kit, Limits, Provider};
use crate::agent::session::Session;
use crate::agent::turn::{Agent, Budget, Conversation, Purse, Turned};
use crate::agent::undo::UndoLog;
use crate::provider::ChatMessage;
use crate::tools::{Tool, Workspace, fs, run, selfhost, toolchain, vcs};

pub enum Command {
    /// Answer this, and everything it takes to answer it.
    Prompt(String),
    Stop,
}

/// What an agent needs to know before it exists.
pub struct Setup {
    pub workspace: PathBuf,
    /// Required for a new session; a resumed one takes the model it started
    /// with unless this overrides it.
    pub model: Option<String>,
    pub resume: Option<String>,
    /// Paths the file tools must not touch — the API key file above all.
    pub deny: Vec<PathBuf>,
    /// What one run may do: tool rounds per turn, and what the whole run may
    /// spend.
    pub run: crate::agent::turn::RunLimits,
    pub run_timeout: std::time::Duration,
    pub build_timeout: std::time::Duration,
    /// What sub-agents are allowed: depth, how many at once, what they may
    /// spend between them.
    pub limits: Limits,
    /// What the model's context window will take.
    pub context: crate::agent::context::Policy,
    /// What gears may do to itself, and where a restart request is left for
    /// the interface to act on.
    pub selfhost: crate::tools::selfhost::Policy,
    pub restart: crate::tools::selfhost::Restart,
    /// Tools the caller brings, on top of the built-in ones: `fetch`, which
    /// needs a transport, and whatever a test wants to substitute.
    pub tools: Vec<Box<dyn Tool>>,
}

impl Setup {
    pub fn new(workspace: PathBuf) -> Setup {
        Setup {
            workspace,
            model: None,
            resume: None,
            deny: Vec::new(),
            run: crate::agent::turn::RunLimits::default(),
            run_timeout: crate::tools::run::DEFAULT_TIMEOUT,
            build_timeout: crate::tools::run::DEFAULT_BUILD_TIMEOUT,
            limits: Limits::default(),
            context: crate::agent::context::Policy::default(),
            selfhost: crate::tools::selfhost::Policy::default(),
            restart: crate::tools::selfhost::Restart::new(),
            tools: Vec::new(),
        }
    }
}

pub struct Harness {
    commands: Option<Sender<Command>>,
    events: Receiver<Event>,
    cancel: Cancel,
    pause: Pause,
    thread: Option<JoinHandle<()>>,
    workspace: PathBuf,
    model: String,
    session_id: String,
    undo: Arc<UndoLog>,
    opening: String,
}

impl Harness {
    pub fn start(mut setup: Setup, provider: Provider) -> Result<Harness, String> {
        let mut workspace = Workspace::new(&setup.workspace)?;
        for path in &setup.deny {
            workspace = workspace.deny(path);
        }
        // Canonical from here on: the undo log strips this prefix off every
        // path it records, and the session lives under it.
        let root = workspace.root().to_path_buf();

        let opened = open(&root, &setup)?;
        let session_id = opened.session.id().to_string();
        let model = opened.conversation.model().to_string();

        let undo = Arc::new(UndoLog::new(&root, &session_id)?);
        let workspace = Arc::new(workspace.with_undo(undo.clone()));
        let selfhost = selfhost::tools(
            &root,
            &session_id,
            workspace.clone(),
            &setup.selfhost,
            &setup.restart,
        )?;
        // Shared, not owned: a sub-agent works the same workspace through the
        // same tools, filtered by what it is allowed rather than rebuilt.
        let tools: Vec<Arc<dyn Tool>> = fs::tools(workspace.clone())
            .into_iter()
            .chain([run::tool(workspace.clone(), setup.run_timeout)])
            .chain(toolchain::for_platform(
                workspace.clone(),
                setup.build_timeout,
            ))
            // Nothing at all on a workspace under no version control; on
            // Motor OS, which has no git, stubs that say so instead.
            .chain(vcs::for_platform(&root, workspace.clone()))
            // These three are always there, and do something only where gears
            // has been told it may work on its own source: a model that cannot
            // find out why it may not improvises instead.
            .chain(selfhost)
            .chain(setup.tools.drain(..))
            .map(Arc::from)
            .collect();

        let (event_tx, events) = event_channel();
        let (command_tx, command_rx) = channel();
        let mut bus = Bus::new(ROOT, event_tx.clone());
        let cancel = bus.canceller();
        let pause = bus.pauser();
        // The run's purse, where the user set a cap at all: the root agent
        // spends out of it, and so do sub-agents through their own.
        let purse = Arc::new(Purse::new(setup.run));
        let run: Option<Arc<dyn Budget>> = purse.capped().then(|| purse.clone() as Arc<dyn Budget>);
        let agents = Agents::new(
            Kit {
                root: root.clone(),
                tools,
                provider: provider.clone(),
                model: model.clone(),
                max_steps: setup.run.max_steps,
                context: setup.context,
            },
            setup.limits,
            run.clone(),
            event_tx,
            pause.clone(),
        );
        let tools = agents.registry(0, false);

        let mut conversation = opened.conversation.with_journal(Box::new(opened.session));
        // A resumed conversation already carries the prompt it was started
        // with, recorded in the session: what was sent is what is sent again.
        if opened.fresh {
            conversation.push(ChatMessage::system(prompt::build(&root, &tools.names())))?;
        }

        let mut agent = Agent::new(provider, tools, conversation)
            .with_max_steps(setup.run.max_steps)
            .with_context(setup.context);
        if let Some(run) = run {
            agent = agent.with_budget(run);
        }
        agent.measured(opened.measured);

        let thread = std::thread::spawn(move || {
            while let Ok(Command::Prompt(text)) = command_rx.recv() {
                let outcome = agent.turn(&text, &mut bus);
                // The turn is where sub-agents end: one the model started and
                // never waited for has nowhere left to deliver an answer.
                let stopped = agents.stop_all();
                if stopped > 0 && bus.notice(left_running(stopped)).is_err() {
                    break;
                }
                // What the user is shown as spent is everything spent on their
                // behalf, sub-agents included.
                let mut usage = agent.usage();
                usage.merge(&agents.spending());
                if bus.turn_end(usage, outcome == Turned::Done).is_err() || outcome == Turned::Gone
                {
                    break;
                }
            }
            let _ = bus.exit();
        });

        Ok(Harness {
            commands: Some(command_tx),
            events,
            cancel,
            pause,
            thread: Some(thread),
            workspace: root,
            model,
            session_id,
            undo,
            opening: opened.opening,
        })
    }

    pub fn events(&self) -> &Receiver<Event> {
        &self.events
    }

    /// Ask the root agent to stop its current turn at the next safe point.
    pub fn cancel(&self) {
        self.cancel.raise();
        self.pause.wake();
    }

    pub fn set_paused(&self, paused: bool) {
        self.pause.set(paused);
    }

    pub fn toggle_paused(&self) -> bool {
        self.pause.toggle()
    }

    pub fn paused(&self) -> bool {
        self.pause.pending()
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn undo(&self) -> &Arc<UndoLog> {
        &self.undo
    }

    /// What to tell the user on the way in: which session this is, and what
    /// was found in it.
    pub fn opening(&self) -> &str {
        &self.opening
    }

    /// Hand the agent something to do. An error means it is no longer there.
    pub fn send(&self, command: Command) -> Result<(), String> {
        match &self.commands {
            Some(commands) => commands
                .send(command)
                .map_err(|_| "the agent stopped".to_string()),
            None => Err("the agent stopped".to_string()),
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Dropping the sender is what ends the agent's loop; the join is what
        // makes sure the session file is closed and its lock released before
        // the process goes away.
        if let Some(commands) = self.commands.take() {
            let _ = commands.send(Command::Stop);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What opening the session gave us.
struct Opened {
    session: Session,
    conversation: Conversation,
    /// What to tell the user on the way in.
    opening: String,
    /// Whether this is a new session — which is what needs a system prompt.
    fresh: bool,
    /// The endpoint's own count for the last request the session recorded, so
    /// that a resumed conversation knows its size before it sends anything.
    measured: u64,
}

/// Open the session this run works in, and the conversation that goes with it.
fn open(root: &Path, setup: &Setup) -> Result<Opened, String> {
    let Some(id) = &setup.resume else {
        let model = setup.model.clone().ok_or(NO_MODEL)?;
        let session = Session::create(root, &model)?;
        let opening = format!("session {}", session.id());
        return Ok(Opened {
            session,
            conversation: Conversation::new(model),
            opening,
            fresh: true,
            measured: 0,
        });
    };

    let (session, transcript) = Session::resume(root, id)?;
    let model = setup
        .model
        .clone()
        .or_else(|| transcript.model.clone())
        .ok_or(NO_MODEL)?;
    let mut opening = format!(
        "resumed session {id}: {} messages, {}",
        transcript.messages.len(),
        transcript.usage.summary()
    );
    if transcript.unknown > 0 {
        opening.push_str(&format!(
            "; {} records from a newer gears were skipped",
            transcript.unknown
        ));
    }
    if transcript.damaged > 0 {
        opening.push_str(&format!("; {} unreadable records", transcript.damaged));
    }
    Ok(Opened {
        session,
        conversation: Conversation::resumed(model, transcript.messages, transcript.usage),
        opening,
        fresh: false,
        measured: transcript.last_prompt_tokens,
    })
}

const NO_MODEL: &str = "no model: pass -m MODEL or set provider.model in the config";

fn left_running(stopped: usize) -> String {
    match stopped {
        1 => "a sub-agent was still working and was stopped".to_string(),
        n => format!("{n} sub-agents were still working and were stopped"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::Event;
    use crate::agent::turn::Journal;
    use crate::provider::{
        ChatRequest, Completion, EventSink, FinishReason, ModelProvider, ProviderError, Usage,
    };
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Fixed(Mutex<Vec<Completion>>);

    impl ModelProvider for Fixed {
        fn complete(
            &self,
            _req: &ChatRequest,
            sink: &mut dyn EventSink,
        ) -> Result<Completion, ProviderError> {
            let completion = self.0.lock().unwrap().pop().unwrap_or_else(|| Completion {
                content: "nothing more to say".to_string(),
                finish_reason: Some(FinishReason::Stop),
                ..Completion::default()
            });
            sink.on_content(&completion.content)
                .map_err(|e| ProviderError::Aborted(e.to_string()))?;
            Ok(completion)
        }
    }

    fn answers(texts: &[&str]) -> Provider {
        Arc::new(Fixed(Mutex::new(
            texts
                .iter()
                .rev()
                .map(|text| Completion {
                    content: text.to_string(),
                    finish_reason: Some(FinishReason::Stop),
                    usage: Usage {
                        prompt_tokens: 3,
                        completion_tokens: 1,
                        ..Usage::default()
                    },
                    ..Completion::default()
                })
                .collect(),
        )))
    }

    /// A provider that counts what it is sent the way an endpoint does — from
    /// the request itself — and knows a request to summarize when it sees one.
    #[derive(Default)]
    struct Fat {
        peak: Mutex<u64>,
        summaries: Mutex<usize>,
    }

    impl ModelProvider for Fat {
        fn complete(
            &self,
            req: &ChatRequest,
            sink: &mut dyn EventSink,
        ) -> Result<Completion, ProviderError> {
            let tokens = (serde_json::to_string(req).unwrap().len() / 4) as u64;
            let mut peak = self.peak.lock().unwrap();
            *peak = (*peak).max(tokens);

            let asked = req.messages.last().and_then(|m| m.content.as_deref());
            let content = match asked.is_some_and(|text| text.contains("all you will have")) {
                true => {
                    *self.summaries.lock().unwrap() += 1;
                    "they asked about the weather, over and over".to_string()
                }
                false => "noted".to_string(),
            };
            sink.on_content(&content)
                .map_err(|e| ProviderError::Aborted(e.to_string()))?;
            Ok(Completion {
                content,
                finish_reason: Some(FinishReason::Stop),
                usage: Usage {
                    prompt_tokens: tokens,
                    completion_tokens: 4,
                    ..Usage::default()
                },
                ..Completion::default()
            })
        }
    }

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-harness-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Send a prompt and collect what comes back, up to the end of the turn.
    fn ask(harness: &Harness, prompt: &str) -> Vec<Event> {
        harness.send(Command::Prompt(prompt.to_string())).unwrap();
        let mut seen = Vec::new();
        while let Ok(event) = harness.events().recv() {
            let end = matches!(event, Event::TurnEnd { .. } | Event::Exit { .. });
            seen.push(event);
            if end {
                break;
            }
        }
        seen
    }

    fn said(events: &[Event]) -> String {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Token { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_new_session_is_started_prompted_and_kept() {
        let dir = workspace("new");
        std::fs::write(dir.join("AGENTS.md"), "House rule: be terse.\n").unwrap();
        let mut setup = Setup::new(dir.clone());
        setup.model = Some("test/model".to_string());

        let harness = Harness::start(setup, answers(&["first", "second"])).unwrap();
        let id = harness.session_id().to_string();
        assert!(harness.opening().contains(&id), "{}", harness.opening());
        assert_eq!(said(&ask(&harness, "hello")), "first");
        assert_eq!(said(&ask(&harness, "again")), "second");
        drop(harness);

        // The session records both exchanges, and the system prompt gears
        // actually sent — including the project's own instructions.
        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.model.as_deref(), Some("test/model"));
        assert_eq!(transcript.messages.len(), 5);
        let system = transcript.messages[0].content.clone().unwrap();
        assert!(system.contains("House rule: be terse."), "{system}");
        assert!(system.contains("read_file, write_file"), "{system}");
        assert_eq!(transcript.usage.total_tokens(), 8);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A capped run stops when the cap is reached, and stays stopped: the
    /// quota a budget stands for is not restored by the user typing again.
    #[test]
    fn a_capped_run_stops_when_the_cap_is_reached() {
        let dir = workspace("budget");
        let mut setup = Setup::new(dir.clone());
        setup.model = Some("test/model".to_string());
        setup.run = crate::agent::turn::RunLimits {
            budget_tokens: Some(6),
            ..crate::agent::turn::RunLimits::default()
        };

        // Four tokens a turn, so the third is one the run cannot afford.
        let harness = Harness::start(setup, answers(&["first", "second", "third"])).unwrap();
        assert_eq!(said(&ask(&harness, "hello")), "first");
        assert_eq!(said(&ask(&harness, "again")), "second");

        let events = ask(&harness, "once more");
        assert_eq!(said(&events), "", "the request went out anyway");
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Failed { text, .. }
                if text.contains("the run budget of 6 tokens is spent (8 so far)"))),
            "{events:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_resumed_session_carries_on_where_it_left_off() {
        let dir = workspace("resume");
        let mut setup = Setup::new(dir.clone());
        setup.model = Some("test/model".to_string());
        let harness = Harness::start(setup, answers(&["one"])).unwrap();
        let id = harness.session_id().to_string();
        ask(&harness, "first prompt");
        drop(harness);

        let mut setup = Setup::new(dir.clone());
        setup.resume = Some(id.clone());
        let harness = Harness::start(setup, answers(&["two"])).unwrap();
        assert_eq!(harness.session_id(), id);
        // The model came from the session, not from a flag.
        assert_eq!(harness.model(), "test/model");
        assert!(
            harness.opening().contains("3 messages"),
            "{}",
            harness.opening()
        );
        assert_eq!(said(&ask(&harness, "second prompt")), "two");
        drop(harness);

        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.messages.len(), 5);
        // One system prompt, not two: a resumed session does not get another.
        let systems = transcript
            .messages
            .iter()
            .filter(|m| m.role == crate::provider::Role::System)
            .count();
        assert_eq!(systems, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The end of the exit criterion for plan step 8: a session long enough to
    /// fill the window is compacted while it runs, and comes back off disk as
    /// what it was compacted to rather than as what was first written.
    #[test]
    fn a_compacted_session_resumes_as_it_was_left() {
        const BUDGET: u64 = 6_000;
        let policy = crate::agent::context::Policy {
            budget: BUDGET,
            summarize: true,
        };
        let dir = workspace("compaction");
        let mut setup = Setup::new(dir.clone());
        setup.model = Some("test/model".to_string());
        setup.context = policy;

        let fat = Arc::new(Fat::default());
        let harness = Harness::start(setup, fat.clone()).unwrap();
        let id = harness.session_id().to_string();
        for turn in 0..8 {
            let long = "tell me about the weather ".repeat(120);
            ask(&harness, &format!("{turn}: {long}"));
        }
        drop(harness);

        let peak = *fat.peak.lock().unwrap();
        assert!(peak <= BUDGET, "{peak} tokens against a budget of {BUDGET}");
        assert!(
            *fat.summaries.lock().unwrap() >= 1,
            "nothing was summarized"
        );

        // What the session holds is the compacted conversation: the summary
        // stands where the first exchanges were, and they are gone.
        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.damaged, 0);
        let has = |needle: &str| {
            transcript
                .messages
                .iter()
                .filter_map(|m| m.content.as_deref())
                .any(|text| text.contains(needle))
        };
        assert!(
            has("over and over"),
            "no summary: {:?}",
            transcript.messages
        );
        assert!(!has("0: tell me"), "the first exchange survived");
        assert_eq!(transcript.messages[0].role, crate::provider::Role::System);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A resumed session knows its size before it sends anything: what the
    /// endpoint counted for the last request it made is in the transcript.
    /// Without that, the first request after a resume would be the one nobody
    /// had measured — and on a session this long, the largest there had been.
    #[test]
    fn a_resumed_session_is_cut_back_before_the_first_request() {
        const BUDGET: u64 = 8_000;
        let dir = workspace("resume-trim");
        let id = {
            let mut session = Session::create(&dir, "test/model").unwrap();
            session
                .message(&ChatMessage::system("you are gears"))
                .unwrap();
            for round in 0..6 {
                let call = format!("call_{round}");
                session
                    .message(&ChatMessage {
                        role: crate::provider::Role::Assistant,
                        content: None,
                        tool_calls: vec![crate::provider::ToolCall::new(
                            &call,
                            "read_file",
                            r#"{"path":"big.rs"}"#,
                        )],
                        tool_call_id: None,
                    })
                    .unwrap();
                session
                    .message(&ChatMessage::tool_result(call, "x".repeat(6_000)))
                    .unwrap();
            }
            // What the endpoint counted for the last request of that session.
            session
                .usage(&Usage {
                    prompt_tokens: 9_000,
                    completion_tokens: 20,
                    ..Usage::default()
                })
                .unwrap();
            session.id().to_string()
        };

        let resume = |budget: u64| {
            let mut setup = Setup::new(dir.clone());
            setup.resume = Some(id.clone());
            setup.context = crate::agent::context::Policy {
                budget,
                summarize: false,
            };
            let fat = Arc::new(Fat::default());
            let harness = Harness::start(setup, fat.clone()).unwrap();
            ask(&harness, "carry on");
            drop(harness);
            *fat.peak.lock().unwrap()
        };

        let managed = resume(BUDGET);
        assert!(managed <= BUDGET, "{managed} tokens on the first request");
        // And it was the accounting that did it: the same session resumed with
        // context management off sends the whole thing.
        let unmanaged = resume(0);
        assert!(unmanaged > BUDGET, "{unmanaged} tokens unmanaged");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_run_without_a_model_says_so_before_anything_else() {
        let dir = workspace("nomodel");
        let error = match Harness::start(Setup::new(dir.clone()), answers(&[])) {
            Err(error) => error,
            Ok(_) => panic!("started without a model"),
        };
        assert!(error.contains("provider.model"), "{error}");
        // Nothing was created on the way to finding out.
        assert!(Session::list(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
