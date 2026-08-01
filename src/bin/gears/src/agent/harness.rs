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

use crate::agent::bus::{Bus, Event, ROOT};
use crate::agent::prompt;
use crate::agent::registry::{Agents, Kit, Limits, Provider};
use crate::agent::session::Session;
use crate::agent::turn::{Agent, Conversation, Turned};
use crate::agent::undo::UndoLog;
use crate::provider::ChatMessage;
use crate::tools::{Tool, Workspace, fs, run, toolchain, vcs};

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
    pub max_steps: usize,
    pub run_timeout: std::time::Duration,
    pub build_timeout: std::time::Duration,
    /// What sub-agents are allowed: depth, how many at once, what they may
    /// spend between them.
    pub limits: Limits,
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
            max_steps: crate::agent::turn::DEFAULT_MAX_STEPS,
            run_timeout: crate::tools::run::DEFAULT_TIMEOUT,
            build_timeout: crate::tools::run::DEFAULT_BUILD_TIMEOUT,
            limits: Limits::default(),
            tools: Vec::new(),
        }
    }
}

pub struct Harness {
    commands: Option<Sender<Command>>,
    events: Receiver<Event>,
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

        let (session, mut conversation, opening, fresh) = open(&root, &setup)?;
        let session_id = session.id().to_string();
        let model = conversation.model().to_string();

        let undo = Arc::new(UndoLog::new(&root, &session_id));
        let workspace = Arc::new(workspace.with_undo(undo.clone()));
        // Shared, not owned: a sub-agent works the same workspace through the
        // same tools, filtered by what it is allowed rather than rebuilt.
        let tools: Vec<Arc<dyn Tool>> = fs::tools(workspace.clone())
            .into_iter()
            .chain([run::tool(workspace.clone(), setup.run_timeout)])
            .chain(toolchain::tools(
                toolchain::host(),
                workspace.clone(),
                setup.build_timeout,
            ))
            // Nothing at all on a workspace under no version control, which is
            // the Motor OS v1 story as much as it is an unversioned directory.
            .chain(vcs::tools(vcs::host(&root), workspace))
            .chain(setup.tools.drain(..))
            .map(Arc::from)
            .collect();

        let (event_tx, events) = channel();
        let (command_tx, command_rx) = channel();
        let mut bus = Bus::new(ROOT, event_tx.clone());
        let agents = Agents::new(
            Kit {
                root: root.clone(),
                tools,
                provider: provider.clone(),
                model: model.clone(),
                max_steps: setup.max_steps,
            },
            setup.limits,
            event_tx,
        );
        let tools = agents.registry(0, false, &bus.canceller());

        conversation = conversation.with_journal(Box::new(session));
        // A resumed conversation already carries the prompt it was started
        // with, recorded in the session: what was sent is what is sent again.
        if fresh {
            conversation.push(ChatMessage::system(prompt::build(&root, &tools.names())))?;
        }

        let mut agent = Agent::new(provider, tools, conversation).with_max_steps(setup.max_steps);

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
            thread: Some(thread),
            workspace: root,
            model,
            session_id,
            undo,
            opening,
        })
    }

    pub fn events(&self) -> &Receiver<Event> {
        &self.events
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

/// Open the session this run works in, and the conversation that goes with it.
fn open(root: &Path, setup: &Setup) -> Result<(Session, Conversation, String, bool), String> {
    let Some(id) = &setup.resume else {
        let model = setup.model.clone().ok_or(NO_MODEL)?;
        let session = Session::create(root, &model)?;
        let opening = format!("session {}", session.id());
        return Ok((session, Conversation::new(model), opening, true));
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
    let conversation = Conversation::resumed(model, transcript.messages, transcript.usage);
    Ok((session, conversation, opening, false))
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

    #[test]
    fn a_run_without_a_model_says_so_before_anything_else() {
        let dir = workspace("nomodel");
        let error = match Harness::start(Setup::new(dir.clone()), answers(&[])) {
            Err(error) => error,
            Ok(_) => panic!("started without a model"),
        };
        assert!(error.contains("provider.model"), "{error}");
        // Nothing was created on the way to finding out.
        assert!(Session::list(&dir).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
