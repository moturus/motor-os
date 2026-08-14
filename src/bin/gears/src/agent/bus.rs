//! The event bus.
//!
//! Everything the user sees travels one way over one channel: agents send,
//! the UI thread receives, and only the UI thread touches the terminal. That
//! is what keeps two sub-agents from interleaving half-lines on top of each
//! other — every event says which agent it came from, and the renderer breaks
//! the line when the speaker changes — and it is why the permission gate sits
//! on the UI side of the bus: an agent *asks*, it never prompts.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Condvar, Mutex};

use crate::provider::{EventSink, UsageMeter};

/// Which agent an event came from. Zero is the one the user talks to;
/// sub-agents are numbered from one, in the order they were spawned.
pub type AgentId = u32;

pub const ROOT: AgentId = 0;

/// Which foreground pipe produced a live tool-output chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolStream {
    Stdout,
    Stderr,
}

/// The one-shot answer to a question put to the UI.
pub struct Reply<T>(Sender<T>);

impl<T> Reply<T> {
    /// Answer. Dropping a `Reply` unanswered is not a bug: the asker reads
    /// silence as a refusal, which is the safe meaning of "the UI went away".
    pub fn send(self, value: T) {
        let _ = self.0.send(value);
    }
}

impl<T> std::fmt::Debug for Reply<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Reply")
    }
}

/// The asking end: blocks until the UI answers or drops the reply.
pub struct Ask<T>(Receiver<T>);

impl<T> Ask<T> {
    pub fn wait(self) -> Option<T> {
        self.0.recv().ok()
    }
}

pub fn question<T>() -> (Reply<T>, Ask<T>) {
    let (tx, rx) = channel();
    (Reply(tx), Ask(rx))
}

/// What the user said about one pending call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// Allow this one and every later call under the same key.
    Always,
}

impl Decision {
    pub fn allowed(self) -> bool {
        !matches!(self, Decision::Deny)
    }
}

/// A call waiting on permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRequest {
    /// What an "always" answer is remembered under: the tool's name, or
    /// something narrower where the name alone is too coarse.
    pub key: String,
    /// One line for the prompt — `write_file src/main.rs`.
    pub detail: String,
}

#[derive(Debug)]
pub enum Event {
    /// A piece of the answer, as it streams.
    Token {
        agent: AgentId,
        text: String,
    },
    /// A piece of the model's reasoning, for endpoints that stream it.
    Reasoning {
        agent: AgentId,
        text: String,
    },
    ToolStart {
        agent: AgentId,
        detail: String,
    },
    /// A bounded piece of foreground tool output. Formatting belongs to the
    /// UI; the event preserves which pipe produced it.
    ToolOutput {
        agent: AgentId,
        stream: ToolStream,
        text: String,
    },
    /// Time spent in the active foreground tool, emitted while it still runs.
    ToolProgress {
        agent: AgentId,
        elapsed: std::time::Duration,
    },
    ToolEnd {
        agent: AgentId,
        ok: bool,
        detail: String,
        /// The whole result, carried only when `detail` is a summary of it —
        /// so that the UI can offer to show what the screen left out, and a
        /// result that fits on its line costs nothing extra.
        full: Option<String>,
    },
    Permission {
        agent: AgentId,
        request: PermissionRequest,
        reply: Reply<Decision>,
    },
    /// Something worth saying that is neither output nor a failure.
    Notice {
        agent: AgentId,
        text: String,
    },
    /// The turn ended badly. The agent stays alive; the user can re-send.
    Failed {
        agent: AgentId,
        text: String,
    },
    /// One prompt has been dealt with, for better or worse. `ok` is whether
    /// the model actually answered — a cancelled or failed turn ends here too.
    TurnEnd {
        agent: AgentId,
        usage: UsageMeter,
        ok: bool,
    },
    /// The agent thread is finished.
    Exit {
        agent: AgentId,
    },
}

impl Event {
    /// Who this came from. Every event says so, because with more than one
    /// agent talking the answer decides where the line goes.
    pub fn agent(&self) -> AgentId {
        match self {
            Event::Token { agent, .. }
            | Event::Reasoning { agent, .. }
            | Event::ToolStart { agent, .. }
            | Event::ToolOutput { agent, .. }
            | Event::ToolProgress { agent, .. }
            | Event::ToolEnd { agent, .. }
            | Event::Permission { agent, .. }
            | Event::Notice { agent, .. }
            | Event::Failed { agent, .. }
            | Event::TurnEnd { agent, .. }
            | Event::Exit { agent } => *agent,
        }
    }
}

/// Nobody is listening any more, so there is no point going on.
#[derive(Debug)]
pub struct Gone;

impl std::fmt::Display for Gone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the interface went away")
    }
}

/// A request that one agent stop what it is doing. Per agent rather than per
/// process, because a parent cancels a sub-agent without touching itself; ^C
/// on the host arrives by a different road — the process-wide interrupt flag —
/// and both are checked together.
#[derive(Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Cancel {
        Cancel::default()
    }

    pub fn raise(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn pending(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Take the request, clearing it.
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

/// A scheduling gate shared by every agent in one harness.
#[derive(Clone, Default)]
pub struct Pause(Arc<(Mutex<bool>, Condvar)>);

impl Pause {
    pub fn new() -> Pause {
        Pause::default()
    }

    pub fn set(&self, paused: bool) {
        let (state, wake) = &*self.0;
        *state.lock().unwrap() = paused;
        wake.notify_all();
    }

    pub fn toggle(&self) -> bool {
        let (state, wake) = &*self.0;
        let mut paused = state.lock().unwrap();
        *paused = !*paused;
        let result = *paused;
        wake.notify_all();
        result
    }

    pub fn pending(&self) -> bool {
        *self.0.0.lock().unwrap()
    }

    fn wait(&self, cancel: &Cancel) {
        let (state, wake) = &*self.0;
        let mut paused = state.lock().unwrap();
        while *paused && !cancel.pending() && !crate::platform::interrupt_pending() {
            paused = wake
                .wait_timeout(paused, std::time::Duration::from_millis(50))
                .unwrap()
                .0;
        }
    }

    pub(crate) fn wake(&self) {
        self.0.1.notify_all();
    }
}

/// An agent's end of the bus.
pub struct Bus {
    agent: AgentId,
    tx: Sender<Event>,
    cancel: Cancel,
    pause: Pause,
}

impl Bus {
    pub fn new(agent: AgentId, tx: Sender<Event>) -> Bus {
        Bus::with_pause(agent, tx, Pause::new())
    }

    pub(crate) fn with_pause(agent: AgentId, tx: Sender<Event>, pause: Pause) -> Bus {
        Bus {
            agent,
            tx,
            cancel: Cancel::new(),
            pause,
        }
    }

    pub fn agent(&self) -> AgentId {
        self.agent
    }

    /// A handle for stopping this agent's turn from another thread.
    pub fn canceller(&self) -> Cancel {
        self.cancel.clone()
    }

    pub fn pauser(&self) -> Pause {
        self.pause.clone()
    }

    /// Everything a tool needs from the agent that is running it. The
    /// context owns cloned handles so subprocess reader threads may carry it.
    pub fn execution(&self) -> crate::tools::Execution {
        crate::tools::Execution::new(self.agent, self.tx.clone(), self.cancel.clone())
    }

    pub fn wait_if_paused(&self) {
        self.pause.wait(&self.cancel);
    }

    /// Whether this turn has been asked to stop. A ^C is the user stopping
    /// *everything*, so every agent that sees one records it as its own.
    pub fn cancelled(&self) -> bool {
        if crate::platform::interrupt_pending() {
            self.cancel.raise();
        }
        self.cancel.pending()
    }

    /// Take the request to stop, clearing it. Called by whoever is about to
    /// act on it, so that a later ^C is a new request rather than an echo.
    pub fn take_cancel(&self) -> bool {
        // Both, not either: a stale flag left behind would cancel the next
        // turn before it started. The process-wide flag is the root's alone —
        // a sub-agent that ate the user's ^C would leave the parent running.
        let mine = self.cancel.take();
        let interrupt = self.agent == ROOT && crate::platform::take_interrupt();
        interrupt || mine
    }

    pub fn emit(&self, event: Event) -> Result<(), Gone> {
        self.tx.send(event).map_err(|_| Gone)
    }

    pub fn notice(&self, text: impl Into<String>) -> Result<(), Gone> {
        self.emit(Event::Notice {
            agent: self.agent,
            text: text.into(),
        })
    }

    pub fn failed(&self, text: impl Into<String>) -> Result<(), Gone> {
        self.emit(Event::Failed {
            agent: self.agent,
            text: text.into(),
        })
    }

    pub fn tool_start(&self, detail: impl Into<String>) -> Result<(), Gone> {
        self.emit(Event::ToolStart {
            agent: self.agent,
            detail: detail.into(),
        })
    }

    pub fn tool_end(
        &self,
        ok: bool,
        detail: impl Into<String>,
        full: Option<String>,
    ) -> Result<(), Gone> {
        self.emit(Event::ToolEnd {
            agent: self.agent,
            ok,
            detail: detail.into(),
            full,
        })
    }

    pub fn turn_end(&self, usage: UsageMeter, ok: bool) -> Result<(), Gone> {
        self.emit(Event::TurnEnd {
            agent: self.agent,
            usage,
            ok,
        })
    }

    pub fn exit(&self) -> Result<(), Gone> {
        self.emit(Event::Exit { agent: self.agent })
    }

    /// Put a call to the user and wait. A UI that answers nothing denies.
    pub fn ask(&self, request: PermissionRequest) -> Decision {
        let (reply, ask) = question();
        let sent = self.emit(Event::Permission {
            agent: self.agent,
            request,
            reply,
        });
        match sent {
            Ok(()) => ask.wait().unwrap_or(Decision::Deny),
            Err(Gone) => Decision::Deny,
        }
    }
}

/// Streamed deltas go straight onto the bus — and this is where a pending ^C
/// stops a turn: the error travels down through the provider to the transport,
/// which drops the connection. The flag is read, not taken; the turn loop
/// clears it once it has worked out what the interrupt meant.
impl EventSink for Bus {
    fn on_content(&mut self, text: &str) -> std::io::Result<()> {
        self.stream(Event::Token {
            agent: self.agent,
            text: text.to_string(),
        })
    }

    fn on_reasoning(&mut self, text: &str) -> std::io::Result<()> {
        self.stream(Event::Reasoning {
            agent: self.agent,
            text: text.to_string(),
        })
    }
}

impl Bus {
    fn stream(&self, event: Event) -> std::io::Result<()> {
        if self.cancelled() {
            return Err(std::io::Error::other("interrupted"));
        }
        self.emit(event)
            .map_err(|gone| std::io::Error::other(gone.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bus() -> (Bus, Receiver<Event>) {
        let (tx, rx) = channel();
        (Bus::new(ROOT, tx), rx)
    }

    #[test]
    fn deltas_reach_the_ui_as_events() {
        let (mut bus, rx) = bus();
        bus.on_content("Hel").unwrap();
        bus.on_reasoning("hmm").unwrap();
        bus.tool_start("read_file src/main.rs").unwrap();
        bus.tool_end(true, "312 bytes", Some("<the file>".to_string()))
            .unwrap();

        let events: Vec<Event> = rx.try_iter().collect();
        assert!(matches!(&events[0], Event::Token { text, .. } if text == "Hel"));
        assert!(matches!(&events[1], Event::Reasoning { text, .. } if text == "hmm"));
        assert!(
            matches!(&events[2], Event::ToolStart { detail, .. } if detail.contains("main.rs"))
        );
        assert!(matches!(&events[3], Event::ToolEnd { ok: true, full, .. } if full.is_some()));
    }

    #[test]
    fn a_question_blocks_until_the_ui_answers() {
        let (bus, rx) = bus();
        let asked = std::thread::spawn(move || {
            bus.ask(PermissionRequest {
                key: "write_file".to_string(),
                detail: "write_file notes.txt".to_string(),
            })
        });

        match rx.recv().unwrap() {
            Event::Permission { request, reply, .. } => {
                assert_eq!(request.key, "write_file");
                reply.send(Decision::Always);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(asked.join().unwrap(), Decision::Always);
    }

    /// Both ways of getting no answer mean the same thing, because the only
    /// safe reading of an absent user is "no".
    #[test]
    fn silence_denies() {
        let (bus, rx) = bus();
        let asked = std::thread::spawn(move || {
            bus.ask(PermissionRequest {
                key: "write_file".to_string(),
                detail: "write_file notes.txt".to_string(),
            })
        });
        // A UI that reads the question and drops the reply unanswered.
        drop(rx.recv().unwrap());
        assert_eq!(asked.join().unwrap(), Decision::Deny);

        // And a UI that is not there at all.
        let (tx, rx) = channel();
        drop(rx);
        let bus = Bus::new(ROOT, tx);
        assert_eq!(
            bus.ask(PermissionRequest {
                key: "k".to_string(),
                detail: "d".to_string(),
            }),
            Decision::Deny
        );
    }

    #[test]
    fn a_closed_bus_stops_the_stream() {
        let (tx, rx) = channel();
        let mut bus = Bus::new(ROOT, tx);
        drop(rx);
        assert!(bus.notice("nobody hears this").is_err());
        // And a streamed delta fails too, which is what cancels the request.
        assert!(bus.on_content("x").is_err());
    }

    #[test]
    fn decisions_say_whether_the_call_may_run() {
        assert!(Decision::Allow.allowed());
        assert!(Decision::Always.allowed());
        assert!(!Decision::Deny.allowed());
    }
}
