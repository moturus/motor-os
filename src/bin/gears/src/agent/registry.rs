//! The agent registry: every sub-agent that exists, and what they may cost.
//!
//! An agent is a thread, a conversation and a model id. Everything else it
//! works with is shared: one workspace, one undo log, one permission gate on
//! the far side of the bus, one provider — the host backend spawns a curl of
//! its own per request, so sharing it is not sharing a connection.
//!
//! What is *not* shared is the conversation, which is the point. A sub-agent
//! starts from its task and nothing else, and only its last message comes
//! back. That is the whole bargain: a long search costs the parent one tool
//! result instead of a filled context window.
//!
//! Three guardrails, because nobody is watching a sub-agent the way the user
//! watches the root: how deep spawning may go, how many may run at once, and
//! what they may spend between them. The last is enforced against the
//! endpoint's own accounting. It is a pocket inside the run's own budget where
//! the user set one (`turn.rs`): what a sub-agent spends, the run has spent.

use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::agent::bus::{AgentId, Bus, Cancel, Event, Pause};
use crate::agent::prompt;
use crate::agent::turn::{Agent, Budget, Conversation, Turned, affordable};
use crate::provider::{ChatMessage, ModelProvider, Usage, UsageMeter};
use crate::tools::{Registry, Tool};

/// A provider several agents share.
pub type Provider = Arc<dyn ModelProvider + Send + Sync>;

/// How long a waiting parent sleeps between looks. It is woken the moment an
/// agent finishes; the timeout is for the one thing no wake-up can carry —
/// the process-wide ^C flag, which a signal handler only sets.
const POLL: Duration = Duration::from_millis(50);

/// What sub-agents are allowed. The defaults are the proposal's: one level
/// deep, four at a time, and no spend cap until somebody sets one.
#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    /// How deep spawning goes. 0 means no sub-agents at all — the tools are
    /// not registered, which is also what Motor OS v1 gets.
    pub depth: usize,
    pub concurrent: usize,
    /// USD, where the endpoint reports cost (plan decision 10).
    pub budget_usd: Option<f64>,
    /// Tokens, which every endpoint reports.
    pub budget_tokens: Option<u64>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            depth: 1,
            concurrent: 4,
            budget_usd: None,
            budget_tokens: None,
        }
    }
}

/// What every agent is built out of.
pub struct Kit {
    /// The workspace root, for the system prompt.
    pub root: PathBuf,
    /// Every tool there is, before any agent's own filtering.
    pub tools: Vec<Arc<dyn Tool>>,
    /// The session-owned store shared by root and sub-agent registries.
    pub artifacts: Arc<crate::agent::artifact::LazyStore>,
    /// Only workspace mutations from sub-agents enter the root session.
    pub(crate) mutation_journal: Option<crate::agent::session::MutationJournal>,
    /// One ordered mutation generation shared by root and writable children.
    pub(crate) mutation_generation: Arc<Mutex<u64>>,
    pub provider: Provider,
    /// The model an agent gets when its parent names none.
    pub model: Arc<Mutex<String>>,
    pub max_steps: usize,
    /// The window every agent has to stay inside. One policy, because they
    /// are all talking to the same endpoint.
    pub context: crate::agent::context::Policy,
}

impl Kit {
    fn selected_model(&self, explicit: Option<String>) -> String {
        explicit.unwrap_or_else(|| self.model.lock().unwrap().clone())
    }
}

/// What a sub-agent had to say for itself when it stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub id: AgentId,
    pub task: String,
    /// Whether it answered, as against failing, running out of budget or
    /// being stopped. Either way `text` says what happened.
    pub ok: bool,
    pub text: String,
}

/// One agent, from the outside. What it was asked to do travels with its
/// outcome instead: this is only what is needed to stop it and to let go.
struct Running {
    id: AgentId,
    cancel: Cancel,
    thread: JoinHandle<()>,
}

#[derive(Default)]
struct State {
    /// Ids are handed out in spawn order and never reused.
    next: AgentId,
    running: Vec<Running>,
    /// Finished, and not yet reported to whoever is waiting.
    done: Vec<Outcome>,
    spent: UsageMeter,
}

impl State {
    /// Let go of the agents that have finished, handing back their threads for
    /// the caller to join once it has let go of the lock: a thread that has
    /// reported its outcome is on its way out, but it took this lock to do so.
    fn harvest(&mut self) -> Vec<JoinHandle<()>> {
        let mut threads = Vec::new();
        let mut index = 0;
        while index < self.running.len() {
            match self
                .done
                .iter()
                .any(|done| done.id == self.running[index].id)
            {
                true => threads.push(self.running.remove(index).thread),
                false => index += 1,
            }
        }
        threads
    }

    /// Whether a wait is over. No named agents means "all of them", which is
    /// the same question as whether any are left.
    fn ready(&self, want: &[AgentId]) -> bool {
        match want.is_empty() {
            true => self.running.is_empty(),
            false => want.iter().all(|id| self.done.iter().any(|o| o.id == *id)),
        }
    }

    /// Take the outcomes a wait was for, oldest agent first. Each is reported
    /// once: what a parent has been told is no longer pending.
    fn collect(&mut self, want: &[AgentId]) -> Vec<Outcome> {
        let (taken, left) = std::mem::take(&mut self.done)
            .into_iter()
            .partition(|o| want.is_empty() || want.contains(&o.id));
        self.done = left;
        let mut taken: Vec<Outcome> = taken;
        taken.sort_by_key(|o| o.id);
        taken
    }
}

pub struct Agents {
    kit: Kit,
    limits: Limits,
    events: SyncSender<Event>,
    pause: Pause,
    state: Mutex<State>,
    /// The run's purse, where the user capped the run. Sub-agents spend out of
    /// it as well as out of their own.
    run: Option<Arc<dyn Budget>>,
    /// Raised by an agent on its way out, so a waiting parent does not have
    /// to sit out the poll interval.
    finished: Condvar,
}

impl Agents {
    pub fn new(
        kit: Kit,
        limits: Limits,
        run: Option<Arc<dyn Budget>>,
        events: SyncSender<Event>,
        pause: Pause,
    ) -> Arc<Agents> {
        Arc::new(Agents {
            kit,
            limits,
            events,
            pause,
            state: Mutex::new(State::default()),
            run,
            finished: Condvar::new(),
        })
    }

    /// The tools one agent gets: everything in the kit it is allowed, plus the
    /// two that make more agents — where making more is still allowed, and
    /// never for a read-only agent, which would otherwise be able to spawn one
    /// that is not.
    pub fn registry(self: &Arc<Self>, depth: usize, read_only: bool) -> Registry {
        let mut registry = Registry::new();
        for tool in &self.kit.tools {
            if !(read_only && tool.mutates()) {
                registry.register_shared(tool.clone());
            }
        }
        if depth < self.limits.depth && !read_only {
            for tool in crate::tools::spawn::tools(self.clone(), depth) {
                registry.register(tool);
            }
        }
        registry.with_artifacts(self.kit.artifacts.clone())
    }

    /// Start one. `depth` is the *parent's* depth; the caller has already been
    /// given the tool only where a child is allowed at all.
    pub fn spawn(
        self: &Arc<Self>,
        depth: usize,
        task: &str,
        model: Option<String>,
        read_only: bool,
    ) -> Result<AgentId, String> {
        // The run's budget before anything else, and before the lock: a run
        // with nothing left has nothing left for this either, and starting a
        // thread to find that out at its first completion is a thread wasted.
        // `self.check()` would take the lock below twice, which std mutexes do
        // not survive.
        if let Some(run) = &self.run {
            run.check().map_err(|error| error.to_string())?;
        }
        // First, so that what counts as running is really running.
        self.reap();
        let mut state = self.state.lock().unwrap();
        if state.running.len() >= self.limits.concurrent {
            return Err(format!(
                "{} sub-agents are already running, which is the limit; \
                 wait for one before starting another",
                self.limits.concurrent
            ));
        }
        affordable(
            self.limits.budget_usd,
            self.limits.budget_tokens,
            &state.spent,
            "sub-agent",
        )
        .map_err(|error| error.to_string())?;

        state.next += 1;
        let id = state.next;
        let bus = Bus::with_pause(id, self.events.clone(), self.pause.clone());
        let cancel = bus.canceller();
        let tools = self.registry(depth + 1, read_only);
        let model = self.kit.selected_model(model);
        let mut conversation = Conversation::new(model);
        if let Some(journal) = &self.kit.mutation_journal {
            conversation = conversation.with_journal(Box::new(journal.clone()));
        }
        conversation.push(ChatMessage::system(prompt::sub_agent(
            &self.kit.root,
            &tools.names(),
            read_only,
        )))?;
        let agent = Agent::new(self.kit.provider.clone(), tools, conversation)
            .with_mutation_generation(self.kit.mutation_generation.clone())
            .with_max_steps(self.kit.max_steps)
            .with_context(self.kit.context)
            .with_budget(self.clone());

        let thread = std::thread::spawn({
            let agents = self.clone();
            let task = task.to_string();
            move || work(agents, id, task, agent, bus)
        });
        state.running.push(Running { id, cancel, thread });
        Ok(id)
    }

    /// Let go of the agents that have finished, so that what is left in
    /// `running` is what is really running.
    fn reap(&self) {
        let threads = self.state.lock().unwrap().harvest();
        join(threads);
    }

    /// Wait for agents to finish and take what they said. An empty `want` is
    /// every agent that is still to report.
    pub fn wait(&self, want: &[AgentId], cancel: &Cancel) -> Result<Vec<Outcome>, String> {
        let mut threads = Vec::new();
        let mut state = self.state.lock().unwrap();
        threads.extend(state.harvest());
        unknown(&state, want)?;
        while !state.ready(want) {
            if cancel.pending() || crate::platform::interrupt_pending() {
                // Stopped, not waited for: an agent inside a long build cannot
                // be hurried, and the user has just said they are done.
                for running in &state.running {
                    running.cancel.raise();
                }
                drop(state);
                join(threads);
                return Err("the agents were stopped".to_string());
            }
            state = self.finished.wait_timeout(state, POLL).unwrap().0;
            threads.extend(state.harvest());
        }
        let collected = state.collect(want);
        drop(state);

        join(threads);
        Ok(collected)
    }

    /// Stop everything still running and forget what nobody collected: the end
    /// of the user's turn, where an agent the model never waited for has
    /// nowhere left to deliver an answer to. Returns how many were working.
    pub fn stop_all(&self) -> usize {
        self.reap();
        let mut state = self.state.lock().unwrap();
        let stopped = state.running.len();
        for running in state.running.drain(..) {
            running.cancel.raise();
            // Not joined. A sub-agent waiting on a command it started stops no
            // faster than the command does, and the user's terminal must not
            // wait for it: it takes the flag at its next step and lets go.
            drop(running.thread);
        }
        state.done.clear();
        stopped
    }

    /// What sub-agents have cost so far, for the parent's own accounting.
    pub fn spending(&self) -> UsageMeter {
        self.state.lock().unwrap().spent
    }

    /// Record an outcome — unless nobody is expecting one, which is what
    /// [`Agents::stop_all`] leaves behind.
    fn finish(&self, outcome: Outcome) {
        let mut state = self.state.lock().unwrap();
        if state.running.iter().any(|r| r.id == outcome.id) {
            state.done.push(outcome);
        }
        self.finished.notify_all();
    }
}

/// The shared purse. Only sub-agents carry one — and what they spend is spent
/// out of the run's as well, which is why both are asked and both are charged.
impl Budget for Agents {
    fn check(&self) -> Result<(), crate::agent::turn::BudgetExhausted> {
        if let Some(run) = &self.run {
            run.check()?;
        }
        affordable(
            self.limits.budget_usd,
            self.limits.budget_tokens,
            &self.state.lock().unwrap().spent,
            "sub-agent",
        )
    }

    fn spent(&self, usage: &Usage) {
        // Outside our own lock: the run's purse is a different one, and an
        // order between the two is a deadlock waiting for a reason.
        if let Some(run) = &self.run {
            run.spent(usage);
        }
        self.state.lock().unwrap().spent.add(usage);
    }
}

/// Agents the caller named that this registry has never heard of, or has
/// already reported on. A wait for one of those would never end.
fn unknown(state: &State, want: &[AgentId]) -> Result<(), String> {
    let missing: Vec<String> = want
        .iter()
        .filter(|id| {
            !state.running.iter().any(|r| r.id == **id) && !state.done.iter().any(|o| o.id == **id)
        })
        .map(|id| id.to_string())
        .collect();
    match missing.is_empty() {
        true => Ok(()),
        false => Err(format!(
            "no agent {} is running; each one reports back once",
            missing.join(", ")
        )),
    }
}

fn join(threads: Vec<JoinHandle<()>>) {
    for thread in threads {
        let _ = thread.join();
    }
}

/// One sub-agent's whole life: answer the task, say so, report.
fn work(agents: Arc<Agents>, id: AgentId, task: String, mut agent: Agent<Provider>, mut bus: Bus) {
    let outcome = agent.turn(&task, &mut bus);
    let (ok, text) = answer(agent.conversation(), outcome);
    // Only the good ending is announced: a failure, a cancellation and an
    // exhausted budget have all already said so on the bus, in their own
    // words, and saying it twice reads as two things going wrong.
    if ok {
        let _ = bus.notice("done");
    }
    agents.finish(Outcome { id, task, ok, text });
}

/// What the parent is told, which is the last thing the agent said or the
/// reason there is nothing to tell.
fn answer(conversation: &Conversation, outcome: Turned) -> (bool, String) {
    match outcome {
        Turned::Done => match conversation.answer() {
            Some(text) => (true, text.to_string()),
            None => (
                false,
                "the agent finished without saying anything".to_string(),
            ),
        },
        Turned::Waiting => (false, "the agent is waiting for the user".to_string()),
        Turned::Cancelled => (false, "the agent was stopped".to_string()),
        Turned::Failed(why) => (false, why),
        Turned::Gone => (false, "the agent lost hold of gears".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::{ROOT, event_channel};
    use crate::agent::turn::{Purse, RunLimits};
    use crate::provider::{
        ChatRequest, Completion, EventSink, FinishReason, ProviderError, ToolSpec,
    };
    use crate::tools::{Tool, schema};
    use serde_json::{Value, json};
    use std::sync::mpsc::Receiver;

    /// A provider that answers with the task it was given, after `delay` —
    /// which is how a test makes two agents overlap on purpose.
    struct Parrot {
        delay: Duration,
        cost: Option<f64>,
    }

    impl ModelProvider for Parrot {
        fn complete(
            &self,
            req: &ChatRequest,
            sink: &mut dyn EventSink,
        ) -> Result<Completion, ProviderError> {
            std::thread::sleep(self.delay);
            let text = format!(
                "done: {}",
                req.messages
                    .last()
                    .and_then(|m| m.content.clone())
                    .unwrap_or_default()
            );
            sink.on_content(&text)
                .map_err(|e| ProviderError::Aborted(e.to_string()))?;
            Ok(Completion {
                content: text,
                finish_reason: Some(FinishReason::Stop),
                usage: Usage {
                    prompt_tokens: 10,
                    completion_tokens: 2,
                    cost: self.cost,
                    ..Usage::default()
                },
                ..Completion::default()
            })
        }
    }

    /// A tool that changes something, so read-only filtering has something to
    /// filter.
    struct Scribble;

    impl Tool for Scribble {
        fn name(&self) -> &'static str {
            "scribble"
        }

        fn spec(&self) -> ToolSpec {
            ToolSpec::new("scribble", "Change something.", schema(json!({}), &[]))
        }

        fn mutates(&self) -> bool {
            true
        }

        fn call(&self, _args: &Value) -> Result<String, String> {
            Ok("scribbled".to_string())
        }
    }

    fn agents(
        limits: Limits,
        delay: Duration,
        cost: Option<f64>,
    ) -> (Arc<Agents>, Receiver<Event>) {
        let (registry, events, _) = purse(limits, delay, cost, RunLimits::default());
        (registry, events)
    }

    /// The same, plus the run's purse the sub-agents charge.
    fn purse(
        limits: Limits,
        delay: Duration,
        cost: Option<f64>,
        run: RunLimits,
    ) -> (Arc<Agents>, Receiver<Event>, Arc<Purse>) {
        let (tx, events) = event_channel();
        let kit = Kit {
            root: std::env::temp_dir(),
            tools: vec![Arc::new(Scribble)],
            artifacts: Arc::new(
                crate::agent::artifact::LazyStore::new(
                    std::env::temp_dir(),
                    "19-2".to_string(),
                    1024,
                    4096,
                )
                .unwrap(),
            ),
            mutation_journal: None,
            mutation_generation: Arc::new(Mutex::new(0)),
            provider: Arc::new(Parrot { delay, cost }),
            model: Arc::new(Mutex::new("test/model".to_string())),
            max_steps: 4,
            context: crate::agent::context::Policy::default(),
        };
        let run = Arc::new(Purse::new(run));
        let registry = Agents::new(kit, limits, Some(run.clone()), tx, Pause::new());
        (registry, events, run)
    }

    fn quick(limits: Limits) -> (Arc<Agents>, Receiver<Event>) {
        agents(limits, Duration::ZERO, None)
    }

    #[test]
    fn future_sub_agents_use_the_shared_default_unless_explicit() {
        let (agents, _events) = quick(Limits::default());
        assert_eq!(agents.kit.selected_model(None), "test/model");
        *agents.kit.model.lock().unwrap() = "next/model".to_string();
        assert_eq!(agents.kit.selected_model(None), "next/model");
        assert_eq!(
            agents
                .kit
                .selected_model(Some("explicit/model".to_string())),
            "explicit/model"
        );
    }

    #[test]
    fn a_sub_agent_answers_and_the_answer_comes_back_once() {
        let (agents, events) = quick(Limits::default());
        let id = agents.spawn(0, "count the crabs", None, false).unwrap();
        assert_eq!(id, 1);

        let outcomes = agents.wait(&[], &Cancel::new()).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].ok, "{:?}", outcomes[0]);
        assert_eq!(outcomes[0].task, "count the crabs");
        assert_eq!(outcomes[0].text, "done: count the crabs");

        // Reported once: a second wait has nothing left and nothing pending.
        assert!(agents.wait(&[], &Cancel::new()).unwrap().is_empty());
        assert!(agents.wait(&[1], &Cancel::new()).is_err());

        // What the user saw came from the agent, not from the root.
        let seen: Vec<Event> = events.try_iter().collect();
        assert!(seen.iter().all(|e| e.agent() == 1), "{seen:?}");
        assert!(
            seen.iter()
                .any(|e| matches!(e, Event::Notice { text, .. } if text == "done"))
        );
        assert_eq!(agents.spending().completions, 1);
    }

    #[test]
    fn agents_run_at_the_same_time_up_to_the_limit() {
        let limits = Limits {
            concurrent: 2,
            ..Limits::default()
        };
        let (agents, _events) = agents(limits, Duration::from_millis(60), None);
        agents.spawn(0, "first", None, false).unwrap();
        agents.spawn(0, "second", None, false).unwrap();

        let full = agents.spawn(0, "third", None, false).unwrap_err();
        assert!(full.contains("2 sub-agents are already running"), "{full}");

        // Both really were running at once: they are waited for together, and
        // both answers are there.
        let outcomes = agents.wait(&[], &Cancel::new()).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].id, 1);
        assert_eq!(outcomes[1].task, "second");

        // And with them finished there is room again.
        assert_eq!(agents.spawn(0, "third", None, false).unwrap(), 3);
        agents.wait(&[], &Cancel::new()).unwrap();
    }

    /// The two guardrails that shape what an agent *is*: how deep it can go,
    /// and whether it can change anything.
    #[test]
    fn what_an_agent_may_do_is_decided_before_it_starts() {
        let (agents, _events) = quick(Limits::default());
        let root = agents.registry(0, false);
        assert_eq!(root.names(), ["scribble", "spawn_agent", "wait_agents"]);

        // At the depth limit there is nothing to spawn with, which is also
        // what a depth of 0 gives the root — the Motor OS v1 shape.
        let deep = agents.registry(1, false);
        assert_eq!(deep.names(), ["scribble"]);

        // A read-only agent keeps nothing that changes anything, and cannot
        // make an agent that would.
        let scout = agents.registry(0, true);
        assert!(scout.names().is_empty(), "{:?}", scout.names());
    }

    #[test]
    fn the_budget_is_spent_by_agents_and_then_there_are_no_more() {
        let limits = Limits {
            budget_tokens: Some(20),
            ..Limits::default()
        };
        let (agents, _events) = quick(limits);
        agents.spawn(0, "first", None, false).unwrap();
        agents.wait(&[], &Cancel::new()).unwrap();
        assert_eq!(agents.spending().total_tokens(), 12);

        // 12 of 20 spent is still affordable; 24 is not, and the agent that
        // reached the limit says so rather than being cut off in silence.
        agents.spawn(0, "second", None, false).unwrap();
        let outcomes = agents.wait(&[], &Cancel::new()).unwrap();
        assert!(outcomes[0].ok, "{:?}", outcomes[0]);
        let spent = agents.spawn(0, "third", None, false).unwrap_err();
        assert!(spent.contains("20 tokens is spent"), "{spent}");
    }

    /// Cost in USD where the endpoint reports it, which is the budget users
    /// actually mean.
    #[test]
    fn a_priced_endpoint_is_budgeted_in_money() {
        let limits = Limits {
            budget_usd: Some(0.01),
            ..Limits::default()
        };
        let (agents, _events) = agents(limits, Duration::ZERO, Some(0.006));
        for task in ["first", "second"] {
            agents.spawn(0, task, None, false).unwrap();
            agents.wait(&[], &Cancel::new()).unwrap();
        }
        let spent = agents.spawn(0, "third", None, false).unwrap_err();
        assert!(spent.contains("$0.01 is spent"), "{spent}");
        assert!(spent.contains("$0.0120"), "{spent}");
    }

    /// What a sub-agent spends, the run has spent: one bill, two pockets. The
    /// sub-agents here have no budget of their own, so anything that stops them
    /// is the run's.
    #[test]
    fn what_sub_agents_spend_comes_out_of_the_runs_budget() {
        let run = RunLimits {
            budget_usd: Some(0.01),
            ..RunLimits::default()
        };
        let (agents, _events, purse) = purse(Limits::default(), Duration::ZERO, Some(0.006), run);

        agents.spawn(0, "first", None, false).unwrap();
        agents.wait(&[], &Cancel::new()).unwrap();
        assert_eq!(purse.spending().cost_usd(), Some(0.006));
        // Counted in both, and neither is a copy of the other: the sub-agents'
        // own pocket holds the same completion.
        assert_eq!(agents.spending().cost_usd(), Some(0.006));

        agents.spawn(0, "second", None, false).unwrap();
        agents.wait(&[], &Cancel::new()).unwrap();
        // Now the run is short, and it is the run that says so — a sub-agent
        // budget was never set.
        let spent = agents.spawn(0, "third", None, false).unwrap_err();
        assert!(spent.contains("the run budget of $0.01"), "{spent}");
        assert!(purse.check().is_err());
    }

    /// An agent nobody waited for is stopped when the turn ends, and what it
    /// would have said does not turn up in the next one.
    #[test]
    fn an_agent_nobody_waits_for_is_stopped() {
        let (agents, _events) = agents(Limits::default(), Duration::from_millis(50), None);
        agents.spawn(0, "left behind", None, false).unwrap();
        assert_eq!(agents.stop_all(), 1);

        std::thread::sleep(Duration::from_millis(120));
        assert!(agents.wait(&[], &Cancel::new()).unwrap().is_empty());
        assert!(agents.wait(&[1], &Cancel::new()).is_err());
        // Ids are not reused: the next agent is the second one there was.
        assert_eq!(agents.spawn(0, "after", None, false).unwrap(), 2);
        agents.wait(&[], &Cancel::new()).unwrap();
    }

    /// A ^C reaches a waiting parent, which stops what it was waiting for.
    #[test]
    fn a_cancelled_wait_stops_the_agents_it_was_waiting_for() {
        let (agents, _events) = agents(Limits::default(), Duration::from_secs(30), None);
        let id = agents.spawn(0, "forever", None, false).unwrap();
        let cancel = Cancel::new();
        cancel.raise();

        let stopped = agents.wait(&[id], &cancel).unwrap_err();
        assert_eq!(stopped, "the agents were stopped");
        // The agent was told, which is what it acts on at its next step.
        let state = agents.state.lock().unwrap();
        assert!(state.running[0].cancel.pending());
    }

    #[test]
    fn waiting_for_an_agent_that_is_not_there_is_the_models_mistake() {
        let (agents, _events) = quick(Limits::default());
        let error = agents.wait(&[7], &Cancel::new()).unwrap_err();
        assert!(error.contains("no agent 7"), "{error}");
    }

    /// The root's own id is never handed to a sub-agent, so events cannot be
    /// mistaken for the user's own turn.
    #[test]
    fn the_root_is_not_one_of_them() {
        let (agents, _events) = quick(Limits::default());
        assert_eq!(agents.spawn(0, "first", None, false).unwrap(), ROOT + 1);
        agents.wait(&[], &Cancel::new()).unwrap();
    }
}
