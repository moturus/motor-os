//! Terminal-independent reduction of the live agent stream.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::agent::bus::{AgentId, Event, PermissionRequest, ROOT};
use crate::agent::context::Window;
use crate::agent::task::Task;
use crate::provider::{ChatMessage, UsageMeter};

use super::transcript::Transcript;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activity {
    Idle,
    Model,
    Tool { detail: String, elapsed: Duration },
    Permission { detail: String },
    Cancelled,
    Failed { detail: String },
    Completed,
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    agent: AgentId,
    request: PermissionRequest,
    artifact: Option<ArtifactPage>,
    previous_pages: Vec<u64>,
    scroll: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPage {
    pub start: u64,
    pub end: u64,
    pub total: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelChoice {
    models: Vec<String>,
    selected: usize,
}

impl ModelChoice {
    pub fn models(&self) -> &[String] {
        &self.models
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn model(&self) -> &str {
        &self.models[self.selected]
    }
}

impl Approval {
    pub fn agent(&self) -> AgentId {
        self.agent
    }

    pub fn request(&self) -> &PermissionRequest {
        &self.request
    }

    pub fn artifact(&self) -> Option<&ArtifactPage> {
        self.artifact.as_ref()
    }

    pub fn previous_page(&self) -> Option<u64> {
        self.previous_pages.last().copied()
    }

    pub fn scroll(&self) -> usize {
        self.scroll
    }
}

/// The small live projection shared by terminal renderers.
#[derive(Debug, Clone, PartialEq)]
pub struct State {
    agents: BTreeMap<AgentId, Activity>,
    task: Option<Task>,
    model: Option<String>,
    paused: bool,
    context: Window,
    usage: UsageMeter,
    approval: Option<Approval>,
    model_choice: Option<ModelChoice>,
    draft: String,
    draft_cursor: usize,
    transcript: Transcript,
    scroll: usize,
}

impl Default for State {
    fn default() -> State {
        let mut agents = BTreeMap::new();
        agents.insert(ROOT, Activity::Idle);
        State {
            agents,
            task: None,
            model: None,
            paused: false,
            context: Window::default(),
            usage: UsageMeter::new(),
            approval: None,
            model_choice: None,
            draft: String::new(),
            draft_cursor: 0,
            transcript: Transcript::new(
                crate::config::Resources::default().max_live_render_queue_bytes,
            ),
            scroll: 0,
        }
    }
}

impl State {
    pub fn new() -> State {
        State::default()
    }

    pub fn activity(&self, agent: AgentId) -> Option<&Activity> {
        self.agents.get(&agent)
    }

    pub fn agents(&self) -> &BTreeMap<AgentId, Activity> {
        &self.agents
    }

    pub fn task(&self) -> Option<&Task> {
        self.task.as_ref()
    }

    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    pub fn paused(&self) -> bool {
        self.paused
    }

    pub fn context(&self) -> Window {
        self.context
    }

    pub fn usage(&self) -> UsageMeter {
        self.usage
    }

    pub fn approval(&self) -> Option<&Approval> {
        self.approval.as_ref()
    }

    pub fn model_choice(&self) -> Option<&ModelChoice> {
        self.model_choice.as_ref()
    }

    pub fn draft(&self) -> &str {
        &self.draft
    }

    pub fn draft_cursor(&self) -> usize {
        self.draft_cursor
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn scroll(&self) -> usize {
        self.scroll
    }

    pub fn with_transcript_limit(limit: usize) -> State {
        State {
            transcript: Transcript::new(limit),
            ..State::default()
        }
    }

    pub fn record_message(&mut self, message: &ChatMessage) {
        self.transcript.record(message);
    }

    pub fn set_transcript(&mut self, transcript: Transcript) -> bool {
        if self.transcript == transcript {
            return false;
        }
        self.transcript = transcript;
        self.scroll = self.scroll.min(self.transcript.lines().saturating_sub(1));
        true
    }

    pub fn scroll_up(&mut self, lines: usize) -> bool {
        let next = self
            .scroll
            .saturating_add(lines)
            .min(self.transcript.lines().saturating_sub(1));
        let changed = next != self.scroll;
        self.scroll = next;
        changed
    }

    pub fn scroll_down(&mut self, lines: usize) -> bool {
        let next = self.scroll.saturating_sub(lines);
        let changed = next != self.scroll;
        self.scroll = next;
        changed
    }

    /// Task state is already durable program data; the UI receives a snapshot
    /// rather than reconstructing it from model prose.
    pub fn set_task(&mut self, task: Option<Task>) -> bool {
        if self.task == task {
            return false;
        }
        self.task = task;
        true
    }

    pub fn set_runtime(&mut self, model: &str, paused: bool, context: Window) -> bool {
        let mut changed = false;
        if self.model.as_deref() != Some(model) {
            self.model = Some(model.to_string());
            changed = true;
        }
        if self.paused != paused {
            self.paused = paused;
            changed = true;
        }
        if self.context != context {
            self.context = context;
            changed = true;
        }
        changed
    }

    pub fn set_draft(&mut self, draft: &str, cursor: usize) -> bool {
        let cursor = cursor.min(draft.len());
        if self.draft == draft && self.draft_cursor == cursor {
            return false;
        }
        draft.clone_into(&mut self.draft);
        self.draft_cursor = cursor;
        true
    }

    pub fn open_model_choice(&mut self, models: Vec<String>) -> bool {
        if models.is_empty() {
            return false;
        }
        self.model_choice = Some(ModelChoice {
            models,
            selected: 0,
        });
        true
    }

    pub fn move_model_choice(&mut self, down: bool) -> bool {
        let Some(choice) = self.model_choice.as_mut() else {
            return false;
        };
        let next = match down {
            true => (choice.selected + 1).min(choice.models.len() - 1),
            false => choice.selected.saturating_sub(1),
        };
        let changed = next != choice.selected;
        choice.selected = next;
        changed
    }

    pub fn take_model_choice(&mut self) -> Option<String> {
        self.model_choice
            .take()
            .map(|choice| choice.model().to_string())
    }

    pub fn cancel_model_choice(&mut self) -> bool {
        self.model_choice.take().is_some()
    }

    pub fn start_turn(&mut self) -> bool {
        let activity = Activity::Model;
        if self.agents.get(&ROOT) == Some(&activity) {
            return false;
        }
        self.agents.insert(ROOT, activity);
        true
    }

    pub fn resolve_approval(&mut self, agent: AgentId) -> bool {
        if self.approval.as_ref().map(Approval::agent) != Some(agent) {
            return false;
        }
        self.approval = None;
        if matches!(self.agents.get(&agent), Some(Activity::Permission { .. })) {
            self.agents.insert(agent, Activity::Model);
        }
        true
    }

    pub fn start_approval_artifact(&mut self, page: ArtifactPage) -> bool {
        let Some(approval) = self.approval.as_mut() else {
            return false;
        };
        approval.artifact = Some(page);
        approval.previous_pages.clear();
        approval.scroll = 0;
        true
    }

    pub fn advance_approval_artifact(&mut self, page: ArtifactPage) -> bool {
        let Some(approval) = self.approval.as_mut() else {
            return false;
        };
        let Some(current) = approval.artifact.as_ref() else {
            return false;
        };
        if page.start != current.end {
            return false;
        }
        approval.previous_pages.push(current.start);
        approval.artifact = Some(page);
        approval.scroll = 0;
        true
    }

    pub fn retreat_approval_artifact(&mut self, page: ArtifactPage) -> bool {
        let Some(approval) = self.approval.as_mut() else {
            return false;
        };
        if approval.previous_pages.last().copied() != Some(page.start) {
            return false;
        }
        approval.previous_pages.pop();
        approval.artifact = Some(page);
        approval.scroll = 0;
        true
    }

    pub fn set_approval_scroll(&mut self, scroll: usize) -> bool {
        let Some(approval) = self.approval.as_mut() else {
            return false;
        };
        let changed = approval.scroll != scroll;
        approval.scroll = scroll;
        changed
    }

    /// Apply one event and say whether the visible projection changed.
    pub fn apply(&mut self, event: &Event) -> bool {
        let agent = event.agent();
        let old_lines = self.transcript.lines();
        let mut changed = self.transcript.apply(event);
        if changed && self.scroll > 0 {
            let new_lines = self.transcript.lines();
            self.scroll = match new_lines.cmp(&old_lines) {
                std::cmp::Ordering::Greater => self.scroll.saturating_add(new_lines - old_lines),
                std::cmp::Ordering::Less => self.scroll.saturating_sub(old_lines - new_lines),
                std::cmp::Ordering::Equal => self.scroll,
            }
            .min(new_lines.saturating_sub(1));
        }
        let next = match event {
            Event::Token { .. } | Event::Reasoning { .. } => Some(Activity::Model),
            Event::ToolStart { detail, .. } => Some(Activity::Tool {
                detail: detail.clone(),
                elapsed: Duration::ZERO,
            }),
            Event::ToolProgress { elapsed, .. } => match self.agents.get(&agent) {
                Some(Activity::Tool { detail, .. }) => Some(Activity::Tool {
                    detail: detail.clone(),
                    elapsed: *elapsed,
                }),
                _ => None,
            },
            Event::ToolEnd { .. } => Some(Activity::Model),
            Event::Permission { request, .. } => {
                let approval = Approval {
                    agent,
                    request: request.clone(),
                    artifact: None,
                    previous_pages: Vec::new(),
                    scroll: 0,
                };
                if self.approval.as_ref() != Some(&approval) {
                    self.approval = Some(approval);
                    changed = true;
                }
                Some(Activity::Permission {
                    detail: request.detail.clone(),
                })
            }
            Event::Notice { text, .. } if text == "cancelled" => Some(Activity::Cancelled),
            Event::Failed { text, .. } => Some(Activity::Failed {
                detail: text.clone(),
            }),
            Event::TurnEnd { usage, ok, .. } => {
                if agent == ROOT && self.usage != *usage {
                    self.usage = *usage;
                    changed = true;
                }
                match ok {
                    true => Some(Activity::Completed),
                    false
                        if matches!(
                            self.agents.get(&agent),
                            Some(Activity::Cancelled | Activity::Failed { .. })
                        ) =>
                    {
                        None
                    }
                    false => Some(Activity::Failed {
                        detail: "turn ended without an answer".to_string(),
                    }),
                }
            }
            Event::Exit { .. } => Some(Activity::Exited),
            Event::ToolOutput { .. } | Event::Notice { .. } => None,
        };
        match next {
            Some(activity) if self.agents.get(&agent) != Some(&activity) => {
                self.agents.insert(agent, activity);
                changed = true;
            }
            _ => {}
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::bus::{PermissionRequest, question};
    use crate::agent::task::{ItemState, Mode};
    use crate::provider::UsageMeter;

    #[test]
    fn agent_activity_reduces_without_crossing_agent_boundaries() {
        let mut state = State::new();
        state.apply(&Event::ToolStart {
            agent: ROOT,
            detail: "test --lib".into(),
        });
        state.apply(&Event::ToolProgress {
            agent: ROOT,
            elapsed: Duration::from_millis(250),
        });
        state.apply(&Event::Token {
            agent: 2,
            text: "reviewing".into(),
        });

        assert_eq!(
            state.activity(ROOT),
            Some(&Activity::Tool {
                detail: "test --lib".into(),
                elapsed: Duration::from_millis(250),
            })
        );
        assert_eq!(state.activity(2), Some(&Activity::Model));
    }

    #[test]
    fn task_usage_and_terminal_states_are_explicit() {
        let mut state = State::new();
        let mut task = Task::new("fix it".into(), vec!["edit".into()], Mode::Code).unwrap();
        task.transition(1, ItemState::Pending, ItemState::Active, None)
            .unwrap();
        assert!(state.set_task(Some(task.clone())));
        assert!(!state.set_task(Some(task.clone())));
        assert!(state.set_draft("next question", 0));
        state.apply(&Event::Notice {
            agent: ROOT,
            text: "cancelled".into(),
        });
        state.apply(&Event::TurnEnd {
            agent: ROOT,
            usage: UsageMeter::new(),
            ok: false,
        });

        assert_eq!(state.task(), Some(&task));
        assert_eq!(state.draft(), "next question");
        assert_eq!(state.activity(ROOT), Some(&Activity::Cancelled));
        assert_eq!(state.usage(), UsageMeter::new());
    }

    #[test]
    fn permission_state_does_not_take_ownership_of_the_reply() {
        let (reply, answer) = question();
        let event = Event::Permission {
            agent: 3,
            request: PermissionRequest::new("write_file", "write_file src/main.rs")
                .with_preview("diff"),
            reply,
        };
        let mut state = State::new();
        state.apply(&event);
        assert_eq!(
            state.activity(3),
            Some(&Activity::Permission {
                detail: "write_file src/main.rs".into(),
            })
        );
        assert_eq!(state.approval().unwrap().agent(), 3);
        assert_eq!(
            state.approval().unwrap().request().preview.as_deref(),
            Some("diff")
        );
        assert!(state.resolve_approval(3));
        assert!(state.approval().is_none());
        assert_eq!(state.activity(3), Some(&Activity::Model));
        let Event::Permission { reply, .. } = event else {
            unreachable!()
        };
        reply.send(crate::agent::bus::Decision::Deny);
        assert_eq!(answer.wait(), Some(crate::agent::bus::Decision::Deny));
    }

    #[test]
    fn model_choice_is_single_selection_and_preserves_the_draft() {
        let mut state = State::new();
        state.set_draft("unfinished prompt", 5);
        assert!(state.open_model_choice(vec!["one".into(), "two".into(), "three".into()]));
        assert_eq!(state.model_choice().unwrap().model(), "one");
        assert!(state.move_model_choice(true));
        assert_eq!(state.model_choice().unwrap().model(), "two");
        assert!(state.move_model_choice(true));
        assert!(!state.move_model_choice(true));
        assert_eq!(state.take_model_choice().as_deref(), Some("three"));
        assert_eq!(
            (state.draft(), state.draft_cursor()),
            ("unfinished prompt", 5)
        );

        assert!(state.open_model_choice(vec!["one".into(), "two".into()]));
        assert!(state.move_model_choice(true));
        assert!(state.cancel_model_choice());
        assert!(state.model_choice().is_none());
        assert_eq!(
            (state.draft(), state.draft_cursor()),
            ("unfinished prompt", 5)
        );
    }
}
