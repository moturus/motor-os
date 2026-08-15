//! Terminal-independent reduction of the live agent stream.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::agent::bus::{AgentId, Event, ROOT};
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

/// The small live projection shared by terminal renderers.
#[derive(Debug, Clone, PartialEq)]
pub struct State {
    agents: BTreeMap<AgentId, Activity>,
    task: Option<Task>,
    usage: UsageMeter,
    draft: String,
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
            usage: UsageMeter::new(),
            draft: String::new(),
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

    pub fn usage(&self) -> UsageMeter {
        self.usage
    }

    pub fn draft(&self) -> &str {
        &self.draft
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

    pub fn set_draft(&mut self, draft: &str) -> bool {
        if self.draft == draft {
            return false;
        }
        draft.clone_into(&mut self.draft);
        true
    }

    pub fn start_turn(&mut self) -> bool {
        let activity = Activity::Model;
        if self.agents.get(&ROOT) == Some(&activity) {
            return false;
        }
        self.agents.insert(ROOT, activity);
        true
    }

    /// Apply one event and say whether the visible projection changed.
    pub fn apply(&mut self, event: &Event) -> bool {
        let agent = event.agent();
        let old_lines = self.transcript.lines();
        let mut changed = self.transcript.apply(event);
        if changed && self.scroll > 0 {
            let added = self.transcript.lines().saturating_sub(old_lines);
            self.scroll = self.scroll.saturating_add(added);
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
            Event::Permission { request, .. } => Some(Activity::Permission {
                detail: request.detail.clone(),
            }),
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
        assert!(state.set_draft("next question"));
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
            request: PermissionRequest {
                key: "write_file".into(),
                detail: "write_file src/main.rs".into(),
                preview: Some("diff".into()),
            },
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
        let Event::Permission { reply, .. } = event else {
            unreachable!()
        };
        reply.send(crate::agent::bus::Decision::Deny);
        assert_eq!(answer.wait(), Some(crate::agent::bus::Decision::Deny));
    }
}
