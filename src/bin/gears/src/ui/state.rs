//! Terminal-independent reduction of the live agent stream.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::agent::bus::{AgentId, Event, ROOT};
use crate::agent::task::Task;
use crate::provider::UsageMeter;

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
}

impl Default for State {
    fn default() -> State {
        let mut agents = BTreeMap::new();
        agents.insert(ROOT, Activity::Idle);
        State {
            agents,
            task: None,
            usage: UsageMeter::new(),
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

    /// Task state is already durable program data; the UI receives a snapshot
    /// rather than reconstructing it from model prose.
    pub fn set_task(&mut self, task: Option<Task>) {
        self.task = task;
    }

    /// Apply one event and say whether the visible projection changed.
    pub fn apply(&mut self, event: &Event) -> bool {
        let agent = event.agent();
        let mut changed = false;
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
        state.set_task(Some(task.clone()));
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
