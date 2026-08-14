//! `spawn_agent` and `wait_agents`: the two calls that make more of gears.
//!
//! Everything that decides whether an agent may exist — depth, how many at
//! once, what they may spend — lives in `agent/registry.rs`. What lives here
//! is the part the model sees: start one and go on with something else, then
//! come back for the answer.
//!
//! Spawning is put to the user like any other change. An agent that can write
//! is a change to the workspace at one remove, and it is also the one call
//! that can spend money on its own — so it asks, and a read-only agent, whose
//! registry keeps nothing that mutates, does not get this tool at all.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{Execution, Tool, bool_arg, clip, opt_string, schema, string_arg};
use crate::agent::bus::{AgentId, Cancel};
use crate::agent::registry::{Agents, Outcome};
use crate::provider::ToolSpec;

/// Both tools for an agent at `depth`. A wait takes cancellation from the
/// execution context of the call that is actually waiting.
pub fn tools(agents: Arc<Agents>, depth: usize) -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(SpawnTool {
            agents: agents.clone(),
            depth,
        }),
        Box::new(WaitTool { agents }),
    ]
}

struct SpawnTool {
    agents: Arc<Agents>,
    depth: usize,
}

impl Tool for SpawnTool {
    fn name(&self) -> &'static str {
        "spawn_agent"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "spawn_agent",
            "Start another agent on one piece of work and return at once, so \
             that several run at the same time. It has its own conversation \
             and sees nothing of this one. Use it for work that would fill \
             this context with material you do not need — searching a large \
             tree, reading a long file to answer one question — and collect \
             the answer with wait_agents, which is the only way to hear from \
             it. An agent nobody waits for is stopped when this turn ends.",
            schema(
                json!({
                    "task": {
                        "type": "string",
                        "description": "What to do, in full. The agent starts \
                                        from this and nothing else, so name \
                                        the files, the question and what a \
                                        useful answer would say.",
                    },
                    "model": {
                        "type": "string",
                        "description": "Model id. The default is the one you \
                                        are using; a cheaper model is the \
                                        point of sending a scout.",
                    },
                    "read_only": {
                        "type": "boolean",
                        "description": "Give it only the tools that change \
                                        nothing — reading, listing, \
                                        searching, fetching. Default false.",
                    },
                }),
                &["task"],
            ),
        )
    }

    fn mutates(&self) -> bool {
        true
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        let task = string_arg(args, "task")?;
        if task.trim().is_empty() {
            return Err("say what the agent should do".to_string());
        }
        let model = opt_string(args, "model")?;
        let read_only = bool_arg(args, "read_only", false)?;
        let id = self.agents.spawn(self.depth, &task, model, read_only)?;
        Ok(format!("agent {id} started"))
    }
}

struct WaitTool {
    agents: Arc<Agents>,
}

impl Tool for WaitTool {
    fn name(&self) -> &'static str {
        "wait_agents"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "wait_agents",
            "Wait for agents started with spawn_agent and return what they \
             said. With no arguments it waits for every one that has not \
             reported yet. Each answer comes back once.",
            schema(
                json!({
                    "agents": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Agent numbers to wait for. The \
                                        default is all of them.",
                    },
                }),
                &[],
            ),
        )
    }

    fn mutates(&self) -> bool {
        false
    }

    fn call(&self, args: &Value) -> Result<String, String> {
        self.wait(args, &Cancel::new())
    }

    fn execute(&self, args: &Value, execution: &Execution) -> Result<String, String> {
        self.wait(args, execution.cancellation())
    }
}

impl WaitTool {
    fn wait(&self, args: &Value, cancel: &Cancel) -> Result<String, String> {
        let want = ids(args)?;
        let outcomes = self.agents.wait(&want, cancel)?;
        match outcomes.is_empty() {
            true => Err("no agents are running".to_string()),
            false => Ok(report(&outcomes)),
        }
    }
}

/// The agent numbers a call names, which are small whole numbers or nothing.
fn ids(args: &Value) -> Result<Vec<AgentId>, String> {
    let bad =
        |what: String| format!("argument 'agents' must be a list of agent numbers, got {what}");
    match &args["agents"] {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_u64()
                    .and_then(|number| AgentId::try_from(number).ok())
                    .ok_or_else(|| bad(format!("{item} in it")))
            })
            .collect(),
        other => Err(bad(other.to_string())),
    }
}

/// What the agents said, one after another, each under a line saying whose
/// answer it is and whether it is one.
fn report(outcomes: &[Outcome]) -> String {
    outcomes
        .iter()
        .map(|outcome| {
            format!(
                "agent {} ({}) {}:\n{}",
                outcome.id,
                clip(&outcome.task, 60),
                match outcome.ok {
                    true => "answered",
                    false => "did not finish",
                },
                outcome.text
            )
        })
        .collect::<Vec<String>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_numbers_are_read_or_refused() {
        assert_eq!(ids(&json!({})).unwrap(), Vec::<AgentId>::new());
        assert_eq!(ids(&json!({"agents": [2, 3]})).unwrap(), [2, 3]);
        for bad in [
            json!({"agents": ["2"]}),
            json!({"agents": [-1]}),
            json!({"agents": 2}),
        ] {
            let error = ids(&bad).unwrap_err();
            assert!(error.contains("list of agent numbers"), "{bad}: {error}");
        }
    }

    #[test]
    fn what_the_agents_said_is_labelled_with_who_said_it() {
        let outcomes = [
            Outcome {
                id: 2,
                task: "count the crabs".to_string(),
                ok: true,
                text: "three".to_string(),
            },
            Outcome {
                id: 3,
                task: "x".repeat(80),
                ok: false,
                text: "the agent was stopped".to_string(),
            },
        ];
        let text = report(&outcomes);
        assert!(text.starts_with("agent 2 (count the crabs) answered:\nthree"));
        assert!(text.contains("agent 3 ("), "{text}");
        assert!(text.contains("…) did not finish:\n"), "{text}");
    }
}
