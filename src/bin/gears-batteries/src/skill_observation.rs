//! A passing check while a skill is loaded records co-occurrence, not causation.

use serde_json::{Value, json};

use crate::Event;
use crate::paths::ToolContext;
use crate::turns::Turn;

pub fn observe(event: &Event, context: &ToolContext) -> Result<Value, String> {
    if event.event != "entry"
        || event.payload["role"] != "tool"
        || event.payload["tool_call"]["name"] != "check"
        || event.payload["outcome"] != "completed"
    {
        return Ok(json!({}));
    }
    let mut state = crate::hook_state(event)?;
    let Some(active) = state.get("turn_record") else {
        return Ok(json!({}));
    };
    let mut turn: Turn =
        serde_json::from_value(active.clone()).map_err(|error| error.to_string())?;
    let check_entry = event.payload["id"]
        .as_str()
        .ok_or("check observation lacks an entry id")?;
    let Some(check) = crate::check_state::turn_receipt(&state, check_entry) else {
        return Ok(json!({}));
    };
    if check["passed"] != true || state["last_check"]["current"] != true {
        return Ok(json!({}));
    }
    let Some(hash) = state
        .get("skill_view_snapshot")
        .or_else(|| state.get("skill_snapshot"))
    else {
        return Ok(json!({}));
    };
    let snapshot = crate::skill_snapshot::load(
        context,
        hash.as_str().ok_or("invalid loaded skill snapshot")?,
    )?;
    if snapshot.loaded.is_empty() {
        return Ok(json!({}));
    }
    for skill in snapshot.loaded {
        turn.skill_observations.push(json!({"version": 1, "kind": "observed", "relation": "passing_check_while_skill_loaded",
            "name": skill.name, "hash": skill.content.hash(), "load_source": skill.source,
            "check_source": {"session": context.session, "entry": check_entry}, "date_ms": crate::pending::now_ms()?,
            "causal_claim": false, "user_accepted": false}));
    }
    state["turn_record"] = serde_json::to_value(turn).map_err(|error| error.to_string())?;
    Ok(json!({"state": state}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_format::Source;
    use crate::skill_format::Content;
    use crate::skill_snapshot::{Loaded, Snapshot};

    #[test]
    fn observations_record_only_the_skills_loaded_when_a_check_passes() {
        let path = std::env::temp_dir().join(format!(
            "batteries-skill-observation-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let snapshot = Snapshot {
            version: 1,
            catalog: Vec::new(),
            loaded: vec![Loaded {
                name: "checks".into(),
                content: Content {
                    skill_md: "---\nname: checks\ndescription: Run checks.\n---\nInstructions.\n"
                        .into(),
                    notes_md: None,
                },
                source: Source {
                    review: None,
                    session: "s1".into(),
                    entries: vec!["load-entry".into()],
                },
            }],
        };
        let hash = crate::skill_snapshot::save(&context, &snapshot).unwrap();
        let turn = Turn {
            version: 1,
            checks: vec![json!({"entry_id": "check-entry", "passed": true})],
            ..Turn::default()
        };
        let mut event = Event {
            protocol_version: 1,
            event: "entry".into(),
            workspace: context.workspace.clone(),
            session: crate::Session {
                id: "s1".into(),
                path: None,
                state: Some(json!({"skill_snapshot": hash,
                "turn_record": turn, "last_check": {"version": 1, "entry_id": "check-entry", "current": true,
                "receipt": {"version": 1, "kind": "check", "argv": ["compiler"], "system": "motor", "exit_status": 0,
                    "duration_ms": 1, "passed": true, "stdout": "", "stderr": "", "output_truncated": false, "output_file": null}}})),
            },
            payload: json!({"role": "tool", "id": "check-entry", "tool_call": {"name": "check"}, "outcome": "completed"}),
        };
        let response = observe(&event, &context).unwrap();
        let fact = &response["state"]["turn_record"]["skill_observations"][0];
        assert_eq!(fact["load_source"]["entries"], json!(["load-entry"]));
        assert_eq!(fact["check_source"]["entry"], "check-entry");
        assert_eq!(fact["causal_claim"], false);
        event.session.state.as_mut().unwrap()["last_check"]["current"] = json!(false);
        assert!(observe(&event, &context).unwrap().get("state").is_none());
        event.session.state.as_mut().unwrap()["last_check"]["current"] = json!(true);
        event.payload["outcome"] = json!("not_started");
        assert!(observe(&event, &context).unwrap().get("state").is_none());
        event.payload["outcome"] = json!("completed");
        let empty = crate::skill_snapshot::save(
            &context,
            &Snapshot {
                version: 1,
                catalog: Vec::new(),
                loaded: Vec::new(),
            },
        )
        .unwrap();
        event.session.state.as_mut().unwrap()["skill_snapshot"] = json!(empty);
        assert!(observe(&event, &context).unwrap().get("state").is_none());
        // Loading after that check must not create an observation at turn end.
        event.session.state.as_mut().unwrap()["skill_snapshot"] = json!(hash);
        event.event = "turn_end".into();
        event.payload = json!({"status": "completed"});
        assert!(observe(&event, &context).unwrap().get("state").is_none());
        std::fs::remove_dir_all(path).unwrap();
    }
}
