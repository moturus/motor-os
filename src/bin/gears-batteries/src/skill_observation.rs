//! A passing check while a skill is loaded records co-occurrence, not causation.

use serde_json::{Value, json};

use crate::Event;
use crate::paths::ToolContext;
use crate::turns::Turn;

pub fn observe(event: &Event, context: &ToolContext) -> Result<Value, String> {
    if event.event != "turn_end" || event.payload["status"] != "completed" {
        return Ok(json!({}));
    }
    let mut state = crate::hook_state(event)?;
    let Some(active) = state.get("turn_record") else {
        return Ok(json!({}));
    };
    let mut turn: Turn =
        serde_json::from_value(active.clone()).map_err(|error| error.to_string())?;
    let check = turn.checks.iter().rev().find(|check| {
        check["passed"] == true
            && state["last_check"]["current"] == true
            && check["entry_id"] == state["last_check"]["entry_id"]
    });
    let Some(check) = check else {
        return Ok(json!({}));
    };
    let check_entry = check["entry_id"]
        .as_str()
        .ok_or("passing check observation lacks an entry id")?
        .to_string();
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
    fn only_completed_turns_with_a_current_check_record_noncausal_observations() {
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
            event: "turn_end".into(),
            workspace: context.workspace.clone(),
            session: crate::Session {
                id: "s1".into(),
                path: None,
                state: Some(json!({"skill_snapshot": hash,
                "turn_record": turn, "last_check": {"entry_id": "check-entry", "current": true}})),
            },
            payload: json!({"status": "completed"}),
        };
        let response = observe(&event, &context).unwrap();
        let fact = &response["state"]["turn_record"]["skill_observations"][0];
        assert_eq!(fact["load_source"]["entries"], json!(["load-entry"]));
        assert_eq!(fact["check_source"]["entry"], "check-entry");
        assert_eq!(fact["causal_claim"], false);
        event.session.state.as_mut().unwrap()["last_check"]["current"] = json!(false);
        assert!(observe(&event, &context).unwrap().get("state").is_none());
        event.session.state.as_mut().unwrap()["last_check"]["current"] = json!(true);
        event.payload["status"] = json!("cancelled");
        assert!(observe(&event, &context).unwrap().get("state").is_none());
        std::fs::remove_dir_all(path).unwrap();
    }
}
