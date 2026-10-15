//! Freeze available skills while delivering corrections once on each branch.

use serde_json::{Value, json};

use crate::batteries::Event;
use crate::batteries::paths::ToolContext;
use crate::batteries::skill_snapshot::Snapshot;

pub fn initialize(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let mut state = crate::batteries::hook_state(event)?;
    if let Some(prefix) = crate::batteries::prefix_state(event)? {
        let hash = match prefix.get("skill_snapshot") {
            Some(hash) => hash
                .as_str()
                .ok_or("invalid historical skill reference")?
                .to_string(),
            None => crate::batteries::skill_snapshot::save(
                context,
                &Snapshot {
                    version: 1,
                    catalog: Vec::new(),
                    loaded: Vec::new(),
                },
            )?,
        };
        if state["skill_snapshot"] != hash {
            state.as_object_mut().unwrap().remove("skill_view_snapshot");
        }
        state["skill_snapshot"] = json!(hash);
    }
    let old_hash = state
        .get("skill_snapshot")
        .map(|hash| hash.as_str().ok_or("invalid skill snapshot reference"))
        .transpose()?;
    let saved = old_hash
        .map(|hash| crate::batteries::skill_snapshot::load(context, hash))
        .transpose()?;
    let (catalog, notices) =
        crate::batteries::skill_catalog::load(context, crate::batteries::skill_catalog::platform());
    let preserve = event.payload["preserve_prefix"] == true;
    let compacted = event.payload["reason"] == "compaction";
    let refresh = saved.is_none() || (!preserve && compacted);
    let desired = if refresh {
        Snapshot {
            version: 1,
            catalog,
            loaded: Vec::new(),
        }
    } else if preserve {
        saved.as_ref().unwrap().clone()
    } else {
        crate::batteries::skill_snapshot::reconcile(context, saved.as_ref().unwrap(), &catalog)?
    };
    let hash = if saved.as_ref() == Some(&desired) {
        old_hash.unwrap().to_string()
    } else {
        crate::batteries::skill_snapshot::save(context, &desired)?
    };
    if let Some(old_hash) = old_hash
        && saved.as_ref() != Some(&desired)
        && state.get("skill_view_snapshot").is_none()
    {
        state["skill_view_snapshot"] = json!(old_hash);
    }
    if preserve && compacted {
        state.as_object_mut().unwrap().remove("skill_view_snapshot");
    }
    state["skill_snapshot"] = json!(hash);
    let fragments = if desired.catalog.is_empty() {
        Vec::new()
    } else {
        vec![crate::batteries::skill_catalog::prompt(&desired.catalog)?]
    };
    let mut response = json!({"prompt_fragments": fragments});
    if event.session.state.as_ref() != Some(&state) {
        response["state"] = state;
    }
    if !notices.is_empty() {
        response["notice"] = json!(notices.join("\n"));
    }
    Ok(response)
}

pub fn observe(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let mut state = crate::batteries::hook_state(event)?;
    let Some(hash) = state.get("skill_snapshot") else {
        return Ok(json!({}));
    };
    let frozen = crate::batteries::skill_snapshot::load(
        context,
        hash.as_str().ok_or("invalid skill snapshot reference")?,
    )?;
    let previous = state
        .get("skill_view_snapshot")
        .map(|hash| {
            crate::batteries::skill_snapshot::load(
                context,
                hash.as_str().ok_or("invalid skill view reference")?,
            )
        })
        .transpose()?
        .unwrap_or_else(|| frozen.clone());
    let (catalog, notices) =
        crate::batteries::skill_catalog::load(context, crate::batteries::skill_catalog::platform());
    let desired = crate::batteries::skill_snapshot::reconcile(context, &frozen, &catalog)?;
    let mut response = json!({});
    if let Some(note) = crate::batteries::skill_snapshot::changes(&previous, &desired)? {
        state["skill_view_snapshot"] =
            json!(crate::batteries::skill_snapshot::save(context, &desired)?);
        response["state"] = state;
        response["context"] = json!(crate::provider::Message::user(note));
    }
    if !notices.is_empty() {
        response["notice"] = json!(notices.join("\n"));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::memory_format::Source;
    use crate::batteries::pending::Decision;
    use crate::batteries::skill_format::Content;
    use crate::batteries::skill_snapshot::Loaded;

    #[test]
    fn notes_corrections_and_withdrawals_reach_running_resumed_and_forked_branches_once() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-context-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let mut content = Content { skill_md: "---\nname: checks\ndescription: Run checks.\nmetadata: {platforms: motor linux}\n---\nInstructions.\n".into(), notes_md: Some("Original quirk.".into()) };
        crate::batteries::skill_store::write(&context, "checks", Some(&content)).unwrap();
        crate::batteries::skill_store::admit(
            &context,
            "checks",
            &content.hash(),
            Decision::Approve,
        )
        .unwrap();
        let mut event = Event {
            protocol_version: 1,
            event: "initialize".into(),
            workspace: context.workspace.clone(),
            session: crate::batteries::Session {
                id: "s1".into(),
                path: None,
                state: None,
            },
            payload: json!({}),
        };
        let initial = initialize(&event, &context).unwrap();
        let mut snapshot = crate::batteries::skill_snapshot::load(
            &context,
            initial["state"]["skill_snapshot"].as_str().unwrap(),
        )
        .unwrap();
        snapshot.loaded.push(Loaded {
            name: "checks".into(),
            content: content.clone(),
            source: Source {
                review: None,
                session: "s1".into(),
                entries: vec!["e1".into()],
            },
        });
        let hash = crate::batteries::skill_snapshot::save(&context, &snapshot).unwrap();
        event.session.state = Some(json!({"skill_snapshot": hash, "other": "preserved"}));
        let branch = event.session.state.clone();
        content.notes_md = Some("Corrected quirk.".into());
        crate::batteries::skill_store::write(&context, "checks", Some(&content)).unwrap();
        let withdrawal = observe(&event, &context).unwrap();
        assert!(
            withdrawal["context"]
                .to_string()
                .contains("Withdraw loaded skill checks")
        );
        assert!(
            !withdrawal["context"]
                .to_string()
                .contains("Corrected quirk.")
        );
        event.session.state = Some(withdrawal["state"].clone());
        assert!(observe(&event, &context).unwrap().get("context").is_none());
        crate::batteries::skill_store::admit(
            &context,
            "checks",
            &content.hash(),
            Decision::Approve,
        )
        .unwrap();
        let corrected = observe(&event, &context).unwrap();
        assert!(
            corrected["context"]
                .to_string()
                .contains("Corrected quirk.")
        );
        event.session.state = Some(corrected["state"].clone());
        assert!(observe(&event, &context).unwrap().get("context").is_none());
        event.session.state = branch;
        let resumed = initialize(&event, &context).unwrap();
        assert_ne!(resumed["state"]["skill_snapshot"], hash);
        assert_eq!(resumed["state"]["other"], "preserved");
        event.session.state = Some(resumed["state"].clone());
        assert!(
            observe(&event, &context).unwrap()["context"]
                .to_string()
                .contains("Corrected quirk.")
        );
        crate::batteries::skill_store::write(&context, "checks", None).unwrap();
        let removed = initialize(&event, &context).unwrap();
        assert!(removed["prompt_fragments"].as_array().unwrap().is_empty());
        std::fs::remove_dir_all(path).unwrap();
    }
}
