//! Saved sources and branches that loaded the proposal's exact old bytes.

use serde_json::Value;

use crate::paths::ToolContext;
use crate::skill_pending::Proposal;

pub fn describe(context: &ToolContext, proposal: &Proposal) -> Result<Value, String> {
    crate::memory_sources::describe_with(context, &proposal.source, |session| {
        let Some(before) = &proposal.before else {
            return Ok(false);
        };
        for entry in session
            .entries()
            .iter()
            .filter(|entry| entry.kind == "hook_state")
        {
            for field in ["skill_snapshot", "skill_view_snapshot"] {
                let Some(hash) = entry.data["state"][field].as_str() else {
                    continue;
                };
                let snapshot = crate::skill_snapshot::load(context, hash)?;
                if snapshot
                    .loaded
                    .iter()
                    .any(|skill| skill.name == proposal.name && &skill.content == before)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_format::Source;
    use crate::skill_format::Content;
    use crate::skill_snapshot::{Loaded, Snapshot};
    use gears::provider::Message;
    use gears::session::{HookState, Store};
    use serde_json::json;

    #[test]
    fn exact_loaded_versions_and_available_citations_are_read_without_mutation() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-sources-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let store = Store::with_root(&path.join("workspace"), path.join("state")).unwrap();
        let mut session = store.create(false, None).unwrap();
        let id = session
            .append_message(&Message::user("Correct the check instructions."))
            .unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            session.id().into(),
            session.path(),
        )
        .unwrap();
        let source = Source {
            review: None,
            session: session.id().into(),
            entries: vec![id, "missing".into()],
        };
        let content = Content {
            skill_md: "---\nname: checks\ndescription: Run checks.\n---\nSteps.\n".into(),
            notes_md: Some("Old note.".into()),
        };
        let hash = crate::skill_snapshot::save(
            &context,
            &Snapshot {
                version: 1,
                catalog: Vec::new(),
                loaded: vec![Loaded {
                    name: "checks".into(),
                    content: content.clone(),
                    source: source.clone(),
                }],
            },
        )
        .unwrap();
        session
            .append_hook_state(&HookState {
                hook: "batteries".into(),
                state: json!({"skill_view_snapshot": hash}),
                context: None,
            })
            .unwrap();
        let bytes = std::fs::read(session.path().unwrap()).unwrap();
        let mut proposal = Proposal {
            version: 1,
            kind: "skill".into(),
            name: "checks".into(),
            before: Some(content),
            after: None,
            source,
            date_ms: 1,
        };
        let evidence = describe(&context, &proposal).unwrap();
        assert_eq!(
            evidence["sessions_with_old_snapshot"],
            json!([session.id()])
        );
        assert_eq!(evidence["evidence"][0]["available"], true);
        assert_eq!(evidence["evidence"][1]["available"], false);
        proposal.before.as_mut().unwrap().notes_md = Some("Different note.".into());
        assert_eq!(
            describe(&context, &proposal).unwrap()["sessions_with_old_snapshot"],
            json!([])
        );
        assert_eq!(std::fs::read(session.path().unwrap()).unwrap(), bytes);
        drop(session);
        std::fs::remove_dir_all(path).unwrap();
    }
}
