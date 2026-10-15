//! Minimal admissions preserve selected versions without source-session artifacts.

use gears::batteries::{
    eval_state, memory,
    memory_format::{Source, Target},
    paths::ToolContext,
    pending::Decision,
    skill_format::Content,
    skill_pending, skill_store,
};
use std::path::Path;

pub fn run_fixture(root: &Path) -> Result<(), String> {
    let source = super::eval_states::prepare(root)?;
    for (name, agent) in [("curated", false), ("learned", true)] {
        let content = Content {
            skill_md: format!(
                "---\nname: {name}\ndescription: Check work.\n---\n## When it applies\nRust.\n## Steps\nCheck.\n## How to check\nPasses.\n## Pitfalls\nStale files.\n"
            ),
            notes_md: None,
        };
        if agent {
            let proposal = skill_pending::Proposal {
                version: 1,
                kind: "skill".into(),
                cleanup: None,
                name: name.into(),
                before: None,
                after: Some(content),
                source: Source {
                    session: "origin".into(),
                    entries: vec!["e1".into()],
                    review: None,
                },
                date_ms: 1,
            };
            let id = skill_pending::propose(&source, &proposal)?.unwrap();
            skill_pending::decide(&source, &id, Decision::Approve)?;
        } else {
            skill_store::write(&source, name, Some(&content))?;
            skill_store::admit(&source, name, &content.hash(), Decision::Approve)?;
        }
    }
    source.state.replace_file(
        Path::new("batteries/sessions/origin/reviews.jsonl"),
        b"holdout answer must not be copied\n",
    )?;
    let frozen = eval_state::capture(&source)?;
    let original = std::fs::read(source.state.path().join("batteries/changes.jsonl")).unwrap();
    let mut installed = Vec::new();
    for (label, learning) in [("baseline", false), ("learning", true)] {
        let workspace = root.join(label);
        std::fs::create_dir(&workspace).unwrap();
        let state = root.join(format!("{label}-state"));
        let versions = frozen.install(&workspace, &state, learning)?;
        assert!(frozen.install(&workspace, &state, learning).is_err());
        let context = ToolContext::new(workspace, state, "eval".into(), None)?;
        assert!(!gears::batteries::review_config::load(&context.state)?.enabled);
        gears::batteries::workspace_memory::require_approved(&context)?;
        let global = memory::load(&context, Target::Global)?;
        assert!(
            global
                .entries
                .iter()
                .any(|e| e.metadata.id == "global-user")
        );
        assert!(
            global
                .entries
                .iter()
                .any(|e| e.metadata.id == "curated-fact")
        );
        assert_eq!(
            global.entries.iter().any(|e| e.metadata.id == "learned"),
            learning
        );
        assert_eq!(
            memory::load(&context, Target::Workspace)?.entries.len(),
            usize::from(learning)
        );
        assert_eq!(memory::load(&context, Target::User)?.entries.len(), 1);
        assert!(skill_store::approved(
            &context,
            "curated",
            &skill_store::current(&context, "curated")?.unwrap().hash()
        )?);
        assert_eq!(
            skill_store::current(&context, "learned")?.is_some(),
            learning
        );
        for excluded in [
            "sessions",
            "batteries/pending",
            "batteries/sessions",
            "batteries/last-review.json",
        ] {
            assert!(!context.state.path().join(excluded).exists());
        }
        let history =
            std::fs::read_to_string(context.state.path().join("batteries/changes.jsonl")).unwrap();
        assert!(!history.contains("origin"));
        assert!(!history.contains("holdout answer"));
        assert!(!history.contains("project-learned"));
        installed.push(versions);
    }
    assert_eq!(installed[0]["settings_hash"], installed[1]["settings_hash"]);
    assert_eq!(installed[0]["skills"].as_array().unwrap().len(), 1);
    assert_eq!(installed[1]["skills"].as_array().unwrap().len(), 2);
    assert_eq!(
        std::fs::read(source.state.path().join("batteries/changes.jsonl")).unwrap(),
        original
    );
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
