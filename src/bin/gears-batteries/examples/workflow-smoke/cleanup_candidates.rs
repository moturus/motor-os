//! Current-version provenance, literal overlap hints and explicit UTC dates.

use gears_batteries::{
    memory_format::Source, paths::ToolContext, pending::Decision, skill_cleanup,
    skill_format::Content, skill_pending, skill_store,
};
use std::path::Path;

fn content(name: &str, when: &str) -> Content {
    Content {
        skill_md: format!(
            "---\nname: {name}\ndescription: Run checks.\n---\n## When it applies\n{when}\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n"
        ),
        notes_md: None,
    }
}

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let context = ToolContext::new(workspace.into(), root.into(), "s1".into(), None)?;
    let agent = content("agent", "Rust work.");
    let mut proposal = skill_pending::Proposal {
        version: 1,
        kind: "skill".into(),
        cleanup: None,
        name: "agent".into(),
        before: None,
        after: Some(agent.clone()),
        source: Source {
            review: None,
            session: "s1".into(),
            entries: vec!["e1".into()],
        },
        date_ms: 1,
    };
    let id = skill_pending::propose(&context, &proposal)?.unwrap();
    skill_pending::decide(&context, &id, Decision::Approve)?;
    for name in ["imported", "edited"] {
        let value = content(name, "  RUST   work. ");
        skill_store::write(&context, name, Some(&value))?;
        skill_store::admit(&context, name, &value.hash(), Decision::Approve)?;
    }
    let versions = skill_cleanup::versions(&context)?;
    assert_eq!(versions.len(), 3);
    assert_eq!(versions.iter().filter(|v| v.origin.is_some()).count(), 1);
    assert_eq!(
        versions[0].origin.as_ref().unwrap().0.source,
        proposal.source
    );
    assert!(versions[0].origin.as_ref().unwrap().1 > 0);
    let overlaps = skill_cleanup::overlaps(&versions);
    assert_eq!(overlaps.len(), 1);
    assert_eq!(
        overlaps[0]["names"],
        serde_json::json!(["agent", "edited", "imported"])
    );
    assert!(overlaps[0]["basis"].as_str().unwrap().contains("identical"));
    proposal.before = Some(agent.clone());
    proposal.after.as_mut().unwrap().notes_md = Some("An unaccepted change.".into());
    let id = skill_pending::propose(&context, &proposal)?.unwrap();
    skill_pending::decide(&context, &id, Decision::Deny)?;
    assert!(skill_cleanup::versions(&context)?[0].origin.is_some());
    // An explicit user admission relinquishes agent ownership of even identical bytes.
    skill_store::admit(&context, "agent", &agent.hash(), Decision::Approve)?;
    assert!(
        skill_cleanup::versions(&context)?
            .iter()
            .all(|v| v.origin.is_none())
    );
    let id = skill_pending::propose(&context, &proposal)?.unwrap();
    skill_pending::decide(&context, &id, Decision::Approve)?;
    assert!(skill_cleanup::versions(&context)?[0].origin.is_some());
    let mut edited = proposal.after.unwrap();
    edited.notes_md = Some("User edited this version.".into());
    skill_store::write(&context, "agent", Some(&edited))?;
    assert_eq!(skill_cleanup::versions(&context)?.len(), 2);
    skill_store::admit(&context, "agent", &edited.hash(), Decision::Approve)?;
    assert!(
        skill_cleanup::versions(&context)?
            .iter()
            .all(|v| v.origin.is_none())
    );
    assert_eq!(skill_cleanup::cutoff("1970-01-01")?, 0);
    assert_eq!(skill_cleanup::cutoff("2000-01-01")?, 946684800000);
    assert_eq!(skill_cleanup::cutoff("2024-02-29")?, 1709164800000);
    assert_eq!(
        skill_cleanup::cutoff("2000-03-01")? - skill_cleanup::cutoff("2000-02-29")?,
        86400000
    );
    for invalid in [
        "",
        "1969-12-31",
        "2023-02-29",
        "2100-02-29",
        "2024-04-31",
        "2024-00-01",
        "2024-13-01",
        "2024-01-00",
        "2024-1-01",
        "2024-01-01Z",
        "xxxx-01-01",
    ] {
        assert!(skill_cleanup::cutoff(invalid).is_err(), "{invalid}");
    }
    gears_batteries::journal::append_at(
        &context.state,
        &context.state.file(Path::new("batteries/changes.jsonl"))?,
        &serde_json::json!({"version": 2}),
    )?;
    assert!(skill_cleanup::versions(&context).is_err());
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
