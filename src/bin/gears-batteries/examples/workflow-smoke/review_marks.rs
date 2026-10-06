//! Portable persistence and session-isolation checks, without a model request.

use std::path::Path;

use gears_batteries::paths::ToolContext;
use gears_batteries::review_config::Model;
use gears_batteries::review_marks::{self as marks, Disposition, Reason};

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let context = ToolContext::new(workspace.into(), root.into(), "source".into(), None)?;
    let executor = Model {
        provider: "local".into(),
        model: "executor-v1".into(),
    };
    let create = |entry, reason, focus| marks::create(&context, entry, reason, focus, &executor);
    assert!(marks::due(&context)?.is_empty());
    assert!(
        !root.exists(),
        "reading absent marks must not create their directory"
    );
    let command = create("e1", Reason::Command, "Check the new procedure")?;
    assert_eq!(
        create("e1", Reason::Command, "Check the new procedure")?,
        command
    );
    let compact = create("e1", Reason::Compaction, "")?;
    let focused = create("e1", Reason::Command, "Check something else")?;
    let later = create("e2", Reason::Command, "Check the new procedure")?;
    assert_eq!(marks::due(&context)?.len(), 4);
    let saved = marks::load(&context, &command)?.unwrap();
    assert_eq!(saved.entry, "e1");
    assert_eq!(saved.reason, Reason::Command);
    assert_eq!(saved.executor, executor);
    assert_eq!(saved.disposition, Disposition::Due);

    // Dropping and reopening the data context simulates an interrupted runner.
    let resumed = ToolContext::new(workspace.into(), root.into(), "source".into(), None)?;
    assert_eq!(marks::due(&resumed)?.len(), 4);
    marks::finish(&resumed, &command, Disposition::Completed)?;
    marks::finish(&resumed, &command, Disposition::Completed)?;
    assert_eq!(
        create("e1", Reason::Command, "Check the new procedure")?,
        command
    );
    assert_eq!(
        marks::load(&resumed, &command)?.unwrap().disposition,
        Disposition::Completed
    );
    assert!(marks::finish(&resumed, &command, Disposition::Due).is_err());
    assert!(marks::finish(&resumed, &command, Disposition::Dropped).is_err());
    marks::finish(&resumed, &compact, Disposition::Dropped)?;
    assert_eq!(create("e1", Reason::Compaction, "")?, compact);
    assert_eq!(
        marks::load(&resumed, &compact)?.unwrap().disposition,
        Disposition::Dropped
    );
    assert_eq!(marks::due(&resumed)?.len(), 2);
    assert_eq!(marks::load(&resumed, &later)?.unwrap().entry, "e2");

    let other = ToolContext::new(workspace.into(), root.into(), "other".into(), None)?;
    assert!(marks::due(&other)?.is_empty());
    assert!(marks::load(&other, &focused)?.is_none());
    let other_id = marks::create(
        &other,
        "e1",
        Reason::Command,
        "Check something else",
        &executor,
    )?;
    assert_ne!(other_id, focused);
    let bytes = std::fs::read(context.data_file(&format!("reviews/{focused}.json"))?)
        .map_err(|error| error.to_string())?;
    other.replace_data(&format!("reviews/{focused}.json"), &bytes)?;
    assert!(
        marks::load(&other, &focused)
            .unwrap_err()
            .contains("foreign")
    );

    let name = format!("reviews/{focused}.json");
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    changed["focus"] = serde_json::json!("Changed content");
    context.replace_data(&name, &serde_json::to_vec(&changed).unwrap())?;
    assert!(
        marks::load(&context, &focused)
            .unwrap_err()
            .contains("identity")
    );
    for invalid in [b"{".to_vec(), vec![b' '; 16 * 1024 + 1]] {
        context.replace_data(&name, &invalid)?;
        assert!(create("e1", Reason::Command, "Check something else").is_err());
        assert_eq!(std::fs::read(context.data_file(&name)?).unwrap(), invalid);
    }
    context.replace_data(&name, &bytes)?;
    assert_eq!(marks::due(&context)?.len(), 2);
    for (entry, reason, focus) in [
        ("", Reason::Command, ""),
        ("bad\nentry", Reason::Command, ""),
        ("e1", Reason::Compaction, "unexpected focus"),
        ("e1", Reason::Command, "bad\0focus"),
    ] {
        assert!(create(entry, reason, focus).is_err());
    }
    assert!(create("e1", Reason::Command, &"x".repeat(4097)).is_err());
    assert!(marks::load(&context, "../../foreign").is_err());
    println!("gears batteries review marks ALL PASS");
    Ok(())
}
