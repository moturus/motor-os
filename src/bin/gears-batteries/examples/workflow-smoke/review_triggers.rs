//! Saved command and compaction marks stay isolated and do not call a provider.

use std::path::Path;

use gears::provider::Message;
use gears::session::{Compaction, Store};
use gears_batteries::{Event, Session, paths::ToolContext, review_marks, review_triggers};
use serde_json::json;

pub fn run(workspace: &Path, root: &Path) -> Result<(), String> {
    let store = Store::with_root(workspace, root.into())?;
    let mut parent = store.create(false, None)?;
    parent.set_provider("local")?;
    parent.set_model("executor")?;
    let entry = parent.append_message(&Message::assistant("Finished the task"))?;
    let context = ToolContext::new(
        workspace.into(),
        root.into(),
        parent.id().into(),
        parent.path(),
    )?;
    let mut event = Event {
        protocol_version: 1,
        event: "command".into(),
        workspace: workspace.into(),
        session: Session {
            id: parent.id().into(),
            path: parent.path().map(Path::to_path_buf),
            state: None,
        },
        payload: json!({"name": "review", "argument": "Check the demonstrated procedure."}),
    };
    assert!(
        review_triggers::record(&event, &context)
            .unwrap_err()
            .contains("disabled")
    );
    assert!(review_marks::due(&context)?.is_empty());
    let configuration = b"version=1\n[reviews]\nenabled=true\n[reviews.executor]\nprovider='local'\nmodel='executor'\n[reviews.reviewer]\nprovider='local'\nmodel='reviewer'\n";
    context
        .state
        .replace_file(Path::new("batteries.toml"), configuration)?;
    let before = std::fs::read(parent.path().unwrap()).map_err(|error| error.to_string())?;
    assert_eq!(
        review_triggers::record(&event, &context)?["notice"],
        "Review marked due."
    );
    let marks = review_marks::due(&context)?;
    assert_eq!(marks.len(), 1);
    assert_eq!(marks[0].entry, entry);
    assert_eq!(marks[0].reason, review_marks::Reason::Command);
    assert_eq!(marks[0].focus, "Check the demonstrated procedure.");
    review_triggers::record(&event, &context)?;
    assert_eq!(review_marks::due(&context)?.len(), 1);
    review_marks::finish(&context, &marks[0].id(), review_marks::Disposition::Dropped)?;
    assert_eq!(
        review_triggers::record(&event, &context)?["notice"],
        "This review was dismissed."
    );
    assert!(review_marks::due(&context)?.is_empty());
    event.payload["argument"] = json!("different focus");
    review_triggers::record(&event, &context)?;
    assert_eq!(review_marks::due(&context)?.len(), 1);
    event.event = "before_compact".into();
    event.payload = json!({});
    review_triggers::record(&event, &context)?;
    let marks = review_marks::due(&context)?;
    assert_eq!(marks.len(), 2);
    let compact = marks
        .iter()
        .find(|mark| mark.reason == review_marks::Reason::Compaction)
        .unwrap();
    assert_eq!(compact.entry, entry);
    assert!(compact.focus.is_empty());
    assert_eq!(
        std::fs::read(parent.path().unwrap()).map_err(|error| error.to_string())?,
        before
    );
    parent.append_compaction(&Compaction {
        summary: "Later summary".into(),
        retained_tail: Vec::new(),
        tokens_before: 100,
    })?;
    assert_eq!(
        store
            .read(parent.id())?
            .at(&compact.entry)?
            .context_messages()?[0]
            .text_content(),
        "Finished the task"
    );
    parent.set_model("other")?;
    assert_eq!(review_triggers::record(&event, &context)?, json!({}));
    event.event = "command".into();
    event.payload = json!({"name": "review", "argument": ""});
    assert!(
        review_triggers::record(&event, &context)
            .unwrap_err()
            .contains("executor")
    );
    parent.set_model("executor")?;
    for focus in ["\0".into(), "x".repeat(4097)] {
        event.payload["argument"] = json!(focus);
        assert!(review_triggers::record(&event, &context).is_err());
    }
    event.session.state = Some(json!({"run_kind": "review"}));
    assert!(
        review_triggers::record(&event, &context)
            .unwrap_err()
            .contains("another review")
    );
    event.event = "before_compact".into();
    assert_eq!(review_triggers::record(&event, &context)?, json!({}));
    let other = ToolContext::new(workspace.into(), root.into(), "other-session".into(), None)?;
    assert!(review_marks::due(&other)?.is_empty());
    assert!(review_triggers::record(&event, &other).is_err());
    event.session.state = None;
    event.session.path = None;
    assert_eq!(review_triggers::record(&event, &context)?, json!({}));
    event.event = "command".into();
    assert!(
        review_triggers::record(&event, &context)
            .unwrap_err()
            .contains("saved session")
    );
    assert_eq!(review_marks::due(&context)?.len(), 2);
    println!("gears batteries review triggers ALL PASS");
    Ok(())
}
