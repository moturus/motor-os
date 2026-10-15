//! Review triggers retain an exact saved entry and never start a model run.

use serde_json::{Value, json};

use crate::batteries::{Event, paths::ToolContext, review_config, review_marks};

pub fn specification() -> Value {
    json!({"name": "review", "help": "Mark this conversation for an enabled review: /review [focus]."})
}

pub fn record(event: &Event, context: &ToolContext) -> Result<Value, String> {
    let command = event.event == "command" && event.payload["name"] == "review";
    if !command && event.event != "before_compact" {
        return Err("unknown review trigger".into());
    }
    if event.session.id != context.session {
        return Err("review trigger belongs to another session".into());
    }
    let skipped = |reason: &str| {
        if command {
            Err(reason.to_string())
        } else {
            Ok(json!({}))
        }
    };
    if event
        .session
        .state
        .as_ref()
        .is_some_and(|state| state["run_kind"] == "review")
    {
        return skipped("reviews cannot schedule another review");
    }
    let settings = review_config::load(&context.state)?;
    if !settings.enabled {
        return skipped("reviews are disabled; configure the model pair in user batteries.toml");
    }
    let Some(path) = &event.session.path else {
        return skipped("reviews need a saved session");
    };
    let snapshot = crate::session::read_snapshot(path)?;
    if snapshot.id() != context.session {
        return Err("saved review session identity differs".into());
    }
    let executor = review_config::Model {
        provider: snapshot.provider().unwrap_or_else(|| "default".into()),
        model: snapshot
            .model()
            .ok_or("saved review session has no model")?,
    };
    if !settings.enabled_for(&executor.provider, &executor.model) {
        return skipped("reviews are not enabled for this executor provider/model pair");
    }
    let entry = snapshot
        .active_leaf()
        .ok_or("review session has no saved entry")?;
    // Refuse an unfinished tool round before creating a mark the runner cannot read.
    snapshot.at(entry)?;
    let (reason, focus) = if command {
        (
            review_marks::Reason::Command,
            event.payload["argument"]
                .as_str()
                .ok_or("invalid /review focus")?,
        )
    } else {
        (review_marks::Reason::Compaction, "")
    };
    let id = review_marks::create(context, entry, reason, focus, &executor)?;
    let mark = review_marks::load(context, &id)?.ok_or("review mark disappeared")?;
    let notice = match mark.disposition {
        review_marks::Disposition::Due => "Review marked due.",
        review_marks::Disposition::Completed => "This review is already completed.",
        review_marks::Disposition::Dropped => "This review was dismissed.",
    };
    Ok(json!({"notice": notice}))
}
