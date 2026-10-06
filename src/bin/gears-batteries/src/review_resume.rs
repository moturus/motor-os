//! A resumed session needs an explicit answer before unfinished reviews run.

use serde_json::{Value, json};

use crate::{Event, paths::ToolContext, review_marks};

pub fn initialize(
    event: &Event,
    context: &ToolContext,
    state: &Value,
    defer_question: bool,
) -> Result<Value, String> {
    if event.session.id != context.session {
        return Err("unfinished reviews belong to another session".into());
    }
    if event.session.path.is_none()
        || state["run_kind"] == "review"
        || !matches!(
            event.payload["reason"].as_str(),
            Some("startup" | "resume" | "new" | "fork" | "clone")
        )
    {
        return Ok(json!({}));
    }
    let ids: Vec<_> = review_marks::due(context)?
        .iter()
        .map(review_marks::Mark::id)
        .collect();
    let mut state = state.clone();
    if ids.is_empty() {
        if state.get("awaiting_reviews").is_none() && state.get("reviews_paused").is_none() {
            return Ok(json!({}));
        }
        state.as_object_mut().unwrap().remove("awaiting_reviews");
        state.as_object_mut().unwrap().remove("reviews_paused");
        return Ok(json!({"state": state}));
    }
    state["awaiting_reviews"] = json!(ids);
    state["reviews_paused"] = json!(true);
    let mut response = json!({"state": state});
    if !defer_question {
        response["question"] = question(context, &response["state"])?["question"].clone();
    }
    Ok(response)
}

fn ids(state: &Value) -> Result<Vec<String>, String> {
    serde_json::from_value(state["awaiting_reviews"].clone())
        .map_err(|error| format!("invalid unfinished review question: {error}"))
}

fn id(context: &ToolContext, ids: &[String]) -> String {
    crate::snapshot::digest(
        json!(["resume_reviews", context.session, ids])
            .to_string()
            .as_bytes(),
    )
}

pub fn question(context: &ToolContext, state: &Value) -> Result<Value, String> {
    if state.get("awaiting_reviews").is_none() {
        return Ok(json!({}));
    }
    let ids = ids(state)?;
    if ids.is_empty() || state["reviews_paused"] != true {
        return Err("invalid unfinished review question".into());
    }
    for id in &ids {
        review_marks::load(context, id)?.ok_or("unfinished review mark is missing")?;
    }
    Ok(json!({"question": {"id": id(context, &ids),
        "text": format!("Run the {} unfinished reviews from this session?", ids.len()),
        "choices": [{"value": "run", "label": "Run reviews"},
            {"value": "drop", "label": "Dismiss reviews"}]}}))
}

pub fn owns_answer(event: &Event, context: &ToolContext) -> bool {
    ids(event.session.state.as_ref().unwrap_or(&Value::Null))
        .is_ok_and(|ids| event.payload["id"] == id(context, &ids))
}

pub fn answer(event: &Event, context: &ToolContext) -> Result<Value, String> {
    if event.session.id != context.session {
        return Err("unfinished reviews belong to another session".into());
    }
    let mut state = crate::hook_state(event)?;
    let question = question(context, &state)?;
    if question.get("question").is_none() || event.payload["id"] != question["question"]["id"] {
        return Err("unfinished review answer belongs to another question".into());
    }
    if event.payload["answer"].is_null() {
        return Ok(
            json!({"notice": "Unfinished reviews remain paused until you answer on resume."}),
        );
    }
    if event.payload["attended"] != true {
        return Err("unfinished reviews need an attended answer".into());
    }
    let notice = match event.payload["answer"].as_str() {
        Some("run") => "Unfinished reviews remain due and may run after the next turn.",
        Some("drop") => {
            for id in ids(&state)? {
                if review_marks::load(context, &id)?
                    .is_some_and(|mark| mark.disposition == review_marks::Disposition::Due)
                {
                    review_marks::finish(context, &id, review_marks::Disposition::Dropped)?;
                }
            }
            "Unfinished reviews dismissed."
        }
        _ => return Err("invalid unfinished review answer".into()),
    };
    state.as_object_mut().unwrap().remove("awaiting_reviews");
    state["reviews_paused"] = json!(false);
    Ok(json!({"state": state, "notice": notice}))
}
