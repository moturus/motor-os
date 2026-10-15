//! Paired outcomes remain descriptive; missing costs and review time are not zero.

use crate::batteries::paths::ToolContext;
use serde_json::{Value, json};
use std::path::Path;

pub fn acquisition(context: &ToolContext) -> Result<Value, String> {
    let (mut approved, mut denied) = (0u64, 0u64);
    crate::batteries::journal::visit(
        &context.state,
        Path::new("batteries/changes.jsonl"),
        |record| {
            if record.get("proposal").is_some() {
                match record["decision"].as_str() {
                    Some("approve") => approved += 1,
                    Some("deny") => denied += 1,
                    _ => {}
                }
            }
            Ok(())
        },
    )?;
    let (latest, warning) = match crate::batteries::review_status::latest(&context.state) {
        Ok(value) => (value, None),
        Err(error) => (None, Some(error)),
    };
    Ok(
        json!({"approved_proposals":approved,"denied_proposals":denied,
        "decision_coverage":"all recorded source-directory history; may include unrelated work",
        "human_review_seconds":null,"postponement_count":null,
        "review_cost_usd":null,"latest_review_usage":latest.map(|r|r["usage"].clone()),
        "warning":warning,"limitations":"Only the latest review is retained; historical review/denial/interruption costs and human time are not fully recorded."}),
    )
}

pub fn summarize(
    rows: &[Value],
    inputs: Value,
    settings: Value,
    criterion: &str,
    acquisition: Value,
    elapsed_ms: u64,
) -> Value {
    let arms:[Value;2]=["baseline","learning"].map(|arm|{
        let selected:Vec<_>=rows.iter().filter(|r|r["arm"]==arm).collect();
        let accepted=selected.iter().filter(|r|r["actor"]["completed"]==true
            && all_passed(&r["acceptance"]) && all_passed(&r["regressions"])).count();
        let regressions=selected.iter().filter(|r|r["regressions"].as_array().is_some_and(|checks|checks.iter().any(|r|r["passed"]==false))).count();
        let known:Vec<_>=selected.iter().filter_map(|r|r["actor"]["usage"]["cost_usd"].as_f64().filter(|v|v.is_finite()&&*v>=0.0)).collect();
        let complete=!selected.is_empty()&&known.len()==selected.len()
            &&selected.iter().all(|r|r["actor"]["usage"]["cost_is_partial"]==false);
        let sum=known.iter().sum::<f64>();
        let reported=(!known.is_empty()&&sum.is_finite()).then_some(sum);
        json!({"arm":arm,"trials":selected.len(),"accepted":accepted,
            "accepted_rate":(!selected.is_empty()).then(||accepted as f64/selected.len() as f64),
            "regression_failures":regressions,
            "regression_unchecked":selected.iter().filter(|r|r["regressions"].as_array().is_none_or(|checks|checks.is_empty())).count(),
            "actor_failures":selected.iter().filter(|r|r["actor"]["completed"]!=true).count(),
            "actor_elapsed_ms":total(selected.iter().map(|r|r["actor"]["duration_ms"].as_u64())),
            "criterion_elapsed_ms":total(selected.iter().flat_map(|r|["acceptance","regressions"].into_iter().flat_map(move |kind|r[kind].as_array().into_iter().flatten())).map(|r|r["duration_ms"].as_u64())),
            "tool_calls":total(selected.iter().map(|r|r["actor"]["tool_calls"].as_u64())),
            "tool_failures":total(selected.iter().map(|r|r["actor"]["tool_failures"].as_u64())),
            "model_cost":{"reported_usd":reported,"complete":complete&&reported.is_some()},
            "tool_cost_usd":null})
    });
    json!({"version":1,"inputs":inputs,"settings":settings,"criterion":criterion,
        "elapsed_ms":elapsed_ms,"arms":arms,"trials":rows,"learning_acquisition":acquisition,
        "total_cost_usd":null,"verdict":"insufficient_evidence",
        "reason":"Apply the stated criterion to held-out task coverage and costs before judging a model pair. Equal observed rates do not establish equivalence; unrecorded review/tool costs and human time remain unknown.",
        "reviews_enabled":false})
}

fn all_passed(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|records| !records.is_empty() && records.iter().all(|r| r["passed"] == true))
}

fn total(mut values: impl Iterator<Item = Option<u64>>) -> Option<u64> {
    values.try_fold(0u64, |sum, value| sum.checked_add(value?))
}
