//! Regression failures prevent acceptance; unknown cost/time never become evidence.

use gears_batteries::eval_report;
use serde_json::json;
use std::path::Path;

pub fn run_fixture(root: &Path) -> Result<(), String> {
    let source = super::eval_states::prepare(root)?;
    let acquisition = eval_report::acquisition(&source)?;
    assert!(acquisition["review_cost_usd"].is_null());
    assert!(acquisition["human_review_seconds"].is_null());
    let rows = vec![
        json!({"arm":"baseline","actor":{"completed":true,"duration_ms":10,"tool_calls":2,"tool_failures":0,"usage":{"cost_usd":0.25,"cost_is_partial":false}},"acceptance":[{"passed":true,"duration_ms":1}],"regressions":[{"passed":true,"duration_ms":1}]}),
        json!({"arm":"learning","actor":{"completed":true,"tool_calls":2,"tool_failures":1,"usage":{"cost_usd":null,"cost_is_partial":false}},"acceptance":[{"passed":true,"duration_ms":1}],"regressions":[{"passed":false,"duration_ms":1}]}),
    ];
    let report = eval_report::summarize(
        &rows,
        json!({}),
        json!({}),
        "No new regressions.",
        acquisition,
        20,
    );
    assert_eq!(report["arms"][0]["accepted"], 1);
    assert_eq!(report["arms"][1]["accepted"], 0);
    assert_eq!(report["arms"][1]["regression_failures"], 1);
    assert!(report["arms"][1]["model_cost"]["reported_usd"].is_null());
    assert!(report["arms"][1]["actor_elapsed_ms"].is_null());
    assert_eq!(report["arms"][0]["model_cost"]["complete"], true);
    assert!(report["total_cost_usd"].is_null());
    let mut equal = rows;
    equal[1] = equal[0].clone();
    equal[1]["arm"] = json!("learning");
    equal[1]["actor"]["usage"]["cost_is_partial"] = json!(true);
    let report = eval_report::summarize(
        &equal,
        json!({}),
        json!({}),
        "Equal quality within a stated tolerance.",
        json!({}),
        20,
    );
    assert_eq!(
        report["arms"][0]["accepted_rate"],
        report["arms"][1]["accepted_rate"]
    );
    assert_eq!(report["verdict"], "insufficient_evidence");
    assert_eq!(report["reviews_enabled"], false);
    assert_eq!(report["arms"][1]["model_cost"]["complete"], false);
    let unavailable = eval_report::summarize(
        &[json!({"arm":"learning","actor":{"completed":false},"acceptance":[],"regressions":[]})],
        json!({}),
        json!({}),
        "No new regressions.",
        json!({}),
        1,
    );
    assert_eq!(unavailable["arms"][1]["regression_failures"], 0);
    assert_eq!(unavailable["arms"][1]["regression_unchecked"], 1);
    assert!(unavailable["arms"][1]["tool_calls"].is_null());
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
