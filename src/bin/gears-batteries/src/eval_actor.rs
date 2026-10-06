//! Owned ephemeral trials retain structured events and uncertain costs explicitly.

use crate::eval_prepare::{Prepared, Trial};
use gears::process::{self, Cancellation, Request};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub struct Selection<'a> {
    pub gears: &'a Path,
    pub provider: &'a str,
    pub model: &'a str,
    pub timeout: Duration,
}

pub fn run(
    prepared: &Prepared,
    trial: &Trial,
    selection: &Selection<'_>,
    cancel: &Cancellation,
) -> Result<Value, String> {
    if selection.timeout < Duration::from_secs(1)
        || selection.timeout > Duration::from_secs(3600)
        || [selection.provider, selection.model]
            .iter()
            .any(|name| name.trim().is_empty() || name.chars().any(char::is_control))
    {
        return Err("evaluation needs explicit provider/model and a 1–3600 second deadline".into());
    }
    let args = vec![
        "--config".into(),
        prepared.config.path.display().to_string(),
        "--gears-dir".into(),
        trial.state.display().to_string(),
        "--ephemeral".into(),
        "--output".into(),
        "jsonl".into(),
        "--provider".into(),
        selection.provider.into(),
        "--model".into(),
        selection.model.into(),
        "-p".into(),
        prepared.task.task.prompt.clone(),
    ];
    let start = Instant::now();
    let output = process::run(
        &Request {
            program: selection
                .gears
                .to_str()
                .ok_or("Gears program path must be UTF-8")?
                .into(),
            args,
            cwd: trial.workspace.clone(),
            stdin: None,
            timeout: selection.timeout,
            max_output_bytes: 8 * 1024 * 1024,
            env: vec![],
            remove_env: vec![gears::provider::KEY_ENV.into()],
        },
        cancel,
        &mut |_, _| {},
    )
    .map_err(|e| e.to_string())?;
    let directory = trial
        .workspace
        .parent()
        .unwrap()
        .strip_prefix(prepared.root.path())
        .map_err(|e| e.to_string())?;
    prepared
        .root
        .replace_file(&directory.join("actor.jsonl"), output.stdout.as_bytes())?;
    prepared
        .root
        .replace_file(&directory.join("actor.stderr"), output.stderr.as_bytes())?;
    process::ensure_cleanup()?;
    let records = output
        .stdout
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>();
    let (records, parse_error) = match records {
        Ok(records) => (records, None),
        Err(e) => (vec![], Some(e.to_string())),
    };
    let final_record = records
        .iter()
        .rev()
        .find(|record| record["type"] == "final");
    let usage = final_record.and_then(|r| r.get("usage")).or_else(|| {
        records
            .iter()
            .rev()
            .find(|r| r["type"] == "usage")
            .and_then(|r| r.get("total"))
    });
    let events_complete = output.stdout_dropped == 0 && parse_error.is_none();
    let complete = output.success()
        && output.stdout_dropped == 0
        && parse_error.is_none()
        && final_record.is_some_and(|r| r["success"] == true);
    let tools: Vec<_> = records
        .iter()
        .filter(|r| r["type"] == "tool_result")
        .collect();
    Ok(
        json!({"version":1,"completed":complete,"exit_status":output.code,
        "events_artifact":directory.join("actor.jsonl"),"stderr_artifact":directory.join("actor.stderr"),
        "duration_ms":start.elapsed().as_millis().min(u64::MAX as u128) as u64,
        "timed_out":output.timed_out,"cancelled":output.cancelled,
        "stdout_dropped":output.stdout_dropped,"stderr_dropped":output.stderr_dropped,
        "events_complete":events_complete,"parse_error":parse_error,"error":final_record.and_then(|r|r["error"].as_str()).map(|s|s.chars().take(1024).collect::<String>()),"usage":usage,
        "tool_calls":events_complete.then(||records.iter().filter(|r|r["type"]=="tool_start").count()),"tool_failures":events_complete.then(||tools.iter().filter(|r|r["is_error"]==true).count()),
        "declared_checks":tools.iter().filter(|r|r["name"]=="check").map(|r|json!({"outcome":r["outcome"],"is_error":r["is_error"],"content_hash":crate::snapshot::digest(r["content"].to_string().as_bytes())})).collect::<Vec<_>>() }),
    )
}
