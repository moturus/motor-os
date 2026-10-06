//! Alternating paired trials use fresh copies and preserve failed outcomes.

use crate::{
    eval_actor::{self, Selection},
    eval_command,
    eval_prepare::Prepared,
    eval_report,
};
use gears::process::{self, Cancellation};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};

pub struct Settings {
    pub repetitions: usize,
    pub command_timeout: Duration,
    pub criterion: String,
}

pub fn run(
    prepared: &Prepared,
    actor: &Selection<'_>,
    settings: &Settings,
    acquisition: Value,
    cancel: &Cancellation,
) -> Result<Value, String> {
    if !(2..=16).contains(&settings.repetitions)
        || !(Duration::from_secs(1)..=Duration::from_secs(3600)).contains(&settings.command_timeout)
        || settings.criterion.trim().is_empty()
        || settings.criterion.len() > 8192
        || settings
            .criterion
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err("evaluation needs 2–16 repetitions, a 1–3600 second command deadline and an explicit criterion (at most 8 KiB)".into());
    }
    let start = Instant::now();
    let configuration = json!({"provider":actor.provider,"model":actor.model,
        "actor_seconds":actor.timeout.as_secs(),"command_seconds":settings.command_timeout.as_secs(),
        "repetitions":settings.repetitions,"order":"alternating baseline/learning, then learning/baseline"});
    let mut rows = Vec::new();
    let mut preflight = json!(null);
    let save = |rows: &[Value],
                preflight: &Value,
                status: &str,
                error: Option<&str>|
     -> Result<Value, String> {
        let mut report = eval_report::summarize(
            rows,
            prepared.identity.clone(),
            configuration.clone(),
            &settings.criterion,
            acquisition.clone(),
            start.elapsed().as_millis().min(u64::MAX as u128) as u64,
        );
        report["status"] = json!(status);
        report["error"] = json!(error);
        report["preflight"] = preflight.clone();
        prepared.root.replace_file(
            Path::new("report.json"),
            &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
        )?;
        Ok(report)
    };
    save(&rows, &preflight, "running", None)?;
    let result = (|| -> Result<(), String> {
        if cancel.cancelled() {
            return Err("evaluation cancelled".into());
        }
        let initial = prepared.trial(0, false)?;
        preflight = json!({"regressions":commands(&prepared.task.task.regressions,prepared,&initial.workspace,settings.command_timeout,"preflight",cancel)?});
        save(&rows, &preflight, "running", None)?;
        if !passed(&preflight["regressions"]) {
            return Err(
                "original workspace regression preflight failed; no model trial started".into(),
            );
        }
        for pair in 0..settings.repetitions {
            let order = if pair % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            };
            for learning in order {
                if cancel.cancelled() {
                    return Err("evaluation cancelled".into());
                }
                let ordinal = rows.len() + 1;
                let trial = prepared.trial(ordinal, learning)?;
                let result = eval_actor::run(prepared, &trial, actor, cancel);
                let (actor, failed) = match result {
                    Ok(value) => (value, None),
                    Err(error) => (json!({"completed":false,"error":error}), Some(error)),
                };
                let row = json!({"pair":pair,"arm":if learning{"learning"}else{"baseline"},"ordinal":ordinal,"versions":trial.versions,"actor":actor,"acceptance":[],"regressions":[]});
                // Save actor failures before propagating uncertain process or storage state.
                if let Some(error) = failed {
                    rows.push(row);
                    save(&rows, &preflight, "failed", Some(&error))?;
                    return Err(error);
                }
                process::ensure_cleanup()?;
                rows.push(row);
                save(&rows, &preflight, "running", None)?;
                rows.last_mut().unwrap()["acceptance"] = commands(
                    &prepared.task.task.acceptance,
                    prepared,
                    &trial.workspace,
                    settings.command_timeout,
                    "acceptance",
                    cancel,
                )?;
                rows.last_mut().unwrap()["regressions"] = commands(
                    &prepared.task.task.regressions,
                    prepared,
                    &trial.workspace,
                    settings.command_timeout,
                    "regressions",
                    cancel,
                )?;
                save(&rows, &preflight, "running", None)?;
                if cancel.cancelled() {
                    return Err("evaluation cancelled".into());
                }
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => save(&rows, &preflight, "complete", None),
        Err(error) => save(
            &rows,
            &preflight,
            if cancel.cancelled() {
                "cancelled"
            } else {
                "failed"
            },
            Some(&error),
        ),
    }
}

fn commands(
    vectors: &[Vec<String>],
    prepared: &Prepared,
    workspace: &Path,
    timeout: Duration,
    kind: &str,
    cancel: &Cancellation,
) -> Result<Value, String> {
    let mut outcomes = Vec::new();
    for (index, argv) in vectors.iter().enumerate() {
        if cancel.cancelled() {
            break;
        }
        let mut outcome = eval_command::run(
            argv,
            &prepared.task.task.workspace,
            workspace,
            timeout,
            cancel,
        )?;
        let directory = workspace
            .parent()
            .unwrap()
            .strip_prefix(prepared.root.path())
            .map_err(|e| e.to_string())?;
        for stream in ["stdout", "stderr"] {
            if let Some(text) = outcome[stream].as_str() {
                let path = directory.join(format!("{kind}-{index:02}.{stream}"));
                prepared.root.replace_file(&path, text.as_bytes())?;
                let bytes = text.len();
                let preview: String = text.chars().take(1024).collect();
                outcome[format!("{stream}_artifact")] = json!(path);
                outcome[format!("{stream}_saved_bytes")] = json!(bytes);
                outcome[stream] = json!(preview);
            }
        }
        outcomes.push(outcome);
    }
    Ok(json!(outcomes))
}
fn passed(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|rows| !rows.is_empty() && rows.iter().all(|r| r["passed"] == true))
}
