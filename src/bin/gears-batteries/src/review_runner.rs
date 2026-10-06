//! Reviews run under the parent's owned process tree and finish marks once.

use std::path::Path;

use gears::{
    config::Config,
    process::{self, Cancellation, Output},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    paths::ToolContext,
    review_marks::{self, Disposition},
};

#[derive(Deserialize)]
struct Final {
    #[serde(rename = "type")]
    kind: String,
    success: bool,
    error: Option<String>,
    answer: Option<String>,
    usage: Usage,
}

#[derive(Deserialize, Serialize)]
struct Usage {
    completions: u64,
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    cost_usd: Option<f64>,
    cost_is_partial: bool,
}

pub fn from_env() -> Result<usize, String> {
    if !gears::platform::install_interrupt_handler() {
        return Err("cannot install review interrupt handler".into());
    }
    let context = ToolContext::from_env()?;
    let parent = std::env::var_os("GEARS_SESSION_PATH").ok_or("review needs GEARS_SESSION_PATH")?;
    let path = std::env::var_os("GEARS_CONFIG_PATH").map(std::path::PathBuf::from);
    let config = Config::load_user(path.as_deref())?;
    let gears = std::env::current_exe()
        .map_err(|error| error.to_string())?
        .with_file_name("gears");
    run(
        &context,
        Path::new(&parent),
        &config,
        &gears,
        &Cancellation::new(),
    )
}

pub fn run(
    context: &ToolContext,
    parent: &Path,
    config: &Config,
    gears: &Path,
    cancellation: &Cancellation,
) -> Result<usize, String> {
    if !crate::review_config::load(&context.state)?.enabled {
        return Ok(0);
    }
    let mut completed = 0;
    for mark in review_marks::due(context)? {
        if cancellation.cancelled() {
            return Err("review interrupted; mark remains due".into());
        }
        let id = mark.id();
        let Some(mut launch) = crate::review_launch::prepare(context, parent, config, &id, "")?
        else {
            continue;
        };
        let instructions = crate::review_instructions::build(context, parent, &mark, &launch.hook)?;
        let prompt = launch
            .request
            .args
            .iter()
            .position(|arg| arg == "-p")
            .ok_or("review launch has no prompt")?;
        launch.request.args[prompt + 1] = instructions;
        launch.request.program = gears
            .to_str()
            .ok_or("review executable path must be UTF-8")?
            .into();
        let output = process::run(&launch.request, cancellation, &mut |_, _| {})
            .map_err(|error| format!("review {id} failed; mark remains due: {error}"))?;
        if cancellation.cancelled() {
            return Err("review interrupted; mark remains due".into());
        }
        complete(context, &id, &output)?;
        completed += 1;
    }
    Ok(completed)
}

pub fn complete(context: &ToolContext, id: &str, output: &Output) -> Result<(), String> {
    if !output.success() {
        return Err(format!(
            "review {id} failed; mark remains due:\n{}",
            output.model_text(4096)
        ));
    }
    if !output.stdout.ends_with('\n') {
        return Err("review final record is incomplete; mark remains due".into());
    }
    let final_record: Final = serde_json::from_str(output.stdout.lines().last().unwrap_or(""))
        .map_err(|error| format!("invalid review final record; mark remains due: {error}"))?;
    if final_record.kind != "final" || !final_record.success || final_record.error.is_some() {
        return Err("review did not finish successfully; mark remains due".into());
    }
    let mark = review_marks::load(context, id)?.ok_or("review mark is missing")?;
    if mark.disposition != Disposition::Due {
        return Err("review mark is already handled".into());
    }
    let answer: String = final_record
        .answer
        .unwrap_or_default()
        .chars()
        .take(1024)
        .collect();
    let record = json!({"version": 1, "session": context.session, "workspace": context.workspace,
        "mark": id, "executor": mark.executor, "reviewer": crate::review_config::load(&context.state)?.reviewer, "date_ms": crate::pending::now_ms()?, "answer": answer, "usage": final_record.usage});
    let bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    // Completion is durable first; failure to update status must not rerun the mark.
    review_marks::finish(context, id, Disposition::Completed)?;
    context
        .state
        .replace_file(Path::new("batteries/last-review.json"), &bytes)
}
