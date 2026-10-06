//! Prepare an isolated review only after checking its saved source and policy.

use std::path::Path;

use gears::{config::Config, process::Request};
use serde_json::json;

use crate::{paths::ToolContext, review_config, review_marks};

pub struct Launch {
    pub request: Request,
    pub hook: String,
    pub reviewer: review_config::Model,
}

pub fn prepare(
    context: &ToolContext,
    parent_path: &Path,
    config: &Config,
    mark_id: &str,
    instructions: &str,
) -> Result<Option<Launch>, String> {
    let settings = review_config::load(&context.state)?;
    if !settings.enabled {
        return Ok(None);
    }
    let mark = review_marks::load(context, mark_id)?.ok_or("review mark is missing")?;
    if mark.disposition != review_marks::Disposition::Due
        || !settings.enabled_for(&mark.executor.provider, &mark.executor.model)
    {
        return Ok(None);
    }
    let snapshot = gears::session::read_snapshot(parent_path)?;
    if snapshot.id() != context.session || snapshot.workspace() != context.workspace {
        return Err("review source belongs to another session or workspace".into());
    }
    let mut hooks = config.hooks.iter().filter(|hook| {
        hook.command.len() == 2
            && Path::new(&hook.command[0])
                .file_name()
                .is_some_and(|name| name == "gears-batteries")
            && hook.command[1] == "hook"
    });
    let hook = hooks
        .next()
        .ok_or("review needs a configured batteries hook")?;
    if hooks.next().is_some() {
        return Err("review needs exactly one batteries hook".into());
    }
    let state = snapshot.hook_state(&hook.name).unwrap_or_else(|| json!({}));
    if state["run_kind"] == "review" || state["reviews_paused"] == true {
        return Ok(None);
    }
    for event in [
        "initialize",
        "permission",
        "tool_execute",
        "turn_start",
        "entry",
        "context",
    ] {
        if hook
            .events
            .as_ref()
            .is_some_and(|events| !events.iter().any(|name| name == event))
        {
            return Err(format!("review batteries hook must subscribe to {event}"));
        }
    }
    let selected = snapshot.at(&mark.entry)?;
    if selected.provider().unwrap_or_else(|| "default".into()) != mark.executor.provider
        || selected.model().as_deref() != Some(mark.executor.model.as_str())
    {
        return Err("review mark executor differs from its saved entry".into());
    }
    let reviewer = settings.reviewer.ok_or("reviewer is not configured")?;
    config
        .provider(&reviewer.provider)
        .ok_or("reviewer provider is not configured in Gears")?;
    let selected_reviewer = reviewer.clone();
    let limits = config
        .after_turn
        .as_ref()
        .ok_or("review needs after_turn limits")?;
    let overlay = json!({"run_kind": "review", "review_run": {
        "session": context.session, "path": parent_path, "mark": mark_id
    }});
    let mut args = vec![
        "--workspace".into(),
        path_arg(&context.workspace)?,
        "--fork".into(),
        path_arg(parent_path)?,
        "--fork-entry".into(),
        mark.entry,
        "--ephemeral".into(),
        "--preserve-prefix".into(),
        "--provider".into(),
        reviewer.provider,
        "--model".into(),
        reviewer.model,
        "--hook-state".into(),
        format!("{}={overlay}", hook.name),
        "--output".into(),
        "jsonl".into(),
        "-p".into(),
        instructions.into(),
    ];
    if let Some(path) = &config.config_path {
        args.extend(["--config".into(), path_arg(path)?]);
    }
    Ok(Some(Launch {
        hook: hook.name.clone(),
        reviewer: selected_reviewer,
        request: Request {
            program: path_arg(
                &std::env::current_exe()
                    .map_err(|error| error.to_string())?
                    .with_file_name("gears"),
            )?,
            args,
            cwd: context.workspace.clone(),
            stdin: None,
            timeout: limits.timeout,
            max_output_bytes: limits.max_output_bytes,
            env: Vec::new(),
            remove_env: vec![gears::provider::KEY_ENV.into()],
        },
    }))
}

fn path_arg(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or("review paths must be UTF-8".into())
}
