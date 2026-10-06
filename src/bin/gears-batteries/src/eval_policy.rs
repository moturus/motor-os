//! Unattended evaluation authority is limited to one copied workspace and check.

use crate::{Event, paths::ToolContext};
use gears::provider::ToolCall;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

const FILE: &str = "batteries/eval-policy.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    workspace: PathBuf,
    check: Vec<String>,
}

pub fn install(context: &ToolContext, check: &[String]) -> Result<(), String> {
    crate::check_config::validate(check)?;
    if context.state.existing_file(Path::new(FILE))?.is_some() {
        return Err("evaluation authority is already installed".into());
    }
    let value = json!({"check":check});
    let text = toml::to_string(&value).map_err(|e| e.to_string())?;
    gears::state::StateRoot::new(context.workspace.clone())?
        .replace_file(Path::new(".gears/batteries.toml"), text.as_bytes())?;
    let policy = Policy {
        version: 1,
        workspace: context.workspace.clone(),
        check: check.to_vec(),
    };
    context.state.replace_file(
        Path::new(FILE),
        &serde_json::to_vec(&policy).map_err(|e| e.to_string())?,
    )
}

pub fn permission(event: &Event, context: &ToolContext) -> Result<Option<Value>, String> {
    let Some(path) = context.state.existing_file(Path::new(FILE))? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16384 {
        return Err("evaluation authority exceeds 16 KiB".into());
    }
    let policy: Policy = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if policy.version != 1 || policy.workspace != context.workspace || event.session.path.is_some()
    {
        return Err(
            "evaluation authority requires its exact workspace and an ephemeral session".into(),
        );
    }
    crate::check_config::validate(&policy.check)?;
    let call: ToolCall =
        serde_json::from_value(event.payload["tool_call"].clone()).map_err(|e| e.to_string())?;
    let args: Value = serde_json::from_str(&call.arguments).map_err(|e| e.to_string())?;
    if !args.is_object() {
        return Err("tool arguments must be an object".into());
    }
    let allow = match call.name.as_str() {
        "todo" | "skill_view" => true,
        "check" => {
            if args != json!({})
                || crate::check_config::load(context, crate::check_config::system())?.as_ref()
                    != Some(&policy.check)
            {
                return Err("evaluation check must match its frozen declaration".into());
            }
            let mut response = crate::check_approval::prepare(event, context)?;
            response["decision"] = json!("allow");
            return Ok(Some(response));
        }
        "read_file" | "search_files" | "write_file" | "patch" => {
            let writing = matches!(call.name.as_str(), "write_file" | "patch");
            let input = args["path"]
                .as_str()
                .or_else(|| (call.name == "search_files").then_some("."))
                .ok_or("evaluation file tool needs a path")?;
            let path = context.resolve(input, writing)?;
            let relative = path.strip_prefix(&context.workspace).ok();
            relative.is_some_and(|relative| {
                !writing
                    || !(relative.starts_with(".gears")
                        || relative == Path::new("AGENTS.md")
                        || relative == Path::new(".gears.md"))
            }) && !(call.name == "search_files" && context.state.path().starts_with(&path))
        }
        _ => false,
    };
    Ok(Some(json!({"decision":if allow {"allow"} else {"deny"}})))
}
