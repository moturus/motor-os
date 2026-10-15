//! Pin tool definitions and resolve configuration resources before paired trials.

use crate::batteries::{eval_task::Task, paths::ToolContext};
use crate::{config::Config, tools::Registry};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub struct Pinned {
    pub path: PathBuf,
    pub identity: Value,
}

pub fn prepare(
    context: &ToolContext,
    task: &Task,
    path: &Path,
    destination: &Path,
    batteries: &Path,
) -> Result<Pinned, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let mut checked = PathBuf::new();
    for component in path.components() {
        checked.push(component);
        if std::fs::symlink_metadata(&checked)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("symbolic evaluation configuration path refused".into());
        }
    }
    let parent = path
        .parent()
        .ok_or("evaluation configuration has no parent")?;
    ToolContext::new(
        parent.into(),
        context.state.path().into(),
        "eval-config".into(),
        None,
    )?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("evaluation configuration must be a regular file".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|e| e.to_string())?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("evaluation configuration exceeds 64 KiB".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
    let mut value: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let table = value
        .as_table_mut()
        .ok_or("evaluation configuration must be a table")?;
    if let Some(provider) = table.get_mut("provider") {
        provider_paths(provider, parent)?;
    }
    if let Some(providers) = table
        .get_mut("providers")
        .and_then(toml::Value::as_table_mut)
    {
        for (_, provider) in providers.iter_mut() {
            provider_paths(provider, parent)?;
        }
    }
    table.remove("after_turn");
    table.remove("trace");
    let resolved = toml::to_string(&value).map_err(|e| e.to_string())?;
    let config = Config::parse(&resolved)?;
    if config.hooks.len() != 1
        || config.hooks[0].command.len() != 2
        || Path::new(&config.hooks[0].command[0])
            .file_name()
            .is_none_or(|name| name != "gears-batteries")
        || config.hooks[0].command[1] != "hook"
    {
        return Err("evaluation needs exactly one direct gears-batteries hook".into());
    }
    for event in [
        "initialize",
        "permission",
        "tool_execute",
        "tool_result",
        "turn_start",
        "entry",
        "before_stop",
        "turn_end",
        "context",
    ] {
        if config.hooks[0]
            .events
            .as_ref()
            .is_some_and(|events| !events.iter().any(|name| name == event))
        {
            return Err(format!("evaluation hook must subscribe to {event}"));
        }
    }
    let registry = Registry::load(&config.tools, context.state.path())?;
    let selected = ToolContext::new(
        context.workspace.clone(),
        destination.into(),
        "eval-config".into(),
        None,
    )?;
    let root = &selected.state;
    if std::fs::symlink_metadata(root.path()).is_ok() {
        return Err("pinned configuration destination must not exist".into());
    }
    root.directory(Path::new(""))?;
    let mut tools = Vec::new();
    let mut identities = Vec::new();
    for (index, tool) in registry.tools().iter().enumerate() {
        if !matches!(
            tool.name.as_str(),
            "read_file" | "search_files" | "write_file" | "patch" | "check"
        ) {
            continue;
        }
        let directory = root.path().join(format!("tools/{index}"));
        let mut source = task.clone();
        source.workspace = tool.directory.clone();
        source.exclude.clear();
        let identity = crate::batteries::eval_copy::workspace(&source, &directory)?;
        tools.push(
            toml::Value::try_from(json!({"directory":directory,"enabled":tool.enabled}))
                .map_err(|e| e.to_string())?,
        );
        identities.push(json!({"name":tool.name,"enabled":tool.enabled,"copy":identity}));
    }
    let table = value.as_table_mut().unwrap();
    table.insert("tools".into(), toml::Value::Array(tools));
    table.get_mut("hooks").unwrap().as_array_mut().unwrap()[0]
        .as_table_mut()
        .unwrap()
        .insert(
            "command".into(),
            toml::Value::Array(vec![
                toml::Value::String(
                    batteries
                        .to_str()
                        .ok_or("batteries path must be UTF-8")?
                        .into(),
                ),
                toml::Value::String("hook".into()),
            ]),
        );
    let text = toml::to_string(&value).map_err(|e| e.to_string())?;
    let verified = Config::parse(&text)?;
    root.replace_file(Path::new("gears.toml"), text.as_bytes())?;
    let path = root.path().join("gears.toml");
    Ok(Pinned {
        path,
        identity: json!({"version":1,"source_hash":crate::batteries::snapshot::digest(&bytes),
        "config_hash":crate::batteries::snapshot::digest(text.as_bytes()),"tools":identities,
        "max_tool_rounds":verified.max_tool_rounds,"after_turn":false}),
    })
}

fn provider_paths(provider: &mut toml::Value, parent: &Path) -> Result<(), String> {
    let table = provider.as_table_mut().ok_or("provider must be a table")?;
    for name in ["key_file", "api_key_file", "ca_cert"] {
        if let Some(value) = table.get_mut(name) {
            let path = Path::new(
                value
                    .as_str()
                    .ok_or("provider resource path must be a string")?,
            );
            if !path.is_absolute() {
                *value = toml::Value::String(
                    parent
                        .join(path)
                        .to_str()
                        .ok_or("provider path must be UTF-8")?
                        .into(),
                );
            }
        }
    }
    Ok(())
}
