//! Directory-backed tool definitions; loading metadata never starts a tool.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::config::ToolDirectory;
use crate::state::StateRoot;

#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub parameters: Value,
    pub prompt: Option<String>,
    pub display: Option<String>,
    pub read_only: bool,
    pub directory: PathBuf,
    pub enabled_by_default: bool,
    pub process: ProcessTool,
}

#[derive(Debug, Clone)]
pub struct ProcessTool {
    pub command: Option<Vec<String>>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub stdin_arguments: bool,
    pub stdout_only: bool,
    pub normal_exit_statuses: Vec<i32>,
}

#[derive(Debug, Default)]
pub struct Registry {
    tools: Vec<Tool>,
}

impl Registry {
    pub fn load(entries: &[ToolDirectory], base: &Path) -> Result<Self, String> {
        let mut tools = Vec::with_capacity(entries.len());
        let mut names = HashSet::new();
        for entry in entries {
            let directory = if entry.directory.is_absolute() {
                checked_directory(&entry.directory)?
            } else {
                StateRoot::new(base.to_path_buf())?
                    .existing_directory(&entry.directory)?
                    .ok_or_else(|| {
                        format!("{}: tool directory not found", entry.directory.display())
                    })?
            };
            let tool = Tool::load(&directory, entry.enabled)?;
            if !names.insert(tool.name.clone()) {
                return Err(format!("duplicate tool name {:?}", tool.name));
            }
            tools.push(tool);
        }
        Ok(Self { tools })
    }

    pub fn tools(&self) -> &[Tool] {
        &self.tools
    }
}

impl Tool {
    fn load(directory: &Path, enabled_by_default: bool) -> Result<Self, String> {
        let raw: RawManifest = toml::from_str(&read_file(directory, "tool.toml")?)
            .map_err(|error| format!("{}/tool.toml: {error}", directory.display()))?;
        if raw.version != 1 || raw.kind != "process" {
            return Err(format!(
                "{}: unsupported tool version or kind",
                directory.display()
            ));
        }
        if raw.name.is_empty()
            || !raw
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(format!(
                "{}: invalid tool name {:?}",
                directory.display(),
                raw.name
            ));
        }
        // Check resources on both systems so a dormant override cannot hide
        // a missing file until this directory is copied to another machine.
        for platform in [&raw.linux, &raw.motor] {
            if let Some(file) = &platform.parameters {
                let schema: Value = serde_json::from_str(&read_file(directory, file)?)
                    .map_err(|error| format!("{}/{}: {error}", directory.display(), file))?;
                if schema.get("type").and_then(Value::as_str) != Some("object") {
                    return Err(format!(
                        "{}/{}: parameters must be an object schema",
                        directory.display(),
                        file
                    ));
                }
            }
            if let Some(file) = &platform.prompt {
                read_file(directory, file)?;
            }
        }
        #[cfg(unix)]
        let platform = raw.linux;
        #[cfg(not(unix))]
        let platform = raw.motor;
        let description = platform.description.or(raw.description).unwrap_or_default();
        if description.trim().is_empty() {
            return Err(format!(
                "{}: tool description is empty",
                directory.display()
            ));
        }
        let parameters_file = platform
            .parameters
            .or(raw.parameters)
            .ok_or_else(|| format!("{}: tool needs parameters", directory.display()))?;
        let parameters: Value = serde_json::from_str(&read_file(directory, &parameters_file)?)
            .map_err(|error| format!("{}/{}: {error}", directory.display(), parameters_file))?;
        if parameters.get("type").and_then(Value::as_str) != Some("object") {
            return Err(format!(
                "{}/{}: parameters must be an object schema",
                directory.display(),
                parameters_file
            ));
        }
        let prompt = platform
            .prompt
            .or(raw.prompt)
            .map(|file| read_file(directory, &file))
            .transpose()?
            .filter(|text| !text.trim().is_empty());
        let process = ProcessTool::parse(raw.process, directory)?;
        Ok(Self {
            name: raw.name,
            description,
            parameters,
            prompt,
            display: platform.display.or(raw.display),
            read_only: raw.read_only,
            directory: directory.to_path_buf(),
            enabled_by_default,
            process,
        })
    }
}

#[derive(Deserialize)]
struct RawManifest {
    version: u32,
    kind: String,
    name: String,
    description: Option<String>,
    parameters: Option<String>,
    prompt: Option<String>,
    display: Option<String>,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    linux: RawPlatform,
    #[serde(default)]
    motor: RawPlatform,
    process: RawProcess,
}

#[derive(Default, Deserialize)]
struct RawPlatform {
    description: Option<String>,
    parameters: Option<String>,
    prompt: Option<String>,
    display: Option<String>,
}

#[derive(Deserialize)]
struct RawProcess {
    timeout_seconds: Option<u64>,
    max_output_bytes: Option<usize>,
    stdin: Option<String>,
    output: Option<String>,
    normal_exit_statuses: Option<Vec<i32>>,
    command: RawCommand,
}

#[derive(Deserialize)]
struct RawCommand {
    common: Option<Vec<String>>,
    linux: Option<Vec<String>>,
    motor: Option<Vec<String>>,
}

impl ProcessTool {
    fn parse(raw: RawProcess, directory: &Path) -> Result<Self, String> {
        let timeout = raw.timeout_seconds.unwrap_or(30);
        let max_output = raw.max_output_bytes.unwrap_or(1024 * 1024);
        if !(1..=3600).contains(&timeout) || !(1024..=16 * 1024 * 1024).contains(&max_output) {
            return Err(format!(
                "{}: invalid process timeout or output limit",
                directory.display()
            ));
        }
        let stdin_arguments = match raw.stdin.as_deref().unwrap_or("null") {
            "arguments" => true,
            "null" => false,
            other => {
                return Err(format!(
                    "{}: invalid process stdin {other:?}",
                    directory.display()
                ));
            }
        };
        let stdout_only = match raw.output.as_deref().unwrap_or("shell") {
            "stdout" => true,
            "shell" => false,
            other => {
                return Err(format!(
                    "{}: invalid process output {other:?}",
                    directory.display()
                ));
            }
        };
        for command in [&raw.command.common, &raw.command.linux, &raw.command.motor]
            .into_iter()
            .flatten()
        {
            if command.is_empty() || command[0].is_empty() {
                return Err(format!("{}: empty process command", directory.display()));
            }
        }
        #[cfg(unix)]
        let command = raw.command.linux.or(raw.command.common);
        #[cfg(not(unix))]
        let command = raw.command.motor.or(raw.command.common);
        Ok(Self {
            command,
            timeout: Duration::from_secs(timeout),
            max_output_bytes: max_output,
            stdin_arguments,
            stdout_only,
            normal_exit_statuses: raw.normal_exit_statuses.unwrap_or_else(|| vec![0]),
        })
    }
}

fn checked_directory(path: &Path) -> Result<PathBuf, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "{}: tool directory is not a regular directory",
            path.display()
        ));
    }
    Ok(path.to_path_buf())
}

fn read_file(directory: &Path, name: &str) -> Result<String, String> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(format!(
            "{name:?}: tool resource must be one file in its directory"
        ));
    }
    let path = directory.join(name);
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{}: tool resource is not a regular file",
            path.display()
        ));
    }
    std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_directory_loads_without_running_its_command() {
        let root = std::env::temp_dir().join(format!("gears-tools-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let directory = root.join("tools/example");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("parameters.json"), r#"{"type":"object"}"#).unwrap();
        std::fs::write(directory.join("prompt.md"), "Use this tool when needed.").unwrap();
        std::fs::write(
            directory.join("tool.toml"),
            r#"version = 1
kind = 'process'
name = 'example'
description = 'An example.'
parameters = 'parameters.json'
prompt = 'prompt.md'
read_only = true
[process]
stdin = 'arguments'
output = 'stdout'
normal_exit_statuses = [0, 1]
[process.command]
common = ['/no-such-program', '{path}']
"#,
        )
        .unwrap();
        let entries = vec![ToolDirectory {
            directory: PathBuf::from("tools/example"),
            enabled: true,
        }];
        let registry = Registry::load(&entries, &root).unwrap();
        let tool = &registry.tools()[0];
        assert_eq!(tool.name, "example");
        assert!(tool.enabled_by_default && tool.read_only);
        assert!(tool.process.stdin_arguments && tool.process.stdout_only);
        assert_eq!(tool.process.normal_exit_statuses, [0, 1]);
        assert_eq!(tool.prompt.as_deref(), Some("Use this tool when needed."));
        assert!(Registry::load(&[entries[0].clone(), entries[0].clone()], &root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
