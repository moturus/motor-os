//! Directory-backed tool definitions; loading metadata never starts a tool.

use std::collections::{HashMap, HashSet};
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
    pub arguments: Arguments,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub stdin_arguments: bool,
    pub stdout_only: bool,
    pub normal_exit_statuses: Vec<i32>,
    pub allowed_flags: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Arguments {
    #[serde(default)]
    pub before_double_dash: Vec<String>,
    #[serde(default)]
    pub after_double_dash: Vec<String>,
    #[serde(flatten)]
    pub mappings: HashMap<String, ArgumentMapping>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ArgumentMapping {
    String,
    BooleanFlag { flag: String },
    IntegerOption { flag: String },
    Enum { values: HashMap<String, String> },
    StringList,
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
            .transpose()?;
        if prompt.as_ref().is_some_and(|text| text.trim().is_empty()) {
            return Err(format!("{}: tool prompt is empty", directory.display()));
        }
        let process = ProcessTool::parse(raw.process, directory, &parameters)?;
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
    allowed_flags: Option<Vec<String>>,
    #[serde(default)]
    arguments: Arguments,
    command: RawCommand,
}

#[derive(Deserialize)]
struct RawCommand {
    common: Option<Vec<String>>,
    linux: Option<Vec<String>>,
    motor: Option<Vec<String>>,
}

impl ProcessTool {
    fn parse(raw: RawProcess, directory: &Path, parameters: &Value) -> Result<Self, String> {
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
            validate_program(directory, &command[0])?;
            if command
                .iter()
                .any(|part| part.starts_with('{') && part.ends_with('}'))
            {
                return Err(format!(
                    "{}: command contains a placeholder",
                    directory.display()
                ));
            }
            if !raw.arguments.mappings.is_empty() && command.iter().any(|part| part == "--") {
                return Err(format!(
                    "{}: mapped command must leave -- to the argument table",
                    directory.display()
                ));
            }
        }
        let normal_exit_statuses = raw.normal_exit_statuses.unwrap_or_else(|| vec![0]);
        if normal_exit_statuses.is_empty()
            || normal_exit_statuses
                .iter()
                .any(|status| !(0..=255).contains(status))
        {
            return Err(format!(
                "{}: invalid normal exit statuses",
                directory.display()
            ));
        }
        let allowed_flags = raw.allowed_flags.unwrap_or_default();
        if allowed_flags.iter().any(|flag| {
            !flag.starts_with('-')
                || flag == "--"
                || flag
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        }) {
            return Err(format!("{}: invalid allowed flag", directory.display()));
        }
        raw.arguments
            .validate(directory, parameters, stdin_arguments)?;
        #[cfg(unix)]
        let command = raw.command.linux.or(raw.command.common);
        #[cfg(not(unix))]
        let command = raw.command.motor.or(raw.command.common);
        Ok(Self {
            command,
            arguments: raw.arguments,
            timeout: Duration::from_secs(timeout),
            max_output_bytes: max_output,
            stdin_arguments,
            stdout_only,
            normal_exit_statuses,
            allowed_flags,
        })
    }
}

impl Arguments {
    fn validate(
        &self,
        directory: &Path,
        schema: &Value,
        stdin_arguments: bool,
    ) -> Result<(), String> {
        let properties = schema.get("properties").and_then(Value::as_object);
        let mut names = HashSet::new();
        for (after_delimiter, name) in self
            .before_double_dash
            .iter()
            .map(|name| (false, name))
            .chain(self.after_double_dash.iter().map(|name| (true, name)))
        {
            if !names.insert(name) {
                return Err(format!(
                    "{}: duplicate argument mapping {name:?}",
                    directory.display()
                ));
            }
            let mapping = self.mappings.get(name).ok_or_else(|| {
                format!("{}: missing argument mapping {name:?}", directory.display())
            })?;
            let property = properties
                .and_then(|items| items.get(name))
                .ok_or_else(|| {
                    format!(
                        "{}: mapped argument {name:?} is absent from the schema",
                        directory.display()
                    )
                })?;
            let expected = match mapping {
                ArgumentMapping::String | ArgumentMapping::Enum { .. } => "string",
                ArgumentMapping::BooleanFlag { .. } => "boolean",
                ArgumentMapping::IntegerOption { .. } => "integer",
                ArgumentMapping::StringList => "array",
            };
            if property.get("type").and_then(Value::as_str) != Some(expected) {
                return Err(format!(
                    "{}: argument {name:?} must have schema type {expected}",
                    directory.display()
                ));
            }
            if matches!(mapping, ArgumentMapping::StringList)
                && (!after_delimiter
                    || property.pointer("/items/type").and_then(Value::as_str) != Some("string"))
            {
                return Err(format!(
                    "{}: string list {name:?} needs string items after --",
                    directory.display()
                ));
            }
            match mapping {
                ArgumentMapping::BooleanFlag { flag } | ArgumentMapping::IntegerOption { flag } => {
                    if !flag.starts_with('-')
                        || flag == "--"
                        || flag
                            .bytes()
                            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
                    {
                        return Err(format!(
                            "{}: invalid fixed flag for {name:?}",
                            directory.display()
                        ));
                    }
                }
                ArgumentMapping::Enum { values }
                    if values.is_empty()
                        || values.iter().any(|(key, value)| {
                            key.is_empty() || value.is_empty() || value == "--"
                        }) =>
                {
                    return Err(format!(
                        "{}: invalid enum values for {name:?}",
                        directory.display()
                    ));
                }
                _ => {}
            }
        }
        if self.mappings.len() != names.len() {
            return Err(format!(
                "{}: argument mapping is not in the order list",
                directory.display()
            ));
        }
        if !self.mappings.is_empty() && stdin_arguments {
            return Err(format!(
                "{}: mapped arguments cannot also use stdin arguments",
                directory.display()
            ));
        }
        if !stdin_arguments
            && let Some(properties) = properties
            && properties.keys().any(|name| !names.contains(name))
        {
            return Err(format!(
                "{}: schema has an unmapped command argument",
                directory.display()
            ));
        }
        Ok(())
    }
}

fn validate_program(directory: &Path, program: &str) -> Result<(), String> {
    if program == "gears-batteries" || Path::new(program).is_absolute() {
        return Ok(());
    }
    let Some(relative) = program.strip_prefix("./") else {
        return Err(format!(
            "{directory:?}: program {program:?} needs an absolute or ./ path"
        ));
    };
    let state = StateRoot::new(directory.to_path_buf())?;
    state
        .existing_file(Path::new(relative))?
        .ok_or_else(|| format!("{directory:?}: program {program:?} not found"))?;
    Ok(())
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
    fn typed_mapping_checks_schema_and_placement() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "ignore_case": {"type": "boolean"},
                "limit": {"type": "integer"},
                "mode": {"type": "string"},
                "paths": {"type": "array", "items": {"type": "string"}}
            }
        });
        let raw: RawProcess = toml::from_str(
            r#"
            [command]
            common = ["/bin/rg"]
            [arguments]
            before_double_dash = ["ignore_case", "limit", "mode"]
            after_double_dash = ["paths"]
            [arguments.ignore_case]
            type = "boolean_flag"
            flag = "-i"
            [arguments.limit]
            type = "integer_option"
            flag = "-m"
            [arguments.mode]
            type = "enum"
            values = { files = "-l", count = "-c" }
            [arguments.paths]
            type = "string_list"
        "#,
        )
        .unwrap();
        let directory = Path::new("/tmp/example-tool");
        assert!(ProcessTool::parse(raw, directory, &schema).is_ok());

        let invalid: RawProcess = toml::from_str(
            r#"
            [command]
            common = ["/bin/rg"]
            [arguments]
            before_double_dash = ["paths"]
            [arguments.paths]
            type = "string_list"
        "#,
        )
        .unwrap();
        assert!(
            ProcessTool::parse(invalid, directory, &schema)
                .unwrap_err()
                .contains("after --")
        );
    }

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
common = ['/no-such-program']
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
        let manifest = std::fs::read_to_string(directory.join("tool.toml")).unwrap();
        std::fs::write(
            directory.join("tool.toml"),
            manifest.replace("/no-such-program", "sh"),
        )
        .unwrap();
        assert!(
            Registry::load(&entries, &root)
                .unwrap_err()
                .contains("absolute or ./")
        );
        std::fs::write(
            directory.join("tool.toml"),
            manifest.replace("/no-such-program", "./../run"),
        )
        .unwrap();
        assert!(Registry::load(&entries, &root).is_err());
        std::fs::write(directory.join("run"), "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::write(
            directory.join("tool.toml"),
            manifest.replace("/no-such-program", "./run"),
        )
        .unwrap();
        assert!(Registry::load(&entries, &root).is_ok());
        std::fs::write(directory.join("prompt.md"), "\n").unwrap();
        assert!(
            Registry::load(&entries, &root)
                .unwrap_err()
                .contains("prompt is empty")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
