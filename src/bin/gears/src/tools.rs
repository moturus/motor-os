//! Directory-backed tool definitions; loading metadata never starts a tool.

use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{Config, ToolDirectory};
use crate::process::{self, Cancellation, Stream};
use crate::provider::KEY_ENV;
use crate::provider::ToolSpec;
use crate::shell_state;
use crate::state::StateRoot;

#[derive(Debug, Clone, Serialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub parameters: Value,
    pub display: Option<String>,
    pub read_only: bool,
    pub directory: PathBuf,
    pub enabled_by_default: bool,
    #[serde(skip)]
    pub enabled: bool,
    pub process: ProcessTool,
}

pub struct ExecutionContext<'a> {
    pub workspace: &'a Path,
    pub session_id: &'a str,
    pub session_path: Option<&'a Path>,
    pub shell_state: Option<&'a Path>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessTool {
    pub command: Option<Vec<String>>,
    pub arguments: Arguments,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub stdin_arguments: bool,
    pub stdout_only: bool,
    pub normal_exit_statuses: Vec<i32>,
    pub shell_state: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Arguments {
    #[serde(default)]
    pub before_double_dash: Vec<String>,
    #[serde(default)]
    pub after_double_dash: Vec<String>,
    #[serde(flatten)]
    pub mappings: BTreeMap<String, ArgumentMapping>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ArgumentMapping {
    String,
    StringOption {
        flag: String,
    },
    BooleanFlag {
        flag: String,
    },
    IntegerOption {
        flag: String,
    },
    Enum {
        values: BTreeMap<String, String>,
    },
    EnumOption {
        flag: String,
        values: BTreeMap<String, String>,
    },
    StringList,
    TimeoutSeconds,
}

#[derive(Debug, Default, Clone)]
pub struct Registry {
    tools: Vec<Tool>,
}

impl Registry {
    pub fn load_config(config: &Config) -> Result<Self, String> {
        if config.tools.is_empty() {
            return Ok(Self::default());
        }
        match &config.tool_base {
            Some(base) => Self::load(&config.tools, base),
            None => Self::load(&config.tools, &crate::directory::default_root()?),
        }
    }

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

    pub fn enabled(&self, name: &str) -> Option<&Tool> {
        self.tools
            .iter()
            .find(|tool| tool.name == name && tool.enabled && tool.process.command.is_some())
    }

    pub fn enabled_tools(&self) -> impl Iterator<Item = &Tool> {
        self.tools
            .iter()
            .filter(|tool| tool.enabled && tool.process.command.is_some())
    }

    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<(), String> {
        let tool = self
            .tools
            .iter_mut()
            .find(|tool| tool.name == name)
            .ok_or_else(|| format!("unknown directory tool {name:?}"))?;
        tool.enabled = enabled;
        Ok(())
    }
}

impl Tool {
    /// Stable approval key for this directory tool and its executable.
    pub fn approval_identity(&self) -> Result<String, String> {
        let executable_hash = match self.process.command.as_ref().and_then(|argv| argv.first()) {
            Some(program) if program.starts_with("./") => {
                let relative = Path::new(program.trim_start_matches("./"));
                let path = StateRoot::new(self.directory.clone())?
                    .existing_file(relative)?
                    .ok_or_else(|| {
                        format!("{}: executable disappeared", self.directory.display())
                    })?;
                Some(hash_bytes(
                    &std::fs::read(&path)
                        .map_err(|error| format!("{}: {error}", path.display()))?,
                ))
            }
            Some(program) if program == "gears-batteries" => {
                let path = process::program_path(program)?;
                Some(hash_bytes(
                    &std::fs::read(&path)
                        .map_err(|error| format!("{}: {error}", path.display()))?,
                ))
            }
            _ => None,
        };
        let mut process = serde_json::to_value(&self.process)
            .map_err(|error| format!("cannot serialize approval identity: {error}"))?;
        process["allowed_flags"] = serde_json::json!([]);
        let identity = serde_json::json!({
            "name": self.name,
            "kind": "process",
            "owner": self.directory,
            "description": self.description,
            "parameters": self.parameters,
            // Removed manifest fields keep their empty values, so saved approvals stay valid.
            "prompt": null,
            "display": self.display,
            "read_only": self.read_only,
            "process": process,
            "executable_hash": executable_hash,
        });
        let bytes = serde_json::to_vec(&identity)
            .map_err(|error| format!("cannot serialize approval identity: {error}"))?;
        Ok(hash_bytes(&bytes))
    }

    pub fn spec(&self) -> ToolSpec {
        ToolSpec::new(&self.name, &self.description, self.parameters.clone())
    }

    pub fn display_detail(&self, arguments: &str) -> Result<Option<String>, String> {
        let Some(template) = self.display.as_deref() else {
            return Ok(None);
        };
        let values: Value = serde_json::from_str(arguments)
            .map_err(|error| format!("invalid arguments for {}: {error}", self.name))?;
        let values = values
            .as_object()
            .ok_or_else(|| format!("{} arguments must be an object", self.name))?;
        let mut rendered = Vec::new();
        for part in template.split_whitespace() {
            if let Some(name) = display_field(part) {
                let value = values
                    .get(name)
                    .ok_or_else(|| format!("{} display needs argument {name:?}", self.name))?;
                rendered.push(value.to_string());
            } else {
                rendered.push(part.to_string());
            }
        }
        Ok(Some(rendered.join(" ")))
    }

    pub fn execute(
        &self,
        arguments: &str,
        context: &ExecutionContext<'_>,
        cancellation: &Cancellation,
        observer: &mut dyn FnMut(Stream, &str),
    ) -> Result<process::Output, process::RunError> {
        let values: Value = serde_json::from_str(arguments).map_err(|error| process::RunError {
            detail: format!("invalid arguments for {}: {error}", self.name),
            started: false,
        })?;
        let mut command = self
            .process
            .expand_arguments(&values, &self.parameters)
            .map_err(|detail| process::RunError {
                detail,
                started: false,
            })?;
        let timeout = self
            .process
            .call_timeout(&values)
            .map_err(|detail| process::RunError {
                detail,
                started: false,
            })?;
        let program = command.remove(0);
        let program = if let Some(relative) = program.strip_prefix("./") {
            self.directory.join(relative)
        } else {
            PathBuf::from(program)
        };
        let mut env = vec![
            (
                "GEARS_TOOL_DIR".to_string(),
                self.directory.display().to_string(),
            ),
            ("GEARS_TOOL_NAME".to_string(), self.name.clone()),
            (
                "GEARS_WORKSPACE".to_string(),
                context.workspace.display().to_string(),
            ),
            (
                "GEARS_SESSION_ID".to_string(),
                context.session_id.to_string(),
            ),
        ];
        let mut remove_env = vec![KEY_ENV.to_string()];
        if let Some(path) = context.session_path {
            env.push(("GEARS_SESSION_PATH".to_string(), path.display().to_string()));
        } else {
            remove_env.push("GEARS_SESSION_PATH".to_string());
        }
        if let Some(path) = context.shell_state {
            env.push(("GEARS_SH_STATE_DIR".to_string(), path.display().to_string()));
        } else {
            remove_env.push("GEARS_SH_STATE_DIR".to_string());
        }
        if let Some(directory) = context.shell_state {
            shell_state::prepare(directory).map_err(|detail| process::RunError {
                detail: format!("cannot prepare shell state: {detail}"),
                started: false,
            })?;
        }
        let output = process::run(
            &process::Request {
                program: program.display().to_string(),
                args: command,
                cwd: context.workspace.to_path_buf(),
                stdin: self
                    .process
                    .stdin_arguments
                    .then(|| arguments.as_bytes().to_vec()),
                timeout,
                max_output_bytes: self.process.max_output_bytes,
                env,
                remove_env,
            },
            cancellation,
            observer,
        );
        if let Some(directory) = context.shell_state {
            let interrupted = match &output {
                Ok(output) => output.cancelled || output.timed_out,
                Err(_) => true,
            };
            if let Err(detail) = shell_state::finish(directory, interrupted) {
                let detail = format!("cannot save shell state: {detail}");
                return Err(match output {
                    Ok(_) => process::RunError {
                        detail,
                        started: true,
                    },
                    Err(mut error) => {
                        error.detail.push_str(&format!("; {detail}"));
                        error
                    }
                });
            }
        }
        output
    }

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
        let file = raw
            .parameters
            .as_ref()
            .ok_or_else(|| format!("{}: tool needs parameters", directory.display()))?;
        let parameters = read_schema(directory, file)?;
        // Validate both platforms before selecting one, so a dormant override
        // cannot hide a broken mapping until deployment elsewhere.
        let stdin_arguments = raw.process.stdin.as_deref() == Some("arguments");
        for platform in [&raw.linux, &raw.motor] {
            if let Some(arguments) = &platform.process.arguments {
                arguments.validate(directory, &parameters, stdin_arguments)?;
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
        let process = ProcessTool::parse_with_arguments(
            raw.process,
            directory,
            &parameters,
            platform.process.arguments,
        )?;
        let display = raw.display;
        if let Some(template) = display.as_deref() {
            validate_display(template, &parameters, directory)?;
        }
        Ok(Self {
            name: raw.name,
            description,
            parameters,
            display,
            read_only: raw.read_only,
            directory: directory.to_path_buf(),
            enabled_by_default,
            enabled: enabled_by_default,
            process,
        })
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_schema(directory: &Path, file: &str) -> Result<Value, String> {
    let schema: Value = serde_json::from_str(&read_file(directory, file)?)
        .map_err(|error| format!("{}/{}: {error}", directory.display(), file))?;
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!(
            "{}/{}: parameters must be an object schema",
            directory.display(),
            file
        ));
    }
    Ok(schema)
}

fn display_field(part: &str) -> Option<&str> {
    part.strip_prefix('{')?.strip_suffix('}')
}

fn validate_display(template: &str, schema: &Value, directory: &Path) -> Result<(), String> {
    if template.trim().is_empty() {
        return Err(format!("{}: tool display is empty", directory.display()));
    }
    for part in template.split_whitespace() {
        if let Some(name) = display_field(part) {
            if name.is_empty()
                || name.contains(['{', '}'])
                || schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|properties| properties.get(name))
                    .is_none()
            {
                return Err(format!(
                    "{}: invalid display placeholder {part:?}",
                    directory.display()
                ));
            }
        } else if part.contains(['{', '}']) {
            return Err(format!(
                "{}: display placeholders must occupy a whole field",
                directory.display()
            ));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    version: u32,
    kind: String,
    name: String,
    description: Option<String>,
    parameters: Option<String>,
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
#[serde(deny_unknown_fields)]
struct RawPlatform {
    description: Option<String>,
    #[serde(default)]
    process: RawPlatformProcess,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlatformProcess {
    arguments: Option<Arguments>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProcess {
    timeout_seconds: Option<u64>,
    max_output_bytes: Option<usize>,
    stdin: Option<String>,
    output: Option<String>,
    normal_exit_statuses: Option<Vec<i32>>,
    #[serde(default)]
    shell_state: bool,
    #[serde(default)]
    arguments: Arguments,
    command: RawCommand,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommand {
    common: Option<Vec<String>>,
    linux: Option<Vec<String>>,
    motor: Option<Vec<String>>,
}

impl ProcessTool {
    #[cfg(test)]
    fn parse(raw: RawProcess, directory: &Path, parameters: &Value) -> Result<Self, String> {
        Self::parse_with_arguments(raw, directory, parameters, None)
    }

    fn parse_with_arguments(
        mut raw: RawProcess,
        directory: &Path,
        parameters: &Value,
        override_arguments: Option<Arguments>,
    ) -> Result<Self, String> {
        if let Some(arguments) = override_arguments {
            raw.arguments = arguments;
        }
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
            shell_state: raw.shell_state,
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
                ArgumentMapping::String
                | ArgumentMapping::StringOption { .. }
                | ArgumentMapping::Enum { .. }
                | ArgumentMapping::EnumOption { .. } => "string",
                ArgumentMapping::BooleanFlag { .. } => "boolean",
                ArgumentMapping::IntegerOption { .. } => "integer",
                ArgumentMapping::TimeoutSeconds => "integer",
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
            if after_delimiter
                && matches!(
                    mapping,
                    ArgumentMapping::StringOption { .. }
                        | ArgumentMapping::BooleanFlag { .. }
                        | ArgumentMapping::IntegerOption { .. }
                        | ArgumentMapping::Enum { .. }
                        | ArgumentMapping::EnumOption { .. }
                        | ArgumentMapping::TimeoutSeconds
                )
            {
                return Err(format!(
                    "{}: fixed option {name:?} must be before --",
                    directory.display()
                ));
            }
            let flag = match mapping {
                ArgumentMapping::StringOption { flag }
                | ArgumentMapping::BooleanFlag { flag }
                | ArgumentMapping::IntegerOption { flag }
                | ArgumentMapping::EnumOption { flag, .. } => Some(flag),
                _ => None,
            };
            if flag.is_some_and(|flag| {
                !flag.starts_with('-')
                    || flag == "--"
                    || flag
                        .bytes()
                        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            }) {
                return Err(format!(
                    "{}: invalid fixed flag for {name:?}",
                    directory.display()
                ));
            }
            let values = match mapping {
                ArgumentMapping::Enum { values } | ArgumentMapping::EnumOption { values, .. } => {
                    Some(values)
                }
                _ => None,
            };
            if values.is_some_and(|values| {
                values.is_empty()
                    || values
                        .iter()
                        .any(|(key, value)| key.is_empty() || value.is_empty() || value == "--")
            }) {
                return Err(format!(
                    "{}: invalid enum values for {name:?}",
                    directory.display()
                ));
            }
        }
        if self.mappings.len() != names.len() {
            return Err(format!(
                "{}: argument mapping is not in the order list",
                directory.display()
            ));
        }
        if self
            .mappings
            .values()
            .filter(|mapping| matches!(mapping, ArgumentMapping::TimeoutSeconds))
            .count()
            > 1
        {
            return Err(format!(
                "{}: more than one timeout argument",
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

impl ProcessTool {
    pub fn call_timeout(&self, arguments: &Value) -> Result<Duration, String> {
        let Some((name, _)) = self
            .arguments
            .mappings
            .iter()
            .find(|(_, mapping)| matches!(mapping, ArgumentMapping::TimeoutSeconds))
        else {
            return Ok(self.timeout);
        };
        let Some(value) = arguments.get(name) else {
            return Ok(self.timeout);
        };
        let seconds = value
            .as_u64()
            .ok_or_else(|| format!("{name:?} must be a positive integer"))?;
        if seconds == 0 || seconds > self.timeout.as_secs() {
            return Err(format!(
                "{name:?} must be between 1 and {} seconds",
                self.timeout.as_secs()
            ));
        }
        Ok(Duration::from_secs(seconds))
    }

    pub fn expand_arguments(
        &self,
        arguments: &Value,
        schema: &Value,
    ) -> Result<Vec<String>, String> {
        let supplied = arguments
            .as_object()
            .ok_or_else(|| "tool arguments must be an object".to_string())?;
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required {
                let name = name
                    .as_str()
                    .ok_or("invalid required property in tool schema")?;
                if !supplied.contains_key(name) {
                    return Err(format!("missing required tool argument {name:?}"));
                }
            }
        }
        let Some(mut command) = self.command.clone() else {
            return Err("tool is unavailable on this system".to_string());
        };
        if self.arguments.mappings.is_empty() {
            if !self.stdin_arguments && !supplied.is_empty() {
                return Err("tool has no argument mappings".to_string());
            }
            return Ok(command);
        }
        if supplied
            .keys()
            .any(|name| !self.arguments.mappings.contains_key(name))
        {
            return Err("tool call contains an unmapped argument".to_string());
        }
        let mut after = Vec::new();
        for name in &self.arguments.before_double_dash {
            if let Some(value) = supplied.get(name) {
                self.expand_one(name, value, false, &mut command, &mut after)?;
            }
        }
        for name in &self.arguments.after_double_dash {
            if let Some(value) = supplied.get(name) {
                self.expand_one(name, value, true, &mut command, &mut after)?;
            }
        }
        if !self.arguments.after_double_dash.is_empty() {
            command.push("--".to_string());
        }
        command.extend(after);
        Ok(command)
    }

    fn expand_one(
        &self,
        name: &str,
        value: &Value,
        after_delimiter: bool,
        before: &mut Vec<String>,
        after: &mut Vec<String>,
    ) -> Result<(), String> {
        let mapping = &self.arguments.mappings[name];
        match mapping {
            ArgumentMapping::String => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("{name:?} must be a string"))?;
                self.push_model_string(text, after_delimiter, before, after)?;
            }
            ArgumentMapping::StringOption { flag } => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("{name:?} must be a string"))?;
                if text.starts_with('-') {
                    return Err(format!("argument {text:?} must follow --"));
                }
                before.push(flag.clone());
                before.push(text.to_string());
            }
            ArgumentMapping::BooleanFlag { flag } => {
                let enabled = value
                    .as_bool()
                    .ok_or_else(|| format!("{name:?} must be a boolean"))?;
                if enabled {
                    before.push(flag.clone());
                }
            }
            ArgumentMapping::IntegerOption { flag } => {
                let integer = value
                    .as_i64()
                    .map(|number| number.to_string())
                    .or_else(|| value.as_u64().map(|number| number.to_string()))
                    .ok_or_else(|| format!("{name:?} must be an integer"))?;
                before.push(flag.clone());
                before.push(integer);
            }
            ArgumentMapping::Enum { values } => {
                let key = value
                    .as_str()
                    .ok_or_else(|| format!("{name:?} must be a string"))?;
                let selected = values
                    .get(key)
                    .ok_or_else(|| format!("{name:?} has an unsupported value"))?;
                before.push(selected.clone());
            }
            ArgumentMapping::EnumOption { flag, values } => {
                let key = value
                    .as_str()
                    .ok_or_else(|| format!("{name:?} must be a string"))?;
                let selected = values
                    .get(key)
                    .ok_or_else(|| format!("{name:?} has an unsupported value"))?;
                before.push(flag.clone());
                before.push(selected.clone());
            }
            ArgumentMapping::StringList => {
                let items = value
                    .as_array()
                    .ok_or_else(|| format!("{name:?} must be an array"))?;
                for item in items {
                    let text = item
                        .as_str()
                        .ok_or_else(|| format!("{name:?} needs string items"))?;
                    self.push_model_string(text, true, before, after)?;
                }
            }
            ArgumentMapping::TimeoutSeconds => {}
        }
        Ok(())
    }

    fn push_model_string(
        &self,
        value: &str,
        after_delimiter: bool,
        before: &mut Vec<String>,
        after: &mut Vec<String>,
    ) -> Result<(), String> {
        if after_delimiter {
            after.push(value.to_string());
        } else if value.starts_with('-') {
            return Err(format!("argument {value:?} must follow --"));
        } else {
            before.push(value.to_string());
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
    fn shared_example_lists_all_shipped_tools_disabled() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"));
        let config = Config::load_user(Some(&base.join("config/gears.toml"))).unwrap();
        let registry = Registry::load(&config.tools, base).unwrap();
        assert_eq!(registry.tools().len(), 14);
        assert_eq!(registry.enabled_tools().count(), 0);
        assert!(registry.tools().iter().all(|tool| !tool.enabled_by_default));
        // Every shipped tool directory is offered by one of the two samples.
        let batteries = Config::load_user(Some(&base.join("config/gears-batteries.toml"))).unwrap();
        let configured = config
            .tools
            .iter()
            .chain(&batteries.tools)
            .map(|tool| tool.directory.clone())
            .collect::<HashSet<_>>();
        for directory in std::fs::read_dir(base.join("tools")).unwrap() {
            let directory = directory.unwrap();
            if directory.file_type().unwrap().is_dir() {
                let path = PathBuf::from("tools").join(directory.file_name());
                assert!(configured.contains(&path), "{}", path.display());
            }
        }
        let cargo = registry
            .tools()
            .iter()
            .find(|tool| tool.name == "cargo")
            .unwrap();
        #[cfg(unix)]
        assert_eq!(cargo.process.command.as_ref().unwrap(), &["/usr/bin/cargo"]);
        #[cfg(not(unix))]
        assert!(cargo.process.command.is_none());
    }

    #[test]
    fn shipped_rg_and_gix_have_typed_platform_commands() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR"));
        let registry = Registry::load(
            &["rg", "gix"].map(|name| ToolDirectory {
                directory: PathBuf::from(format!("tools/{name}")),
                enabled: true,
            }),
            base,
        )
        .unwrap();
        let rg = &registry.tools()[0];
        let argv = rg
            .process
            .expand_arguments(
                &serde_json::json!({"fixed_strings":true,"pattern":"-needle","path":"a * b.txt"}),
                &rg.parameters,
            )
            .unwrap();
        assert_eq!(&argv[1..], ["-F", "--", "-needle", "a * b.txt"]);
        assert_eq!(rg.process.normal_exit_statuses, [0, 1]);
        assert!(rg.read_only);
        let gix = &registry.tools()[1];
        assert!(!gix.read_only);
        #[cfg(unix)]
        assert!(gix.process.command.is_none());
        #[cfg(not(unix))]
        assert_eq!(
            gix.process.command.as_ref().unwrap(),
            &["/devtools/bin/gix"]
        );
    }

    #[test]
    fn approval_identity_tracks_package_executable_and_schema() {
        let directory =
            std::env::temp_dir().join(format!("gears-approval-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("run"), b"first").unwrap();
        std::fs::write(directory.join("parameters.json"), r#"{"type":"object"}"#).unwrap();
        std::fs::write(
            directory.join("tool.toml"),
            "version = 1\nkind = 'process'\nname = 'sample'\ndescription = 'Sample'\nparameters = 'parameters.json'\n[process.command]\ncommon = ['./run']\n",
        )
        .unwrap();
        let tool = Tool::load(&directory, true).unwrap();
        let original = tool.approval_identity().unwrap();
        assert_eq!(original.len(), 64);
        let mut disabled = tool.clone();
        disabled.enabled = false;
        assert_eq!(disabled.approval_identity().unwrap(), original);
        std::fs::write(directory.join("run"), b"second").unwrap();
        assert_ne!(tool.approval_identity().unwrap(), original);
        let mut changed_schema = tool.clone();
        changed_schema.parameters =
            serde_json::json!({"type":"object","properties":{"x":{"type":"string"}}});
        assert_ne!(
            changed_schema.approval_identity().unwrap(),
            tool.approval_identity().unwrap()
        );
        let mut changed_description = tool.clone();
        changed_description.description.push_str(" updated");
        assert_ne!(
            changed_description.approval_identity().unwrap(),
            tool.approval_identity().unwrap()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn platform_argument_overrides_match_each_schema() {
        let root = std::env::temp_dir().join(format!("gears-platform-map-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("parameters.json"),
            r#"{"type":"object","properties":{"path":{"type":"string"}}}"#,
        )
        .unwrap();
        let manifest = r#"
version = 1
kind = "process"
name = "example"
description = "Example"
parameters = "parameters.json"
[process.command]
common = ["/no-program"]
[process.arguments]
after_double_dash = ["path"]
[process.arguments.path]
type = "string"
[motor.process.arguments]
before_double_dash = ["path"]
[motor.process.arguments.path]
type = "string"
"#;
        std::fs::write(root.join("tool.toml"), manifest).unwrap();
        let entries = [ToolDirectory {
            directory: root.clone(),
            enabled: true,
        }];
        let registry = Registry::load(&entries, &root).unwrap();
        let tool = &registry.tools()[0];
        #[cfg(unix)]
        assert_eq!(
            tool.process
                .expand_arguments(&serde_json::json!({"path":"one"}), &tool.parameters)
                .unwrap(),
            ["/no-program", "--", "one"]
        );
        #[cfg(not(unix))]
        assert_eq!(
            tool.process
                .expand_arguments(&serde_json::json!({"path":"one"}), &tool.parameters)
                .unwrap(),
            ["/no-program", "one"]
        );
        // The dormant platform's mapping is still checked against the schema.
        std::fs::write(
            root.join("tool.toml"),
            manifest.replace(
                "[motor.process.arguments.path]\ntype = \"string\"",
                "[motor.process.arguments.path]\ntype = \"string_list\"",
            ),
        )
        .unwrap();
        assert!(
            Registry::load(&entries, &root)
                .unwrap_err()
                .contains("schema type array")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

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
    fn typed_timeout_is_bounded_by_the_manifest_without_adding_argv() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"timeout": {"type": "integer"}}
        });
        let raw: RawProcess = toml::from_str(
            r#"
            timeout_seconds = 3
            [command]
            common = ["/bin/true"]
            [arguments]
            before_double_dash = ["timeout"]
            [arguments.timeout]
            type = "timeout_seconds"
        "#,
        )
        .unwrap();
        let process = ProcessTool::parse(raw, Path::new("/tmp/example-tool"), &schema).unwrap();
        assert_eq!(
            process.call_timeout(&serde_json::json!({})).unwrap(),
            Duration::from_secs(3)
        );
        let arguments = serde_json::json!({"timeout": 1});
        assert_eq!(
            process.call_timeout(&arguments).unwrap(),
            Duration::from_secs(1)
        );
        assert_eq!(
            process.expand_arguments(&arguments, &schema).unwrap(),
            ["/bin/true"]
        );
        for value in [0, 4, -1] {
            assert!(
                process
                    .call_timeout(&serde_json::json!({"timeout": value}))
                    .is_err()
            );
        }
    }

    #[test]
    fn typed_mapping_expands_without_splitting_or_flag_injection() {
        let schema = serde_json::json!({
            "type": "object", "required": ["pattern"],
            "properties": {
                "ignore_case": {"type": "boolean"},
                "limit": {"type": "integer"},
                "mode": {"type": "string"},
                "filter": {"type": "string"},
                "kind": {"type": "string"},
                "pattern": {"type": "string"},
                "paths": {"type": "array", "items": {"type": "string"}}
            }
        });
        let raw: RawProcess = toml::from_str(
            r#"
            [command]
            common = ["/bin/rg", "--color=never"]
            [arguments]
            before_double_dash = ["ignore_case", "limit", "mode", "filter", "kind"]
            after_double_dash = ["pattern", "paths"]
            [arguments.ignore_case]
            type = "boolean_flag"
            flag = "-i"
            [arguments.limit]
            type = "integer_option"
            flag = "-m"
            [arguments.mode]
            type = "enum"
            values = { files = "-l", count = "-c" }
            [arguments.filter]
            type = "string_option"
            flag = "-g"
            [arguments.kind]
            type = "enum_option"
            flag = "-type"
            values = { file = "f", directory = "d" }
            [arguments.pattern]
            type = "string"
            [arguments.paths]
            type = "string_list"
        "#,
        )
        .unwrap();
        let process = ProcessTool::parse(raw, Path::new("/tmp/example-tool"), &schema).unwrap();
        let arguments = serde_json::json!({
            "ignore_case": true, "limit": 3, "mode": "files", "filter": "literal [name]", "kind": "file",
            "pattern": "two words", "paths": ["-literal", "dir with spaces"]
        });
        assert_eq!(
            process.expand_arguments(&arguments, &schema).unwrap(),
            [
                "/bin/rg",
                "--color=never",
                "-i",
                "-m",
                "3",
                "-l",
                "-g",
                "literal [name]",
                "-type",
                "f",
                "--",
                "two words",
                "-literal",
                "dir with spaces"
            ]
        );
        let invalid = serde_json::json!({"pattern": "ok", "filter": "-unsafe"});
        assert!(process.expand_arguments(&invalid, &schema).is_err());
        let invalid = serde_json::json!({"pattern": "ok", "kind": "socket"});
        assert!(process.expand_arguments(&invalid, &schema).is_err());
        assert!(
            process
                .expand_arguments(&serde_json::json!({"paths": []}), &schema)
                .unwrap_err()
                .contains("missing required")
        );
        assert!(
            process
                .expand_arguments(
                    &serde_json::json!({"pattern": "x", "mode": "unsafe"}),
                    &schema
                )
                .unwrap_err()
                .contains("unsupported value")
        );
        assert!(
            process
                .expand_arguments(&serde_json::json!({"pattern": "x", "extra": "x"}), &schema)
                .unwrap_err()
                .contains("unmapped")
        );

        let mut before = Vec::new();
        let mut after = Vec::new();
        assert!(
            process
                .push_model_string("-unsafe", false, &mut before, &mut after)
                .is_err()
        );
        process
            .push_model_string("--release", true, &mut before, &mut after)
            .unwrap();
        assert!(before.is_empty());
        assert_eq!(after, ["--release"]);
    }

    #[cfg(unix)]
    #[test]
    fn mapped_tool_runs_with_one_argument_containing_spaces() {
        let schema = serde_json::json!({
            "type": "object", "required": ["text"],
            "properties": {"text": {"type": "string"}}
        });
        let raw: RawProcess = toml::from_str(
            r#"
            [command]
            common = ["/usr/bin/printf", "%s"]
            [arguments]
            after_double_dash = ["text"]
            [arguments.text]
            type = "string"
        "#,
        )
        .unwrap();
        let directory = std::env::temp_dir();
        let tool = Tool {
            name: "print".to_string(),
            description: "Print text".to_string(),
            parameters: schema.clone(),
            display: Some("print {text}".to_string()),
            read_only: true,
            directory: directory.clone(),
            enabled_by_default: true,
            enabled: true,
            process: ProcessTool::parse(raw, &directory, &schema).unwrap(),
        };
        let workspace = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert!(validate_display("print {text}", &schema, &directory).is_ok());
        assert!(validate_display("print prefix{text}", &schema, &directory).is_err());
        assert!(validate_display("print {missing}", &schema, &directory).is_err());
        assert_eq!(
            tool.display_detail(r#"{"text":"two words"}"#).unwrap(),
            Some("print \"two words\"".to_string())
        );
        assert!(
            tool.display_detail("{}")
                .unwrap_err()
                .contains("display needs argument")
        );
        let output = tool
            .execute(
                r#"{"text":"two words"}"#,
                &ExecutionContext {
                    workspace: &workspace,
                    session_id: "session-test",
                    session_path: None,
                    shell_state: None,
                },
                &Cancellation::new(),
                &mut |_, _| {},
            )
            .unwrap();
        assert_eq!(output.stdout, "two words");
        assert!(output.success());
        assert!(!output.timed_out && !output.cancelled);
    }

    #[test]
    fn listed_directory_loads_without_running_its_command() {
        let root = std::env::temp_dir().join(format!("gears-tools-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let directory = root.join("tools/example");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("parameters.json"), r#"{"type":"object"}"#).unwrap();
        std::fs::write(
            directory.join("tool.toml"),
            r#"version = 1
kind = 'process'
name = 'example'
description = 'An example.'
parameters = 'parameters.json'
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
        assert_eq!(registry.enabled_tools().count(), 1);
        assert_eq!(registry.enabled("example").unwrap().spec().name, "example");
        assert!(tool.enabled_by_default && tool.read_only);
        assert!(tool.process.stdin_arguments && tool.process.stdout_only);
        assert_eq!(tool.process.normal_exit_statuses, [0, 1]);
        let disabled = Registry::load(
            &[ToolDirectory {
                directory: PathBuf::from("tools/example"),
                enabled: false,
            }],
            &root,
        )
        .unwrap();
        assert_eq!(disabled.enabled_tools().count(), 0);
        assert!(disabled.enabled("example").is_none());
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
        // Fields this version does not support are refused, not ignored.
        std::fs::write(
            directory.join("tool.toml"),
            manifest.replace("read_only = true", "read_only = true\nprompt = 'prompt.md'"),
        )
        .unwrap();
        assert!(
            Registry::load(&entries, &root)
                .unwrap_err()
                .contains("unknown field")
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
