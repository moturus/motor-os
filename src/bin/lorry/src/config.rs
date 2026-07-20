use crate::diagnostic::{Error, Result};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoCompat {
    V1_97,
    V1_98,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Config {
    pub cargo_compat: Option<CargoCompat>,
    pub rustc: Option<PathBuf>,
    pub default_target: Option<String>,
    pub build_rustflags: Vec<String>,
    pub targets: BTreeMap<TargetSelector, TargetOptions>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetSelector {
    Triple(String),
    Cfg(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetOptions {
    pub linker: Option<PathBuf>,
    pub runner: Option<Vec<String>>,
    pub rustflags: Vec<String>,
}

impl Config {
    pub fn load(package_root: &Path) -> Result<Self> {
        let environment = env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        Self::load_with_environment(package_root, &environment)
    }

    fn load_with_environment(
        package_root: &Path,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self> {
        reject_environment(environment)?;
        let mut config = Config::default();
        load_lorry_layers(package_root, environment, &mut config)?;
        load_cargo_layers(package_root, environment, &mut config)?;
        apply_cargo_environment(environment, &mut config)?;
        Ok(config)
    }

    pub fn selected_target(&self, command_target: Option<&str>) -> Result<Option<String>> {
        let target = command_target
            .map(str::to_owned)
            .or_else(|| self.default_target.clone());
        if let Some(target) = target.as_deref() {
            validate_target(target)?;
        }
        Ok(target)
    }

    pub fn target_options(&self, target: &str, matching_cfgs: &[String]) -> Result<TargetOptions> {
        let mut result = TargetOptions::default();
        let mut matching_runners = Vec::new();
        let mut matching_linkers = Vec::new();

        for (selector, options) in &self.targets {
            let matches = match selector {
                TargetSelector::Triple(triple) => triple == target,
                TargetSelector::Cfg(expression) => matching_cfgs.contains(expression),
            };
            if !matches {
                continue;
            }
            result.rustflags.extend(options.rustflags.iter().cloned());
            if let Some(linker) = &options.linker {
                matching_linkers.push((selector, linker));
            }
            if let Some(runner) = &options.runner {
                matching_runners.push((selector, runner));
            }
        }

        // Cargo gives an exact target table priority over matching cfg tables.
        if let Some(exact) = self.targets.get(&TargetSelector::Triple(target.to_owned())) {
            if exact.linker.is_some() {
                matching_linkers
                    .retain(|(selector, _)| matches!(selector, TargetSelector::Triple(_)));
            }
            if exact.runner.is_some() {
                matching_runners
                    .retain(|(selector, _)| matches!(selector, TargetSelector::Triple(_)));
            }
        }
        if matching_linkers.len() > 1 {
            return Err(Error::failure(format!(
                "target `{target}` matches more than one configured linker"
            ))
            .with_help("configure one exact target linker or make the cfg selectors disjoint"));
        }
        if matching_runners.len() > 1 {
            return Err(Error::failure(format!(
                "target `{target}` matches more than one configured runner"
            ))
            .with_help("configure one exact target runner or make the cfg selectors disjoint"));
        }
        result.linker = matching_linkers.first().map(|(_, value)| (*value).clone());
        result.runner = matching_runners.first().map(|(_, value)| (*value).clone());
        Ok(result)
    }
}

fn reject_environment(environment: &BTreeMap<String, String>) -> Result<()> {
    for variable in [
        "CARGO_TARGET_DIR",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        if environment.contains_key(variable) {
            let explanation = if variable == "CARGO_TARGET_DIR" {
                "Lorry uses the isolated `target/lorry` artifact root"
            } else {
                "compiler wrappers are outside the Stage-1 identity contract"
            };
            return Err(Error::failure(format!(
                "environment variable `{variable}` is not supported: {explanation}"
            ))
            .with_help(format!("unset `{variable}` before invoking Lorry")));
        }
    }
    Ok(())
}

fn load_lorry_layers(
    package_root: &Path,
    environment: &BTreeMap<String, String>,
    config: &mut Config,
) -> Result<()> {
    let mut layers = Vec::new();
    if cfg!(target_os = "motor") {
        layers.push(PathBuf::from("/sys/tools/rust/cfg/lorry.toml"));
        layers.push(PathBuf::from("/user/cfg/lorry.toml"));
    } else if let Some(home) = environment.get("HOME") {
        layers.push(Path::new(home).join(".config/lorry/lorry.toml"));
    }
    if let Some(local) = nearest_file(package_root, "lorry.toml") {
        if !layers.contains(&local) {
            layers.push(local);
        }
    }
    for path in layers {
        if path.is_file() {
            merge_lorry_file(&path, config)?;
        }
    }
    Ok(())
}

fn merge_lorry_file(path: &Path, config: &mut Config) -> Result<()> {
    let source = read_config(path)?;
    let entries = parse_entries(path, &source)?;
    let mut version = None;
    for entry in entries {
        match (entry.table.as_str(), entry.key.as_str()) {
            ("", "config-version") => {
                let value = entry.integer(path)?;
                if value != 1 {
                    return Err(entry.error(
                        path,
                        "unsupported Lorry configuration version",
                        "set `config-version = 1`",
                    ));
                }
                version = Some(());
            }
            ("", "cargo-compat-version") => {
                config.cargo_compat = Some(match entry.string(path)?.as_str() {
                    "1.97" => CargoCompat::V1_97,
                    "1.98" => CargoCompat::V1_98,
                    value => {
                        return Err(entry.error(
                            path,
                            format!("unsupported Cargo compatibility family `{value}`"),
                            "choose `1.97` or `1.98`",
                        ));
                    }
                });
            }
            ("toolchain", "rustc") => {
                let value = PathBuf::from(entry.string(path)?);
                if !value.is_absolute() {
                    return Err(entry.error(
                        path,
                        "configured `toolchain.rustc` must be an absolute path",
                        "use an absolute compiler path",
                    ));
                }
                config.rustc = Some(value);
            }
            _ => {
                return Err(entry.error(
                    path,
                    format!(
                        "unsupported Stage-1 Lorry configuration key `{}`",
                        entry.full_key()
                    ),
                    "remove the key or use a later Lorry stage that supports it",
                ));
            }
        }
    }
    if version.is_none() {
        return Err(Error::failure(format!(
            "Lorry configuration `{}` is missing `config-version = 1`",
            path.display()
        )));
    }
    Ok(())
}

fn load_cargo_layers(
    package_root: &Path,
    environment: &BTreeMap<String, String>,
    config: &mut Config,
) -> Result<()> {
    let cargo_home = environment
        .get("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            environment
                .get("HOME")
                .map(|home| Path::new(home).join(".cargo"))
        });

    let mut layers = Vec::new();
    if let Some(home) = cargo_home.as_deref() {
        if let Some(path) = cargo_config_in(home) {
            layers.push(path);
        }
    }
    let mut ancestors: Vec<_> = package_root.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        let directory = ancestor.join(".cargo");
        if cargo_home
            .as_deref()
            .is_some_and(|home| same_path(home, &directory))
        {
            continue;
        }
        if let Some(path) = cargo_config_in(&directory) {
            layers.push(path);
        }
    }
    for path in layers {
        merge_cargo_file(&path, config)?;
    }
    Ok(())
}

fn cargo_config_in(directory: &Path) -> Option<PathBuf> {
    let legacy = directory.join("config");
    if legacy.is_file() {
        Some(legacy)
    } else {
        let current = directory.join("config.toml");
        current.is_file().then_some(current)
    }
}

fn merge_cargo_file(path: &Path, config: &mut Config) -> Result<()> {
    let source = read_config(path)?;
    let entries = parse_entries(path, &source)?;
    let definition_root = path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("/"));

    for entry in entries {
        if entry.table == "build" {
            match entry.key.as_str() {
                "target" => {
                    let value = entry.string(path)?;
                    validate_target_at(path, entry.line, &value)?;
                    config.default_target = Some(value);
                }
                "rustflags" => {
                    config.build_rustflags.extend(entry.words(path)?);
                }
                "target-dir" => {
                    return Err(entry.error(
                        path,
                        "Cargo `build.target-dir` is not supported",
                        "remove it; Lorry always writes below `target/lorry`",
                    ));
                }
                "rustc-wrapper" | "rustc-workspace-wrapper" => {
                    return Err(entry.error(
                        path,
                        format!("Cargo `build.{}` is not supported", entry.key),
                        "remove the wrapper; compiler wrappers are outside Stage 1",
                    ));
                }
                _ => return Err(unsupported_cargo(path, &entry)),
            }
            continue;
        }
        if let Some(selector) = parse_target_table(path, entry.line, &entry.table)? {
            let options = config.targets.entry(selector).or_default();
            match entry.key.as_str() {
                "linker" => {
                    let value = entry.string(path)?;
                    options.linker = Some(resolve_program_path(definition_root, &value));
                }
                "runner" => {
                    let mut value = entry.words(path)?;
                    if value.is_empty() {
                        return Err(entry.error(
                            path,
                            "target runner cannot be empty",
                            "configure an executable and optional arguments",
                        ));
                    }
                    value[0] = resolve_program_path(definition_root, &value[0])
                        .to_string_lossy()
                        .into_owned();
                    options.runner = Some(value);
                }
                "rustflags" => options.rustflags.extend(entry.words(path)?),
                _ => return Err(unsupported_cargo(path, &entry)),
            }
            continue;
        }
        return Err(unsupported_cargo(path, &entry));
    }
    Ok(())
}

fn unsupported_cargo(path: &Path, entry: &Entry) -> Error {
    entry.error(
        path,
        format!("unsupported Cargo configuration key `{}`", entry.full_key()),
        "Lorry reads only build.target, build.rustflags, and target linker/runner/rustflags",
    )
}

fn apply_cargo_environment(
    environment: &BTreeMap<String, String>,
    config: &mut Config,
) -> Result<()> {
    if let Some(target) = environment.get("CARGO_BUILD_TARGET") {
        validate_target(target)?;
        config.default_target = Some(target.clone());
    }
    if let Some(flags) = environment.get("CARGO_BUILD_RUSTFLAGS") {
        config.build_rustflags = split_words(flags).map_err(|message| {
            Error::failure(format!("invalid `CARGO_BUILD_RUSTFLAGS`: {message}"))
        })?;
    }

    const PREFIX: &str = "CARGO_TARGET_";
    for (key, value) in environment {
        let Some(suffix) = key.strip_prefix(PREFIX) else {
            continue;
        };
        let (encoded, field) = if let Some(target) = suffix.strip_suffix("_LINKER") {
            (target, "linker")
        } else if let Some(target) = suffix.strip_suffix("_RUNNER") {
            (target, "runner")
        } else if let Some(target) = suffix.strip_suffix("_RUSTFLAGS") {
            (target, "rustflags")
        } else {
            continue;
        };
        let target = config
            .default_target
            .iter()
            .chain(config.targets.keys().filter_map(|selector| match selector {
                TargetSelector::Triple(target) => Some(target),
                TargetSelector::Cfg(_) => None,
            }))
            .find(|target| encode_target_environment(target) == encoded)
            .cloned()
            .unwrap_or_else(|| decode_target_environment(encoded));
        validate_target(&target)?;
        let options = config
            .targets
            .entry(TargetSelector::Triple(target))
            .or_default();
        match field {
            "linker" => options.linker = Some(PathBuf::from(value)),
            "runner" => {
                options.runner = Some(
                    split_words(value)
                        .map_err(|message| Error::failure(format!("invalid `{key}`: {message}")))?,
                )
            }
            "rustflags" => {
                options.rustflags = split_words(value)
                    .map_err(|message| Error::failure(format!("invalid `{key}`: {message}")))?
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn encode_target_environment(target: &str) -> String {
    target.to_ascii_uppercase().replace('-', "_")
}

fn decode_target_environment(encoded: &str) -> String {
    // Cargo's environment spelling loses the distinction between `_` and `-`.
    // Preserve the only underscored architecture admitted by the initial
    // Linux/Motor target set, and use hyphens for the remaining separators.
    if let Some(rest) = encoded.strip_prefix("X86_64_") {
        format!("x86_64-{}", rest.to_ascii_lowercase().replace('_', "-"))
    } else {
        encoded.to_ascii_lowercase().replace('_', "-")
    }
}

pub fn environment_rustflags() -> Result<Option<Vec<String>>> {
    if let Some(encoded) = env::var_os("CARGO_ENCODED_RUSTFLAGS") {
        let encoded = encoded
            .into_string()
            .map_err(|_| Error::failure("`CARGO_ENCODED_RUSTFLAGS` contains non-Unicode data"))?;
        return Ok(Some(encoded.split('\u{1f}').map(str::to_owned).collect()));
    }
    if let Some(flags) = env::var_os("RUSTFLAGS") {
        let flags = flags
            .into_string()
            .map_err(|_| Error::failure("`RUSTFLAGS` contains non-Unicode data"))?;
        return split_words(&flags)
            .map(Some)
            .map_err(|message| Error::failure(format!("invalid `RUSTFLAGS`: {message}")));
    }
    Ok(None)
}

fn parse_target_table(path: &Path, line: usize, table: &str) -> Result<Option<TargetSelector>> {
    let Some(raw) = table.strip_prefix("target.") else {
        return Ok(None);
    };
    let value = unquote(raw).unwrap_or(raw).trim();
    if value.starts_with("cfg(") && value.ends_with(')') {
        if value.len() <= 5 {
            return Err(Error::at(
                path,
                line,
                "empty Cargo target cfg selector",
                "use a non-empty cfg expression",
            ));
        }
        Ok(Some(TargetSelector::Cfg(value.to_owned())))
    } else {
        validate_target_at(path, line, value)?;
        Ok(Some(TargetSelector::Triple(value.to_owned())))
    }
}

fn validate_target(target: &str) -> Result<()> {
    validate_target_at(Path::new("<configuration>"), 1, target)
}

fn validate_target_at(path: &Path, line: usize, target: &str) -> Result<()> {
    let valid = !target.is_empty()
        && !target.ends_with(".json")
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(Error::at(
            path,
            line,
            format!("unsupported target `{target}`"),
            "use an installed target triple; custom JSON targets are deferred",
        ));
    }
    Ok(())
}

fn resolve_program_path(definition_root: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() || !value.contains('/') {
        path.to_path_buf()
    } else {
        definition_root.join(path)
    }
}

fn read_config(path: &Path) -> Result<String> {
    fs::read_to_string(path)
        .map_err(|error| Error::failure(format!("failed to read `{}`: {error}", path.display())))
}

fn nearest_file(start: &Path, name: &str) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn same_path(left: &Path, right: &Path) -> bool {
    fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf())
        == fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf())
}

#[derive(Clone, Debug)]
struct Entry {
    table: String,
    key: String,
    value: ConfigValue,
    line: usize,
}

impl Entry {
    fn full_key(&self) -> String {
        if self.table.is_empty() {
            self.key.clone()
        } else {
            format!("{}.{}", self.table, self.key)
        }
    }

    fn string(&self, path: &Path) -> Result<String> {
        match &self.value {
            ConfigValue::String(value) => Ok(value.clone()),
            _ => Err(self.error(
                path,
                format!("configuration key `{}` must be a string", self.full_key()),
                "use a quoted TOML string",
            )),
        }
    }

    fn integer(&self, path: &Path) -> Result<u64> {
        match self.value {
            ConfigValue::Integer(value) => Ok(value),
            _ => Err(self.error(
                path,
                format!("configuration key `{}` must be an integer", self.full_key()),
                "use an unsigned integer",
            )),
        }
    }

    fn words(&self, path: &Path) -> Result<Vec<String>> {
        match &self.value {
            ConfigValue::Strings(values) => Ok(values.clone()),
            ConfigValue::String(value) => split_words(value).map_err(|message| {
                self.error(
                    path,
                    format!(
                        "invalid argument string for `{}`: {message}",
                        self.full_key()
                    ),
                    "use an argument array when values contain complex quoting",
                )
            }),
            _ => Err(self.error(
                path,
                format!(
                    "configuration key `{}` must be a string or string array",
                    self.full_key()
                ),
                "use a quoted string or an array of quoted arguments",
            )),
        }
    }

    fn error(
        &self,
        path: &Path,
        message: impl std::fmt::Display,
        help: impl Into<String>,
    ) -> Error {
        Error::at(path, self.line, message, help)
    }
}

#[derive(Clone, Debug)]
enum ConfigValue {
    String(String),
    Strings(Vec<String>),
    Integer(u64),
    Bool,
}

fn parse_entries(path: &Path, source: &str) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    let mut current_table = String::new();
    let mut seen = BTreeMap::<(String, String), usize>::new();
    for (index, raw) in source.lines().enumerate() {
        let line = index + 1;
        let text = strip_comment(raw).trim();
        if text.is_empty() {
            continue;
        }
        if text.starts_with('[') {
            let Some(table) = text
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .map(str::trim)
            else {
                return Err(Error::at(
                    path,
                    line,
                    "malformed configuration table",
                    "close the table header on the same line",
                ));
            };
            if table.is_empty() || table.starts_with('[') {
                return Err(Error::at(
                    path,
                    line,
                    "array tables are not supported in Stage-1 configuration",
                    "use one ordinary table for each supported target",
                ));
            }
            current_table = table.to_owned();
            continue;
        }
        let Some((raw_key, raw_value)) = text.split_once('=') else {
            return Err(Error::at(
                path,
                line,
                "expected a configuration `key = value` assignment",
                "put each Stage-1 value on one line",
            ));
        };
        let key = raw_key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(Error::at(
                path,
                line,
                format!("unsupported configuration key `{key}`"),
                "use a simple bare key",
            ));
        }
        let identity = (current_table.clone(), key.to_owned());
        if seen.insert(identity, line).is_some() {
            return Err(Error::at(
                path,
                line,
                format!(
                    "duplicate configuration key `{}{}{}.`",
                    current_table,
                    if current_table.is_empty() { "" } else { "." },
                    key
                )
                .trim_end_matches('.'),
                "remove the duplicate key",
            ));
        }
        entries.push(Entry {
            table: current_table.clone(),
            key: key.to_owned(),
            value: parse_config_value(path, line, raw_value.trim())?,
            line,
        });
    }
    Ok(entries)
}

fn parse_config_value(path: &Path, line: usize, value: &str) -> Result<ConfigValue> {
    if value.starts_with('"') || value.starts_with('\'') {
        return parse_quoted(path, line, value).map(ConfigValue::String);
    }
    if value.starts_with('[') {
        return parse_array(path, line, value).map(ConfigValue::Strings);
    }
    if matches!(value, "true" | "false") {
        return Ok(ConfigValue::Bool);
    }
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value.parse().map(ConfigValue::Integer).map_err(|_| {
            Error::at(
                path,
                line,
                "configuration integer is out of range",
                "use an unsigned 64-bit integer",
            )
        });
    }
    Err(Error::at(
        path,
        line,
        format!("unsupported Stage-1 configuration value `{value}`"),
        "use a one-line string, string array, boolean, or unsigned integer",
    ))
}

fn parse_quoted(path: &Path, line: usize, value: &str) -> Result<String> {
    let quote = value.as_bytes()[0];
    if value.len() < 2 || value.as_bytes()[value.len() - 1] != quote {
        return Err(Error::at(
            path,
            line,
            "unterminated configuration string",
            "close the string on the same line",
        ));
    }
    let body = &value[1..value.len() - 1];
    if quote == b'\'' {
        if body.contains('\'') || body.chars().any(char::is_control) {
            return Err(Error::at(
                path,
                line,
                "invalid literal configuration string",
                "remove embedded quotes and control characters",
            ));
        }
        return Ok(body.to_owned());
    }
    let mut result = String::new();
    let mut escaped = false;
    for character in body.chars() {
        if escaped {
            match character {
                '"' | '\\' => result.push(character),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                _ => {
                    return Err(Error::at(
                        path,
                        line,
                        format!("unsupported configuration escape `\\{character}`"),
                        "use \\\", \\\\, \\n, \\r, or \\t",
                    ));
                }
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' || character.is_control() {
            return Err(Error::at(
                path,
                line,
                "invalid character in configuration string",
                "escape quotes and control characters",
            ));
        } else {
            result.push(character);
        }
    }
    if escaped {
        return Err(Error::at(
            path,
            line,
            "unterminated configuration escape",
            "complete the escape before the closing quote",
        ));
    }
    Ok(result)
}

fn parse_array(path: &Path, line: usize, value: &str) -> Result<Vec<String>> {
    let Some(body) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(Error::at(
            path,
            line,
            "unterminated configuration array",
            "close the array on the same line",
        ));
    };
    let mut result = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in body.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quote == Some(b'"') && byte == b'\\' {
            escaped = true;
        } else if matches!(byte, b'"' | b'\'') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
        } else if byte == b',' && quote.is_none() {
            let item = body[start..index].trim();
            if !item.is_empty() {
                result.push(parse_quoted(path, line, item)?);
            }
            start = index + 1;
        }
    }
    if quote.is_some() {
        return Err(Error::at(
            path,
            line,
            "unterminated string in configuration array",
            "close every string on the same line",
        ));
    }
    let item = body[start..].trim();
    if !item.is_empty() {
        result.push(parse_quoted(path, line, item)?);
    }
    Ok(result)
}

fn split_words(value: &str) -> std::result::Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for character in value.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            started = true;
        } else if character == '\\' && quote != Some('\'') {
            escaped = true;
            started = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
                started = true;
            } else {
                word.push(character);
            }
        } else if character.is_whitespace() && quote.is_none() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(character);
            started = true;
        }
    }
    if escaped {
        return Err("trailing backslash".to_owned());
    }
    if let Some(quote) = quote {
        return Err(format!("unterminated `{quote}` quote"));
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

fn unquote(value: &str) -> Option<&str> {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(bytes[0], b'\'' | b'"') && bytes[0] == bytes[value.len() - 1] {
            return Some(&value[1..value.len() - 1]);
        }
    }
    None
}

fn strip_comment(text: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in text.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quote == Some(b'"') && byte == b'\\' {
            escaped = true;
        } else if matches!(byte, b'"' | b'\'') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
        } else if byte == b'#' && quote.is_none() {
            return &text[..index];
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "lorry-config-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn layers_lorry_and_cargo_configuration() {
        let temp = TempDir::new();
        let home = temp.0.join("home");
        let package = temp.0.join("work/pkg");
        fs::create_dir_all(home.join(".config/lorry")).unwrap();
        fs::create_dir_all(home.join(".cargo")).unwrap();
        fs::create_dir_all(package.join(".cargo")).unwrap();
        fs::write(
            home.join(".config/lorry/lorry.toml"),
            "config-version = 1\ncargo-compat-version = \"1.97\"\n\
             [toolchain]\nrustc = \"/base/rustc\"\n",
        )
        .unwrap();
        fs::write(
            package.join("lorry.toml"),
            "config-version = 1\ncargo-compat-version = \"1.98\"\n",
        )
        .unwrap();
        fs::write(
            home.join(".cargo/config.toml"),
            "[build]\ntarget = \"x86_64-unknown-linux-musl\"\nrustflags = [\"--cfg\", \"base\"]\n",
        )
        .unwrap();
        fs::write(
            package.join(".cargo/config.toml"),
            "[build]\nrustflags = \"--cfg local\"\n\
             [target.x86_64-unknown-linux-musl]\n\
             linker = \"tools/ld\"\nrunner = [\"runner\", \"--flag\"]\n",
        )
        .unwrap();

        let environment =
            BTreeMap::from([("HOME".to_owned(), home.to_string_lossy().into_owned())]);
        let config = Config::load_with_environment(&package, &environment).unwrap();
        assert_eq!(config.cargo_compat, Some(CargoCompat::V1_98));
        assert_eq!(config.rustc, Some(PathBuf::from("/base/rustc")));
        assert_eq!(
            config.default_target.as_deref(),
            Some("x86_64-unknown-linux-musl")
        );
        assert_eq!(config.build_rustflags, ["--cfg", "base", "--cfg", "local"]);
        let target = config
            .target_options("x86_64-unknown-linux-musl", &[])
            .unwrap();
        assert_eq!(target.linker, Some(package.join("tools/ld")));
        assert_eq!(target.runner.unwrap(), ["runner", "--flag"]);
    }

    #[test]
    fn environment_overrides_target_configuration() {
        let temp = TempDir::new();
        let package = temp.0.join("pkg");
        fs::create_dir_all(&package).unwrap();
        let environment = BTreeMap::from([
            ("HOME".to_owned(), temp.0.join("home").display().to_string()),
            (
                "CARGO_BUILD_TARGET".to_owned(),
                "x86_64-unknown-motor".to_owned(),
            ),
            (
                "CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUNNER".to_owned(),
                "motor-run --quiet".to_owned(),
            ),
        ]);
        let config = Config::load_with_environment(&package, &environment).unwrap();
        assert_eq!(
            config.default_target.as_deref(),
            Some("x86_64-unknown-motor")
        );
        assert_eq!(
            config
                .target_options("x86_64-unknown-motor", &[])
                .unwrap()
                .runner
                .unwrap(),
            ["motor-run", "--quiet"]
        );
    }

    #[test]
    fn rejects_output_overrides_wrappers_and_unknown_keys() {
        let temp = TempDir::new();
        let package = temp.0.join("pkg");
        fs::create_dir_all(package.join(".cargo")).unwrap();
        let home = temp.0.join("home").display().to_string();
        for variable in [
            "CARGO_TARGET_DIR",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
        ] {
            let environment = BTreeMap::from([
                ("HOME".to_owned(), home.clone()),
                (variable.to_owned(), "".into()),
            ]);
            assert!(Config::load_with_environment(&package, &environment).is_err());
        }

        fs::write(
            package.join(".cargo/config.toml"),
            "[build]\ntarget-dir = \"elsewhere\"\n",
        )
        .unwrap();
        let environment = BTreeMap::from([("HOME".to_owned(), home)]);
        assert!(Config::load_with_environment(&package, &environment).is_err());
    }

    #[test]
    fn splits_cargo_argument_strings_without_a_shell() {
        assert_eq!(
            split_words(r#"one "two words" 'three words' four\ five"#).unwrap(),
            ["one", "two words", "three words", "four five"]
        );
        assert!(split_words("'unterminated").is_err());
    }
}
