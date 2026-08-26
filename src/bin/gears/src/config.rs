//! Small, versioned configuration for the provider, runtime, and hooks.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

const DEFAULT_CONTEXT_TOKENS: u64 = 128_000;
const DEFAULT_OUTPUT_RESERVE: u64 = 16_384;
const DEFAULT_RECENT_TAIL: u64 = 20_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookConfig {
    pub name: String,
    pub command: Vec<String>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextConfig {
    pub window_tokens: u64,
    pub output_reserve_tokens: u64,
    pub recent_tail_tokens: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub egress_allowlist: Vec<String>,
    pub allow_plain_http_loopback: bool,
    pub base_url: String,
    pub model: Option<String>,
    pub models: Vec<String>,
    pub key_file: Option<PathBuf>,
    pub ca_cert: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub log_level: crate::trace::Level,
    pub sh_timeout: Duration,
    pub max_tool_rounds: usize,
    pub context: ContextConfig,
    pub hooks: Vec<HookConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            egress_allowlist: vec!["openrouter.ai".to_string()],
            allow_plain_http_loopback: false,
            base_url: crate::provider::openai_compat::OPENROUTER_BASE_URL.to_string(),
            model: None,
            models: Vec::new(),
            key_file: None,
            ca_cert: None,
            log_file: None,
            log_level: crate::trace::Level::Info,
            sh_timeout: Duration::from_secs(120),
            max_tool_rounds: 32,
            context: ContextConfig {
                window_tokens: DEFAULT_CONTEXT_TOKENS,
                output_reserve_tokens: DEFAULT_OUTPUT_RESERVE,
                recent_tail_tokens: DEFAULT_RECENT_TAIL,
            },
            hooks: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
struct RawConfig {
    version: u32,
    #[serde(default)]
    net: RawNet,
    #[serde(default)]
    provider: RawProvider,
    #[serde(default)]
    models: RawModels,
    #[serde(default)]
    trace: RawTrace,
    #[serde(default)]
    runtime: RawRuntime,
    #[serde(default)]
    context: RawContext,
    #[serde(default)]
    hooks: Vec<RawHook>,
}

#[derive(Default, Deserialize)]
struct RawNet {
    egress_allowlist: Option<Vec<String>>,
    allow_plain_http_loopback: Option<bool>,
}

#[derive(Default, Deserialize)]
struct RawProvider {
    base_url: Option<String>,
    model: Option<String>,
    key_file: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
struct RawModels {
    used: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
struct RawTrace {
    file: Option<PathBuf>,
    level: Option<String>,
}

#[derive(Default, Deserialize)]
struct RawRuntime {
    sh_timeout_seconds: Option<u64>,
    max_tool_rounds: Option<usize>,
}

#[derive(Default, Deserialize)]
struct RawContext {
    window_tokens: Option<u64>,
    output_reserve_tokens: Option<u64>,
    recent_tail_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct RawHook {
    name: String,
    command: Vec<String>,
    timeout_seconds: Option<u64>,
    max_output_bytes: Option<usize>,
}

impl Config {
    pub fn default_path() -> Option<PathBuf> {
        #[cfg(target_os = "motor")]
        {
            Some(PathBuf::from("/user/cfg/gears.toml"))
        }
        #[cfg(all(unix, not(target_os = "motor")))]
        {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".config/gears.toml"))
        }
        #[cfg(not(any(target_os = "motor", unix)))]
        {
            None
        }
    }

    pub fn load_user(explicit: Option<&Path>) -> Result<Self, String> {
        let (path, required) = match explicit {
            Some(path) => (path.to_path_buf(), true),
            None => match Self::default_path() {
                Some(path) => (path, false),
                None => return Ok(Self::default()),
            },
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
                Ok(Self::default())
            }
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let raw: RawConfig = toml::from_str(text).map_err(|error| error.to_string())?;
        if raw.version != 1 {
            return Err(format!(
                "unsupported config version {} (expected 1)",
                raw.version
            ));
        }
        let defaults = Self::default();
        let egress_allowlist = raw
            .net
            .egress_allowlist
            .unwrap_or(defaults.egress_allowlist)
            .into_iter()
            .map(|host| validate_host(&host))
            .collect::<Result<Vec<_>, _>>()?;
        let base_url = raw.provider.base_url.unwrap_or(defaults.base_url);
        crate::provider::Endpoint::new(&base_url)
            .map_err(|error| format!("bad provider.base_url: {error}"))?;
        for path in [&raw.provider.key_file, &raw.provider.ca_cert]
            .into_iter()
            .flatten()
        {
            if !path.is_absolute() {
                return Err(format!("provider path {} must be absolute", path.display()));
            }
        }
        let log_level = match raw.trace.level {
            Some(level) => crate::trace::Level::parse(&level)
                .ok_or_else(|| format!("unknown trace level {level:?}"))?,
            None => defaults.log_level,
        };
        let sh_timeout = bounded_seconds(
            "runtime.sh_timeout_seconds",
            raw.runtime.sh_timeout_seconds.unwrap_or(120),
            1,
            3600,
        )?;
        let max_tool_rounds = raw.runtime.max_tool_rounds.unwrap_or(32);
        if !(1..=256).contains(&max_tool_rounds) {
            return Err("runtime.max_tool_rounds must be between 1 and 256".to_string());
        }
        let context = ContextConfig {
            window_tokens: raw.context.window_tokens.unwrap_or(DEFAULT_CONTEXT_TOKENS),
            output_reserve_tokens: raw
                .context
                .output_reserve_tokens
                .unwrap_or(DEFAULT_OUTPUT_RESERVE),
            recent_tail_tokens: raw
                .context
                .recent_tail_tokens
                .unwrap_or(DEFAULT_RECENT_TAIL),
        };
        validate_context(context)?;
        let mut names = std::collections::HashSet::new();
        let mut hooks = Vec::with_capacity(raw.hooks.len());
        for hook in raw.hooks {
            if hook.name.is_empty() || !valid_name(&hook.name) {
                return Err(format!("invalid hook name {:?}", hook.name));
            }
            if !names.insert(hook.name.clone()) {
                return Err(format!("duplicate hook name {:?}", hook.name));
            }
            if hook.command.is_empty() || hook.command[0].is_empty() {
                return Err(format!("hook {:?} has no command", hook.name));
            }
            let timeout = bounded_seconds(
                "hooks.timeout_seconds",
                hook.timeout_seconds.unwrap_or(30),
                1,
                3600,
            )?;
            let max_output_bytes = hook.max_output_bytes.unwrap_or(1024 * 1024);
            if !(1024..=16 * 1024 * 1024).contains(&max_output_bytes) {
                return Err(format!(
                    "hook {:?} max_output_bytes must be between 1024 and 16777216",
                    hook.name
                ));
            }
            hooks.push(HookConfig {
                name: hook.name,
                command: hook.command,
                timeout,
                max_output_bytes,
            });
        }
        let mut models = raw.models.used.unwrap_or_default();
        models.retain(|model| !model.trim().is_empty());
        let mut seen_models = std::collections::HashSet::new();
        models.retain(|model| seen_models.insert(model.clone()));
        Ok(Self {
            egress_allowlist,
            allow_plain_http_loopback: raw.net.allow_plain_http_loopback.unwrap_or(false),
            base_url,
            model: raw.provider.model.filter(|model| !model.trim().is_empty()),
            models,
            key_file: raw.provider.key_file,
            ca_cert: raw.provider.ca_cert,
            log_file: raw.trace.file,
            log_level,
            sh_timeout,
            max_tool_rounds,
            context,
            hooks,
        })
    }
}

fn bounded_seconds(name: &str, value: u64, minimum: u64, maximum: u64) -> Result<Duration, String> {
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be between {minimum} and {maximum}"));
    }
    Ok(Duration::from_secs(value))
}

fn validate_host(host: &str) -> Result<String, String> {
    let host = host.to_ascii_lowercase();
    if host.is_empty()
        || host.contains(['/', ':', '@'])
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(format!("bad egress host {host:?}"));
    }
    Ok(host)
}

fn valid_name(name: &str) -> bool {
    name.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn validate_context(context: ContextConfig) -> Result<(), String> {
    if context.window_tokens < 4096 {
        return Err("context.window_tokens must be at least 4096".to_string());
    }
    if context.output_reserve_tokens >= context.window_tokens {
        return Err("context.output_reserve_tokens must be below window_tokens".to_string());
    }
    if context.recent_tail_tokens
        >= context
            .window_tokens
            .saturating_sub(context.output_reserve_tokens)
    {
        return Err("context.recent_tail_tokens leaves no room for a summary".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_has_redesign_defaults() {
        let config = Config::parse("version = 1").unwrap();
        assert_eq!(config.max_tool_rounds, 32);
        assert_eq!(config.context.output_reserve_tokens, 16_384);
        assert!(config.hooks.is_empty());
    }

    #[test]
    fn hooks_are_ordered_and_unique() {
        let config = Config::parse(
            r#"
version = 1
[[hooks]]
name = "first"
command = ["/bin/first", "--json"]
[[hooks]]
name = "second"
command = ["/bin/second"]
"#,
        )
        .unwrap();
        assert_eq!(config.hooks[0].name, "first");
        assert_eq!(config.hooks[1].name, "second");
        assert!(
            Config::parse(
                r#"
version = 1
[[hooks]]
name = "same"
command = ["one"]
[[hooks]]
name = "same"
command = ["two"]
"#
            )
            .is_err()
        );
    }

    #[test]
    fn context_bounds_are_checked() {
        assert!(
            Config::parse(
                "version = 1\n[context]\nwindow_tokens = 10000\noutput_reserve_tokens = 10000"
            )
            .is_err()
        );
    }
}
