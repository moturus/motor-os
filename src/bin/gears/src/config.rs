//! Small, versioned configuration for the provider, runtime, and hooks.

use std::collections::BTreeMap;
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
pub struct NamedProvider {
    pub base_url: String,
    pub plain_http: bool,
    pub model: Option<String>,
    pub key_file: Option<PathBuf>,
    pub ca_cert: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub egress_allowlist: Vec<String>,
    pub plain_http_allowlist: Vec<String>,
    pub base_url: String,
    /// `base_url` is plaintext; its host was checked against both lists.
    pub plain_http: bool,
    pub model: Option<String>,
    pub models: Vec<String>,
    pub key_file: Option<PathBuf>,
    pub ca_cert: Option<PathBuf>,
    pub providers: BTreeMap<String, NamedProvider>,
    pub default_provider: String,
    pub default_model: Option<String>,
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
            plain_http_allowlist: Vec::new(),
            base_url: crate::provider::openai_compat::OPENROUTER_BASE_URL.to_string(),
            plain_http: false,
            model: None,
            models: Vec::new(),
            key_file: None,
            ca_cert: None,
            providers: BTreeMap::new(),
            default_provider: "default".to_string(),
            default_model: None,
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
    default_provider: Option<String>,
    default_model: Option<String>,
    #[serde(default)]
    net: RawNet,
    #[serde(default)]
    provider: RawProvider,
    #[serde(default)]
    providers: BTreeMap<String, RawProvider>,
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
    plain_http_allowlist: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
struct RawProvider {
    base_url: Option<String>,
    model: Option<String>,
    #[serde(alias = "api_key_file")]
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
    pub fn provider(&self, name: &str) -> Option<NamedProvider> {
        if name == "default" {
            Some(NamedProvider {
                base_url: self.base_url.clone(),
                plain_http: self.plain_http,
                model: self.model.clone(),
                key_file: self.key_file.clone(),
                ca_cert: self.ca_cert.clone(),
            })
        } else {
            self.providers.get(name).cloned()
        }
    }

    pub fn default_path() -> Option<PathBuf> {
        #[cfg(target_os = "motor")]
        {
            Some(PathBuf::from("/user/cfg/gears/gears.toml"))
        }
        #[cfg(all(unix, not(target_os = "motor")))]
        {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".gears/gears.toml"))
        }
        #[cfg(not(any(target_os = "motor", unix)))]
        {
            None
        }
    }

    fn legacy_path() -> Option<PathBuf> {
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
        if let Some(path) = explicit {
            return Self::read_config(path)?
                .ok_or_else(|| format!("{}: not found", path.display()));
        }
        Self::load_candidates([Self::default_path(), Self::legacy_path()])
    }

    fn load_candidates(paths: [Option<PathBuf>; 2]) -> Result<Self, String> {
        for path in paths.into_iter().flatten() {
            if let Some(config) = Self::read_config(&path)? {
                return Ok(config);
            }
        }
        Ok(Self::default())
    }

    fn read_config(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse_at(&text, path)
                .map(Some)
                .map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        Self::parse_with_base(text, None)
    }

    fn parse_at(text: &str, path: &Path) -> Result<Self, String> {
        Self::parse_with_base(text, path.parent())
    }

    fn parse_with_base(text: &str, base: Option<&Path>) -> Result<Self, String> {
        let raw: RawConfig = toml::from_str(text).map_err(|error| error.to_string())?;
        if raw.version != 1 {
            return Err(format!(
                "unsupported config version {} (expected 1)",
                raw.version
            ));
        }
        let defaults = Self::default();
        let egress_allowlist = validate_hosts(
            raw.net
                .egress_allowlist
                .unwrap_or(defaults.egress_allowlist),
        )?;
        let plain_http_allowlist =
            validate_hosts(raw.net.plain_http_allowlist.unwrap_or_default())?;
        if let Some(host) = plain_http_allowlist
            .iter()
            .find(|host| !egress_allowlist.contains(host))
        {
            return Err(format!(
                "net.plain_http_allowlist host {host:?} must also be in net.egress_allowlist"
            ));
        }
        let base_url = raw.provider.base_url.unwrap_or(defaults.base_url);
        let endpoint = crate::provider::Endpoint::new(&base_url)
            .map_err(|error| format!("bad provider.base_url: {error}"))?;
        let plain_http = endpoint.url().scheme() == crate::net::Scheme::Http;
        if plain_http {
            // Refuse at load time, so the user sees this rather than a key
            // error or a per-request refusal.
            crate::net::EgressPolicy::new(&egress_allowlist)
                .with_plain_http_allowlist(&plain_http_allowlist)
                .check(endpoint.url())
                .map_err(|error| {
                    format!(
                        "provider.base_url: {error}; list the host in both \
                         net.egress_allowlist and net.plain_http_allowlist"
                    )
                })?;
        }
        let key_file = provider_path(raw.provider.key_file, base)?;
        let ca_cert = provider_path(raw.provider.ca_cert, base)?;
        let mut providers = BTreeMap::new();
        for (name, provider) in raw.providers {
            if name.is_empty() || !valid_name(&name) || name == "default" {
                return Err(format!("invalid provider name {name:?}"));
            }
            let base_url = provider
                .base_url
                .ok_or_else(|| format!("provider {name:?} needs base_url"))?;
            let endpoint = crate::provider::Endpoint::new(&base_url)
                .map_err(|error| format!("bad provider {name:?} base_url: {error}"))?;
            let plain_http = endpoint.url().scheme() == crate::net::Scheme::Http;
            if plain_http {
                crate::net::EgressPolicy::new(&egress_allowlist)
                    .with_plain_http_allowlist(&plain_http_allowlist)
                    .check(endpoint.url())
                    .map_err(|error| format!("provider {name:?} base_url: {error}"))?;
            }
            providers.insert(
                name,
                NamedProvider {
                    base_url,
                    plain_http,
                    model: provider.model.filter(|model| !model.trim().is_empty()),
                    key_file: provider_path(provider.key_file, base)?,
                    ca_cert: provider_path(provider.ca_cert, base)?,
                },
            );
        }
        let default_provider = match raw.default_provider {
            Some(name) if name == "default" || providers.contains_key(&name) => name,
            Some(name) => return Err(format!("unknown default_provider {name:?}")),
            None if providers.len() == 1 => providers.keys().next().unwrap().clone(),
            None if providers.len() > 1 => {
                return Err("default_provider is required with multiple providers".to_string());
            }
            None => "default".to_string(),
        };
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
            plain_http_allowlist,
            base_url,
            plain_http,
            model: raw.provider.model.filter(|model| !model.trim().is_empty()),
            models,
            key_file,
            ca_cert,
            providers,
            default_provider,
            default_model: raw.default_model.filter(|model| !model.trim().is_empty()),
            log_file: raw.trace.file,
            log_level,
            sh_timeout,
            max_tool_rounds,
            context,
            hooks,
        })
    }
}

fn provider_path(path: Option<PathBuf>, base: Option<&Path>) -> Result<Option<PathBuf>, String> {
    path.map(|path| {
        if path.is_absolute() {
            Ok(path)
        } else {
            base.map(|base| base.join(&path))
                .ok_or_else(|| format!("provider path {} needs a config file", path.display()))
        }
    })
    .transpose()
}

fn bounded_seconds(name: &str, value: u64, minimum: u64, maximum: u64) -> Result<Duration, String> {
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be between {minimum} and {maximum}"));
    }
    Ok(Duration::from_secs(value))
}

fn validate_hosts(hosts: Vec<String>) -> Result<Vec<String>, String> {
    hosts.iter().map(|host| validate_host(host)).collect()
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
    fn plaintext_hosts_require_explicit_egress_and_use_the_same_matching() {
        assert!(
            Config::parse("version = 1")
                .unwrap()
                .plain_http_allowlist
                .is_empty()
        );
        let config = Config::parse(
            r#"version = 1
[net]
egress_allowlist = ["192.168.4.1", "Host.Test"]
plain_http_allowlist = ["192.168.4.1", "host.test"]
"#,
        )
        .unwrap();
        assert_eq!(config.plain_http_allowlist, config.egress_allowlist);
        for host in ["192.168.4.1", "api.host.test"] {
            let error = Config::parse(&format!(
                r#"version = 1
[net]
egress_allowlist = ["host.test"]
plain_http_allowlist = ["{host}"]
"#
            ))
            .unwrap_err();
            assert!(error.contains("net.plain_http_allowlist"));
            assert!(error.contains("net.egress_allowlist"));
        }
        assert!(
            Config::parse(
                r#"version = 1
[net]
plain_http_allowlist = ["http://host.test"]
"#
            )
            .is_err()
        );
    }

    #[test]
    fn a_plaintext_endpoint_is_checked_when_the_config_loads() {
        let text = |net: &str| {
            format!(
                r#"version = 1
[provider]
base_url = "http://192.168.4.1:8080/v1"
[net]
{net}
"#
            )
        };
        for net in [
            "",
            r#"egress_allowlist = ["192.168.4.1"]"#,
            r#"egress_allowlist = ["192.168.4.1", "host.test"]
plain_http_allowlist = ["host.test"]"#,
        ] {
            let error = Config::parse(&text(net)).unwrap_err();
            assert!(
                error.contains("plain HTTP is not allowed"),
                "{net}: {error}"
            );
            assert!(error.contains("net.plain_http_allowlist"), "{net}: {error}");
        }
        let config = Config::parse(&text(
            r#"egress_allowlist = ["192.168.4.1"]
plain_http_allowlist = ["192.168.4.1"]"#,
        ))
        .unwrap();
        assert!(config.plain_http);
        assert!(!Config::parse("version = 1").unwrap().plain_http);
    }

    #[test]
    fn minimal_config_has_redesign_defaults() {
        let config = Config::parse("version = 1").unwrap();
        assert_eq!(config.max_tool_rounds, 32);
        assert_eq!(config.context.output_reserve_tokens, 16_384);
        assert!(config.hooks.is_empty());
    }

    #[test]
    fn new_config_path_precedes_legacy_and_resolves_provider_files() {
        let root = std::env::temp_dir().join(format!("gears-config-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("new")).unwrap();
        let current = root.join("new/gears.toml");
        let legacy = root.join("legacy.toml");
        std::fs::write(&legacy, "version = 1\n[provider]\nmodel = 'legacy'\n").unwrap();
        let paths = [Some(current.clone()), Some(legacy.clone())];
        assert_eq!(
            Config::load_candidates(paths.clone())
                .unwrap()
                .model
                .as_deref(),
            Some("legacy")
        );

        std::fs::write(
            &current,
            "version = 1\n[provider]\nmodel = 'current'\napi_key_file = 'secrets/key'\nca_cert = 'ca.pem'\n",
        )
        .unwrap();
        let config = Config::load_candidates(paths).unwrap();
        assert_eq!(config.model.as_deref(), Some("current"));
        assert_eq!(config.key_file, Some(root.join("new/secrets/key")));
        assert_eq!(config.ca_cert, Some(root.join("new/ca.pem")));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_key_file_name_remains_accepted() {
        let config = Config::parse("version = 1\n[provider]\nkey_file = '/secret/key'\n").unwrap();
        assert_eq!(config.key_file, Some(PathBuf::from("/secret/key")));
    }

    #[test]
    fn named_providers_are_validated_and_have_a_selected_default() {
        let path = Path::new("/tmp/gears-test-config/gears.toml");
        let config = Config::parse_at(
            r#"version = 1
default_provider = 'local'
default_model = 'small'
[net]
egress_allowlist = ['127.0.0.1', 'openrouter.ai']
plain_http_allowlist = ['127.0.0.1']
[providers.local]
base_url = 'http://127.0.0.1:9090/v1'
api_key_file = 'secrets/local.key'
model = 'local/model'
[providers.remote]
base_url = 'https://openrouter.ai/api/v1'
"#,
            path,
        )
        .unwrap();
        assert_eq!(config.default_provider, "local");
        assert_eq!(config.default_model.as_deref(), Some("small"));
        assert_eq!(config.providers.len(), 2);
        assert!(config.providers["local"].plain_http);
        assert_eq!(
            config.providers["local"].key_file,
            Some(PathBuf::from("/tmp/gears-test-config/secrets/local.key"))
        );
        assert!(!config.providers["remote"].plain_http);
        assert_eq!(
            config.provider("local").unwrap().model.as_deref(),
            Some("local/model")
        );
        assert!(config.provider("missing").is_none());
        assert!(Config::parse("version = 1\n[providers.one]\nbase_url = 'https://one.test/v1'\n[providers.two]\nbase_url = 'https://two.test/v1'").is_err());
        assert!(Config::parse("version = 1\ndefault_provider = 'missing'").is_err());
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
