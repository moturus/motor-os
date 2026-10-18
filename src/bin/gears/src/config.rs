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
    pub events: Option<Vec<String>>,
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
    /// Model ids offered when choosing a model; any id may still be used.
    pub models: Vec<String>,
    /// Without a key file the provider is sent no `Authorization` header.
    pub key_file: Option<PathBuf>,
    pub ca_cert: Option<PathBuf>,
    pub reasoning_echo: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDirectory {
    pub directory: PathBuf,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub egress_allowlist: Vec<String>,
    pub plain_http_allowlist: Vec<String>,
    pub models: Vec<String>,
    /// Every provider, `[provider]` among them as "default".
    pub providers: BTreeMap<String, NamedProvider>,
    pub tools: Vec<ToolDirectory>,
    /// Where relative tool directories resolve; the Gears directory if `None`.
    pub tool_base: Option<PathBuf>,
    pub default_provider: String,
    pub default_model: Option<String>,
    pub log_file: Option<PathBuf>,
    pub log_level: crate::trace::Level,
    pub max_tool_rounds: usize,
    pub context: ContextConfig,
    pub hooks: Vec<HookConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            egress_allowlist: Vec::new(),
            plain_http_allowlist: Vec::new(),
            models: Vec::new(),
            providers: BTreeMap::new(),
            tools: Vec::new(),
            tool_base: None,
            default_provider: "default".to_string(),
            default_model: None,
            log_file: None,
            log_level: crate::trace::Level::Info,
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
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u32,
    default_provider: Option<String>,
    default_model: Option<String>,
    #[serde(default)]
    net: RawNet,
    provider: Option<RawProvider>,
    #[serde(default)]
    providers: BTreeMap<String, RawProvider>,
    #[serde(default)]
    tools: Vec<RawToolDirectory>,
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
#[serde(deny_unknown_fields)]
struct RawNet {
    egress_allowlist: Option<Vec<String>>,
    plain_http_allowlist: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvider {
    base_url: Option<String>,
    model: Option<String>,
    api_key_file: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    reasoning_echo: Option<bool>,
    models: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToolDirectory {
    directory: PathBuf,
    enabled: bool,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModels {
    used: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrace {
    file: Option<PathBuf>,
    level: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntime {
    max_tool_rounds: Option<usize>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContext {
    window_tokens: Option<u64>,
    output_reserve_tokens: Option<u64>,
    recent_tail_tokens: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHook {
    name: String,
    command: Vec<String>,
    events: Option<Vec<String>>,
    timeout_seconds: Option<u64>,
    max_output_bytes: Option<usize>,
}

impl Config {
    pub fn provider(&self, name: &str) -> Option<NamedProvider> {
        self.providers.get(name).cloned()
    }

    pub fn default_path() -> Option<PathBuf> {
        crate::directory::default_root()
            .ok()
            .map(|root| root.join("gears.toml"))
    }

    pub fn load_user(explicit: Option<&Path>) -> Result<Self, String> {
        if let Some(path) = explicit {
            return Self::read_config(path)?
                .ok_or_else(|| format!("{}: not found", path.display()));
        }
        Self::load_found(&Found::detect(), false)
    }

    /// Load what `detect` found; with both, `source_tree` picks the shipped one.
    pub fn load_found(found: &Found, source_tree: bool) -> Result<Self, String> {
        match (found, source_tree) {
            (Found::User(user), _) | (Found::Both { user, .. }, false) => {
                Self::read_config(user)?.ok_or_else(|| format!("{}: not found", user.display()))
            }
            (Found::SourceTree(package), _) | (Found::Both { package, .. }, true) => {
                let path = package.join("config/gears.toml");
                let mut config = Self::read_config(&path)?
                    .ok_or_else(|| format!("{}: not found", path.display()))?;
                // Its tools are the ones shipped beside it.
                config.tool_base = Some(package.clone());
                Ok(config)
            }
            (Found::Neither(directory), _) => Err(format!(
                "no gears.toml in {}: copy config/gears.toml and tools/ from the Gears \
                 source there",
                directory.display()
            )),
        }
    }

    /// Use the addresses the user chose for providers. A host the user typed is
    /// allowed for egress, and for plain HTTP when its URL uses `http`.
    /// Addresses for providers this file does not define are left for others.
    pub fn apply_urls(&mut self, urls: &BTreeMap<String, String>) -> Result<(), String> {
        for (name, url) in urls {
            let Some(provider) = self.providers.get_mut(name) else {
                continue;
            };
            let endpoint = crate::provider::Endpoint::new(url)
                .map_err(|error| format!("saved address for provider {name:?}: {error}"))?;
            let host = validate_hosts(vec![endpoint.url().host().to_string()])?.remove(0);
            provider.plain_http = endpoint.url().scheme() == crate::net::Scheme::Http;
            if !self.egress_allowlist.contains(&host) {
                self.egress_allowlist.push(host.clone());
            }
            if provider.plain_http && !self.plain_http_allowlist.contains(&host) {
                self.plain_http_allowlist.push(host);
            }
            provider.base_url = url.clone();
        }
        Ok(())
    }

    fn read_config(path: &Path) -> Result<Option<Self>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                // Key and certificate files live in the Gears directory, whichever
                // gears.toml names them.
                let directory = crate::directory::default_root().ok();
                Self::parse_with_base(&text, directory.as_deref())
                    .map(Some)
                    .map_err(|error| format!("{}: {error}", path.display()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        Self::parse_with_base(text, None)
    }

    /// Parse with relative key and certificate paths in `directory`.
    pub fn parse_in(text: &str, directory: &Path) -> Result<Self, String> {
        Self::parse_with_base(text, Some(directory))
    }

    fn parse_with_base(text: &str, base: Option<&Path>) -> Result<Self, String> {
        let raw: RawConfig = toml::from_str(text).map_err(|error| error.to_string())?;
        if raw.version != 1 {
            return Err(format!(
                "unsupported config version {} (expected 1)",
                raw.version
            ));
        }
        let egress_allowlist = validate_hosts(raw.net.egress_allowlist.unwrap_or_default())?;
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
        // `[provider]` is the provider named "default"; nothing is built in.
        let mut providers = BTreeMap::new();
        if let Some(provider) = raw.provider {
            let provider = named_provider(
                "provider",
                provider,
                &egress_allowlist,
                &plain_http_allowlist,
                base,
            )?;
            providers.insert("default".to_string(), provider);
        }
        for (name, provider) in raw.providers {
            if name.is_empty() || !valid_name(&name) || name == "default" {
                return Err(format!("invalid provider name {name:?}"));
            }
            let label = format!("providers.{name}");
            let provider = named_provider(
                &label,
                provider,
                &egress_allowlist,
                &plain_http_allowlist,
                base,
            )?;
            providers.insert(name, provider);
        }
        let default_provider = match raw.default_provider {
            Some(name) if providers.contains_key(&name) => name,
            Some(name) => return Err(format!("unknown default_provider {name:?}")),
            None if providers.len() == 1 => providers.keys().next().unwrap().clone(),
            None if providers.len() > 1 => {
                return Err("default_provider is required with multiple providers".to_string());
            }
            None => "default".to_string(),
        };
        let mut tools = Vec::with_capacity(raw.tools.len());
        for tool in raw.tools {
            if tool.directory.as_os_str().is_empty()
                || (!tool.directory.is_absolute()
                    && tool
                        .directory
                        .components()
                        .any(|component| !matches!(component, std::path::Component::Normal(_))))
            {
                return Err(format!(
                    "invalid tool directory {}",
                    tool.directory.display()
                ));
            }
            tools.push(ToolDirectory {
                directory: tool.directory,
                enabled: tool.enabled,
            });
        }
        let log_level = match raw.trace.level {
            Some(level) => crate::trace::Level::parse(&level)
                .ok_or_else(|| format!("unknown trace level {level:?}"))?,
            None => crate::trace::Level::Info,
        };
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
            if let Some(events) = &hook.events {
                let mut names = std::collections::HashSet::new();
                for event in events {
                    if !crate::hooks::EVENTS.contains(&event.as_str()) || !names.insert(event) {
                        return Err(format!(
                            "hook {:?}: invalid or duplicate event {event:?}",
                            hook.name
                        ));
                    }
                }
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
                events: hook.events,
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
            models,
            providers,
            tools,
            tool_base: None,
            default_provider,
            default_model: raw.default_model.filter(|model| !model.trim().is_empty()),
            log_file: raw.trace.file,
            log_level,
            max_tool_rounds,
            context,
            hooks,
        })
    }
}

/// The `gears.toml` files available when `--config` is not given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// `gears.toml` in the Gears directory.
    User(PathBuf),
    /// The Gears package Gears was built in, whose `config/gears.toml` ships.
    SourceTree(PathBuf),
    Both {
        user: PathBuf,
        package: PathBuf,
    },
    /// Neither; holds the Gears directory.
    Neither(PathBuf),
}

impl Found {
    pub fn detect() -> Self {
        let directory = crate::directory::default_root().unwrap_or_default();
        let user = directory.join("gears.toml");
        let package = std::env::current_exe()
            .ok()
            .and_then(|executable| source_tree_of(&executable));
        match (user.is_file(), package) {
            (true, Some(package)) => Self::Both { user, package },
            (true, None) => Self::User(user),
            (false, Some(package)) => Self::SourceTree(package),
            (false, None) => Self::Neither(directory),
        }
    }
}

/// The package directory when `executable` lies in its `target/` tree, as after
/// `cargo run` or `lorry run`; only the Gears package with its shipped
/// `config/gears.toml` counts.
fn source_tree_of(executable: &Path) -> Option<PathBuf> {
    let target = executable
        .ancestors()
        .find(|path| path.file_name() == Some("target".as_ref()))?;
    let package = target.parent()?;
    let manifest: toml::Table =
        toml::from_str(&std::fs::read_to_string(package.join("Cargo.toml")).ok()?).ok()?;
    let gears = manifest.get("package")?.get("name")?.as_str()? == "gears";
    (gears && package.join("config/gears.toml").is_file()).then(|| package.to_path_buf())
}

fn named_provider(
    label: &str,
    raw: RawProvider,
    egress_allowlist: &[String],
    plain_http_allowlist: &[String],
    base: Option<&Path>,
) -> Result<NamedProvider, String> {
    let base_url = raw
        .base_url
        .ok_or_else(|| format!("{label} needs base_url"))?;
    let endpoint = crate::provider::Endpoint::new(&base_url)
        .map_err(|error| format!("bad {label}.base_url: {error}"))?;
    let plain_http = endpoint.url().scheme() == crate::net::Scheme::Http;
    if plain_http {
        // Refuse at load time, so the user sees this rather than a key error
        // or a per-request refusal.
        crate::net::EgressPolicy::new(egress_allowlist)
            .with_plain_http_allowlist(plain_http_allowlist)
            .check(endpoint.url())
            .map_err(|error| {
                format!(
                    "{label}.base_url: {error}; list the host in both \
                     net.egress_allowlist and net.plain_http_allowlist"
                )
            })?;
    }
    let mut models = raw.models.unwrap_or_default();
    models.retain(|model| !model.trim().is_empty());
    Ok(NamedProvider {
        base_url,
        plain_http,
        model: raw.model.filter(|model| !model.trim().is_empty()),
        models,
        key_file: provider_path(raw.api_key_file, base)?,
        ca_cert: provider_path(raw.ca_cert, base)?,
        reasoning_echo: raw.reasoning_echo,
    })
}

fn provider_path(path: Option<PathBuf>, base: Option<&Path>) -> Result<Option<PathBuf>, String> {
    path.map(|path| {
        if path.is_absolute() {
            Ok(path)
        } else {
            base.map(|base| base.join(&path)).ok_or_else(|| {
                format!("provider path {} needs the Gears directory", path.display())
            })
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
        assert!(config.providers["default"].plain_http);
    }

    #[test]
    fn minimal_config_has_redesign_defaults() {
        let config = Config::parse("version = 1").unwrap();
        assert_eq!(config.max_tool_rounds, 32);
        assert_eq!(config.context.output_reserve_tokens, 16_384);
        assert!(config.hooks.is_empty());
        // No provider or host is built in; they come from the shipped gears.toml.
        assert!(config.provider("default").is_none());
        assert!(config.egress_allowlist.is_empty());
    }

    #[test]
    fn relative_key_files_live_in_the_gears_directory() {
        let directory = Path::new("/home/user/.gears");
        let config = Config::parse_in(
            "version = 1\n[provider]\nbase_url = 'https://one.test/v1'\nmodel = 'current'\napi_key_file = 'secrets/key'\nca_cert = 'ca.pem'\nmodels = ['a', '', 'b']\n",
            directory,
        )
        .unwrap();
        let provider = config.provider("default").unwrap();
        assert_eq!(provider.model.as_deref(), Some("current"));
        assert_eq!(provider.models, ["a", "b"]);
        assert_eq!(provider.key_file, Some(directory.join("secrets/key")));
        assert_eq!(provider.ca_cert, Some(directory.join("ca.pem")));
        assert!(Config::parse("version = 1\n[provider]\nmodel = 'm'").is_err());
    }

    #[test]
    fn saved_addresses_replace_provider_urls_and_allow_their_hosts() {
        let mut config = Config::parse_in(
            include_str!("../config/gears.toml"),
            Path::new("/user/cfg/gears"),
        )
        .unwrap();
        let urls = BTreeMap::from([
            (
                "local".to_string(),
                "http://192.168.4.1:8080/v1".to_string(),
            ),
            ("elsewhere".to_string(), "https://other.test/v1".to_string()),
        ]);
        config.apply_urls(&urls).unwrap();
        assert_eq!(
            config.providers["local"].base_url,
            "http://192.168.4.1:8080/v1"
        );
        assert!(config.providers["local"].plain_http);
        assert!(config.egress_allowlist.contains(&"192.168.4.1".to_string()));
        assert!(
            config
                .plain_http_allowlist
                .contains(&"192.168.4.1".to_string())
        );
        assert!(!config.egress_allowlist.contains(&"other.test".to_string()));
        let bad = BTreeMap::from([("local".to_string(), "not a url".to_string())]);
        assert!(config.apply_urls(&bad).is_err());
    }

    #[test]
    fn the_shipped_config_is_found_from_an_executable_in_the_package_target() {
        let root = std::env::temp_dir().join(format!("gears-source-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let package = root.join("gears");
        std::fs::create_dir_all(package.join("config")).unwrap();
        std::fs::create_dir_all(package.join("target/release")).unwrap();
        std::fs::write(package.join("Cargo.toml"), "[package]\nname = \"gears\"\n").unwrap();
        let executable = package.join("target/release/gears");
        assert_eq!(source_tree_of(&executable), None);
        std::fs::write(package.join("config/gears.toml"), "version = 1\n").unwrap();
        assert_eq!(source_tree_of(&executable), Some(package.clone()));
        assert_eq!(
            source_tree_of(&package.join("target/lorry/debug/gears")),
            Some(package.clone())
        );
        assert_eq!(source_tree_of(&root.join("bin/gears")), None);
        std::fs::write(package.join("Cargo.toml"), "[package]\nname = \"other\"\n").unwrap();
        assert_eq!(source_tree_of(&executable), None);
        let config = Config::load_found(&Found::SourceTree(package.clone()), false).unwrap();
        assert_eq!(config.tool_base, Some(package.clone()));
        let user = root.join("user.toml");
        std::fs::write(&user, "version = 1\n").unwrap();
        let both = Found::Both {
            user,
            package: package.clone(),
        };
        assert_eq!(Config::load_found(&both, false).unwrap().tool_base, None);
        assert_eq!(
            Config::load_found(&both, true).unwrap().tool_base,
            Some(package)
        );
        let error = Config::load_found(&Found::Neither(root.clone()), false).unwrap_err();
        assert!(error.contains("no gears.toml"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_keys_are_refused_in_every_section() {
        for text in [
            "version = 1\nunknown = 1",
            "version = 1\n[after_turn]\ncommand = ['/review']",
            "version = 1\n[provider]\nkey_file = '/secret/key'",
            "version = 1\n[providers.local]\nbase_url = 'https://local.test/v1'\nmodle = 'm'",
            "version = 1\n[runtime]\nsh_timeout_seconds = 5",
            "version = 1\n[net]\negress = ['a.test']",
            "version = 1\n[[tools]]\ndirectory = 'tools/sh'\nenabled = true\nname = 'sh'",
            "version = 1\n[[hooks]]\nname = 'h'\ncommand = ['/h']\nevent = ['initialize']",
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(error.contains("unknown field"), "{text}: {error}");
        }
    }

    #[test]
    fn shipped_batteries_config_loads_both_providers_and_hook() {
        let config = Config::parse_in(
            include_str!("../config/gears-batteries.toml"),
            Path::new("/user/cfg/gears"),
        )
        .unwrap();
        assert_eq!(config.default_provider, "openrouter");
        assert!(config.providers["local"].plain_http);
        assert_eq!(config.providers["local"].key_file, None);
        assert_eq!(
            config.providers["openrouter"].key_file,
            Some(PathBuf::from("/user/cfg/gears/openrouter.key"))
        );
        assert_eq!(
            config.providers.keys().collect::<Vec<_>>(),
            ["local", "openai", "openrouter"]
        );
        assert!(
            config
                .providers
                .values()
                .all(|provider| !provider.models.is_empty())
        );
        let plain = Config::parse_in(
            include_str!("../config/gears.toml"),
            Path::new("/user/cfg/gears"),
        )
        .unwrap();
        assert_eq!(plain.providers, config.providers);
        assert_eq!(config.hooks[0].command, ["gears-batteries", "hook"]);
        assert!(config.tools.iter().all(|tool| tool.enabled));
    }

    #[test]
    fn named_providers_are_validated_and_have_a_selected_default() {
        let path = Path::new("/tmp/gears-test-config");
        let config = Config::parse_in(
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
reasoning_echo = true
[providers.remote]
base_url = 'https://openrouter.ai/api/v1'
reasoning_echo = false
"#,
            path,
        )
        .unwrap();
        assert_eq!(config.default_provider, "local");
        assert_eq!(config.default_model.as_deref(), Some("small"));
        assert_eq!(config.providers.len(), 2);
        assert!(config.providers["local"].plain_http);
        assert_eq!(config.providers["local"].reasoning_echo, Some(true));
        assert_eq!(config.providers["remote"].reasoning_echo, Some(false));
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
    fn tool_directories_are_explicit_and_ordered() {
        let config = Config::parse(
            r#"version = 1
[[tools]]
directory = 'tools/sh'
enabled = true
[[tools]]
directory = '/opt/gears/ls'
enabled = false
"#,
        )
        .unwrap();
        assert_eq!(config.tools.len(), 2);
        assert_eq!(config.tools[0].directory, PathBuf::from("tools/sh"));
        assert!(config.tools[0].enabled);
        assert_eq!(config.tools[1].directory, PathBuf::from("/opt/gears/ls"));
        assert!(!config.tools[1].enabled);
        assert!(Config::default().tools.is_empty());
        assert!(Config::parse("version = 1\n[[tools]]\ndirectory = 'tools/sh'").is_err());
        assert!(
            Config::parse("version = 1\n[[tools]]\ndirectory = '../sh'\nenabled = true").is_err()
        );
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
    fn hook_event_filters_are_explicit_and_validated() {
        let all = serde_json::to_string(crate::hooks::EVENTS).unwrap();
        assert!(
            Config::parse(&format!(
                "version = 1\n[[hooks]]\nname = 'policy'\ncommand = ['/hook']\nevents = {all}"
            ))
            .is_ok()
        );
        let config = Config::parse("version = 1\n[[hooks]]\nname = 'policy'\ncommand = ['/hook']\nevents = ['permission', 'tool_result']").unwrap();
        assert_eq!(
            config.hooks[0].events.as_deref().unwrap(),
            ["permission", "tool_result"]
        );
        for events in ["['typo']", "['permission', 'permission']"] {
            assert!(Config::parse(&format!("version = 1\n[[hooks]]\nname = 'policy'\ncommand = ['/hook']\nevents = {events}")).is_err());
        }
        let empty = Config::parse(
            "version = 1\n[[hooks]]\nname = 'policy'\ncommand = ['/hook']\nevents = []",
        )
        .unwrap();
        assert_eq!(empty.hooks[0].events, Some(Vec::new()));
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
