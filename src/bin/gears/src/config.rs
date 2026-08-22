//! gears configuration: a small TOML file, serde-derived. The russhd idiom:
//! a versioned raw struct (`ConfigV1`), then a separate validation pass into
//! the [`Config`] the rest of the program sees. Unknown fields are tolerated
//! so newer configs still load in older binaries (the self-restart story).

use std::collections::HashSet;
use std::io::Write;
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize, Debug, Default)]
struct NetV1 {
    // `None` (absent) means the default allowlist; an explicit `[]` means no
    // egress at all.
    egress_allowlist: Option<Vec<String>>,
    allow_plain_http_loopback: Option<bool>,
}

#[derive(Deserialize, Debug, Default)]
struct ProviderV1 {
    base_url: Option<String>,
    model: Option<String>,
    key_file: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Default)]
struct ModelsV1 {
    last: Option<String>,
    used: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Default)]
struct TraceV1 {
    file: Option<PathBuf>,
    level: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct PermissionsV1 {
    mode: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
struct ToolsV1 {
    run_timeout_seconds: Option<u64>,
    build_timeout_seconds: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
struct SelfHostV1 {
    enabled: Option<bool>,
    install: Option<PathBuf>,
}

#[derive(Deserialize, Debug, Default)]
struct ContextV1 {
    budget_tokens: Option<u64>,
    summarize: Option<bool>,
}

#[derive(Deserialize, Debug, Default)]
struct ResourcesV1 {
    max_artifact_bytes: Option<u64>,
    max_session_artifact_bytes: Option<u64>,
    max_live_render_queue_bytes: Option<u64>,
    max_range_read_bytes: Option<u64>,
    max_inline_attachment_bytes: Option<u64>,
    search_default_results: Option<u64>,
    search_max_results_per_page: Option<u64>,
    regex_size_limit_bytes: Option<u64>,
    regex_dfa_size_limit_bytes: Option<u64>,
    regex_nest_limit: Option<u64>,
    search_max_file_bytes: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
struct QualityV1 {
    max_regression_percent: Option<u64>,
    stable_samples: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
struct LimitsV1 {
    max_steps: Option<usize>,
    budget_usd: Option<f64>,
    budget_tokens: Option<u64>,
}

#[derive(Deserialize, Debug, Default)]
struct AgentsV1 {
    max_depth: Option<usize>,
    max_concurrent: Option<usize>,
    budget_usd: Option<f64>,
    budget_tokens: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct ConfigV1 {
    version: u32, // Must be 1.
    #[serde(default)]
    net: NetV1,
    #[serde(default)]
    provider: ProviderV1,
    #[serde(default)]
    models: ModelsV1,
    #[serde(default)]
    trace: TraceV1,
    #[serde(default)]
    permissions: PermissionsV1,
    #[serde(default)]
    tools: ToolsV1,
    #[serde(default)]
    limits: LimitsV1,
    #[serde(default)]
    agents: AgentsV1,
    #[serde(default)]
    context: ContextV1,
    #[serde(default)]
    resources: ResourcesV1,
    #[serde(default)]
    quality: QualityV1,
    #[serde(default)]
    selfhost: SelfHostV1,
}

/// Bounds shared by artifact, checkpoint, search, attachment, and rendering paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    pub max_artifact_bytes: usize,
    pub max_session_artifact_bytes: usize,
    pub max_live_render_queue_bytes: usize,
    pub max_range_read_bytes: usize,
    pub max_inline_attachment_bytes: usize,
    pub search_default_results: usize,
    pub search_max_results_per_page: usize,
    pub regex_size_limit_bytes: usize,
    pub regex_dfa_size_limit_bytes: usize,
    pub regex_nest_limit: usize,
    pub search_max_file_bytes: usize,
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 16_777_216,
            max_session_artifact_bytes: 268_435_456,
            max_live_render_queue_bytes: 1_048_576,
            max_range_read_bytes: 1_048_576,
            max_inline_attachment_bytes: 65_536,
            search_default_results: 100,
            search_max_results_per_page: 1_000,
            regex_size_limit_bytes: 10_485_760,
            regex_dfa_size_limit_bytes: 2_097_152,
            regex_nest_limit: 250,
            search_max_file_bytes: 16_777_216,
        }
    }
}

/// Policy used by the explicit performance-quality gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quality {
    pub max_regression_percent: u64,
    pub stable_samples: usize,
}

impl Default for Quality {
    fn default() -> Self {
        Self {
            max_regression_percent: 10,
            stable_samples: 3,
        }
    }
}

/// Validated configuration; `Default` is what gears runs with when the
/// default config file does not exist. Not `Eq`: a spend budget is money, and
/// money is a float here because that is what the endpoint reports.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Host names the network layer may talk to; it refuses everything else.
    pub egress_allowlist: Vec<String>,
    /// **Tests only, and loudly so.** Lets the network layer speak plain HTTP
    /// to a loopback address — which is what the scripted mock endpoint in
    /// gears' own test suite serves. Real traffic is HTTPS, the allowlist
    /// still applies, and on Motor OS the curl crate refuses plain HTTP
    /// outright, so nothing built on this can quietly become the real path.
    pub allow_plain_http_loopback: bool,
    /// The API root of an OpenAI-compatible endpoint.
    pub base_url: String,
    /// Default model id. There is no built-in default: which model to drive
    /// is the user's decision, and guessing one that does not exist at their
    /// endpoint helps nobody.
    pub model: Option<String>,
    /// Models previously selected by the user, most recently used first.
    pub models: Vec<String>,
    /// Key file, when it is not at the default path.
    pub key_file: Option<PathBuf>,
    /// Optional provider-only CA bundle, passed to either curl backend.
    pub ca_cert: Option<PathBuf>,
    /// Trace destination; `--log-file` overrides it.
    pub log_file: Option<PathBuf>,
    pub log_level: crate::trace::Level,
    /// Whether mutating tool calls are put to the user.
    pub permissions: crate::agent::gate::Mode,
    /// How long `run` waits for a command, and `build`/`test` for a compiler
    /// — which needs minutes rather than seconds.
    pub run_timeout: std::time::Duration,
    pub build_timeout: std::time::Duration,
    /// What one run of gears may do: tool rounds in a turn, and what the whole
    /// run may spend. Uncapped unless the user says otherwise — but a quota is
    /// finite whether or not gears knows the number.
    pub run: crate::agent::turn::RunLimits,
    /// What sub-agents are allowed: how deep, how many at once, how much. A
    /// pocket inside `run`, not a second budget beside it.
    pub agents: crate::agent::registry::Limits,
    /// What the model's context window will take, which nothing but the user
    /// can tell gears.
    pub context: crate::agent::context::Policy,
    /// Bounded resources used by output, artifact, and repository tools.
    pub resources: Resources,
    /// Sampling and regression policy for the explicit quality gate.
    pub quality: Quality,
    /// What gears may do to itself: build a new version, install it, restart
    /// into it. Off unless the user says otherwise.
    pub selfhost: crate::tools::selfhost::Policy,
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
            permissions: crate::agent::gate::Mode::Ask,
            run_timeout: crate::tools::run::DEFAULT_TIMEOUT,
            build_timeout: crate::tools::run::DEFAULT_BUILD_TIMEOUT,
            run: crate::agent::turn::RunLimits::default(),
            agents: crate::agent::registry::Limits::default(),
            context: crate::agent::context::Policy::default(),
            resources: Resources::default(),
            quality: Quality::default(),
            selfhost: crate::tools::selfhost::Policy::default(),
        }
    }
}

impl Config {
    /// Where the config file lives by default, or `None` on a platform we
    /// have no location for (gears then runs with the defaults).
    pub fn default_path() -> Option<PathBuf> {
        // Motor OS sets no target family, so `unix` below is never true
        // there; the `not(motor)` guard just keeps the two arms exclusive if
        // that ever changes.
        #[cfg(target_os = "motor")]
        {
            Some(PathBuf::from("/user/cfg/gears.toml"))
        }

        #[cfg(all(unix, not(target_os = "motor")))]
        {
            std::env::home_dir().map(|home| home.join(".config/gears.toml"))
        }

        #[cfg(not(any(target_os = "motor", unix)))]
        {
            None
        }
    }

    /// Load the config: from `explicit` if given (missing then being an
    /// error), else from the default path (missing then meaning defaults).
    pub fn load(explicit: Option<&Path>) -> Result<Config, String> {
        Self::load_user(explicit).map(|(config, _models)| config)
    }

    /// Load configuration together with the user-level model preference store.
    pub fn load_user(explicit: Option<&Path>) -> Result<(Config, ModelStore), String> {
        let (path, required) = match explicit {
            Some(path) => (path.to_path_buf(), true),
            None => match Self::default_path() {
                Some(path) => (path, false),
                None => {
                    return Ok((
                        Config::default(),
                        ModelStore {
                            path: None,
                            required: false,
                            models: Vec::new(),
                        },
                    ));
                }
            },
        };
        let config = match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
                Ok(Config::default())
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }?;
        let store = ModelStore {
            path: Some(path),
            required,
            models: config.models.clone(),
        };
        Ok((config, store))
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let raw: ConfigV1 = toml::from_str(text).map_err(|e| e.to_string())?;
        if raw.version != 1 {
            return Err(format!(
                "unsupported config version {} (expected 1)",
                raw.version
            ));
        }
        let egress_allowlist = match raw.net.egress_allowlist {
            None => Config::default().egress_allowlist,
            Some(hosts) => hosts
                .iter()
                .map(|host| validate_host(host))
                .collect::<Result<_, _>>()?,
        };
        let base_url = match raw.provider.base_url {
            None => Config::default().base_url,
            // Parsed here so a typo fails at startup rather than at the first
            // completion; the host must also be on the allowlist, which the
            // network layer enforces on its own.
            Some(url) => match crate::provider::Endpoint::new(&url) {
                Ok(_) => url,
                Err(e) => return Err(format!("bad provider.base_url: {e}")),
            },
        };
        let log_level = match raw.trace.level.as_deref() {
            None => Config::default().log_level,
            Some(name) => crate::trace::Level::parse(name).ok_or_else(|| {
                format!(
                    "bad trace level '{name}' (expected one of: {})",
                    crate::trace::Level::NAMES
                )
            })?,
        };
        if let Some(path) = &raw.provider.ca_cert
            && !path.is_absolute()
        {
            return Err("provider.ca_cert must be an absolute path".to_string());
        }
        let permissions = match raw.permissions.mode.as_deref() {
            None => Config::default().permissions,
            Some(name) => crate::agent::gate::Mode::parse(name).ok_or_else(|| {
                format!(
                    "bad permissions mode '{name}' (expected one of: {})",
                    crate::agent::gate::Mode::NAMES
                )
            })?,
        };
        let provider_model = raw
            .provider
            .model
            .map(|model| validate_model_id(&model))
            .transpose()?;
        let last = raw
            .models
            .last
            .map(|model| validate_model_id(&model))
            .transpose()?;
        let mut models = raw
            .models
            .used
            .unwrap_or_default()
            .into_iter()
            .map(|model| validate_model_id(&model))
            .collect::<Result<Vec<_>, _>>()?;
        deduplicate(&mut models);
        let model = last.or_else(|| provider_model.clone());
        if let Some(model) = &model {
            remember_in(&mut models, model);
        }
        if let Some(provider_model) = provider_model
            && !models.contains(&provider_model)
        {
            models.push(provider_model);
        }
        Ok(Config {
            egress_allowlist,
            allow_plain_http_loopback: raw.net.allow_plain_http_loopback.unwrap_or(false),
            base_url,
            model,
            models,
            key_file: raw.provider.key_file,
            ca_cert: raw.provider.ca_cert,
            log_file: raw.trace.file,
            log_level,
            permissions,
            run_timeout: timeout(
                raw.tools.run_timeout_seconds,
                "run_timeout_seconds",
                Config::default().run_timeout,
            )?,
            build_timeout: timeout(
                raw.tools.build_timeout_seconds,
                "build_timeout_seconds",
                Config::default().build_timeout,
            )?,
            run: run(&raw.limits)?,
            agents: limits(&raw.agents)?,
            context: context(&raw.context)?,
            resources: resources(&raw.resources)?,
            quality: quality(&raw.quality)?,
            selfhost: crate::tools::selfhost::Policy {
                enabled: raw.selfhost.enabled.unwrap_or(false),
                install: raw.selfhost.install,
            },
        })
    }
}

const MAX_MODEL_ID_BYTES: usize = 1024;

pub(crate) fn validate_model_id(model: &str) -> Result<String, String> {
    if model.is_empty() || model.trim() != model {
        return Err("bad model id: expected non-empty text without surrounding whitespace".into());
    }
    if model.len() > MAX_MODEL_ID_BYTES {
        return Err(format!(
            "bad model id: {} bytes exceeds the {MAX_MODEL_ID_BYTES}-byte limit",
            model.len()
        ));
    }
    if model.chars().any(char::is_control) {
        return Err("bad model id: control characters are not allowed".into());
    }
    Ok(model.to_string())
}

fn deduplicate(models: &mut Vec<String>) {
    let mut seen = HashSet::with_capacity(models.len());
    let mut unique = Vec::with_capacity(models.len());
    for model in std::mem::take(models) {
        if seen.insert(model.clone()) {
            unique.push(model);
        }
    }
    *models = unique;
}

fn remember_in(models: &mut Vec<String>, model: &str) {
    models.retain(|used| used != model);
    models.insert(0, model.to_string());
}

/// The small, user-level part of configuration that Gears updates itself.
pub struct ModelStore {
    path: Option<PathBuf>,
    required: bool,
    models: Vec<String>,
}

impl ModelStore {
    pub fn choices(&self, current: &str) -> Vec<String> {
        let mut models = self.models.clone();
        remember_in(&mut models, current);
        models
    }

    /// Make `model` the remembered default without changing unrelated TOML.
    pub fn remember(&mut self, model: &str) -> Result<(), String> {
        let model = validate_model_id(model)?;
        let path = self
            .path
            .as_deref()
            .ok_or("cannot remember a model: this platform has no user config path")?;
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !self.required => {
                "version = 1\n".to_string()
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        let config =
            Config::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut models = config.models;
        remember_in(&mut models, &model);

        let mut document: toml::Value =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let root = document
            .as_table_mut()
            .ok_or_else(|| format!("{}: config root is not a table", path.display()))?;
        let mut table = match root.get("models") {
            Some(value) => value
                .as_table()
                .cloned()
                .ok_or_else(|| format!("{}: models is not a table", path.display()))?,
            None => toml::Table::new(),
        };
        table.insert("last".into(), toml::Value::String(model));
        table.insert(
            "used".into(),
            toml::Value::Array(models.iter().cloned().map(toml::Value::String).collect()),
        );
        let updated = replace_models_table(&text, table, root.contains_key("models"))?;
        Config::parse(&updated).map_err(|error| format!("{}: {error}", path.display()))?;
        atomic_write(path, updated.as_bytes())?;
        self.models = models;
        Ok(())
    }
}

fn replace_models_table(text: &str, table: toml::Table, existed: bool) -> Result<String, String> {
    let body = toml::to_string(&table).map_err(|error| error.to_string())?;
    let rendered = format!("[models]\n{body}");
    match table_range(text, "[models]") {
        Some(range) => {
            let mut updated = String::with_capacity(text.len() + rendered.len());
            updated.push_str(&text[..range.start]);
            updated.push_str(&rendered);
            if range.end < text.len() && !rendered.ends_with("\n\n") {
                updated.push('\n');
            }
            updated.push_str(&text[range.end..]);
            Ok(updated)
        }
        None if existed => Err(
            "the models table must use a standalone [models] header for Gears to update it".into(),
        ),
        None => {
            let mut updated = text.to_string();
            if !updated.ends_with('\n') {
                updated.push('\n');
            }
            if !updated.ends_with("\n\n") {
                updated.push('\n');
            }
            updated.push_str(&rendered);
            Ok(updated)
        }
    }
}

fn table_range(text: &str, wanted: &str) -> Option<Range<usize>> {
    let mut offset = 0;
    let mut start = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        let header = trimmed.starts_with('[') && trimmed.ends_with(']');
        if let Some(start) = start
            && header
        {
            return Some(start..offset);
        }
        if trimmed == wanted {
            start = Some(offset);
        }
        offset += line.len();
    }
    start.map(|start| start..text.len())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("gears.toml");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let staging = path.with_file_name(format!(".{name}.{}.{nonce}.new", std::process::id()));
    let permissions = std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|error| format!("{}: {error}", staging.display()))?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)
                .map_err(|error| format!("{}: {error}", staging.display()))?;
        }
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .map_err(|error| format!("{}: {error}", staging.display()))?;
        drop(file);
        std::fs::rename(&staging, path).map_err(|error| format!("{}: {error}", path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    result
}

fn quality(raw: &QualityV1) -> Result<Quality, String> {
    let default = Quality::default();
    let samples = raw.stable_samples.unwrap_or(default.stable_samples as u64);
    let stable_samples = usize::try_from(samples)
        .map_err(|_| format!("bad quality.stable_samples {samples} (too large for this system)"))?;
    if stable_samples < 3 {
        return Err(format!(
            "bad quality.stable_samples {stable_samples} (expected at least 3)"
        ));
    }
    Ok(Quality {
        max_regression_percent: raw
            .max_regression_percent
            .unwrap_or(default.max_regression_percent),
        stable_samples,
    })
}

fn resources(raw: &ResourcesV1) -> Result<Resources, String> {
    let default = Resources::default();
    let value = |configured: Option<u64>, name: &str, fallback: usize| {
        let configured = configured.unwrap_or(fallback as u64);
        let value = usize::try_from(configured).map_err(|_| {
            format!("bad resources.{name} {configured} (too large for this system)")
        })?;
        if value == 0 {
            return Err(format!("bad resources.{name} 0 (expected more than zero)"));
        }
        Ok(value)
    };
    let resources = Resources {
        max_artifact_bytes: value(
            raw.max_artifact_bytes,
            "max_artifact_bytes",
            default.max_artifact_bytes,
        )?,
        max_session_artifact_bytes: value(
            raw.max_session_artifact_bytes,
            "max_session_artifact_bytes",
            default.max_session_artifact_bytes,
        )?,
        max_live_render_queue_bytes: value(
            raw.max_live_render_queue_bytes,
            "max_live_render_queue_bytes",
            default.max_live_render_queue_bytes,
        )?,
        max_range_read_bytes: value(
            raw.max_range_read_bytes,
            "max_range_read_bytes",
            default.max_range_read_bytes,
        )?,
        max_inline_attachment_bytes: value(
            raw.max_inline_attachment_bytes,
            "max_inline_attachment_bytes",
            default.max_inline_attachment_bytes,
        )?,
        search_default_results: value(
            raw.search_default_results,
            "search_default_results",
            default.search_default_results,
        )?,
        search_max_results_per_page: value(
            raw.search_max_results_per_page,
            "search_max_results_per_page",
            default.search_max_results_per_page,
        )?,
        regex_size_limit_bytes: value(
            raw.regex_size_limit_bytes,
            "regex_size_limit_bytes",
            default.regex_size_limit_bytes,
        )?,
        regex_dfa_size_limit_bytes: value(
            raw.regex_dfa_size_limit_bytes,
            "regex_dfa_size_limit_bytes",
            default.regex_dfa_size_limit_bytes,
        )?,
        regex_nest_limit: value(
            raw.regex_nest_limit,
            "regex_nest_limit",
            default.regex_nest_limit,
        )?,
        search_max_file_bytes: value(
            raw.search_max_file_bytes,
            "search_max_file_bytes",
            default.search_max_file_bytes,
        )?,
    };
    if resources.max_artifact_bytes > resources.max_session_artifact_bytes {
        return Err(
            "bad resources.max_artifact_bytes: exceeds max_session_artifact_bytes".to_string(),
        );
    }
    if resources.search_default_results > resources.search_max_results_per_page {
        return Err(
            "bad resources.search_default_results: exceeds search_max_results_per_page".to_string(),
        );
    }
    if u32::try_from(resources.regex_nest_limit).is_err() {
        return Err("bad resources.regex_nest_limit: exceeds the regex engine limit".to_string());
    }
    Ok(resources)
}

/// The context budget. Zero is the spelling for "manage nothing" — unlike a
/// sub-agent budget there is no other one — and anything between zero and the
/// floor is a window the system prompt alone would not fit in.
fn context(raw: &ContextV1) -> Result<crate::agent::context::Policy, String> {
    let budget = match raw.budget_tokens {
        None => crate::agent::context::DEFAULT_BUDGET,
        Some(0) => 0,
        Some(tokens) if tokens >= MIN_CONTEXT => tokens,
        Some(tokens) => {
            return Err(format!(
                "bad context.budget_tokens {tokens} (expected 0 to turn it off, \
                 or at least {MIN_CONTEXT})"
            ));
        }
    };
    Ok(crate::agent::context::Policy {
        budget,
        summarize: raw
            .summarize
            .unwrap_or(crate::agent::context::Policy::default().summarize),
    })
}

/// The smallest window worth managing.
const MIN_CONTEXT: u64 = 8_000;

/// What one run may do. Both budgets are off unless set: gears cannot know
/// what the user's quota is, and inventing a number would stop honest work as
/// often as it saved anything. A budget of nothing is refused for the reason
/// the sub-agent one is — it is a way of saying "do not run", which is spelled
/// by not running gears.
fn run(raw: &LimitsV1) -> Result<crate::agent::turn::RunLimits, String> {
    let default = crate::agent::turn::RunLimits::default();
    let max_steps = match raw.max_steps {
        None => default.max_steps,
        Some(steps) if (1..=MAX_STEPS).contains(&steps) => steps,
        Some(steps) => {
            return Err(format!(
                "bad limits.max_steps {steps} (expected 1 to {MAX_STEPS})"
            ));
        }
    };
    if raw.budget_usd.is_some_and(|usd| usd <= 0.0) {
        return Err("bad limits.budget_usd: expected more than zero".to_string());
    }
    if raw.budget_tokens == Some(0) {
        return Err("bad limits.budget_tokens: expected more than zero".to_string());
    }
    Ok(crate::agent::turn::RunLimits {
        max_steps,
        budget_usd: raw.budget_usd,
        budget_tokens: raw.budget_tokens,
    })
}

/// A ceiling on the ceiling. A turn that took a thousand tool rounds is not a
/// turn that needed one more.
const MAX_STEPS: usize = 1_000;

/// What sub-agents are allowed. The bounds are not arithmetic — they are what
/// a user could have meant: a depth of 9 is a typo, and a budget of nothing
/// is a way of saying no sub-agents that already has a spelling (`max_depth =
/// 0`), so it is refused rather than silently obeyed.
fn limits(raw: &AgentsV1) -> Result<crate::agent::registry::Limits, String> {
    let default = crate::agent::registry::Limits::default();
    let bounded = |value: Option<usize>, name: &str, max: usize, default: usize| match value {
        None => Ok(default),
        Some(value) if value <= max => Ok(value),
        Some(value) => Err(format!("bad agents.{name} {value} (expected 0 to {max})")),
    };
    if raw.budget_usd.is_some_and(|usd| usd <= 0.0) {
        return Err("bad agents.budget_usd: expected more than zero".to_string());
    }
    if raw.budget_tokens == Some(0) {
        return Err("bad agents.budget_tokens: expected more than zero".to_string());
    }
    Ok(crate::agent::registry::Limits {
        depth: bounded(raw.max_depth, "max_depth", MAX_DEPTH, default.depth)?,
        concurrent: match bounded(
            raw.max_concurrent,
            "max_concurrent",
            MAX_CONCURRENT,
            default.concurrent,
        )? {
            0 => return Err("bad agents.max_concurrent 0 (use max_depth = 0)".to_string()),
            value => value,
        },
        budget_usd: raw.budget_usd,
        budget_tokens: raw.budget_tokens,
    })
}

/// Ceilings on the ceilings. Agents nest, and each one is a thread and a bill.
const MAX_DEPTH: usize = 4;
const MAX_CONCURRENT: usize = 32;

/// A configured timeout, bounded by what gears is prepared to wait for at all.
fn timeout(
    seconds: Option<u64>,
    name: &str,
    default: std::time::Duration,
) -> Result<std::time::Duration, String> {
    let Some(seconds) = seconds else {
        return Ok(default);
    };
    let asked = std::time::Duration::from_secs(seconds);
    if asked.is_zero() || asked > crate::tools::run::MAX_TIMEOUT {
        return Err(format!(
            "bad tools.{name} {seconds} (expected 1 to {})",
            crate::tools::run::MAX_TIMEOUT.as_secs()
        ));
    }
    Ok(asked)
}

/// Allowlist entries are bare host names — no scheme, port, path or spaces —
/// normalized to lowercase so the network layer can compare them directly.
fn validate_host(host: &str) -> Result<String, String> {
    let bare = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if !bare {
        return Err(format!(
            "bad egress_allowlist entry '{host}': expected a bare host name"
        ));
    }
    Ok(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_store_path(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};

        static NEXT: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir()
            .join(format!(
                "gears-model-store-{}-{}-{name}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
            .join("gears.toml")
    }

    #[test]
    fn full_file_parses() {
        let config = Config::parse(
            r#"
            version = 1
            [net]
            egress_allowlist = ["openrouter.ai", "api.example.com"]
            "#,
        )
        .unwrap();
        assert_eq!(
            config.egress_allowlist,
            ["openrouter.ai", "api.example.com"]
        );
    }

    #[test]
    fn minimal_file_gets_defaults() {
        let config = Config::parse("version = 1").unwrap();
        assert_eq!(config, Config::default());
        assert_eq!(config.egress_allowlist, ["openrouter.ai"]);
    }

    #[test]
    fn empty_allowlist_means_no_egress() {
        let config = Config::parse("version = 1\n[net]\negress_allowlist = []").unwrap();
        assert!(config.egress_allowlist.is_empty());
    }

    #[test]
    fn version_is_mandatory_and_checked() {
        assert!(Config::parse("").is_err());
        let err = Config::parse("version = 2").unwrap_err();
        assert!(err.contains("version 2"), "{err}");
    }

    #[test]
    fn host_entries_are_validated_and_normalized() {
        for bad in ["https://x.com", "x.com/path", "x.com:443", "a b", ""] {
            let text = format!("version = 1\n[net]\negress_allowlist = [\"{bad}\"]");
            assert!(Config::parse(&text).is_err(), "accepted '{bad}'");
        }
        let config =
            Config::parse("version = 1\n[net]\negress_allowlist = [\"OpenRouter.AI\"]").unwrap();
        assert_eq!(config.egress_allowlist, ["openrouter.ai"]);
    }

    #[test]
    fn provider_section_parses() {
        let config = Config::parse(
            r#"
            version = 1
            [provider]
            base_url = "http://127.0.0.1:8099/v1"
            model = "anthropic/claude-sonnet-4.5"
            key_file = "/keys/openrouter.key"
            ca_cert = "/keys/test-ca.pem"
            "#,
        )
        .unwrap();
        assert_eq!(config.base_url, "http://127.0.0.1:8099/v1");
        assert_eq!(config.model.as_deref(), Some("anthropic/claude-sonnet-4.5"));
        assert_eq!(config.key_file, Some(PathBuf::from("/keys/openrouter.key")));
        assert_eq!(config.ca_cert, Some(PathBuf::from("/keys/test-ca.pem")));

        // The default endpoint, and no model until the user names one.
        let config = Config::parse("version = 1").unwrap();
        assert_eq!(config.base_url, "https://openrouter.ai/api/v1");
        assert_eq!(config.model, None);
    }

    #[test]
    fn remembered_model_has_precedence_and_history_is_deduplicated() {
        let config = Config::parse(
            r#"
            version = 1
            [provider]
            model = "legacy"
            [models]
            last = "current"
            used = ["older", "current", "older"]
            "#,
        )
        .unwrap();
        assert_eq!(config.model.as_deref(), Some("current"));
        assert_eq!(config.models, ["current", "older", "legacy"]);

        for bad in ["", " leading", "trailing ", "line\nbreak"] {
            let text = format!("version = 1\n[models]\nlast = {bad:?}");
            assert!(Config::parse(&text).is_err(), "accepted {bad:?}");
        }
        let long = "m".repeat(MAX_MODEL_ID_BYTES + 1);
        let text = format!("version = 1\n[models]\nlast = {long:?}");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn remembering_models_preserves_unmanaged_configuration() {
        let path = model_store_path("preserve");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "# keep this comment\nversion = 1\nfuture = true\n\
             [provider]\nmodel = \"legacy\"\n\
             [models]\nlast = \"older\"\nused = [\"older\", \"legacy\"]\nextra = 7\n\
             [future_table]\nname = \"untouched\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let (_, mut store) = Config::load_user(Some(&path)).unwrap();
        store.remember("new/model").unwrap();
        store.remember("legacy").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# keep this comment"), "{text}");
        assert!(
            text.contains("[future_table]\nname = \"untouched\""),
            "{text}"
        );
        assert_eq!(text.matches("[models]").count(), 1, "{text}");
        assert!(text.contains("extra = 7"), "{text}");
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.model.as_deref(), Some("legacy"));
        assert_eq!(config.models, ["legacy", "new/model", "older"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn remembering_first_model_creates_the_user_config() {
        let path = model_store_path("create");
        let mut store = ModelStore {
            path: Some(path.clone()),
            required: false,
            models: Vec::new(),
        };
        store.remember("first").unwrap();

        let config = Config::load(Some(&path)).unwrap();
        assert_eq!(config.model.as_deref(), Some("first"));
        assert_eq!(config.models, ["first"]);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn an_inline_models_table_is_not_destructively_reformatted() {
        let path = model_store_path("inline");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = "version = 1\nmodels = { last = \"old\", used = [\"old\"] }\n";
        std::fs::write(&path, original).unwrap();
        let (_, mut store) = Config::load_user(Some(&path)).unwrap();
        let error = store.remember("new").unwrap_err();
        assert!(error.contains("standalone [models]"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_bad_base_url_fails_at_startup() {
        let err =
            Config::parse("version = 1\n[provider]\nbase_url = \"openrouter.ai\"").unwrap_err();
        assert!(err.contains("base_url"), "{err}");
    }

    #[test]
    fn a_provider_ca_path_must_be_absolute() {
        let err = Config::parse("version = 1\n[provider]\nca_cert = \"relative.pem\"").unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn the_loopback_carve_out_is_off_unless_asked_for() {
        assert!(
            !Config::parse("version = 1")
                .unwrap()
                .allow_plain_http_loopback
        );
        assert!(
            Config::parse("version = 1\n[net]\nallow_plain_http_loopback = true")
                .unwrap()
                .allow_plain_http_loopback
        );
    }

    #[test]
    fn trace_section_parses() {
        let config =
            Config::parse("version = 1\n[trace]\nfile = \"/tmp/g.log\"\nlevel = \"debug\"")
                .unwrap();
        assert_eq!(config.log_file, Some(PathBuf::from("/tmp/g.log")));
        assert_eq!(config.log_level, crate::trace::Level::Debug);
    }

    #[test]
    fn bad_trace_level_is_rejected() {
        let err = Config::parse("version = 1\n[trace]\nlevel = \"loud\"").unwrap_err();
        assert!(err.contains("loud"), "{err}");
        assert!(err.contains("debug"), "{err}");
    }

    #[test]
    fn the_permission_mode_parses_and_defaults_to_asking() {
        use crate::agent::gate::Mode;
        assert_eq!(Config::parse("version = 1").unwrap().permissions, Mode::Ask);
        assert_eq!(
            Config::parse("version = 1\n[permissions]\nmode = \"auto-approve\"")
                .unwrap()
                .permissions,
            Mode::AutoApprove
        );
        let err = Config::parse("version = 1\n[permissions]\nmode = \"yolo\"").unwrap_err();
        assert!(err.contains("yolo"), "{err}");
        assert!(err.contains("auto-approve"), "{err}");
    }

    #[test]
    fn tool_timeouts_parse_and_are_bounded() {
        use std::time::Duration;
        let config = Config::parse(
            "version = 1\n[tools]\nrun_timeout_seconds = 30\nbuild_timeout_seconds = 1800",
        )
        .unwrap();
        assert_eq!(config.run_timeout, Duration::from_secs(30));
        assert_eq!(config.build_timeout, Duration::from_secs(1800));

        // A build is given minutes by default, a command seconds.
        let config = Config::parse("version = 1").unwrap();
        assert!(config.build_timeout > config.run_timeout);

        for bad in ["run_timeout_seconds = 0", "build_timeout_seconds = 99999"] {
            let err = Config::parse(&format!("version = 1\n[tools]\n{bad}")).unwrap_err();
            assert!(err.contains("expected 1 to 3600"), "{bad}: {err}");
        }
    }

    #[test]
    fn run_limits_parse_and_are_bounded() {
        use crate::agent::turn::{DEFAULT_MAX_STEPS, RunLimits};
        let config = Config::parse(
            "version = 1\n[limits]\nmax_steps = 12\nbudget_usd = 2.5\nbudget_tokens = 300000",
        )
        .unwrap();
        assert_eq!(
            config.run,
            RunLimits {
                max_steps: 12,
                budget_usd: Some(2.5),
                budget_tokens: Some(300_000),
            }
        );

        // Nothing set is the backstop and no budget at all: gears does not
        // know what the user's quota is and will not invent one.
        let config = Config::parse("version = 1").unwrap();
        assert_eq!(config.run, RunLimits::default());
        assert_eq!(config.run.max_steps, DEFAULT_MAX_STEPS);
        assert_eq!(config.run.budget_usd, None);
        assert_eq!(config.run.budget_tokens, None);

        for (bad, expected) in [
            ("max_steps = 0", "expected 1 to 1000"),
            ("max_steps = 1001", "expected 1 to 1000"),
            ("budget_usd = 0.0", "more than zero"),
            ("budget_tokens = 0", "more than zero"),
        ] {
            let error = Config::parse(&format!("version = 1\n[limits]\n{bad}")).unwrap_err();
            assert!(error.contains(expected), "{bad}: {error}");
        }
    }

    #[test]
    fn sub_agent_limits_parse_and_are_bounded() {
        use crate::agent::registry::Limits;
        let config = Config::parse(
            "version = 1\n[agents]\nmax_depth = 2\nmax_concurrent = 8\n\
             budget_usd = 1.5\nbudget_tokens = 200000",
        )
        .unwrap();
        assert_eq!(
            config.agents,
            Limits {
                depth: 2,
                concurrent: 8,
                budget_usd: Some(1.5),
                budget_tokens: Some(200_000),
            }
        );

        // The defaults are the proposal's, and no budget until one is set.
        let config = Config::parse("version = 1").unwrap();
        assert_eq!(config.agents, Limits::default());
        assert_eq!((config.agents.depth, config.agents.concurrent), (1, 4));
        assert_eq!(config.agents.budget_usd, None);

        // Turning sub-agents off has one spelling, and it is not a budget of
        // nothing or a concurrency of nobody.
        assert_eq!(
            Config::parse("version = 1\n[agents]\nmax_depth = 0")
                .unwrap()
                .agents
                .depth,
            0
        );
        for (bad, expected) in [
            ("max_depth = 9", "expected 0 to 4"),
            ("max_concurrent = 99", "expected 0 to 32"),
            ("max_concurrent = 0", "use max_depth = 0"),
            ("budget_usd = 0.0", "more than zero"),
            ("budget_tokens = 0", "more than zero"),
        ] {
            let error = Config::parse(&format!("version = 1\n[agents]\n{bad}")).unwrap_err();
            assert!(error.contains(expected), "{bad}: {error}");
        }
    }

    #[test]
    fn the_context_budget_parses_and_has_a_spelling_for_off() {
        use crate::agent::context::{DEFAULT_BUDGET, Policy};
        assert_eq!(
            Config::parse("version = 1").unwrap().context,
            Policy {
                budget: DEFAULT_BUDGET,
                summarize: true,
            }
        );
        assert!(
            !Config::parse("version = 1\n[context]\nsummarize = false")
                .unwrap()
                .context
                .summarize
        );
        assert_eq!(
            Config::parse("version = 1\n[context]\nbudget_tokens = 200000")
                .unwrap()
                .context
                .budget,
            200_000
        );
        // Zero is how a user says "leave my transcript alone", and is the
        // only value below the floor that means anything.
        assert_eq!(
            Config::parse("version = 1\n[context]\nbudget_tokens = 0")
                .unwrap()
                .context
                .budget,
            0
        );
        let error = Config::parse("version = 1\n[context]\nbudget_tokens = 500").unwrap_err();
        assert!(error.contains("at least 8000"), "{error}");
    }

    #[test]
    fn resource_defaults_and_overrides_parse() {
        assert_eq!(
            Config::parse("version = 1").unwrap().resources,
            Resources::default()
        );
        let config = Config::parse(
            r#"
            version = 1
            [resources]
            max_artifact_bytes = 10
            max_session_artifact_bytes = 20
            max_live_render_queue_bytes = 30
            max_range_read_bytes = 40
            max_inline_attachment_bytes = 50
            search_default_results = 60
            search_max_results_per_page = 70
            regex_size_limit_bytes = 80
            regex_dfa_size_limit_bytes = 90
            regex_nest_limit = 100
            search_max_file_bytes = 110
            "#,
        )
        .unwrap();
        assert_eq!(
            config.resources,
            Resources {
                max_artifact_bytes: 10,
                max_session_artifact_bytes: 20,
                max_live_render_queue_bytes: 30,
                max_range_read_bytes: 40,
                max_inline_attachment_bytes: 50,
                search_default_results: 60,
                search_max_results_per_page: 70,
                regex_size_limit_bytes: 80,
                regex_dfa_size_limit_bytes: 90,
                regex_nest_limit: 100,
                search_max_file_bytes: 110,
            }
        );
    }

    #[test]
    fn quality_policy_has_approved_defaults_and_validated_overrides() {
        assert_eq!(
            Config::parse("version = 1").unwrap().quality,
            Quality::default()
        );
        let config =
            Config::parse("version = 1\n[quality]\nmax_regression_percent = 7\nstable_samples = 5")
                .unwrap();
        assert_eq!(
            config.quality,
            Quality {
                max_regression_percent: 7,
                stable_samples: 5,
            }
        );
        assert_eq!(
            Config::parse("version = 1\n[quality]\nmax_regression_percent = 0\nstable_samples = 3")
                .unwrap()
                .quality
                .max_regression_percent,
            0
        );
        for samples in [0, 1, 2] {
            let error = Config::parse(&format!(
                "version = 1\n[quality]\nstable_samples = {samples}"
            ))
            .unwrap_err();
            assert!(error.contains("at least 3"), "{error}");
        }
    }

    #[test]
    fn resource_values_are_positive_and_representable() {
        for name in [
            "max_artifact_bytes",
            "max_session_artifact_bytes",
            "max_live_render_queue_bytes",
            "max_range_read_bytes",
            "max_inline_attachment_bytes",
            "search_default_results",
            "search_max_results_per_page",
            "regex_size_limit_bytes",
            "regex_dfa_size_limit_bytes",
            "regex_nest_limit",
            "search_max_file_bytes",
        ] {
            let error =
                Config::parse(&format!("version = 1\n[resources]\n{name} = 0")).unwrap_err();
            assert!(
                error.contains(name) && error.contains("more than zero"),
                "{error}"
            );
        }

        let error =
            Config::parse("version = 1\n[resources]\nmax_artifact_bytes = 9223372036854775808")
                .unwrap_err();
        assert!(error.contains("max_artifact_bytes"), "{error}");

        if usize::BITS > 32 {
            let error = Config::parse("version = 1\n[resources]\nregex_nest_limit = 4294967296")
                .unwrap_err();
            assert!(error.contains("regex_nest_limit"), "{error}");
        }
    }

    #[test]
    fn related_resource_bounds_are_consistent() {
        for (text, first, second) in [
            (
                "max_artifact_bytes = 3\nmax_session_artifact_bytes = 2",
                "max_artifact_bytes",
                "max_session_artifact_bytes",
            ),
            (
                "search_default_results = 3\nsearch_max_results_per_page = 2",
                "search_default_results",
                "search_max_results_per_page",
            ),
        ] {
            let error = Config::parse(&format!("version = 1\n[resources]\n{text}")).unwrap_err();
            assert!(error.contains(first) && error.contains(second), "{error}");
        }
    }

    #[test]
    fn self_hosting_is_off_until_it_is_asked_for() {
        assert_eq!(
            Config::parse("version = 1").unwrap().selfhost,
            crate::tools::selfhost::Policy::default()
        );
        let config = Config::parse(
            "version = 1\n[selfhost]\nenabled = true\ninstall = \"/home/you/bin/gears\"",
        )
        .unwrap();
        assert!(config.selfhost.enabled);
        assert_eq!(
            config.selfhost.install,
            Some(PathBuf::from("/home/you/bin/gears"))
        );
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        let config = Config::parse(
            "version = 1\nfuture_knob = true\n[net]\nfuture = 1\n[future_table]\nx = 2",
        )
        .unwrap();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn explicit_missing_file_is_an_error() {
        let path = std::env::temp_dir().join(format!("gears-no-such-{}.toml", std::process::id()));
        let err = Config::load(Some(&path)).unwrap_err();
        assert!(err.contains(path.to_str().unwrap()), "{err}");
    }

    #[test]
    fn explicit_file_loads() {
        let path = std::env::temp_dir().join(format!("gears-cfg-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "version = 1\n[net]\negress_allowlist = [\"h.example\"]",
        )
        .unwrap();
        let config = Config::load(Some(&path)).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(config.egress_allowlist, ["h.example"]);
    }
}
