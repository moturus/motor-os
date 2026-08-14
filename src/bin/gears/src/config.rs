//! gears configuration: a small TOML file, serde-derived. The russhd idiom:
//! a versioned raw struct (`ConfigV1`), then a separate validation pass into
//! the [`Config`] the rest of the program sees. Unknown fields are tolerated
//! so newer configs still load in older binaries (the self-restart story).

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
    selfhost: SelfHostV1,
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
        let (path, required) = match explicit {
            Some(path) => (path.to_path_buf(), true),
            None => match Self::default_path() {
                Some(path) => (path, false),
                None => return Ok(Config::default()),
            },
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
                Ok(Config::default())
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
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
        Ok(Config {
            egress_allowlist,
            allow_plain_http_loopback: raw.net.allow_plain_http_loopback.unwrap_or(false),
            base_url,
            model: raw.provider.model,
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
            selfhost: crate::tools::selfhost::Policy {
                enabled: raw.selfhost.enabled.unwrap_or(false),
                install: raw.selfhost.install,
            },
        })
    }
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
