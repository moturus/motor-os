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
}

/// Validated configuration; `Default` is what gears runs with when the
/// default config file does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Trace destination; `--log-file` overrides it.
    pub log_file: Option<PathBuf>,
    pub log_level: crate::trace::Level,
    /// Whether mutating tool calls are put to the user.
    pub permissions: crate::agent::gate::Mode,
    /// How long `run` waits for a command, and `build`/`test` for a compiler
    /// — which needs minutes rather than seconds.
    pub run_timeout: std::time::Duration,
    pub build_timeout: std::time::Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            egress_allowlist: vec!["openrouter.ai".to_string()],
            allow_plain_http_loopback: false,
            base_url: crate::provider::openai_compat::OPENROUTER_BASE_URL.to_string(),
            model: None,
            key_file: None,
            log_file: None,
            log_level: crate::trace::Level::Info,
            permissions: crate::agent::gate::Mode::Ask,
            run_timeout: crate::tools::run::DEFAULT_TIMEOUT,
            build_timeout: crate::tools::run::DEFAULT_BUILD_TIMEOUT,
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
        })
    }
}

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
            "#,
        )
        .unwrap();
        assert_eq!(config.base_url, "http://127.0.0.1:8099/v1");
        assert_eq!(config.model.as_deref(), Some("anthropic/claude-sonnet-4.5"));
        assert_eq!(config.key_file, Some(PathBuf::from("/keys/openrouter.key")));

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
