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
}

#[derive(Deserialize, Debug, Default)]
struct TraceV1 {
    file: Option<PathBuf>,
    level: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ConfigV1 {
    version: u32, // Must be 1.
    #[serde(default)]
    net: NetV1,
    #[serde(default)]
    trace: TraceV1,
}

/// Validated configuration; `Default` is what gears runs with when the
/// default config file does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Host names the network layer may talk to; it refuses everything else.
    pub egress_allowlist: Vec<String>,
    /// Trace destination; `--log-file` overrides it.
    pub log_file: Option<PathBuf>,
    pub log_level: crate::trace::Level,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            egress_allowlist: vec!["openrouter.ai".to_string()],
            log_file: None,
            log_level: crate::trace::Level::Info,
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
        let log_level = match raw.trace.level.as_deref() {
            None => Config::default().log_level,
            Some(name) => crate::trace::Level::parse(name).ok_or_else(|| {
                format!(
                    "bad trace level '{name}' (expected one of: {})",
                    crate::trace::Level::NAMES
                )
            })?,
        };
        Ok(Config {
            egress_allowlist,
            log_file: raw.trace.file,
            log_level,
        })
    }
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
