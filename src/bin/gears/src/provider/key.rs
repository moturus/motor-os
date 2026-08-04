//! API keys (plan decision 5, proposal option A): a key file, overridable by
//! `OPENROUTER_API_KEY` for one-off runs.
//!
//! The key is the one secret gears holds, and this type exists to make it
//! awkward to leak: it never prints itself, registers itself for redaction
//! the moment it is read, and hands out its text only to the transport. Two
//! things keep it out of everything else — the transport passes it in the
//! *curl child's* environment rather than on a command line, and gears takes
//! it out of its own environment at startup so tools it spawns cannot inherit
//! it. The fs tools' deny-list (step 3 of the plan) covers the file.

use std::path::{Path, PathBuf};

pub struct ApiKey(String);

impl ApiKey {
    /// Validate and take ownership of key text. `source` names where it came
    /// from, for the error message.
    pub fn parse(text: &str, source: &str) -> Result<ApiKey, String> {
        let key = text.trim();
        if key.is_empty() {
            return Err(format!("{source} is empty"));
        }
        // The key becomes a header value in the transport, so a newline in it
        // would smuggle a second header. Refuse anything that is not plain
        // printable ASCII rather than sanitize it.
        if !key.bytes().all(|b| (0x21..0x7f).contains(&b)) {
            return Err(format!(
                "{source} contains characters that cannot appear in an API key"
            ));
        }
        crate::trace::redact(key);
        Ok(ApiKey(key.to_string()))
    }

    pub fn from_file(path: &Path) -> Result<ApiKey, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        ApiKey::parse(&text, &path.display().to_string())
    }

    /// The key file read when the config names none.
    pub fn default_path() -> Option<PathBuf> {
        #[cfg(target_os = "motor")]
        {
            Some(PathBuf::from("/user/cfg/gears/openrouter.key"))
        }

        #[cfg(all(unix, not(target_os = "motor")))]
        {
            std::env::home_dir().map(|home| home.join(".config/gears/openrouter.key"))
        }

        #[cfg(not(any(target_os = "motor", unix)))]
        {
            None
        }
    }

    /// Load from `explicit` if the config named a file, else from the default
    /// path. Deliberately does not read the environment: taking the key out
    /// of gears' own environment is the caller's job, and only the caller
    /// knows it is still single-threaded.
    pub fn load(explicit: Option<&Path>) -> Result<ApiKey, String> {
        match explicit {
            Some(path) => ApiKey::from_file(path),
            None => match ApiKey::default_path() {
                Some(path) if path.exists() => ApiKey::from_file(&path),
                Some(path) => Err(format!(
                    "no API key: set {} or write one to {}",
                    super::KEY_ENV,
                    path.display()
                )),
                None => Err(format!("no API key: set {}", super::KEY_ENV)),
            },
        }
    }

    /// The key itself. The only caller is the transport, which puts it in its
    /// child's environment.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("gears-key-{name}-{}", std::process::id()))
    }

    #[test]
    fn keys_are_trimmed_and_validated() {
        // A key file written by `echo` ends in a newline; that is not part of
        // the key, and it must not reach a header.
        assert_eq!(
            ApiKey::parse("sk-or-v1-abc123\n", "test").unwrap().expose(),
            "sk-or-v1-abc123"
        );
        for bad in ["", "   \n", "sk-abc\ndef", "sk abc", "sk-\u{e9}"] {
            assert!(ApiKey::parse(bad, "test").is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_key_never_prints_itself() {
        let key = ApiKey::parse("sk-secret-value", "test").unwrap();
        assert_eq!(format!("{key:?}"), "ApiKey([redacted])");
        assert!(!format!("{key:?}").contains("secret"));
    }

    #[test]
    fn a_key_file_loads_and_a_missing_one_says_where_to_put_it() {
        let path = temp("file.key");
        std::fs::write(&path, "sk-from-a-file\n").unwrap();
        let key = ApiKey::load(Some(&path)).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(key.expose(), "sk-from-a-file");

        let missing = temp("missing.key");
        let error = ApiKey::load(Some(&missing)).unwrap_err();
        assert!(error.contains(missing.to_str().unwrap()), "{error}");
    }

    #[test]
    fn the_default_path_is_the_platforms_config_directory() {
        let path = ApiKey::default_path().expect("a path on this platform");
        assert!(path.ends_with("gears/openrouter.key"), "{}", path.display());
    }
}
