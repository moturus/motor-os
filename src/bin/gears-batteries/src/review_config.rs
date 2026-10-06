//! Explicit model-pair selection for the optional review experiment.

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Configuration {
    version: u32,
    #[serde(default)]
    reviews: Settings,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub executor: Option<Model>,
    pub reviewer: Option<Model>,
    pub max_proposals: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            executor: None,
            reviewer: None,
            max_proposals: 4,
        }
    }
}

impl Settings {
    pub fn enabled_for(&self, provider: &str, model: &str) -> bool {
        self.enabled
            && self
                .executor
                .as_ref()
                .is_some_and(|selected| selected.provider == provider && selected.model == model)
    }

    fn validate(&self) -> Result<(), String> {
        if self.max_proposals == 0 {
            return Err("reviews.max_proposals must be positive".into());
        }
        if self.enabled && (self.executor.is_none() || self.reviewer.is_none()) {
            return Err(
                "enabled reviews need both executor and reviewer provider/model pairs".into(),
            );
        }
        for selection in [&self.executor, &self.reviewer].into_iter().flatten() {
            for name in [&selection.provider, &selection.model] {
                if name.trim().is_empty() || name.chars().any(char::is_control) {
                    return Err("review provider and model names must be nonempty and contain no control characters".into());
                }
            }
        }
        Ok(())
    }
}

pub fn load(root: &gears::state::StateRoot) -> Result<Settings, String> {
    parse(crate::memory_config::read(root)?.as_deref())
}

fn parse(text: Option<&str>) -> Result<Settings, String> {
    let Some(text) = text else {
        return Ok(Settings::default());
    };
    let configuration: Configuration =
        toml::from_str(text).map_err(|error| format!("invalid user batteries.toml: {error}"))?;
    if configuration.version != 1 {
        return Err("unsupported user batteries.toml version".into());
    }
    configuration.reviews.validate()?;
    Ok(configuration.reviews)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAIR: &str = "\
version = 1
[reviews]
enabled = true
max_proposals = 2
[reviews.executor]
provider = 'local'
model = 'executor-v1'
[reviews.reviewer]
provider = 'openrouter'
model = 'vendor/reviewer:free'
";

    #[test]
    fn reviews_are_off_until_explicitly_enabled_for_the_exact_executor() {
        for text in [
            None,
            Some("version=1"),
            Some("version=1\n[memory]\nuser_chars=500"),
        ] {
            let settings = parse(text).unwrap();
            assert_eq!(settings, Settings::default());
            assert!(!settings.enabled_for("local", "executor-v1"));
        }
        let settings = parse(Some(PAIR)).unwrap();
        assert!(settings.enabled_for("local", "executor-v1"));
        assert!(!settings.enabled_for("openrouter", "executor-v1"));
        assert!(!settings.enabled_for("local", "executor-v2"));
        assert_eq!(settings.max_proposals, 2);
        assert_eq!(settings.reviewer.unwrap().model, "vendor/reviewer:free");
        let settings = parse(Some(&PAIR.replace("enabled = true", "enabled = false"))).unwrap();
        assert!(!settings.enabled_for("local", "executor-v1"));
    }

    #[test]
    fn incomplete_enabled_pairs_invalid_names_and_misspellings_are_errors() {
        for text in [
            "version=2",
            "[reviews]\nenabled=false",
            "version=1\n[reviews]\nenabled=true",
            "version=1\n[reviews]\nmax_proposal=2",
            "version=1\n[reviews]\nmax_proposals=0",
            "version=1\n[reviews.executor]\nprovider='local'",
        ] {
            assert!(parse(Some(text)).is_err(), "{text}");
        }
        for invalid in ["''", "'   '", "\"bad\\nname\"", "\"bad\\u0000name\""] {
            let text = PAIR.replace("'executor-v1'", invalid);
            assert!(parse(Some(&text)).is_err(), "{text}");
        }
    }
}
