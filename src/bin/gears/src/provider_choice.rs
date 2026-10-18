//! User-selected provider and model defaults, and provider addresses the user
//! chose, kept in the Gears directory independently of `--config`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::state::StateRoot;

const FILE: &str = "provider.toml";
const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderChoice {
    pub provider: String,
    pub model: String,
    /// Base URLs replacing the configured ones, by provider name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub urls: BTreeMap<String, String>,
}

impl ProviderChoice {
    pub fn new(provider: &str, model: &str) -> Result<Self, String> {
        if provider.trim().is_empty()
            || model.trim().is_empty()
            || provider.trim() != provider
            || model.trim() != model
        {
            return Err("provider and model defaults must not be empty".to_string());
        }
        Ok(Self {
            provider: provider.to_string(),
            model: model.to_string(),
            urls: BTreeMap::new(),
        })
    }

    pub fn load_default() -> Result<Option<Self>, String> {
        Self::load_at(&crate::directory::default_root()?)
    }

    pub fn save_default(&self) -> Result<(), String> {
        self.save_at(&crate::directory::default_root()?)
    }

    /// Save a new provider and model, keeping the addresses saved before.
    pub fn save_selection(provider: &str, model: &str) -> Result<(), String> {
        Self::save_selection_at(&crate::directory::default_root()?, provider, model)
    }

    fn save_selection_at(directory: &Path, provider: &str, model: &str) -> Result<(), String> {
        let urls = Self::load_at(directory)?
            .map(|saved| saved.urls)
            .unwrap_or_default();
        Self {
            urls,
            ..Self::new(provider, model)?
        }
        .save_at(directory)
    }

    pub fn load_at(directory: &Path) -> Result<Option<Self>, String> {
        let choice: Option<Self> =
            StateRoot::new(directory.to_path_buf())?.load_toml(FILE, VERSION)?;
        choice
            .map(|choice| {
                let urls = choice.urls.clone();
                Self::new(&choice.provider, &choice.model).map(|valid| Self { urls, ..valid })
            })
            .transpose()
            .map_err(|_| {
                let path = directory.join(FILE);
                format!("{}: invalid provider choice", path.display())
            })
    }

    pub fn save_at(&self, directory: &Path) -> Result<(), String> {
        StateRoot::new(directory.to_path_buf())?.save_toml(FILE, VERSION, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choice_is_written_atomically_and_read_back() {
        let root = std::env::temp_dir().join(format!("gears-choice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert!(ProviderChoice::load_at(&root).unwrap().is_none());
        let first = ProviderChoice::new("local", "small").unwrap();
        first.save_at(&root).unwrap();
        let second = ProviderChoice::new("remote", "large").unwrap();
        second.save_at(&root).unwrap();
        assert_eq!(ProviderChoice::load_at(&root).unwrap(), Some(second));
        assert!(std::fs::read_dir(&root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".gears-tmp-")
        }));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_new_selection_keeps_the_saved_addresses() {
        let root = std::env::temp_dir().join(format!("gears-choice-urls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut first = ProviderChoice::new("local", "small").unwrap();
        first
            .urls
            .insert("local".into(), "http://192.168.4.1:8080/v1".into());
        first.save_at(&root).unwrap();
        ProviderChoice::save_selection_at(&root, "openrouter", "large").unwrap();
        let saved = ProviderChoice::load_at(&root).unwrap().unwrap();
        assert_eq!(saved.provider, "openrouter");
        assert_eq!(saved.urls, first.urls);
        std::fs::write(
            root.join("provider.toml"),
            "version = 1\nprovider = 'a'\nmodel = 'b'\nextra = 1\n",
        )
        .unwrap();
        assert!(ProviderChoice::load_at(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
