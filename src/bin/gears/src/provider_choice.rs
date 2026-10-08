//! User-selected provider and model defaults, independent of `--config`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::state::StateRoot;

const FILE: &str = "provider.toml";
const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderChoice {
    pub provider: String,
    pub model: String,
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
        })
    }

    pub fn load_default() -> Result<Option<Self>, String> {
        Self::load_at(&crate::directory::default_root()?)
    }

    pub fn save_default(&self) -> Result<(), String> {
        self.save_at(&crate::directory::default_root()?)
    }

    fn load_at(directory: &Path) -> Result<Option<Self>, String> {
        let choice: Option<Self> =
            StateRoot::new(directory.to_path_buf())?.load_toml(FILE, VERSION)?;
        choice
            .map(|choice| Self::new(&choice.provider, &choice.model))
            .transpose()
            .map_err(|_| {
                let path = directory.join(FILE);
                format!("{}: invalid provider choice", path.display())
            })
    }

    fn save_at(&self, directory: &Path) -> Result<(), String> {
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
}
