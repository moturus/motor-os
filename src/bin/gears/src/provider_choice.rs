//! User-selected provider and model defaults, independent of `--config`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::state::StateRoot;

const FILE: &str = "provider.toml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderChoice {
    version: u32,
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
            version: 1,
            provider: provider.to_string(),
            model: model.to_string(),
        })
    }

    pub fn load_default() -> Result<Option<Self>, String> {
        Self::load_at(&default_dir()?)
    }

    pub fn save_default(&self) -> Result<(), String> {
        self.save_at(&default_dir()?)
    }

    fn load_at(directory: &Path) -> Result<Option<Self>, String> {
        let state = StateRoot::new(directory.to_path_buf())?;
        let Some(path) = state.existing_file(Path::new(FILE))? else {
            return Ok(None);
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let choice: Self =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        if choice.version != 1
            || choice.provider.trim().is_empty()
            || choice.model.trim().is_empty()
            || choice.provider.trim() != choice.provider
            || choice.model.trim() != choice.model
        {
            return Err(format!("{}: invalid provider choice", path.display()));
        }
        Ok(Some(choice))
    }

    fn save_at(&self, directory: &Path) -> Result<(), String> {
        let state = StateRoot::new(directory.to_path_buf())?;
        let text = toml::to_string(self).map_err(|error| error.to_string())?;
        state.replace_file(Path::new(FILE), text.as_bytes())
    }
}

fn default_dir() -> Result<PathBuf, String> {
    Config::default_path()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .ok_or("cannot locate Gears directory".to_string())
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
