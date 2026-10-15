//! User-wide skill limits share the versioned batteries configuration.

use crate::state::StateRoot;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Configuration {
    version: u32,
    #[serde(default)]
    skills: Limits,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub skill_chars: usize,
    pub notes_chars: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            skill_chars: 20000,
            notes_chars: 4000,
        }
    }
}

pub fn load(root: &StateRoot) -> Result<Limits, String> {
    let Some(text) = crate::batteries::memory_config::read(root)? else {
        return Ok(Limits::default());
    };
    let config: Configuration =
        toml::from_str(&text).map_err(|error| format!("invalid user batteries.toml: {error}"))?;
    if config.version != 1 {
        return Err("unsupported user batteries.toml version".into());
    }
    if [config.skills.skill_chars, config.skills.notes_chars]
        .iter()
        .any(|limit| !(1..=65536).contains(limit))
    {
        return Err("skill character limits must be between 1 and 65536".into());
    }
    Ok(config.skills)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn skill_limits_are_independent_of_memory_limits_and_reject_misspellings() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-config-{}", std::process::id()));
        let root = StateRoot::new(path.clone()).unwrap();
        assert_eq!(load(&root).unwrap().skill_chars, 20000);
        root.replace_file(
            Path::new("batteries.toml"),
            b"version=1\n[memory]\nuser_chars=500\n[skills]\nskill_chars=12000\nnotes_chars=2000",
        )
        .unwrap();
        assert_eq!(load(&root).unwrap().skill_chars, 12000);
        assert_eq!(
            crate::batteries::memory_config::load(&root)
                .unwrap()
                .user_chars,
            500
        );
        for text in [
            "version=2",
            "version=1\n[skills]\nskill_char=100",
            "version=1\n[skills]\nnotes_chars=0",
            "version=1\n[skills]\nskill_chars=65537",
        ] {
            root.replace_file(Path::new("batteries.toml"), text.as_bytes())
                .unwrap();
            assert!(load(&root).is_err(), "{text}");
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
