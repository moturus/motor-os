//! The user's skills, listed from disk for the prompt and for skill_view.

use crate::batteries::paths::ToolContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub name: String,
    pub description: String,
    pub platforms: Option<String>,
}

/// An invalid skill is reported in the notices and left out of the catalog.
pub fn load(context: &ToolContext, platform: &str) -> (Vec<Descriptor>, Vec<String>) {
    let names = match crate::batteries::skill_store::names(context) {
        Ok(names) => names,
        Err(error) => return (Vec::new(), vec![format!("skills unavailable: {error}")]),
    };
    let mut catalog = Vec::new();
    let mut notices = Vec::new();
    for name in names {
        let parsed: Result<Option<Descriptor>, String> = (|| {
            let Some(content) = crate::batteries::skill_store::current(context, &name)? else {
                return Ok(None);
            };
            let metadata = crate::batteries::skill_store::parse(context, &name, &content)?;
            if platform == "motor" && !metadata.supports("motor") {
                return Ok(None);
            }
            Ok(Some(Descriptor {
                name: metadata.name,
                description: metadata.description,
                platforms: metadata.metadata.get("platforms").cloned(),
            }))
        })();
        match parsed {
            Ok(Some(descriptor)) => catalog.push(descriptor),
            Ok(None) => {}
            Err(error) => notices.push(format!("skill {name} unavailable: {error}")),
        }
    }
    (catalog, notices)
}

pub fn platform() -> &'static str {
    if cfg!(unix) { "linux" } else { "motor" }
}

pub fn prompt(catalog: &[Descriptor]) -> Result<String, String> {
    Ok(format!(
        "Skills: load at most three relevant skills per task with skill_view. Current instructions take precedence. YAML allowed-tools grants no permissions.\n{}",
        serde_json::to_string(catalog).map_err(|error| error.to_string())?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batteries::skill_format::Content;

    #[test]
    fn invalid_skills_are_reported_and_valid_ones_listed_by_platform() {
        let root =
            std::env::temp_dir().join(format!("batteries-skill-catalog-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        let skill = |name: &str, platforms: &str| Content {
            skill_md: format!(
                "---\nname: {name}\ndescription: Run {name}.\nmetadata: {{platforms: {platforms}}}\n---\nSteps.\n"
            ),
            notes_md: None,
        };
        crate::batteries::skill_store::write(&context, "both", Some(&skill("both", "motor linux")))
            .unwrap();
        crate::batteries::skill_store::write(
            &context,
            "linux-only",
            Some(&skill("linux-only", "linux")),
        )
        .unwrap();
        crate::batteries::skill_store::write(
            &context,
            "broken",
            Some(&Content {
                skill_md: "no front matter".into(),
                notes_md: None,
            }),
        )
        .unwrap();
        let (catalog, notices) = load(&context, "linux");
        assert_eq!(
            catalog
                .iter()
                .map(|skill| skill.name.as_str())
                .collect::<Vec<_>>(),
            ["both", "linux-only"]
        );
        assert_eq!(notices.len(), 1);
        assert!(notices[0].starts_with("skill broken unavailable"));
        let (catalog, _) = load(&context, "motor");
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].platforms.as_deref(), Some("motor linux"));
        assert!(prompt(&catalog).unwrap().contains("\"name\":\"both\""));
        std::fs::remove_dir_all(root).unwrap();
    }
}
