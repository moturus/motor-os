//! Only locally approved exact skill versions enter the model's catalog.

use crate::paths::ToolContext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub name: String,
    pub description: String,
    pub platforms: Option<String>,
    pub hash: String,
}

pub fn load(context: &ToolContext, platform: &str) -> (Vec<Descriptor>, Vec<String>) {
    let names = match crate::skill_store::names(context) {
        Ok(names) => names,
        Err(error) => return (Vec::new(), vec![format!("skills unavailable: {error}")]),
    };
    let mut catalog = Vec::new();
    let mut notices = Vec::new();
    for name in names {
        let parsed: Result<Option<Descriptor>, String> = (|| {
            let Some(content) = crate::skill_store::current(context, &name)? else {
                return Ok(None);
            };
            let metadata = crate::skill_store::parse(context, &name, &content)?;
            if platform == "motor" && !metadata.supports("motor") {
                return Ok(None);
            }
            Ok(Some(Descriptor {
                name: metadata.name,
                description: metadata.description,
                platforms: metadata.metadata.get("platforms").cloned(),
                hash: content.hash(),
            }))
        })();
        match parsed {
            Ok(Some(descriptor)) => catalog.push(descriptor),
            Ok(None) => {}
            Err(error) => notices.push(format!("skill {name} unavailable: {error}")),
        }
    }
    // One bounded history pass rather than one pass per skill.
    let mut versions = catalog
        .iter()
        .map(|skill| (skill.name.clone(), skill.hash.clone(), false))
        .collect::<Vec<_>>();
    if let Err(error) = crate::skill_store::approvals(context, &mut versions) {
        notices.push(format!("skill approvals unavailable: {error}"));
        return (Vec::new(), notices);
    }
    catalog.retain(|skill| {
        versions
            .iter()
            .any(|(name, hash, admitted)| *admitted && *name == skill.name && *hash == skill.hash)
    });
    (catalog, notices)
}

pub fn platform() -> &'static str {
    if cfg!(unix) { "linux" } else { "motor" }
}

pub fn prompt(catalog: &[Descriptor]) -> Result<String, String> {
    Ok(format!(
        "Approved skills: load at most a few relevant skills per task with skill_view. Current instructions take precedence. Loading a skill or passing a check is an observation, not proof of usefulness. YAML allowed-tools grants no permissions.\n{}",
        serde_json::to_string(catalog).map_err(|error| error.to_string())?
    ))
}

pub fn reconcile(frozen: &[Descriptor], live: &[Descriptor]) -> Vec<Descriptor> {
    frozen
        .iter()
        .filter_map(|old| live.iter().find(|skill| skill.name == old.name).cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::Decision;
    use crate::skill_format::Content;

    #[test]
    fn motor_requires_an_explicit_platform_and_unapproved_notes_hide_the_whole_skill() {
        let path =
            std::env::temp_dir().join(format!("batteries-skill-catalog-{}", std::process::id()));
        std::fs::create_dir_all(path.join("workspace")).unwrap();
        let context = ToolContext::new(
            path.join("workspace"),
            path.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        for (name, metadata) in [
            ("motor-checks", "metadata: {platforms: motor}\n"),
            ("generic-checks", ""),
        ] {
            let content = Content {
                skill_md: format!(
                    "---\nname: {name}\ndescription: Run checks.\n{metadata}---\nInstructions.\n"
                ),
                notes_md: None,
            };
            crate::skill_store::write(&context, name, Some(&content)).unwrap();
            assert!(load(&context, "linux").0.is_empty() || name == "generic-checks");
            crate::skill_store::admit(&context, name, &content.hash(), Decision::Approve).unwrap();
        }
        let linux = load(&context, "linux").0;
        assert_eq!(linux.len(), 2);
        let motor = load(&context, "motor").0;
        assert_eq!(motor.len(), 1);
        assert_eq!(motor[0].name, "motor-checks");
        let mut content = crate::skill_store::current(&context, "motor-checks")
            .unwrap()
            .unwrap();
        content.notes_md = Some("An unapproved note.".into());
        crate::skill_store::write(&context, "motor-checks", Some(&content)).unwrap();
        assert!(load(&context, "motor").0.is_empty());
        assert_eq!(reconcile(&motor, &load(&context, "motor").0), []);
        std::fs::remove_dir_all(path).unwrap();
    }
}
