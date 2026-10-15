//! Agent Skills frontmatter is YAML; the Markdown body is preserved verbatim.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use yaml_serde::Value;

pub const MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub skill_md: String,
    pub notes_md: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub metadata: BTreeMap<String, String>,
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

fn bounded(text: &str, limit: usize) -> Result<(), String> {
    if text.len() > MAX_BYTES || text.chars().count() > limit {
        return Err("skill text exceeds its size limit".into());
    }
    if text.contains('\r')
        || text
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
    {
        return Err("skill text must be UTF-8 with LF and no control characters".into());
    }
    Ok(())
}

impl Content {
    pub fn parse(
        &self,
        directory: &str,
        skill_chars: usize,
        notes_chars: usize,
    ) -> Result<Metadata, String> {
        bounded(&self.skill_md, skill_chars)?;
        if let Some(notes) = &self.notes_md {
            bounded(notes, notes_chars)?;
        }
        let text = self
            .skill_md
            .strip_prefix("---\n")
            .ok_or("SKILL.md must begin with YAML frontmatter")?;
        let closing = text
            .lines()
            .enumerate()
            .find(|(_, line)| *line == "---")
            .map(|(index, _)| index)
            .ok_or("SKILL.md has no closing frontmatter delimiter")?;
        let header = text.lines().take(closing).collect::<Vec<_>>().join("\n");
        let value: Value = yaml_serde::from_str(&header)
            .map_err(|error| format!("invalid skill YAML: {error}"))?;
        let fields = value
            .as_mapping()
            .ok_or("skill frontmatter must be a mapping")?;
        if fields.keys().any(|key| !matches!(key, Value::String(_))) {
            return Err("skill frontmatter keys must be strings".into());
        }
        let string = |key: &str| -> Result<Option<&str>, String> {
            fields
                .get(Value::String(key.into()))
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| format!("skill {key} must be a string"))
                })
                .transpose()
        };
        let name = string("name")?.ok_or("skill name is required")?;
        if !valid_name(name) || name != directory {
            return Err("skill name must match its valid directory name".into());
        }
        let description = string("description")?.ok_or("skill description is required")?;
        if description.trim().is_empty() || description.chars().count() > 1024 {
            return Err("skill description must contain 1–1024 characters".into());
        }
        bounded(description, 1024)?;
        string("license")?;
        string("allowed-tools")?; // Descriptive metadata never grants tool authority.
        if let Some(compatibility) = string("compatibility")?
            && (compatibility.trim().is_empty() || compatibility.chars().count() > 500)
        {
            return Err("skill compatibility must contain 1–500 characters".into());
        }
        let mut metadata = BTreeMap::new();
        if let Some(value) = fields.get(Value::String("metadata".into())) {
            let mapping = value
                .as_mapping()
                .ok_or("skill metadata must be a string mapping")?;
            for (key, value) in mapping {
                let key = key.as_str().ok_or("skill metadata keys must be strings")?;
                let value = value
                    .as_str()
                    .ok_or("skill metadata values must be strings")?;
                bounded(key, 65536)?;
                bounded(value, 65536)?;
                metadata.insert(key.into(), value.into());
            }
        }
        Ok(Metadata {
            name: name.into(),
            description: description.into(),
            metadata,
        })
    }

    pub fn validate_written(
        &self,
        name: &str,
        skill_chars: usize,
        notes_chars: usize,
    ) -> Result<(), String> {
        self.parse(name, skill_chars, notes_chars)?;
        let body = self
            .skill_md
            .strip_prefix("---\n")
            .unwrap()
            .split_once("\n---\n")
            .map(|(_, body)| body)
            .ok_or("agent-written skill needs a Markdown body")?;
        for required in ["When it applies", "Steps", "How to check", "Pitfalls"] {
            if !body.lines().any(|line| line == format!("## {required}")) {
                return Err(format!(
                    "agent-written skill requires section: ## {required}"
                ));
            }
        }
        Ok(())
    }

    pub fn hash(&self) -> String {
        crate::batteries::snapshot::digest(
            &serde_json::to_vec(self).expect("string content is serializable"),
        )
    }
}

impl Metadata {
    pub fn supports(&self, platform: &str) -> bool {
        self.metadata
            .get("platforms")
            .is_some_and(|platforms| platforms.split_whitespace().any(|name| name == platform))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content(header: &str) -> Content {
        Content {
            skill_md: format!(
                "---\n{header}\n---\n## When it applies\nRust work.\n## Steps\nRun checks.\n## How to check\nAll pass.\n## Pitfalls\nStale builds.\n"
            ),
            notes_md: None,
        }
    }

    #[test]
    fn parses_yaml_optional_fields_multiline_strings_and_platform_metadata() {
        let skill = content(
            "name: rust-checks\ndescription: >-\n  Run checks: use the\n  declared vector.\nlicense: MIT\ncompatibility: Motor OS\nallowed-tools: sh\nmetadata:\n  platforms: motor linux\n  version: '1.0'\nextension: {ignored: true}",
        );
        let metadata = skill.parse("rust-checks", 20000, 4000).unwrap();
        assert_eq!(metadata.description, "Run checks: use the declared vector.");
        assert!(metadata.supports("motor"));
        assert!(!metadata.supports("mot"));
        skill.validate_written("rust-checks", 20000, 4000).unwrap();
        let old = skill.hash();
        let mut changed = skill;
        changed.notes_md = Some("A quirk observed in use.".into());
        assert_ne!(changed.hash(), old);
        assert_eq!(
            content("name: rust-checks\ndescription: 'Use # literally.'")
                .parse("rust-checks", 20000, 4000)
                .unwrap()
                .description,
            "Use # literally."
        );
    }

    #[test]
    fn rejects_ambiguous_invalid_oversized_and_incomplete_headers() {
        for header in [
            "name: rust-checks",
            "name: rust-checks\ndescription: ''",
            "name: rust-checks\nname: rust-checks\ndescription: checks",
            "name: rust-checks\ndescription: checks\nmetadata: {platforms: [motor]}",
            "name: rust-checks\ndescription: checks\nmetadata: {version: 1}",
            "name: rust-checks\ndescription: [checks]",
            "name: rust-checks\ndescription: \"\\e[31mchecks\"",
            "name: ../escape\ndescription: checks",
            "name: rust-checks\ndescription: checks\ncompatibility: ''",
            "name: rust-checks\ndescription: checks\nlicense: [MIT]",
            "name: rust-checks\ndescription: checks\nmetadata: {version: one, version: two}",
        ] {
            assert!(
                content(header).parse("rust-checks", 20000, 4000).is_err(),
                "{header}"
            );
        }
        let mut skill = content("name: rust-checks\ndescription: checks");
        assert!(skill.parse("other", 20000, 4000).is_err());
        assert!(skill.parse("rust-checks", 10, 4000).is_err());
        skill.skill_md = skill.skill_md.replace("## Pitfalls", "## Other");
        assert!(skill.validate_written("rust-checks", 20000, 4000).is_err());
        skill.notes_md = Some("too long".into());
        assert!(skill.parse("rust-checks", 20000, 2).is_err());
        skill.notes_md = None;
        skill.skill_md = skill.skill_md.replace('\n', "\r\n");
        assert!(skill.parse("rust-checks", 20000, 4000).is_err());
    }
}
