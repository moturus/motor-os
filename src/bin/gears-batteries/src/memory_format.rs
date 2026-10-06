//! Inspectable entry-based memory. Headers are JSON; bodies are plain Markdown.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use gears::state::StateRoot;
use serde::{Deserialize, Serialize};

const HEADER: &str = "# Gears memory v1\n";
pub const MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    User,
    Global,
    Workspace,
}

impl Target {
    pub fn relative(self) -> &'static Path {
        Path::new(match self {
            Self::User => "batteries/USER.md",
            Self::Global => "batteries/MEMORY.md",
            Self::Workspace => ".gears/MEMORY.md",
        })
    }

    pub fn scope(self) -> Scope {
        if self == Self::Workspace {
            Scope::Workspace
        } else {
            Scope::Global
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    User,
    Observed,
    Inferred,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Global,
    Workspace,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub session: String,
    pub entries: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<String>,
}

impl Source {
    pub(crate) fn valid_review(&self) -> bool {
        self.review.as_ref().is_none_or(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub id: String,
    pub kind: Kind,
    pub scope: Scope,
    pub source: Source,
    pub date_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub metadata: Metadata,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Document {
    pub entries: Vec<Entry>,
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

impl Entry {
    pub fn validate(&self, target: Target) -> Result<(), String> {
        let metadata = &self.metadata;
        if !metadata.source.valid_review()
            || !identifier(&metadata.id)
            || !identifier(&metadata.source.session)
            || metadata.source.entries.is_empty()
            || metadata.source.entries.len() > 32
            || metadata.source.entries.iter().any(|id| !identifier(id))
        {
            return Err("memory needs ASCII ids and 1–32 source entry ids".into());
        }
        if metadata.scope != target.scope()
            || (target == Target::User && metadata.kind != Kind::User)
        {
            return Err("memory kind or scope does not match the target file".into());
        }
        if self.text.trim().is_empty()
            || self.text.lines().any(|line| line.starts_with("§ "))
            || self
                .text
                .chars()
                .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
            || metadata
                .applies_to
                .as_ref()
                .is_some_and(|text| text.len() > 2048 || text.chars().any(char::is_control))
        {
            return Err("invalid memory text, reserved § header, or applies_to value".into());
        }
        Ok(())
    }
}

impl Document {
    pub fn parse(text: &str, target: Target, limit: usize) -> Result<Self, String> {
        if text.len() > MAX_BYTES || text.chars().count() > limit {
            return Err(format!("memory file exceeds its {limit} character limit"));
        }
        let body = text
            .strip_prefix(HEADER)
            .ok_or("unsupported memory file format/version")?;
        let mut entries = Vec::new();
        let sections = if body.is_empty() {
            None
        } else {
            Some(
                body.strip_prefix("§ ")
                    .ok_or("memory entry is missing its § header")?,
            )
        };
        for section in sections.into_iter().flat_map(|body| body.split("\n§ ")) {
            let (header, text) = section.split_once('\n').ok_or("memory entry has no body")?;
            let metadata = serde_json::from_str(header)
                .map_err(|error| format!("invalid memory header: {error}"))?;
            entries.push(Entry {
                metadata,
                text: text.trim_end_matches('\n').to_string(),
            });
        }
        let document = Self { entries };
        document.encode(target, limit)?;
        Ok(document)
    }

    pub fn encode(&self, target: Target, limit: usize) -> Result<String, String> {
        let mut text = HEADER.to_string();
        let mut ids = HashSet::new();
        for entry in &self.entries {
            entry.validate(target)?;
            if !ids.insert(&entry.metadata.id) {
                return Err("duplicate memory entry id".into());
            }
            text.push_str("§ ");
            text.push_str(
                &serde_json::to_string(&entry.metadata).map_err(|error| error.to_string())?,
            );
            text.push('\n');
            text.push_str(entry.text.trim_end_matches('\n'));
            text.push('\n');
        }
        if text.len() > MAX_BYTES || text.chars().count() > limit {
            return Err(format!("memory file exceeds its {limit} character limit"));
        }
        Ok(text)
    }
}

pub fn load(root: &StateRoot, target: Target, limit: usize) -> Result<Document, String> {
    let Some(path) = root.existing_file(target.relative())? else {
        return Ok(Document::default());
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "memory file is not UTF-8")?;
    Document::parse(text, target, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, text: &str) -> Entry {
        Entry {
            metadata: Metadata {
                id: id.into(),
                kind: Kind::User,
                scope: Scope::Global,
                source: Source {
                    review: None,
                    session: "session-1".into(),
                    entries: vec!["entry-2".into()],
                },
                date_ms: 1,
                applies_to: Some("Motor OS".into()),
            },
            text: text.into(),
        }
    }

    #[test]
    fn markdown_round_trip_preserves_kind_source_scope_and_unicode() {
        let document = Document {
            entries: vec![
                entry("one", "Prefer Rust.\n\nAn inline § is ordinary text 🦀"),
                entry("two", "Run checks."),
            ],
        };
        let encoded = document.encode(Target::User, 1375).unwrap();
        assert_eq!(
            Document::parse(&encoded, Target::User, 1375).unwrap(),
            document
        );
        assert!(Document::parse(&encoded, Target::Workspace, 2200).is_err());
        assert!(Document::parse(&encoded.replace("v1", "v2"), Target::User, 1375).is_err());
        assert!(Document::parse(&encoded, Target::User, encoded.chars().count() - 1).is_err());
        assert!(Document::parse(&format!("{HEADER}§ "), Target::Global, 2200).is_err());
        assert!(Document::parse(&encoded.replacen("§ ", "", 1), Target::User, 1375).is_err());
        assert_eq!(
            Document::parse(HEADER, Target::Global, 2200).unwrap(),
            Document::default()
        );
    }

    #[test]
    fn ambiguous_ids_headers_controls_and_non_user_preferences_are_rejected() {
        for bad in [
            entry("../escape", "text"),
            entry("one", "text\n§ {}\nbody"),
            entry("one", "bad\rtext"),
        ] {
            assert!(
                Document { entries: vec![bad] }
                    .encode(Target::Global, 2200)
                    .is_err()
            );
        }
        let mut document = Document {
            entries: vec![entry("same", "first"), entry("same", "second")],
        };
        assert!(document.encode(Target::Global, 2200).is_err());
        document.entries.pop();
        document.entries[0].metadata.kind = Kind::Inferred;
        assert!(document.encode(Target::User, 1375).is_err());
        assert!(document.encode(Target::Global, 2200).is_ok());
        document.entries[0].metadata.source.entries.clear();
        assert!(document.encode(Target::Global, 2200).is_err());
    }

    #[test]
    fn loading_memory_never_follows_links_or_accepts_non_utf8() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-format-{}", std::process::id()));
        let root = StateRoot::new(path.clone()).unwrap();
        assert_eq!(
            load(&root, Target::Global, 2200).unwrap(),
            Document::default()
        );
        root.replace_file(Target::Global.relative(), &[255])
            .unwrap();
        assert!(
            load(&root, Target::Global, 2200)
                .unwrap_err()
                .contains("UTF-8")
        );
        #[cfg(unix)]
        {
            let file = root.file(Target::Global.relative()).unwrap();
            std::fs::remove_file(&file).unwrap();
            std::os::unix::fs::symlink(path.join("outside"), file).unwrap();
            assert!(load(&root, Target::Global, 2200).is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
