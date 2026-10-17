//! Plain-text memory files: a `§` header line per entry, then the entry's text.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

use crate::state::StateRoot;
use serde::{Deserialize, Serialize};

const HEADER_V2: &str = "# Gears memory v2\n";
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

    pub fn title(self) -> &'static str {
        match self {
            Self::User => "User memory",
            Self::Global => "Global memory",
            Self::Workspace => "Workspace memory",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    /// `YYYY-MM-DD`, or empty when a hand-written entry gave none.
    #[serde(default)]
    pub date: String,
    /// The id of the session that proposed the entry; empty when hand-written.
    #[serde(default)]
    pub session: String,
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

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

impl Entry {
    pub fn validate(&self) -> Result<(), String> {
        if !identifier(&self.id) || self.id.len() > 32 {
            return Err("memory entry ids are 1–32 ASCII letters, digits, - or _".into());
        }
        if !self.date.is_empty() && !valid_date(&self.date) {
            return Err("memory entry dates are written YYYY-MM-DD".into());
        }
        if !self.session.is_empty() && !identifier(&self.session) {
            return Err("invalid memory entry session id".into());
        }
        if self.text.trim().is_empty()
            || self
                .text
                .lines()
                .any(|line| line == "§" || line.starts_with("§ "))
            || self
                .text
                .chars()
                .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
        {
            return Err(
                "memory text is empty, starts a line with §, or contains control characters".into(),
            );
        }
        Ok(())
    }

    fn header(&self) -> String {
        let mut header = format!("§ {}", self.id);
        if !self.date.is_empty() || !self.session.is_empty() {
            header.push(' ');
            header.push_str(if self.date.is_empty() {
                "-"
            } else {
                &self.date
            });
        }
        if !self.session.is_empty() {
            header.push(' ');
            header.push_str(&self.session);
        }
        header
    }
}

impl Document {
    /// Reads the current format; any other header is refused.
    pub fn parse(text: &str, limit: usize) -> Result<Self, String> {
        if text.len() > MAX_BYTES {
            return Err("memory file exceeds 256 KiB".into());
        }
        let body = text
            .strip_prefix(HEADER_V2)
            .ok_or("unsupported memory file format/version")?;
        let mut entries = Vec::new();
        if !body.is_empty() {
            let body = body
                .strip_prefix("§ ")
                .ok_or("memory entry is missing its § header")?;
            for section in body.split("\n§ ") {
                let (header, text) = section.split_once('\n').ok_or("memory entry has no body")?;
                let text = text.trim_end_matches('\n').to_string();
                entries.push(v2_entry(header, text)?);
            }
        }
        let document = Self { entries };
        document.encode(limit)?;
        Ok(document)
    }

    /// Only entry text counts toward the character limit.
    pub fn encode(&self, limit: usize) -> Result<String, String> {
        let mut text = HEADER_V2.to_string();
        let mut ids = HashSet::new();
        let mut chars = 0;
        for entry in &self.entries {
            entry.validate()?;
            if !ids.insert(&entry.id) {
                return Err("duplicate memory entry id".into());
            }
            chars += entry.text.chars().count();
            text.push_str(&entry.header());
            text.push('\n');
            text.push_str(entry.text.trim_end_matches('\n'));
            text.push('\n');
        }
        if text.len() > MAX_BYTES || chars > limit {
            return Err(format!("memory file exceeds its {limit} character limit"));
        }
        Ok(text)
    }

    pub fn prompt(&self, target: Target) -> String {
        let mut prompt = format!("{}:", target.title());
        for entry in &self.entries {
            prompt.push_str(&format!("\n[{}] {}", entry.id, entry.text));
        }
        prompt
    }
}

fn v2_entry(header: &str, text: String) -> Result<Entry, String> {
    let mut fields = header.split_whitespace();
    let id = fields.next().ok_or("memory entry has no id")?;
    let date = fields.next().unwrap_or("-");
    let session = fields.next().unwrap_or("-");
    if fields.next().is_some() {
        return Err("memory entry header has more than id, date and session".into());
    }
    let field = |value: &str| {
        if value == "-" {
            String::new()
        } else {
            value.to_string()
        }
    };
    Ok(Entry {
        id: id.to_string(),
        date: field(date),
        session: field(session),
        text,
    })
}

/// `YYYY-MM-DD` in UTC for a Unix time in milliseconds.
pub fn date_from_ms(ms: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = (ms / 86_400_000) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Today's date and the current Unix time in milliseconds.
pub fn today() -> Result<(String, u64), String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("cannot date memory change: {error}"))?;
    let ms = u64::try_from(duration.as_millis()).map_err(|_| "memory date is out of range")?;
    Ok((date_from_ms(ms), ms))
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
    Document::parse(text, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, text: &str) -> Entry {
        Entry {
            id: id.into(),
            date: "2026-10-15".into(),
            session: "s1".into(),
            text: text.into(),
        }
    }

    #[test]
    fn both_formats_parse_and_the_current_one_round_trips() {
        let document = Document {
            entries: vec![
                entry(
                    "k7f2",
                    "Run `cargo test --offline`;\nthe VM has no network.",
                ),
                Entry {
                    id: "hand".into(),
                    date: String::new(),
                    session: String::new(),
                    text: "Written by hand.".into(),
                },
                Entry {
                    id: "dated".into(),
                    date: "2026-01-02".into(),
                    session: String::new(),
                    text: "Dated by hand.".into(),
                },
            ],
        };
        let text = document.encode(2200).unwrap();
        assert_eq!(
            text,
            "# Gears memory v2\n§ k7f2 2026-10-15 s1\nRun `cargo test --offline`;\nthe VM has no network.\n§ hand\nWritten by hand.\n§ dated 2026-01-02\nDated by hand.\n"
        );
        assert_eq!(Document::parse(&text, 2200).unwrap(), document);
        assert_eq!(
            Document::parse("# Gears memory v2\n", 10).unwrap(),
            Document::default()
        );
        assert_eq!(
            document.prompt(Target::Workspace),
            "Workspace memory:\n[k7f2] Run `cargo test --offline`;\nthe VM has no network.\n[hand] Written by hand.\n[dated] Dated by hand."
        );
        assert_eq!(date_from_ms(0), "1970-01-01");
        assert_eq!(date_from_ms(951_782_400_000), "2000-02-29");
    }

    #[test]
    fn limits_count_text_only_and_bad_entries_are_refused() {
        let document = Document {
            entries: vec![entry("a", &"x".repeat(100)), entry("b", &"y".repeat(100))],
        };
        assert!(document.encode(200).is_ok());
        assert!(document.encode(199).is_err());
        for bad in [
            Document {
                entries: vec![entry("same", "first"), entry("same", "second")],
            },
            Document {
                entries: vec![entry("bad id!", "text")],
            },
            Document {
                entries: vec![entry("a", "   ")],
            },
            Document {
                entries: vec![entry("a", "line\n§ header")],
            },
            Document {
                entries: vec![entry("a", "bell\u{7}")],
            },
            Document {
                entries: vec![Entry {
                    date: "15-10-2026".into(),
                    ..entry("a", "text")
                }],
            },
        ] {
            assert!(bad.encode(2200).is_err());
        }
        for bad in [
            "no header\n",
            "# Gears memory v2\nno § header\n",
            "# Gears memory v2\n§ id 2026-10-15 s1 extra\ntext\n",
            "# Gears memory v2\n§ id\n",
            "# Gears memory v1\n§ {\"id\":\"old\"}\nOld fact.\n",
        ] {
            assert!(Document::parse(bad, 2200).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn loading_memory_never_follows_links_or_accepts_non_utf8() {
        let path =
            std::env::temp_dir().join(format!("batteries-memory-format-{}", std::process::id()));
        let root = StateRoot::new(path.clone()).unwrap();
        assert!(
            load(&root, Target::Global, 2200)
                .unwrap()
                .entries
                .is_empty()
        );
        root.replace_file(Target::Global.relative(), b"# Gears memory v2\n\xff")
            .unwrap();
        assert!(load(&root, Target::Global, 2200).is_err());
        #[cfg(unix)]
        {
            let file = path.join(Target::Global.relative());
            std::fs::remove_file(&file).unwrap();
            std::os::unix::fs::symlink(path.join("elsewhere"), &file).unwrap();
            assert!(load(&root, Target::Global, 2200).is_err());
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
