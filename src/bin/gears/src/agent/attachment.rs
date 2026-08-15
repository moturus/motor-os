//! Prompt-level path references, before any filesystem access occurs.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    path: String,
}

impl Reference {
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPrompt {
    text: String,
    references: Vec<Reference>,
}

impl ParsedPrompt {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn references(&self) -> &[Reference] {
        &self.references
    }
}

/// Parse `@path`, `@"path with spaces"`, and the literal escape `@@`.
/// Quoted paths accept only `\"` and `\\`; keeping the escape language this
/// small makes malformed references fail instead of changing their meaning.
pub fn parse(input: &str) -> Result<ParsedPrompt, String> {
    let mut text = String::with_capacity(input.len());
    let mut references = Vec::new();
    let mut offset = 0;
    while let Some(relative) = input[offset..].find('@') {
        let at = offset + relative;
        text.push_str(&input[offset..at]);
        let rest = &input[at + 1..];
        if let Some(after) = rest.strip_prefix('@') {
            text.push('@');
            offset = input.len() - after.len();
            continue;
        }
        if let Some(quoted) = rest.strip_prefix('"') {
            let (path, consumed) = quoted_path(quoted, at)?;
            let end = at + 2 + consumed;
            if input[end..]
                .chars()
                .next()
                .is_some_and(|character| !character.is_whitespace())
            {
                return Err(format!(
                    "ambiguous path reference at byte {at}: separate a quoted reference from following text"
                ));
            }
            text.push_str(&input[at..end]);
            references.push(Reference { path });
            offset = end;
            continue;
        }

        let length = rest
            .char_indices()
            .find_map(|(index, character)| character.is_whitespace().then_some(index))
            .unwrap_or(rest.len());
        if length == 0 {
            return Err(format!(
                "empty path reference at byte {at}; use '@@' for '@'"
            ));
        }
        let path = &rest[..length];
        if path.chars().any(char::is_control) {
            return Err(format!(
                "path reference at byte {at} contains a control character"
            ));
        }
        let end = at + 1 + length;
        text.push_str(&input[at..end]);
        references.push(Reference {
            path: path.to_string(),
        });
        offset = end;
    }
    text.push_str(&input[offset..]);
    Ok(ParsedPrompt { text, references })
}

fn quoted_path(input: &str, at: usize) -> Result<(String, usize), String> {
    let mut path = String::new();
    let mut escaped = false;
    for (index, character) in input.char_indices() {
        if escaped {
            match character {
                '"' | '\\' => path.push(character),
                _ => {
                    return Err(format!(
                        "unsupported escape in quoted path reference at byte {at}; use \\\" or \\\\"
                    ));
                }
            }
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => {
                if path.is_empty() {
                    return Err(format!("empty quoted path reference at byte {at}"));
                }
                return Ok((path, index + character.len_utf8()));
            }
            character if character.is_control() => {
                return Err(format!(
                    "quoted path reference at byte {at} contains a control character"
                ));
            }
            character => path.push(character),
        }
    }
    Err(format!("unterminated quoted path reference at byte {at}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(parsed: &ParsedPrompt) -> Vec<&str> {
        parsed.references().iter().map(Reference::path).collect()
    }

    #[test]
    fn plain_quoted_and_literal_references_are_distinct() {
        let parsed = parse("read @src/main.rs and @\"docs/with space.md\" for @@owner").unwrap();
        assert_eq!(
            parsed.text(),
            "read @src/main.rs and @\"docs/with space.md\" for @owner"
        );
        assert_eq!(paths(&parsed), ["src/main.rs", "docs/with space.md"]);
    }

    #[test]
    fn quoted_paths_have_two_explicit_escapes() {
        let parsed = parse(r#"inspect @"quote\"and\\slash" now"#).unwrap();
        assert_eq!(paths(&parsed), [r#"quote"and\slash"#]);
        assert_eq!(parsed.text(), r#"inspect @"quote\"and\\slash" now"#);
    }

    #[test]
    fn unicode_and_repeated_literals_are_preserved() {
        let parsed = parse("@@@資料/メモ.rs @@").unwrap();
        assert_eq!(parsed.text(), "@@資料/メモ.rs @");
        assert_eq!(paths(&parsed), ["資料/メモ.rs"]);
    }

    #[test]
    fn malformed_or_ambiguous_references_fail() {
        for (input, expected) in [
            ("read @", "empty path reference"),
            ("read @\"\"", "empty quoted path reference"),
            ("read @\"missing", "unterminated quoted path reference"),
            (r#"read @"bad\nname""#, "unsupported escape"),
            (r#"read @"one"tail"#, "ambiguous path reference"),
            ("read @\"line\nname\"", "control character"),
        ] {
            let error = parse(input).unwrap_err();
            assert!(error.contains(expected), "{input:?}: {error}");
        }
    }
}
