use crate::buffer::{HighlightType, LexerState};
use crate::syntax::SyntaxHighlighter;

pub struct TomlHighlighter;

impl TomlHighlighter {
    pub fn new() -> Self {
        TomlHighlighter
    }
}

impl SyntaxHighlighter for TomlHighlighter {
    fn name(&self) -> &str { "TOML" }
    fn file_extensions(&self) -> &[&str] { &["toml"] }

    fn highlight_line(&self, chars: &[char], _state: LexerState) -> (Vec<HighlightType>, LexerState) {
        let mut highlights = vec![HighlightType::Normal; chars.len()];
        let mut i = 0;
        let mut seen_equals = false;

        // Skip leading whitespace to check for headers
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }

        if i < chars.len() && chars[i] == '[' {
            // It's likely a header: [section] or [[section]]
            let start = i;
            let mut end = chars.len();
            for j in (start..chars.len()).rev() {
                if chars[j] == ']' {
                    end = j + 1;
                    break;
                }
            }
            for j in start..end {
                highlights[j] = HighlightType::Keyword;
            }
            i = end;
        }

        while i < chars.len() {
            let ch = chars[i];

            // 1. Comments
            if ch == '#' {
                for j in i..chars.len() {
                    highlights[j] = HighlightType::Comment;
                }
                break;
            }

            // 2. Equals sign
            if ch == '=' {
                seen_equals = true;
                highlights[i] = HighlightType::Normal;
                i += 1;
                continue;
            }

            // Inline table support
            if ch == '{' {
                seen_equals = false;
                highlights[i] = HighlightType::Normal;
                i += 1;
                continue;
            }
            if ch == '}' {
                seen_equals = true;
                highlights[i] = HighlightType::Normal;
                i += 1;
                continue;
            }

            // 3. Strings (value or key)
            if ch == '"' || ch == '\'' {
                let quote = ch;
                let hl_type = if seen_equals {
                    HighlightType::StringLiteral
                } else {
                    HighlightType::Type // Key highlight
                };

                highlights[i] = hl_type;
                i += 1;
                while i < chars.len() {
                    highlights[i] = hl_type;
                    if chars[i] == '\\' && i + 1 < chars.len() && quote == '"' {
                        highlights[i + 1] = hl_type;
                        i += 2;
                        continue;
                    }
                    if chars[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // 4. Numbers (only after equals)
            if seen_equals && (ch.is_ascii_digit() || ch == '-' || ch == '+') {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.' || chars[i] == '_' || chars[i] == 'e' || chars[i] == 'E' || chars[i] == '-' || chars[i] == '+') {
                    highlights[i] = HighlightType::Number;
                    i += 1;
                }
                if i - start == 1 && (ch == '-' || ch == '+') {
                    highlights[start] = HighlightType::Normal;
                }
                continue;
            }

            // 5. Keywords (booleans: true, false) - only after equals
            if seen_equals && (ch.is_ascii_alphabetic() || ch == '_') {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word == "true" || word == "false" {
                    for j in start..i {
                        highlights[j] = HighlightType::Keyword;
                    }
                }
                continue;
            }

            // 6. Keys (bare words before equals)
            if !seen_equals && (ch.is_ascii_alphanumeric() || ch == '_' || ch == '-') {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '-') {
                    i += 1;
                }
                for j in start..i {
                    highlights[j] = HighlightType::Type;
                }
                continue;
            }

            i += 1;
        }

        (highlights, LexerState::Normal)
    }
}
