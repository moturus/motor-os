use crate::buffer::{HighlightType, LexerState};
use crate::syntax::SyntaxHighlighter;

pub struct BashHighlighter {
    keywords: &'static [&'static str],
}

impl BashHighlighter {
    pub fn new() -> Self {
        BashHighlighter {
            keywords: &[
                "if", "fi", "then", "else", "elif", "for", "while", "do", "done",
                "case", "esac", "in", "function", "select", "until", "local", "declare"
            ],
        }
    }
}

impl SyntaxHighlighter for BashHighlighter {
    fn name(&self) -> &str { "Bash" }
    fn file_extensions(&self) -> &[&str] { &["sh", "bash"] }

    fn highlight_line(&self, chars: &[char], _state: LexerState) -> (Vec<HighlightType>, LexerState) {
        let mut highlights = vec![HighlightType::Normal; chars.len()];
        let mut i = 0;

        // 1. Check for Shebang at the start of the line
        if chars.len() >= 2 && chars[0] == '#' && chars[1] == '!' {
            for j in 0..chars.len() {
                highlights[j] = HighlightType::Preprocessor;
            }
            return (highlights, LexerState::Normal);
        }

        while i < chars.len() {
            let ch = chars[i];

            // 2. Comments
            if ch == '#' {
                for j in i..chars.len() {
                    highlights[j] = HighlightType::Comment;
                }
                break;
            }

            // 3. Variables ($VAR or ${VAR})
            if ch == '$' && i + 1 < chars.len() {
                highlights[i] = HighlightType::Type;
                i += 1;
                if chars[i] == '{' {
                    highlights[i] = HighlightType::Type;
                    i += 1;
                    while i < chars.len() && chars[i] != '}' {
                        highlights[i] = HighlightType::Type;
                        i += 1;
                    }
                    if i < chars.len() && chars[i] == '}' {
                        highlights[i] = HighlightType::Type;
                        i += 1;
                    }
                } else {
                    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                        highlights[i] = HighlightType::Type;
                        i += 1;
                    }
                }
                continue;
            }

            // 4. String Literals
            if ch == '"' || ch == '\'' {
                let quote = ch;
                highlights[i] = HighlightType::StringLiteral;
                i += 1;
                while i < chars.len() {
                    highlights[i] = HighlightType::StringLiteral;
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        highlights[i + 1] = HighlightType::StringLiteral;
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

            // 5. Numbers
            if ch.is_ascii_digit() {
                while i < chars.len() && chars[i].is_ascii_digit() {
                    highlights[i] = HighlightType::Number;
                    i += 1;
                }
                continue;
            }

            // 6. Keywords (Word boundaries)
            if ch.is_ascii_alphabetic() || ch == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();

                if self.keywords.contains(&word.as_str()) {
                    for j in start..i {
                        highlights[j] = HighlightType::Keyword;
                    }
                }
                continue;
            }

            i += 1;
        }

        (highlights, LexerState::Normal)
    }
}
