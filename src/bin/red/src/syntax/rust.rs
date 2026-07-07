use crate::buffer::{HighlightType, LexerState};
use crate::syntax::SyntaxHighlighter;

pub struct RustHighlighter {
    keywords: &'static [&'static str],
    types: &'static [&'static str],
}

impl RustHighlighter {
    pub fn new() -> Self {
        RustHighlighter {
            keywords: &[
                "fn", "let", "pub", "struct", "impl", "match", "if", "else", "for", "while",
                "in", "return", "use", "mod", "crate", "enum", "type", "const", "static", "mut",
                "self", "Self", "as", "loop", "break", "continue", "unsafe", "where", "trait"
            ],
            types: &[
                "usize", "isize", "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64",
                "i128", "f32", "f64", "bool", "char", "str", "String", "Option", "Result", "Vec"
            ],
        }
    }
}

impl SyntaxHighlighter for RustHighlighter {
    fn name(&self) -> &str { "Rust" }
    fn file_extensions(&self) -> &[&str] { &["rs"] }

    fn highlight_line(&self, chars: &[char], mut state: LexerState) -> (Vec<HighlightType>, LexerState) {
        let mut highlights = vec![HighlightType::Normal; chars.len()];
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            // 1. Handle Block Comment state carrying over from previous lines
            if state == LexerState::InBlockComment {
                highlights[i] = HighlightType::Comment;
                if ch == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                    highlights[i + 1] = HighlightType::Comment;
                    state = LexerState::Normal;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }

            // 2. Comments starting in this line
            if ch == '/' && i + 1 < chars.len() {
                if chars[i + 1] == '/' {
                    for j in i..chars.len() {
                        highlights[j] = HighlightType::Comment;
                    }
                    break;
                } else if chars[i + 1] == '*' {
                    highlights[i] = HighlightType::Comment;
                    highlights[i + 1] = HighlightType::Comment;
                    state = LexerState::InBlockComment;
                    i += 2;
                    continue;
                }
            }

            // 3. String & Char Literals / Lifetimes
            if ch == '"' {
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

            if ch == '\'' {
                // Check if it is a character literal (e.g., 'a' or '\n')
                let is_char_lit = if i + 2 < chars.len() && chars[i + 2] == '\'' && chars[i + 1] != '\\' {
                    true
                } else if i + 3 < chars.len() && chars[i + 1] == '\\' && chars[i + 3] == '\'' {
                    true
                } else {
                    false
                };

                if is_char_lit {
                    highlights[i] = HighlightType::StringLiteral;
                    i += 1;
                    while i < chars.len() {
                        highlights[i] = HighlightType::StringLiteral;
                        if chars[i] == '\\' && i + 1 < chars.len() {
                            highlights[i + 1] = HighlightType::StringLiteral;
                            i += 2;
                            continue;
                        }
                        if chars[i] == '\'' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                } else {
                    // It is a lifetime (e.g., 'a or 'static)
                    highlights[i] = HighlightType::Type;
                    i += 1;
                    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                        highlights[i] = HighlightType::Type;
                        i += 1;
                    }
                }
                continue;
            }

            // 4. Numbers
            if ch.is_ascii_digit() {
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                    highlights[i] = HighlightType::Number;
                    i += 1;
                }
                continue;
            }

            // 5. Keywords, Types, and Macros (Word boundary tokenization)
            if ch.is_ascii_alphabetic() || ch == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();

                let hl_type = if self.keywords.contains(&word.as_str()) {
                    HighlightType::Keyword
                } else if self.types.contains(&word.as_str()) {
                    HighlightType::Type
                } else if i < chars.len() && chars[i] == '!' {
                    i += 1;
                    for j in start..i {
                        highlights[j] = HighlightType::Macro;
                    }
                    continue;
                } else {
                    HighlightType::Normal
                };

                if hl_type != HighlightType::Normal {
                    for j in start..i {
                        highlights[j] = hl_type;
                    }
                }
                continue;
            }

            i += 1;
        }

        (highlights, state)
    }
}
