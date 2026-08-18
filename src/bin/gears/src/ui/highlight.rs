//! Semantic highlighting for fenced code in model Markdown.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Keyword,
    Type,
    String,
    Number,
    Comment,
    Macro,
    Lifetime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Rust,
}

impl Language {
    fn from_info(info: &str) -> Option<Language> {
        let tag = info
            .split_whitespace()
            .next()?
            .trim_start_matches("{.")
            .trim_end_matches('}');
        match tag.to_ascii_lowercase().as_str() {
            "rust" | "rs" => Some(Language::Rust),
            _ => None,
        }
    }
}

struct Fence {
    marker: u8,
    length: usize,
    highlighter: Option<Highlighter>,
}

/// Tracks one Markdown message. Adding a language only requires registering
/// its fence name and constructing its lexer in `Highlighter::new`.
#[derive(Default)]
pub struct Markdown {
    fence: Option<Fence>,
}

impl Markdown {
    pub fn line(&mut self, line: &str) -> Vec<Span> {
        if self
            .fence
            .as_ref()
            .is_some_and(|fence| closing_fence(line, fence.marker, fence.length))
        {
            self.fence = None;
            return Vec::new();
        }
        if let Some(fence) = self.fence.as_mut() {
            return fence
                .highlighter
                .as_mut()
                .map(|highlighter| highlighter.line(line))
                .unwrap_or_default();
        }
        if let Some((marker, length, info)) = opening_fence(line) {
            self.fence = Some(Fence {
                marker,
                length,
                highlighter: Language::from_info(info).map(Highlighter::new),
            });
        }
        Vec::new()
    }
}

fn opening_fence(line: &str) -> Option<(u8, usize, &str)> {
    let line = indentation(line)?;
    let bytes = line.as_bytes();
    let marker = *bytes.first()?;
    if !matches!(marker, b'`' | b'~') {
        return None;
    }
    let length = bytes.iter().take_while(|byte| **byte == marker).count();
    if length < 3 {
        return None;
    }
    let info = line[length..].trim();
    if marker == b'`' && info.contains('`') {
        return None;
    }
    Some((marker, length, info))
}

fn closing_fence(line: &str, marker: u8, opening_length: usize) -> bool {
    let Some(line) = indentation(line) else {
        return false;
    };
    let bytes = line.as_bytes();
    let length = bytes.iter().take_while(|byte| **byte == marker).count();
    length >= opening_length && line[length..].trim().is_empty()
}

fn indentation(line: &str) -> Option<&str> {
    let spaces = line.bytes().take_while(|byte| *byte == b' ').count();
    (spaces <= 3).then(|| &line[spaces..])
}

enum Lexer {
    Rust(Rust),
}

struct Highlighter {
    lexer: Lexer,
}

impl Highlighter {
    fn new(language: Language) -> Highlighter {
        let lexer = match language {
            Language::Rust => Lexer::Rust(Rust::default()),
        };
        Highlighter { lexer }
    }

    fn line(&mut self, line: &str) -> Vec<Span> {
        match &mut self.lexer {
            Lexer::Rust(rust) => rust.line(line),
        }
    }
}

#[derive(Default)]
struct Rust {
    state: RustState,
}

#[derive(Default)]
enum RustState {
    #[default]
    Normal,
    BlockComment(usize),
    RawString(usize),
}

impl Rust {
    fn line(&mut self, line: &str) -> Vec<Span> {
        let bytes = line.as_bytes();
        let mut spans = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            match self.state {
                RustState::BlockComment(depth) => {
                    let (end, depth) = block_comment(bytes, at, depth);
                    push(&mut spans, at, end, Kind::Comment);
                    at = end;
                    self.state = match depth {
                        0 => RustState::Normal,
                        depth => RustState::BlockComment(depth),
                    };
                }
                RustState::RawString(hashes) => {
                    let end = raw_string_end(bytes, at, hashes);
                    push(&mut spans, at, end.unwrap_or(bytes.len()), Kind::String);
                    at = end.unwrap_or(bytes.len());
                    if end.is_some() {
                        self.state = RustState::Normal;
                    }
                }
                RustState::Normal if bytes[at..].starts_with(b"//") => {
                    push(&mut spans, at, bytes.len(), Kind::Comment);
                    break;
                }
                RustState::Normal if bytes[at..].starts_with(b"/*") => {
                    let (end, depth) = block_comment(bytes, at, 0);
                    push(&mut spans, at, end, Kind::Comment);
                    at = end;
                    if depth > 0 {
                        self.state = RustState::BlockComment(depth);
                    }
                }
                RustState::Normal => {
                    let start = at;
                    if let Some((content, hashes)) = raw_string_start(bytes, at) {
                        let end = raw_string_end(bytes, content, hashes);
                        push(&mut spans, start, end.unwrap_or(bytes.len()), Kind::String);
                        at = end.unwrap_or(bytes.len());
                        if end.is_none() {
                            self.state = RustState::RawString(hashes);
                        }
                    } else if let Some(end) = quoted_start(bytes, at) {
                        push(&mut spans, start, end, Kind::String);
                        at = end;
                    } else if bytes[at] == b'\'' {
                        if let Some(end) = char_literal_end(line, at) {
                            push(&mut spans, start, end, Kind::String);
                            at = end;
                        } else {
                            at += 1;
                            at = identifier_end(line, at);
                            push(&mut spans, start, at, Kind::Lifetime);
                        }
                    } else if bytes[at].is_ascii_digit() {
                        at = number_end(bytes, at);
                        push(&mut spans, start, at, Kind::Number);
                    } else {
                        let character = line[at..].chars().next().expect("valid UTF-8");
                        if identifier_start(character) {
                            at = identifier_end(line, at);
                            let word = &line[start..at];
                            let kind = if KEYWORDS.contains(&word) {
                                Some(Kind::Keyword)
                            } else if TYPES.contains(&word)
                                || word.chars().next().is_some_and(char::is_uppercase)
                            {
                                Some(Kind::Type)
                            } else if next_non_space(bytes, at) == Some(b'!') {
                                Some(Kind::Macro)
                            } else {
                                None
                            };
                            if let Some(kind) = kind {
                                push(&mut spans, start, at, kind);
                            }
                        } else {
                            at += character.len_utf8();
                        }
                    }
                }
            }
        }
        spans
    }
}

fn push(spans: &mut Vec<Span>, start: usize, end: usize, kind: Kind) {
    if start < end {
        spans.push(Span { start, end, kind });
    }
}

fn block_comment(bytes: &[u8], mut at: usize, mut depth: usize) -> (usize, usize) {
    while at < bytes.len() {
        if bytes[at..].starts_with(b"/*") {
            depth += 1;
            at += 2;
        } else if bytes[at..].starts_with(b"*/") {
            depth = depth.saturating_sub(1);
            at += 2;
            if depth == 0 {
                break;
            }
        } else {
            at += 1;
        }
    }
    (at, depth)
}

fn raw_string_start(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut cursor = at;
    if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hashes = bytes[cursor..]
        .iter()
        .take_while(|byte| **byte == b'#')
        .count();
    cursor += hashes;
    (bytes.get(cursor) == Some(&b'"')).then_some((cursor + 1, hashes))
}

fn raw_string_end(bytes: &[u8], mut at: usize, hashes: usize) -> Option<usize> {
    while at < bytes.len() {
        if bytes[at] == b'"'
            && bytes
                .get(at + 1..at + 1 + hashes)
                .is_some_and(|tail| tail.iter().all(|byte| *byte == b'#'))
        {
            return Some(at + 1 + hashes);
        }
        at += 1;
    }
    None
}

fn quoted_start(bytes: &[u8], at: usize) -> Option<usize> {
    let quote = match bytes.get(at..) {
        Some([b'"', ..]) => at,
        Some([b'b' | b'c', b'"', ..]) => at + 1,
        Some([b'b', b'\'', ..]) => return char_literal_end_bytes(bytes, at + 1),
        _ => return None,
    };
    Some(quoted_end(bytes, quote))
}

fn quoted_end(bytes: &[u8], quote: usize) -> usize {
    let mut at = quote + 1;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => at = (at + 2).min(bytes.len()),
            b'"' => return at + 1,
            _ => at += 1,
        }
    }
    bytes.len()
}

fn char_literal_end(line: &str, quote: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let content = quote + 1;
    let first = line.get(content..)?.chars().next()?;
    let end = if first == '\\' {
        escaped_char_end(bytes, content)?
    } else {
        content + first.len_utf8()
    };
    (bytes.get(end) == Some(&b'\'')).then_some(end + 1)
}

fn char_literal_end_bytes(bytes: &[u8], quote: usize) -> Option<usize> {
    let content = quote + 1;
    let end = match bytes.get(content)? {
        b'\\' => escaped_char_end(bytes, content)?,
        byte if byte.is_ascii() => content + 1,
        _ => return None,
    };
    (bytes.get(end) == Some(&b'\'')).then_some(end + 1)
}

fn escaped_char_end(bytes: &[u8], slash: usize) -> Option<usize> {
    match *bytes.get(slash + 1)? {
        b'x' => (slash + 4 <= bytes.len()).then_some(slash + 4),
        b'u' if bytes.get(slash + 2) == Some(&b'{') => bytes[slash + 3..]
            .iter()
            .position(|byte| *byte == b'}')
            .map(|offset| slash + 4 + offset),
        _ => Some(slash + 2),
    }
}

fn identifier_start(character: char) -> bool {
    character == '_' || character.is_alphabetic()
}

fn identifier_end(line: &str, mut at: usize) -> usize {
    while let Some(character) = line[at..].chars().next() {
        if character != '_' && !character.is_alphanumeric() {
            break;
        }
        at += character.len_utf8();
        if at == line.len() {
            break;
        }
    }
    at
}

fn number_end(bytes: &[u8], mut at: usize) -> usize {
    while let Some(byte) = bytes.get(at) {
        let exponent_sign = matches!(byte, b'+' | b'-')
            && at > 0
            && matches!(bytes[at - 1], b'e' | b'E' | b'p' | b'P');
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.') || exponent_sign {
            at += 1;
        } else {
            break;
        }
    }
    at
}

fn next_non_space(bytes: &[u8], mut at: usize) -> Option<u8> {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    bytes.get(at).copied()
}

const KEYWORDS: &[&str] = &[
    "Self", "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
    "extern", "false", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true",
    "type", "union", "unsafe", "use", "where", "while", "yield",
];

const TYPES: &[&str] = &[
    "bool", "char", "f32", "f64", "i8", "i16", "i32", "i64", "i128", "isize", "str", "u8", "u16",
    "u32", "u64", "u128", "usize",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(markdown: &mut Markdown, line: &str) -> Vec<Kind> {
        markdown
            .line(line)
            .into_iter()
            .map(|span| span.kind)
            .collect()
    }

    #[test]
    fn rust_fences_dispatch_to_semantic_tokens() {
        let mut markdown = Markdown::default();
        assert!(markdown.line("```rust").is_empty());
        assert_eq!(
            kinds(
                &mut markdown,
                r#"pub fn main() { println!("hello", 42); } // done"#
            ),
            [
                Kind::Keyword,
                Kind::Keyword,
                Kind::Macro,
                Kind::String,
                Kind::Number,
                Kind::Comment,
            ]
        );
        assert!(markdown.line("```").is_empty());
        assert!(markdown.line("fn plain() {}").is_empty());
    }

    #[test]
    fn unknown_fences_remain_unstyled_and_aliases_are_registered() {
        let mut unknown = Markdown::default();
        assert!(unknown.line("```python").is_empty());
        assert!(unknown.line("def fn():").is_empty());
        assert!(unknown.line("```").is_empty());

        let mut rust = Markdown::default();
        rust.line("~~~rs");
        assert_eq!(
            kinds(&mut rust, "let n: usize = 1;"),
            [Kind::Keyword, Kind::Type, Kind::Number]
        );
    }

    #[test]
    fn multiline_rust_lexical_state_is_preserved() {
        let mut markdown = Markdown::default();
        markdown.line("```rust");
        assert_eq!(kinds(&mut markdown, "/* outer"), [Kind::Comment]);
        assert_eq!(
            kinds(&mut markdown, "nested /* x */ end */ let"),
            [Kind::Comment, Kind::Keyword]
        );
        assert_eq!(
            kinds(&mut markdown, "let text = r#\"first"),
            [Kind::Keyword, Kind::String]
        );
        assert_eq!(kinds(&mut markdown, "second\"#;"), [Kind::String]);
    }
}
