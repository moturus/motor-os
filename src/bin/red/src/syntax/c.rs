use crate::buffer::{HighlightType, LexerState};
use crate::syntax::SyntaxHighlighter;

/// Highlighter for C and C++ source and header files.
///
/// A single highlighter covers both languages: the keyword/type sets are the
/// union of C and C++, which is harmless in practice (a `.c` file is very
/// unlikely to use `class` or `namespace` as an identifier). Multi-line
/// `/* ... */` block comments are tracked via `LexerState::InBlockComment`,
/// exactly like the Rust highlighter, so the editor's cascading re-highlight
/// works unchanged.
pub struct CHighlighter {
    keywords: &'static [&'static str],
    types: &'static [&'static str],
}

impl CHighlighter {
    pub fn new() -> Self {
        CHighlighter {
            keywords: &[
                // C control flow / storage / operators-as-words
                "auto", "break", "case", "const", "continue", "default", "do",
                "else", "enum", "extern", "for", "goto", "if", "inline",
                "register", "restrict", "return", "sizeof", "static", "struct",
                "switch", "typedef", "union", "volatile", "while", "signed",
                "unsigned",
                // C11 keywords
                "_Alignas", "_Alignof", "_Atomic", "_Generic", "_Noreturn",
                "_Static_assert", "_Thread_local",
                // C++ additions
                "alignas", "alignof", "and", "and_eq", "asm", "bitand", "bitor",
                "catch", "class", "compl", "concept", "consteval", "constexpr",
                "constinit", "const_cast", "co_await", "co_return", "co_yield",
                "decltype", "delete", "dynamic_cast", "explicit", "export",
                "final", "friend", "mutable", "namespace", "new", "noexcept",
                "not", "not_eq", "operator", "or", "or_eq", "override", "private",
                "protected", "public", "reinterpret_cast", "requires",
                "static_assert", "static_cast", "template", "this",
                "thread_local", "throw", "try", "typeid", "typename", "using",
                "virtual", "xor", "xor_eq",
                // constants treated as keywords
                "true", "false", "nullptr", "NULL",
            ],
            types: &[
                "void", "bool", "char", "short", "int", "long", "float",
                "double", "wchar_t", "char8_t", "char16_t", "char32_t",
                // fixed-width and common typedef'd types
                "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t",
                "int8_t", "int16_t", "int32_t", "int64_t",
                "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                "int_least8_t", "int_least16_t", "int_least32_t", "int_least64_t",
                "uint_least8_t", "uint_least16_t", "uint_least32_t", "uint_least64_t",
                "int_fast8_t", "int_fast16_t", "int_fast32_t", "int_fast64_t",
                "uint_fast8_t", "uint_fast16_t", "uint_fast32_t", "uint_fast64_t",
                "intmax_t", "uintmax_t", "FILE", "va_list",
                // a small set of very common C++ standard types
                "string", "wstring", "string_view", "vector", "array", "map",
                "unordered_map", "set", "unordered_set", "pair", "tuple",
                "unique_ptr", "shared_ptr", "weak_ptr", "optional", "ostream",
                "istream", "nullptr_t",
            ],
        }
    }

    /// A conventional macro / constant name: all uppercase letters, digits and
    /// underscores, at least two characters, and containing a real letter.
    /// This nicely colors things like `MAX_SIZE`, `EXIT_SUCCESS`, `GL_TRUE`.
    fn is_macro_name(word: &str) -> bool {
        if word.len() < 2 {
            return false;
        }
        let mut has_upper = false;
        for c in word.chars() {
            if c.is_ascii_uppercase() {
                has_upper = true;
            } else if !(c.is_ascii_digit() || c == '_') {
                return false;
            }
        }
        has_upper
    }
}

impl SyntaxHighlighter for CHighlighter {
    fn name(&self) -> &str { "C/C++" }

    fn file_extensions(&self) -> &[&str] {
        &[
            "c", "h", "cc", "cpp", "cxx", "c++", "hpp", "hh", "hxx", "h++",
            "inl", "ipp", "tpp", "ino",
            // traditional uppercase C++ extensions (matching is case-sensitive)
            "C", "H", "CC", "CPP", "CXX", "HPP",
        ]
    }

    fn highlight_line(&self, chars: &[char], mut state: LexerState) -> (Vec<HighlightType>, LexerState) {
        let mut highlights = vec![HighlightType::Normal; chars.len()];
        let mut i = 0;
        let started_normal = state == LexerState::Normal;

        // 1. Continue an unterminated block comment carried over from a
        //    previous line.
        if state == LexerState::InBlockComment {
            while i < chars.len() {
                highlights[i] = HighlightType::Comment;
                if chars[i] == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                    highlights[i + 1] = HighlightType::Comment;
                    i += 2;
                    state = LexerState::Normal;
                    break;
                }
                i += 1;
            }
        }

        // 2. Preprocessor directive. Only when the line genuinely begins (in the
        //    normal state) with `#`, allowing leading whitespace. The directive
        //    word (e.g. `#include`, `#define`) is colored as Preprocessor; the
        //    rest of the line is lexed normally below so embedded strings,
        //    comments and numbers still highlight.
        let mut in_include = false;
        if started_normal {
            let mut j = 0;
            while j < chars.len() && (chars[j] == ' ' || chars[j] == '\t') {
                j += 1;
            }
            if j < chars.len() && chars[j] == '#' {
                let mut k = j + 1;
                while k < chars.len() && (chars[k] == ' ' || chars[k] == '\t') {
                    k += 1;
                }
                let dir_start = k;
                while k < chars.len() && (chars[k].is_ascii_alphabetic() || chars[k] == '_') {
                    k += 1;
                }
                let directive: String = chars[dir_start..k].iter().collect();
                for x in j..k {
                    highlights[x] = HighlightType::Preprocessor;
                }
                if directive == "include" || directive == "import" || directive == "include_next" {
                    in_include = true;
                }
                i = k;
            }
        }

        // 3. Main tokenizer.
        while i < chars.len() {
            let ch = chars[i];

            // Block comment start (may end on this line or cascade).
            if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
                highlights[i] = HighlightType::Comment;
                highlights[i + 1] = HighlightType::Comment;
                i += 2;
                state = LexerState::InBlockComment;
                while i < chars.len() {
                    highlights[i] = HighlightType::Comment;
                    if chars[i] == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                        highlights[i + 1] = HighlightType::Comment;
                        i += 2;
                        state = LexerState::Normal;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // Line comment.
            if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
                for j in i..chars.len() {
                    highlights[j] = HighlightType::Comment;
                }
                break;
            }

            // `#include <header>` angle-bracket header.
            if in_include && ch == '<' {
                highlights[i] = HighlightType::StringLiteral;
                i += 1;
                while i < chars.len() {
                    highlights[i] = HighlightType::StringLiteral;
                    let closing = chars[i] == '>';
                    i += 1;
                    if closing {
                        break;
                    }
                }
                continue;
            }

            // String literal.
            if ch == '"' {
                highlights[i] = HighlightType::StringLiteral;
                i += 1;
                while i < chars.len() {
                    highlights[i] = HighlightType::StringLiteral;
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        highlights[i + 1] = HighlightType::StringLiteral;
                        i += 2;
                        continue;
                    }
                    if chars[i] == '"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // Character literal.
            if ch == '\'' {
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
                continue;
            }

            // Numbers: decimal, hex (0x), binary (0b), floats with exponents,
            // suffixes (u/l/f), and C++14 digit separators (1'000).
            if ch.is_ascii_digit()
                || (ch == '.' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit())
            {
                while i < chars.len() {
                    let c = chars[i];
                    if c.is_ascii_alphanumeric() || c == '.' || c == '\'' {
                        highlights[i] = HighlightType::Number;
                        i += 1;
                    } else if (c == '+' || c == '-')
                        && i > 0
                        && matches!(chars[i - 1], 'e' | 'E' | 'p' | 'P')
                    {
                        highlights[i] = HighlightType::Number;
                        i += 1;
                    } else {
                        break;
                    }
                }
                continue;
            }

            // Identifiers: keywords, types, and macro-style constants.
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
                } else if Self::is_macro_name(&word) {
                    HighlightType::Macro
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hl(src: &str, state: LexerState) -> (Vec<HighlightType>, LexerState) {
        let chars: Vec<char> = src.chars().collect();
        CHighlighter::new().highlight_line(&chars, state)
    }

    fn types_of(src: &str) -> Vec<HighlightType> {
        hl(src, LexerState::Normal).0
    }

    #[test]
    fn keywords_and_types() {
        let src = "int main";
        let h = types_of(src);
        // "int" is a type, "main" is a normal identifier.
        assert_eq!(h[0], HighlightType::Type);
        assert_eq!(h[1], HighlightType::Type);
        assert_eq!(h[2], HighlightType::Type);
        assert_eq!(h[4], HighlightType::Normal); // 'm'
    }

    #[test]
    fn control_keyword() {
        let h = types_of("return 0;");
        assert_eq!(h[0], HighlightType::Keyword); // 'r'
        assert_eq!(h[5], HighlightType::Keyword); // 'n' (end of "return")
        assert_eq!(h[6], HighlightType::Normal); // space
        assert_eq!(h[7], HighlightType::Number); // '0'
    }

    #[test]
    fn line_comment() {
        let src = "x // hi";
        let h = types_of(src);
        assert_eq!(h[0], HighlightType::Normal);
        assert_eq!(h[2], HighlightType::Comment);
        assert_eq!(h[6], HighlightType::Comment);
    }

    #[test]
    fn block_comment_cascades() {
        // Opening line leaves us inside a block comment.
        let (h1, s1) = hl("a /* start", LexerState::Normal);
        assert_eq!(h1[0], HighlightType::Normal);
        assert_eq!(h1[2], HighlightType::Comment); // '/'
        assert_eq!(s1, LexerState::InBlockComment);

        // Middle line stays entirely in the comment.
        let (h2, s2) = hl("still comment", LexerState::InBlockComment);
        assert!(h2.iter().all(|&t| t == HighlightType::Comment));
        assert_eq!(s2, LexerState::InBlockComment);

        // Closing line ends the comment; code after `*/` lexes normally.
        let (h3, s3) = hl("end */ int", LexerState::InBlockComment);
        assert_eq!(h3[0], HighlightType::Comment);
        assert_eq!(h3[4], HighlightType::Comment); // '*'
        assert_eq!(h3[5], HighlightType::Comment); // '/'
        assert_eq!(s3, LexerState::Normal);
        assert_eq!(h3[7], HighlightType::Type); // 'i' of int
    }

    #[test]
    fn preprocessor_include_with_header() {
        let src = "#include <stdio.h>";
        let h = types_of(src);
        // `#include`
        for t in &h[0..8] {
            assert_eq!(*t, HighlightType::Preprocessor);
        }
        // `<stdio.h>` as a string literal
        let lt = src.find('<').unwrap();
        let gt = src.find('>').unwrap();
        for t in &h[lt..=gt] {
            assert_eq!(*t, HighlightType::StringLiteral);
        }
    }

    #[test]
    fn preprocessor_define_macro_name() {
        let src = "#define MAX 100";
        let h = types_of(src);
        // `#define` spans indices 0..7.
        for t in &h[0..7] {
            assert_eq!(*t, HighlightType::Preprocessor);
        }
        // MAX is an all-caps macro-style name.
        let m = src.find("MAX").unwrap();
        assert_eq!(h[m], HighlightType::Macro);
        // 100 is a number.
        let n = src.find("100").unwrap();
        assert_eq!(h[n], HighlightType::Number);
    }

    #[test]
    fn strings_and_chars() {
        let src = "char c = '\\n'; char* s = \"hi\";";
        let h = types_of(src);
        assert_eq!(h[0], HighlightType::Type); // 'char'
        let q = src.find('\'').unwrap();
        assert_eq!(h[q], HighlightType::StringLiteral);
        let dq = src.find('"').unwrap();
        assert_eq!(h[dq], HighlightType::StringLiteral);
    }

    #[test]
    fn hex_and_float_numbers() {
        let h = types_of("0xFF 3.14f 1e-9");
        assert_eq!(h[0], HighlightType::Number);
        assert_eq!(h[3], HighlightType::Number); // 'F'
        let f = "0xFF ".len();
        assert_eq!(h[f], HighlightType::Number); // '3'
    }

    #[test]
    fn cpp_keywords() {
        let h = types_of("class Foo : public Bar {};");
        assert_eq!(h[0], HighlightType::Keyword); // class
        let p = "class Foo : ".len();
        assert_eq!(h[p], HighlightType::Keyword); // public
    }

    #[test]
    fn hash_not_at_start_is_not_preprocessor() {
        // A stray '#' mid-line should not be treated as a directive.
        let h = types_of("int x = a # b");
        let hash = "int x = a ".len();
        assert_eq!(h[hash], HighlightType::Normal);
    }
}
