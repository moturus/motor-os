//! Token types produced by the lexer (Phase 1).
//!
//! The lexer recognizes tokens per POSIX §2.3 / §2.10.1 but does NOT expand:
//! `$`-expansions and command substitutions are captured as opaque `Expansion`
//! spans to be sub-parsed during Phase 3, and quoting is preserved (never
//! stripped) so later phases can apply field splitting, pathname expansion, and
//! quote removal correctly.
//!
//! Not yet consumed by the executor — the Phase 2 parser wires this in.
#![allow(dead_code)]

/// A shell word: an ordered list of parts. Concatenating the parts (after
/// expansion + quote removal in Phase 3) yields the final word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word(pub Vec<WordPart>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordPart {
    /// Literal text. `quoted` means these characters came from quotes or a
    /// backslash escape and are therefore protected from field splitting and
    /// pathname expansion; quote removal keeps them verbatim.
    Literal { text: String, quoted: bool },
    /// An unexpanded expansion captured verbatim. `raw` holds the inner text
    /// only — without the leading `$`, without `{}`/`()`/`` `` `` delimiters —
    /// to be parsed in Phase 3 according to `kind`. `quoted` means it appeared
    /// inside double quotes (its result is not field-split).
    Expansion {
        kind: ExpansionKind,
        raw: String,
        quoted: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpansionKind {
    /// `$name` or `${...}`.
    Parameter,
    /// `$(...)` or `` `...` ``.
    Command,
    /// `$(( ... ))`.
    Arithmetic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A WORD. The parser decides (by position) whether it is a reserved word,
    /// a name, an assignment, or a plain argument — that is a Phase 2 concern.
    Word(Word),
    /// A control or redirection operator.
    Op(Operator),
    /// A run of digits immediately preceding an unquoted `<` or `>` (e.g. the
    /// `2` in `2>file`).
    IoNumber(u32),
    /// An unquoted newline: a command separator in the grammar, and the point
    /// at which pending here-document bodies are collected.
    Newline,
    /// A fully collected here-document (`<<` / `<<-`), delimiter and body.
    HereDoc(HereDoc),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    // Control operators (§2.10.1).
    Semi,    // ;
    DSemi,   // ;;
    Amp,     // &
    AndAnd,  // &&
    Pipe,    // |
    OrOr,    // ||
    LParen,  // (
    RParen,  // )
    // Redirection operators. `<<` / `<<-` are represented by Token::HereDoc,
    // not here, because they also carry a collected body.
    Less,      // <
    Great,     // >
    DGreat,    // >>
    LessAnd,   // <&
    GreatAnd,  // >&
    LessGreat, // <>
    Clobber,   // >|
}

/// A here-document redirection. The delimiter has already had quote removal
/// applied; `quoted` records whether it was quoted (which disables expansion of
/// the body in Phase 3). `body` is the collected text with a trailing newline
/// per line, leading tabs stripped when `strip_tabs` (the `<<-` form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HereDoc {
    pub strip_tabs: bool,
    pub quoted: bool,
    pub delim: String,
    pub body: String,
}
