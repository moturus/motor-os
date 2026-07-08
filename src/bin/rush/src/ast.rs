//! Abstract syntax tree produced by the parser (Phase 2).
//!
//! The parser turns the lexer's token stream into this tree for the
//! *non-compound* core of the grammar (POSIX §2.9): a `List` of `AndOr` lists
//! of `Pipeline`s of `Command`s. In Phase 2 the only `Command` is a
//! [`SimpleCommand`]; compound commands (`if`, `for`, `while`, `case`, brace
//! groups, subshells) and function definitions arrive in Phase 4, and the
//! executor that fully walks this tree — with real expansion, pipelines, and
//! redirections — arrives in Phase 3.
//!
//! Some fields and variants are placeholders wired up now for AST stability but
//! only acted on in a later phase (pipeline negation `!`, the `Async` `&`
//! separator, and the fd-duplication redirection operators). Hence the
//! module-level `allow(dead_code)`.
#![allow(dead_code)]

use crate::token::{HereDoc, Word};

/// A complete command: a sequence of and-or lists joined by `;`, `&`, or
/// newlines. This is the whole parse of a line (interactive) or a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List(pub Vec<ListItem>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub and_or: AndOr,
    /// The terminator that followed this and-or list. `Async` (`&`) means the
    /// list runs in the background; honored in Phase 7 (until then it runs
    /// synchronously, like `Seq`).
    pub sep: Separator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Separator {
    /// `;` or a newline: run sequentially, waiting for completion.
    Seq,
    /// `&`: run asynchronously (Phase 7).
    Async,
}

/// A pipeline, optionally followed by `&&`/`||`-joined pipelines. Left
/// associative: `a && b || c` parses as `((a && b) || c)`, i.e. each operator
/// acts on the accumulated status so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndOr {
    pub first: Pipeline,
    pub rest: Vec<(AndOrOp, Pipeline)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndOrOp {
    /// `&&`: run the next pipeline only if the previous status was 0.
    And,
    /// `||`: run the next pipeline only if the previous status was non-zero.
    Or,
}

/// One or more commands connected by `|`. `bang` is the leading `!` negation
/// (recognized in Phase 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub bang: bool,
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Simple(SimpleCommand),
    // Compound commands (Brace/Subshell/If/For/While/Until/Case) and function
    // definitions arrive in Phase 4.
}

/// A simple command: optional variable assignments, a command word and its
/// arguments, and redirections — the three interleaved freely per POSIX §2.9.1
/// (an assignment is only recognized *before* the first word).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    pub assigns: Vec<Assignment>,
    pub words: Vec<Word>,
    pub redirects: Vec<Redirect>,
}

/// A `NAME=value` assignment. `value` is an unexpanded [`Word`]; expansion
/// happens at execution time (Phase 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub name: String,
    pub value: Word,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    /// A redirection to/from a filename `target`, e.g. `> f`, `2>> f`, `< f`.
    /// `fd` is the explicit left-hand IO number, or `None` for the operator's
    /// default (0 for input, 1 for output).
    File {
        fd: Option<u32>,
        op: RedirOp,
        target: Word,
    },
    /// A here-document (`<<` / `<<-`) feeding `fd` (default 0). The body was
    /// collected by the lexer.
    Heredoc { fd: Option<u32>, doc: HereDoc },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirOp {
    Read,      // <
    Write,     // >
    Append,    // >>
    ReadWrite, // <>
    Clobber,   // >|
    DupRead,   // <&   (fd duplication — executed in Phase 3)
    DupWrite,  // >&   (fd duplication — executed in Phase 3)
}
