//! Abstract syntax tree produced by the parser (Phase 2, extended in Phase 4).
//!
//! The parser turns the lexer's token stream into this tree (POSIX §2.9): a
//! `List` of `AndOr` lists of `Pipeline`s of `Command`s. A [`Command`] is a
//! [`SimpleCommand`], a [`CompoundCommand`] (`if`, `for`, `while`/`until`,
//! `case`, brace group `{ … }`, subshell `( … )`) with attached redirections, or
//! a function definition. The executor that walks this tree — with real
//! expansion, pipelines, redirections, and control flow — lives in
//! [`crate::exec`].
//!
//! Some fields and variants are placeholders wired up for AST stability but only
//! acted on in a later phase (the `Async` `&` separator runs synchronously until
//! Phase 7). Hence the module-level `allow(dead_code)`.
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

/// One or more commands connected by `|`. `bang` is the leading `!` negation,
/// which inverts the pipeline's final exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub bang: bool,
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A simple command: `echo hi`, `VAR=x cmd args >file`.
    Simple(SimpleCommand),
    /// A compound command (`if`, `for`, `while`/`until`, `case`, `{ … }`,
    /// `( … )`) with any redirections that apply to the whole construct.
    Compound {
        kind: CompoundCommand,
        redirects: Vec<Redirect>,
    },
    /// A function definition `name() compound-command`. Executing it registers
    /// the function; it produces no output and exits 0.
    Function { name: String, body: FunctionBody },
}

/// A compound command (POSIX §2.9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompoundCommand {
    /// `{ list; }` — runs in the current shell environment.
    Brace(List),
    /// `( list )` — runs in a subshell environment.
    Subshell(List),
    If(IfClause),
    For(ForClause),
    While(WhileClause),
    Case(CaseClause),
}

/// `if cond; then …; [elif cond; then …]…; [else …]; fi`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfClause {
    pub cond: List,
    pub then_branch: List,
    /// Zero or more `elif cond; then body` clauses, in order.
    pub elifs: Vec<(List, List)>,
    pub else_branch: Option<List>,
}

/// `for name [in words…]; do body; done`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForClause {
    pub var: String,
    /// The `in` word list. `None` means the `in` clause was omitted, so the loop
    /// iterates over the positional parameters (`"$@"`); `Some(vec![])` is an
    /// explicit empty list (the body never runs).
    pub words: Option<Vec<Word>>,
    pub body: List,
}

/// `while cond; do body; done` or `until cond; do body; done`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhileClause {
    /// `false` for `while`, `true` for `until` (the condition sense is inverted).
    pub until: bool,
    pub cond: List,
    pub body: List,
}

/// `case word in pat) body ;; … esac`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseClause {
    pub word: Word,
    pub items: Vec<CaseItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseItem {
    /// One or more `|`-separated patterns; the item matches if any does.
    pub patterns: Vec<Word>,
    /// The commands run on a match (may be empty).
    pub body: List,
}

/// A function's stored body: the compound command plus any redirections that
/// were attached to the definition (applied on each invocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionBody {
    pub body: CompoundCommand,
    pub redirects: Vec<Redirect>,
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
