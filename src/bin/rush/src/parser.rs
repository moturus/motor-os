//! Recursive-descent parser (Phase 2, extended in Phase 4): tokens → [`ast`].
//!
//! Grammar handled here (POSIX §2.9):
//!
//! ```text
//! program   := compound_list
//! comp_list := linebreak (and_or (separator and_or)*)?  // stops at a terminator
//! and_or    := pipeline (('&&' | '||') linebreak pipeline)*
//! pipeline  := ['!'] command ('|' linebreak command)*
//! command   := simple_command | compound_command | function_def
//! compound  := brace_group | subshell | if | for | while | until | case
//! simple    := (assignment | word | redirect)+   // assignment only before 1st word
//! ```
//!
//! [`parse_source`] is the single entry point used by both the interactive loop
//! and the `-c`/script paths: it lexes then parses, folding the lexer's
//! "incomplete input" and the parser's own "needs another operand / closing
//! keyword" cases into one [`Parsed::Incomplete`] result that drives PS2
//! continuation. Reserved words (`if`, `for`, `{`, `}`, `!`, …) are recognized
//! only in *command position*; elsewhere they are ordinary words.

use crate::ast::{
    AndOr, AndOrOp, Assignment, CaseClause, CaseItem, Command, CompoundCommand, ForClause,
    FunctionBody, IfClause, List, ListItem, Pipeline, RedirOp, Redirect, Separator, SimpleCommand,
    WhileClause,
};
use crate::lexer::{self, LexError};
use crate::token::{Operator, Token, Word, WordPart};

/// Outcome of parsing a source buffer.
pub enum Parsed {
    /// A complete parse; ready to execute.
    Complete(List),
    /// The buffer ends mid-construct (open quote, dangling `&&`/`|`, unfinished
    /// here-doc, …). The interactive loop should read another line (PS2) and
    /// re-parse the accumulated buffer; non-interactive callers treat this as a
    /// syntax error (unexpected end of input).
    Incomplete,
    /// Nothing to do (blank input or comments only).
    Empty,
    /// A syntax error, with a human-readable message (no leading "rush:").
    Error(String),
}

/// Lex and parse a source buffer into a [`Parsed`] outcome.
pub fn parse_source(src: &str) -> Parsed {
    let tokens = match lexer::tokenize(src) {
        Ok(t) => t,
        Err(LexError::Incomplete(_)) => return Parsed::Incomplete,
    };
    let mut p = Parser { toks: tokens, pos: 0 };
    match p.parse_program() {
        Ok(list) if list.0.is_empty() => Parsed::Empty,
        Ok(list) => Parsed::Complete(list),
        Err(PErr::Incomplete) => Parsed::Incomplete,
        Err(PErr::Syntax(msg)) => Parsed::Error(msg),
    }
}

/// Internal parse error: either "need more input" or a hard syntax error.
enum PErr {
    Incomplete,
    Syntax(String),
}
type PResult<T> = Result<T, PErr>;

struct Parser {
    toks: Vec<Token>,
    pos: usize,
}

fn is_redirect_op(op: Operator) -> bool {
    matches!(
        op,
        Operator::Less
            | Operator::Great
            | Operator::DGreat
            | Operator::LessGreat
            | Operator::Clobber
            | Operator::LessAnd
            | Operator::GreatAnd
    )
}

fn map_redir_op(op: Operator) -> RedirOp {
    match op {
        Operator::Less => RedirOp::Read,
        Operator::Great => RedirOp::Write,
        Operator::DGreat => RedirOp::Append,
        Operator::LessGreat => RedirOp::ReadWrite,
        Operator::Clobber => RedirOp::Clobber,
        Operator::LessAnd => RedirOp::DupRead,
        Operator::GreatAnd => RedirOp::DupWrite,
        other => unreachable!("map_redir_op on non-redirection operator {other:?}"),
    }
}

fn op_display(op: Operator) -> &'static str {
    match op {
        Operator::Semi => ";",
        Operator::DSemi => ";;",
        Operator::Amp => "&",
        Operator::AndAnd => "&&",
        Operator::Pipe => "|",
        Operator::OrOr => "||",
        Operator::LParen => "(",
        Operator::RParen => ")",
        Operator::Less => "<",
        Operator::Great => ">",
        Operator::DGreat => ">>",
        Operator::LessAnd => "<&",
        Operator::GreatAnd => ">&",
        Operator::LessGreat => "<>",
        Operator::Clobber => ">|",
    }
}

fn token_display(t: &Token) -> String {
    match t {
        Token::Op(o) => op_display(*o).to_string(),
        Token::Newline => "newline".to_string(),
        // Render a plain literal word verbatim (handy for reserved-word errors);
        // fall back to "word" for anything containing an expansion.
        Token::Word(w) => match w.0.as_slice() {
            [WordPart::Literal { text, .. }] => text.clone(),
            _ => "word".to_string(),
        },
        Token::IoNumber(n) => n.to_string(),
        Token::HereDoc(_) => "<<".to_string(),
    }
}

/// Split a word into `(name, value)` if it has the form `NAME=value` with a
/// valid name in its leading unquoted literal run — i.e. it is a shell
/// assignment. Returns `None` for ordinary words.
fn split_assignment(w: &Word) -> Option<(String, Word)> {
    let WordPart::Literal { text, quoted: false } = w.0.first()? else {
        return None;
    };
    let eq = text.find('=')?;
    let name = &text[..eq];
    if !crate::is_valid_var_name(name) {
        return None;
    }
    let rest = &text[eq + 1..];
    let mut value = Vec::new();
    if !rest.is_empty() {
        value.push(WordPart::Literal {
            text: rest.to_string(),
            quoted: false,
        });
    }
    value.extend(w.0[1..].iter().cloned());
    Some((name.to_string(), Word(value)))
}

/// The POSIX reserved words (§2.4). They are only *recognized* by the parser
/// when a token appears in command position; elsewhere they are ordinary words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reserved {
    Bang,   // !
    LBrace, // {
    RBrace, // }
    If,
    Then,
    Else,
    Elif,
    Fi,
    For,
    In,
    Do,
    Done,
    While,
    Until,
    Case,
    Esac,
}

impl Reserved {
    fn from_text(s: &str) -> Option<Reserved> {
        Some(match s {
            "!" => Reserved::Bang,
            "{" => Reserved::LBrace,
            "}" => Reserved::RBrace,
            "if" => Reserved::If,
            "then" => Reserved::Then,
            "else" => Reserved::Else,
            "elif" => Reserved::Elif,
            "fi" => Reserved::Fi,
            "for" => Reserved::For,
            "in" => Reserved::In,
            "do" => Reserved::Do,
            "done" => Reserved::Done,
            "while" => Reserved::While,
            "until" => Reserved::Until,
            "case" => Reserved::Case,
            "esac" => Reserved::Esac,
            _ => return None,
        })
    }

    fn text(self) -> &'static str {
        match self {
            Reserved::Bang => "!",
            Reserved::LBrace => "{",
            Reserved::RBrace => "}",
            Reserved::If => "if",
            Reserved::Then => "then",
            Reserved::Else => "else",
            Reserved::Elif => "elif",
            Reserved::Fi => "fi",
            Reserved::For => "for",
            Reserved::In => "in",
            Reserved::Do => "do",
            Reserved::Done => "done",
            Reserved::While => "while",
            Reserved::Until => "until",
            Reserved::Case => "case",
            Reserved::Esac => "esac",
        }
    }
}

/// Whether `s` is a POSIX shell reserved word (§2.4). Used by `type`/`command`
/// to classify a name as a shell keyword.
pub fn is_reserved_word(s: &str) -> bool {
    Reserved::from_text(s).is_some()
}

/// The reserved word a token spells, if it is a single unquoted-literal word
/// matching one. (Whether it is *treated* as reserved is the caller's decision,
/// based on position.)
fn reserved_of_word(w: &Word) -> Option<Reserved> {
    let [WordPart::Literal { text, quoted: false }] = w.0.as_slice() else {
        return None;
    };
    Reserved::from_text(text)
}

fn reserved_of_token(t: &Token) -> Option<Reserved> {
    match t {
        Token::Word(w) => reserved_of_word(w),
        _ => None,
    }
}

/// The text of a single unquoted-literal word that is a valid name — used for a
/// `for` loop variable or a function name.
fn word_as_name(w: &Word) -> Option<&str> {
    let [WordPart::Literal { text, quoted: false }] = w.0.as_slice() else {
        return None;
    };
    if crate::is_valid_var_name(text) {
        Some(text)
    } else {
        None
    }
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }
    fn advance(&mut self) {
        self.pos += 1;
    }
    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Some(Token::Newline)) {
            self.pos += 1;
        }
    }

    fn reserved_peek(&self) -> Option<Reserved> {
        self.peek().and_then(reserved_of_token)
    }

    /// Is the current token a reserved word (or operator) that terminates a
    /// compound list? These end the body of an enclosing construct and are left
    /// for that construct's parser to consume.
    fn at_list_terminator(&self) -> bool {
        match self.peek() {
            Some(Token::Op(Operator::RParen | Operator::DSemi)) => true,
            Some(Token::Word(w)) => matches!(
                reserved_of_word(w),
                Some(
                    Reserved::Then
                        | Reserved::Else
                        | Reserved::Elif
                        | Reserved::Fi
                        | Reserved::Do
                        | Reserved::Done
                        | Reserved::Esac
                        | Reserved::RBrace
                )
            ),
            _ => false,
        }
    }

    fn parse_program(&mut self) -> PResult<List> {
        let list = self.parse_compound_list()?;
        // A complete program consumes all tokens; a leftover terminating keyword
        // (`fi`, `done`, `}`, `)`, `;;`) or stray operator is a syntax error.
        if let Some(tok) = self.peek() {
            return Err(PErr::Syntax(format!(
                "syntax error near unexpected token `{}`",
                token_display(tok)
            )));
        }
        Ok(list)
    }

    /// Parse a compound list: and-or lists separated by `;`/`&`/newlines,
    /// stopping (without consuming) at a list terminator or end of input.
    fn parse_compound_list(&mut self) -> PResult<List> {
        let mut items = Vec::new();
        self.skip_newlines();
        while self.peek().is_some() && !self.at_list_terminator() {
            let and_or = self.parse_and_or()?;
            let sep = match self.peek() {
                Some(Token::Op(Operator::Amp)) => {
                    self.advance();
                    Separator::Async
                }
                Some(Token::Op(Operator::Semi) | Token::Newline) => {
                    self.advance();
                    Separator::Seq
                }
                // No trailing separator: this and-or is the last item; whatever
                // follows (a terminator, EOF, or an error) is the caller's to
                // validate.
                _ => {
                    items.push(ListItem { and_or, sep: Separator::Seq });
                    break;
                }
            };
            items.push(ListItem { and_or, sep });
            self.skip_newlines();
        }
        Ok(List(items))
    }

    fn parse_and_or(&mut self) -> PResult<AndOr> {
        let first = self.parse_pipeline()?;
        let mut rest = Vec::new();
        loop {
            let op = match self.peek() {
                Some(Token::Op(Operator::AndAnd)) => AndOrOp::And,
                Some(Token::Op(Operator::OrOr)) => AndOrOp::Or,
                _ => break,
            };
            self.advance();
            // A newline is allowed after `&&`/`||`; the list continues.
            self.skip_newlines();
            if self.peek().is_none() {
                return Err(PErr::Incomplete);
            }
            rest.push((op, self.parse_pipeline()?));
        }
        Ok(AndOr { first, rest })
    }

    fn parse_pipeline(&mut self) -> PResult<Pipeline> {
        // A leading `!` (reserved word in command position) negates the whole
        // pipeline's exit status.
        let bang = if self.reserved_peek() == Some(Reserved::Bang) {
            self.advance();
            true
        } else {
            false
        };
        let mut commands = vec![self.parse_command()?];
        while matches!(self.peek(), Some(Token::Op(Operator::Pipe))) {
            self.advance();
            self.skip_newlines();
            if self.peek().is_none() {
                return Err(PErr::Incomplete);
            }
            commands.push(self.parse_command()?);
        }
        Ok(Pipeline { bang, commands })
    }

    fn parse_command(&mut self) -> PResult<Command> {
        // Subshell `( … )`.
        if matches!(self.peek(), Some(Token::Op(Operator::LParen))) {
            return self.parse_subshell();
        }
        // Compound commands and function definitions are recognized only here,
        // in command position.
        if let Some(Token::Word(w)) = self.peek() {
            // Function definition: `name ( )`.
            if reserved_of_word(w).is_none()
                && word_as_name(w).is_some()
                && matches!(self.toks.get(self.pos + 1), Some(Token::Op(Operator::LParen)))
                && matches!(self.toks.get(self.pos + 2), Some(Token::Op(Operator::RParen)))
            {
                return self.parse_function_def();
            }
            if let Some(r) = reserved_of_word(w) {
                match r {
                    Reserved::If => return self.parse_if(),
                    Reserved::For => return self.parse_for(),
                    Reserved::While => return self.parse_while_until(false),
                    Reserved::Until => return self.parse_while_until(true),
                    Reserved::Case => return self.parse_case(),
                    Reserved::LBrace => return self.parse_brace_group(),
                    // A closing/middle keyword or a bare `!` here is misplaced.
                    Reserved::Then
                    | Reserved::Else
                    | Reserved::Elif
                    | Reserved::Fi
                    | Reserved::Do
                    | Reserved::Done
                    | Reserved::Esac
                    | Reserved::RBrace
                    | Reserved::In
                    | Reserved::Bang => {
                        return Err(PErr::Syntax(format!(
                            "syntax error near unexpected token `{}`",
                            r.text()
                        )));
                    }
                }
            }
        }
        match self.peek() {
            None => Err(PErr::Incomplete),
            Some(Token::Newline) => {
                Err(PErr::Syntax("syntax error near unexpected newline".to_string()))
            }
            Some(Token::Op(op)) if !is_redirect_op(*op) => Err(PErr::Syntax(format!(
                "syntax error near unexpected token `{}`",
                op_display(*op)
            ))),
            // Word, IoNumber, HereDoc, or a leading redirection operator all
            // begin a simple command.
            _ => Ok(Command::Simple(self.parse_simple()?)),
        }
    }

    fn parse_simple(&mut self) -> PResult<SimpleCommand> {
        let mut assigns = Vec::new();
        let mut words = Vec::new();
        let mut redirects = Vec::new();

        // Consume an owned copy each step so we can freely advance / recurse.
        while let Some(tok) = self.toks.get(self.pos).cloned() {
            match tok {
                Token::Newline => break,
                Token::Op(op) if is_redirect_op(op) => {
                    self.advance();
                    redirects.push(self.parse_redirect(None, op)?);
                }
                // Any other operator (control operator, RParen, …) ends the
                // command; leave it for the caller.
                Token::Op(_) => break,
                Token::IoNumber(n) => {
                    self.advance();
                    redirects.push(self.parse_io_redirect(n)?);
                }
                Token::HereDoc(doc) => {
                    self.advance();
                    redirects.push(Redirect::Heredoc { fd: None, doc });
                }
                Token::Word(w) => {
                    self.advance();
                    if words.is_empty()
                        && let Some((name, value)) = split_assignment(&w)
                    {
                        assigns.push(Assignment { name, value });
                    } else {
                        words.push(w);
                    }
                }
            }
        }

        if assigns.is_empty() && words.is_empty() && redirects.is_empty() {
            return Err(PErr::Syntax("syntax error: empty command".to_string()));
        }
        Ok(SimpleCommand {
            assigns,
            words,
            redirects,
        })
    }

    /// Parse the target of a redirection operator (already consumed): the next
    /// token must be a word (the filename or, for `<&`/`>&`, an fd/`-`).
    fn parse_redirect(&mut self, fd: Option<u32>, op: Operator) -> PResult<Redirect> {
        match self.toks.get(self.pos).cloned() {
            Some(Token::Word(target)) => {
                self.advance();
                Ok(Redirect::File {
                    fd,
                    op: map_redir_op(op),
                    target,
                })
            }
            _ => Err(PErr::Syntax(
                "syntax error: expected a filename after a redirection".to_string(),
            )),
        }
    }

    /// An IO_NUMBER must be immediately followed by a redirection operator or a
    /// here-document.
    fn parse_io_redirect(&mut self, n: u32) -> PResult<Redirect> {
        match self.toks.get(self.pos).cloned() {
            Some(Token::Op(op)) if is_redirect_op(op) => {
                self.advance();
                self.parse_redirect(Some(n), op)
            }
            Some(Token::HereDoc(doc)) => {
                self.advance();
                Ok(Redirect::Heredoc { fd: Some(n), doc })
            }
            _ => Err(PErr::Syntax(
                "syntax error: an IO number must be followed by a redirection".to_string(),
            )),
        }
    }

    /// Parse a trailing list of redirections (attached to a compound command or
    /// a function definition). Returns an empty vec when none follow.
    fn parse_redirect_list(&mut self) -> PResult<Vec<Redirect>> {
        let mut redirects = Vec::new();
        loop {
            match self.toks.get(self.pos).cloned() {
                Some(Token::Op(op)) if is_redirect_op(op) => {
                    self.advance();
                    redirects.push(self.parse_redirect(None, op)?);
                }
                Some(Token::IoNumber(n)) => {
                    self.advance();
                    redirects.push(self.parse_io_redirect(n)?);
                }
                Some(Token::HereDoc(doc)) => {
                    self.advance();
                    redirects.push(Redirect::Heredoc { fd: None, doc });
                }
                _ => break,
            }
        }
        Ok(redirects)
    }

    // ---- reserved-word / operator expectations -----------------------------

    /// Consume a specific reserved word, or fail. End of input yields
    /// `Incomplete` so the interactive loop keeps reading (e.g. an unclosed
    /// `if … fi`).
    fn expect_reserved(&mut self, r: Reserved) -> PResult<()> {
        match self.peek() {
            None => Err(PErr::Incomplete),
            Some(Token::Word(w)) if reserved_of_word(w) == Some(r) => {
                self.advance();
                Ok(())
            }
            Some(tok) => Err(PErr::Syntax(format!(
                "syntax error: expected `{}`, found `{}`",
                r.text(),
                token_display(tok)
            ))),
        }
    }

    fn expect_op(&mut self, op: Operator) -> PResult<()> {
        match self.peek() {
            None => Err(PErr::Incomplete),
            Some(Token::Op(o)) if *o == op => {
                self.advance();
                Ok(())
            }
            Some(tok) => Err(PErr::Syntax(format!(
                "syntax error: expected `{}`, found `{}`",
                op_display(op),
                token_display(tok)
            ))),
        }
    }

    /// Consume a single sequential separator (`;` or newline) that must precede
    /// `do`/`then`/etc.
    fn consume_sequential_sep(&mut self) -> PResult<()> {
        match self.peek() {
            Some(Token::Op(Operator::Semi) | Token::Newline) => {
                self.advance();
                Ok(())
            }
            None => Err(PErr::Incomplete),
            Some(tok) => Err(PErr::Syntax(format!(
                "syntax error near unexpected token `{}`",
                token_display(tok)
            ))),
        }
    }

    // ---- compound commands -------------------------------------------------

    /// `( compound_list )` — a subshell.
    fn parse_subshell(&mut self) -> PResult<Command> {
        self.advance(); // '('
        let body = self.parse_compound_list()?;
        self.expect_op(Operator::RParen)?;
        let redirects = self.parse_redirect_list()?;
        Ok(Command::Compound {
            kind: CompoundCommand::Subshell(body),
            redirects,
        })
    }

    /// `{ compound_list; }` — a brace group (current environment).
    fn parse_brace_group(&mut self) -> PResult<Command> {
        self.advance(); // '{'
        let body = self.parse_compound_list()?;
        self.expect_reserved(Reserved::RBrace)?;
        let redirects = self.parse_redirect_list()?;
        Ok(Command::Compound {
            kind: CompoundCommand::Brace(body),
            redirects,
        })
    }

    /// `do compound_list done`.
    fn parse_do_group(&mut self) -> PResult<List> {
        self.expect_reserved(Reserved::Do)?;
        let body = self.parse_compound_list()?;
        self.expect_reserved(Reserved::Done)?;
        Ok(body)
    }

    fn parse_if(&mut self) -> PResult<Command> {
        self.advance(); // 'if'
        let cond = self.parse_compound_list()?;
        self.expect_reserved(Reserved::Then)?;
        let then_branch = self.parse_compound_list()?;
        let mut elifs = Vec::new();
        let mut else_branch = None;
        loop {
            match self.reserved_peek() {
                Some(Reserved::Elif) => {
                    self.advance();
                    let c = self.parse_compound_list()?;
                    self.expect_reserved(Reserved::Then)?;
                    let t = self.parse_compound_list()?;
                    elifs.push((c, t));
                }
                Some(Reserved::Else) => {
                    self.advance();
                    else_branch = Some(self.parse_compound_list()?);
                    break;
                }
                _ => break,
            }
        }
        self.expect_reserved(Reserved::Fi)?;
        let redirects = self.parse_redirect_list()?;
        Ok(Command::Compound {
            kind: CompoundCommand::If(IfClause {
                cond,
                then_branch,
                elifs,
                else_branch,
            }),
            redirects,
        })
    }

    fn parse_while_until(&mut self, until: bool) -> PResult<Command> {
        self.advance(); // 'while' / 'until'
        let cond = self.parse_compound_list()?;
        let body = self.parse_do_group()?;
        let redirects = self.parse_redirect_list()?;
        Ok(Command::Compound {
            kind: CompoundCommand::While(WhileClause { until, cond, body }),
            redirects,
        })
    }

    fn parse_for(&mut self) -> PResult<Command> {
        self.advance(); // 'for'
        let var = match self.peek() {
            None => return Err(PErr::Incomplete),
            // The loop variable is a NAME and must not be a reserved word.
            Some(Token::Word(w)) if reserved_of_word(w).is_none() => match word_as_name(w) {
                Some(name) => name.to_string(),
                None => {
                    return Err(PErr::Syntax(
                        "syntax error: `for` requires a valid variable name".to_string(),
                    ));
                }
            },
            Some(tok) => {
                return Err(PErr::Syntax(format!(
                    "syntax error near unexpected token `{}`",
                    token_display(tok)
                )));
            }
        };
        self.advance(); // the name
        self.skip_newlines();

        let words = match self.reserved_peek() {
            Some(Reserved::In) => {
                self.advance();
                let mut ws = Vec::new();
                while let Some(Token::Word(w)) = self.peek() {
                    ws.push(w.clone());
                    self.advance();
                }
                self.consume_sequential_sep()?;
                Some(ws)
            }
            // `for name do …` — no `in`; iterate over the positional parameters.
            Some(Reserved::Do) => None,
            // `for name; do …` / `for name <newline> do …`.
            _ => {
                self.consume_sequential_sep()?;
                None
            }
        };
        self.skip_newlines();
        let body = self.parse_do_group()?;
        let redirects = self.parse_redirect_list()?;
        Ok(Command::Compound {
            kind: CompoundCommand::For(ForClause { var, words, body }),
            redirects,
        })
    }

    fn parse_case(&mut self) -> PResult<Command> {
        self.advance(); // 'case'
        let word = match self.peek() {
            None => return Err(PErr::Incomplete),
            Some(Token::Word(w)) => w.clone(),
            Some(tok) => {
                return Err(PErr::Syntax(format!(
                    "syntax error near unexpected token `{}`",
                    token_display(tok)
                )));
            }
        };
        self.advance(); // the subject word
        self.skip_newlines();
        self.expect_reserved(Reserved::In)?;
        self.skip_newlines();

        let mut items = Vec::new();
        loop {
            self.skip_newlines();
            if self.reserved_peek() == Some(Reserved::Esac) {
                self.advance();
                break;
            }
            if self.peek().is_none() {
                return Err(PErr::Incomplete);
            }
            // Optional leading `(` before the pattern list.
            if matches!(self.peek(), Some(Token::Op(Operator::LParen))) {
                self.advance();
            }
            // Pattern list: WORD ('|' WORD)* ')'.
            let mut patterns = Vec::new();
            loop {
                match self.peek() {
                    None => return Err(PErr::Incomplete),
                    Some(Token::Word(w)) => {
                        patterns.push(w.clone());
                        self.advance();
                    }
                    Some(tok) => {
                        return Err(PErr::Syntax(format!(
                            "syntax error: expected a `case` pattern, found `{}`",
                            token_display(tok)
                        )));
                    }
                }
                match self.peek() {
                    Some(Token::Op(Operator::Pipe)) => {
                        self.advance();
                    }
                    Some(Token::Op(Operator::RParen)) => {
                        self.advance();
                        break;
                    }
                    None => return Err(PErr::Incomplete),
                    Some(tok) => {
                        return Err(PErr::Syntax(format!(
                            "syntax error: expected `)` or `|` in a `case` pattern, found `{}`",
                            token_display(tok)
                        )));
                    }
                }
            }
            let body = self.parse_compound_list()?;
            items.push(CaseItem { patterns, body });
            // `;;` introduces another item; `esac` (handled at the loop top) ends
            // the construct. The last item may omit `;;`.
            if matches!(self.peek(), Some(Token::Op(Operator::DSemi))) {
                self.advance();
            }
        }
        let redirects = self.parse_redirect_list()?;
        Ok(Command::Compound {
            kind: CompoundCommand::Case(CaseClause { word, items }),
            redirects,
        })
    }

    // ---- function definitions ----------------------------------------------

    /// `name ( ) compound_command` — the `name ( )` was verified by the caller.
    fn parse_function_def(&mut self) -> PResult<Command> {
        let name = match self.peek() {
            Some(Token::Word(w)) => word_as_name(w)
                .expect("function name verified by caller")
                .to_string(),
            _ => unreachable!("parse_function_def at a non-word token"),
        };
        self.advance(); // name
        self.expect_op(Operator::LParen)?;
        self.expect_op(Operator::RParen)?;
        self.skip_newlines();
        // The body is a compound command (its trailing redirections become the
        // function's).
        match self.parse_command()? {
            Command::Compound { kind, redirects } => Ok(Command::Function {
                name,
                body: FunctionBody {
                    body: kind,
                    redirects,
                },
            }),
            _ => Err(PErr::Syntax(
                "syntax error: a function body must be a compound command".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_source, Parsed};
    use crate::ast::{AndOrOp, Command, CompoundCommand, List, RedirOp, Redirect, Separator};
    use crate::token::WordPart;

    /// Parse, asserting a complete parse, and return the `List`.
    fn parse(src: &str) -> List {
        match parse_source(src) {
            Parsed::Complete(list) => list,
            Parsed::Incomplete => panic!("expected Complete, got Incomplete for {src:?}"),
            Parsed::Empty => panic!("expected Complete, got Empty for {src:?}"),
            Parsed::Error(m) => panic!("expected Complete, got Error({m:?}) for {src:?}"),
        }
    }

    /// The literal text of a word, concatenating its parts (test helper — real
    /// expansion is Phase 3).
    fn word_text(w: &crate::token::Word) -> String {
        w.0.iter()
            .map(|p| match p {
                WordPart::Literal { text, .. } => text.clone(),
                WordPart::Expansion { raw, .. } => format!("${{{raw}}}"),
            })
            .collect()
    }

    fn only_simple(list: &List) -> &crate::ast::SimpleCommand {
        assert_eq!(list.0.len(), 1, "expected a single list item");
        let ao = &list.0[0].and_or;
        assert!(ao.rest.is_empty(), "expected no &&/|| operators");
        assert_eq!(ao.first.commands.len(), 1, "expected a single command");
        match &ao.first.commands[0] {
            Command::Simple(s) => s,
            other => panic!("expected a simple command, got {other:?}"),
        }
    }

    #[test]
    fn simple_command_with_args() {
        let list = parse("echo hello world");
        let s = only_simple(&list);
        assert!(s.assigns.is_empty());
        assert!(s.redirects.is_empty());
        let argv: Vec<String> = s.words.iter().map(word_text).collect();
        assert_eq!(argv, vec!["echo", "hello", "world"]);
    }

    #[test]
    fn semicolon_list() {
        let list = parse("echo a; echo b");
        assert_eq!(list.0.len(), 2);
        assert_eq!(list.0[0].sep, Separator::Seq);
        assert_eq!(list.0[1].sep, Separator::Seq);
    }

    #[test]
    fn trailing_separator_and_blank_lines() {
        // A trailing `;` and surrounding newlines do not create empty items.
        let list = parse("\n\necho a;\n");
        assert_eq!(list.0.len(), 1);
    }

    #[test]
    fn ampersand_is_async_separator() {
        let list = parse("echo a & echo b");
        assert_eq!(list.0.len(), 2);
        assert_eq!(list.0[0].sep, Separator::Async);
    }

    #[test]
    fn and_or_is_left_associative() {
        let list = parse("a && b || c");
        assert_eq!(list.0.len(), 1);
        let ao = &list.0[0].and_or;
        assert_eq!(ao.rest.len(), 2);
        assert_eq!(ao.rest[0].0, AndOrOp::And);
        assert_eq!(ao.rest[1].0, AndOrOp::Or);
    }

    #[test]
    fn pipeline_has_multiple_commands() {
        let list = parse("a | b | c");
        let ao = &list.0[0].and_or;
        assert_eq!(ao.first.commands.len(), 3);
        assert!(!ao.first.bang);
    }

    #[test]
    fn leading_assignments_split_from_words() {
        let list = parse("A=1 B=2 echo hi");
        let s = only_simple(&list);
        assert_eq!(s.assigns.len(), 2);
        assert_eq!(s.assigns[0].name, "A");
        assert_eq!(word_text(&s.assigns[0].value), "1");
        assert_eq!(s.assigns[1].name, "B");
        let argv: Vec<String> = s.words.iter().map(word_text).collect();
        assert_eq!(argv, vec!["echo", "hi"]);
    }

    #[test]
    fn assignment_after_word_is_an_argument() {
        // `echo A=1` — the `A=1` is a normal argument, not an assignment.
        let list = parse("echo A=1");
        let s = only_simple(&list);
        assert!(s.assigns.is_empty());
        assert_eq!(s.words.len(), 2);
    }

    #[test]
    fn assignment_only_command() {
        let list = parse("FOO=bar");
        let s = only_simple(&list);
        assert_eq!(s.assigns.len(), 1);
        assert!(s.words.is_empty());
    }

    #[test]
    fn redirect_attaches_to_command() {
        let list = parse("echo hi > out");
        let s = only_simple(&list);
        assert_eq!(s.words.len(), 2);
        assert_eq!(s.redirects.len(), 1);
        match &s.redirects[0] {
            Redirect::File { fd, op, target } => {
                assert_eq!(*fd, None);
                assert_eq!(*op, RedirOp::Write);
                assert_eq!(word_text(target), "out");
            }
            other => panic!("expected File redirect, got {other:?}"),
        }
    }

    #[test]
    fn io_number_redirect() {
        let list = parse("cmd 2>> log");
        let s = only_simple(&list);
        match &s.redirects[0] {
            Redirect::File { fd, op, .. } => {
                assert_eq!(*fd, Some(2));
                assert_eq!(*op, RedirOp::Append);
            }
            other => panic!("expected File redirect, got {other:?}"),
        }
    }

    #[test]
    fn redirect_may_precede_the_command_word() {
        // `> out echo hi` is a valid simple command (redirect in the prefix).
        let list = parse("> out echo hi");
        let s = only_simple(&list);
        assert_eq!(s.redirects.len(), 1);
        let argv: Vec<String> = s.words.iter().map(word_text).collect();
        assert_eq!(argv, vec!["echo", "hi"]);
    }

    #[test]
    fn here_document_becomes_a_redirect() {
        let list = parse("cat <<EOF\nhello\nEOF\n");
        let s = only_simple(&list);
        assert_eq!(s.words.len(), 1);
        match &s.redirects[0] {
            Redirect::Heredoc { fd, doc } => {
                assert_eq!(*fd, None);
                assert_eq!(doc.delim, "EOF");
                assert_eq!(doc.body, "hello\n");
            }
            other => panic!("expected Heredoc redirect, got {other:?}"),
        }
    }

    #[test]
    fn incomplete_when_operator_dangles() {
        assert!(matches!(parse_source("echo a &&"), Parsed::Incomplete));
        assert!(matches!(parse_source("echo a |"), Parsed::Incomplete));
        // Lexer-level incompleteness surfaces the same way.
        assert!(matches!(parse_source("echo 'unterminated"), Parsed::Incomplete));
        assert!(matches!(parse_source("cat <<EOF\nbody"), Parsed::Incomplete));
    }

    #[test]
    fn empty_and_comment_only_inputs() {
        assert!(matches!(parse_source(""), Parsed::Empty));
        assert!(matches!(parse_source("   \n  \n"), Parsed::Empty));
        assert!(matches!(parse_source("# just a comment"), Parsed::Empty));
    }

    #[test]
    fn syntax_errors() {
        assert!(matches!(parse_source(";"), Parsed::Error(_)));
        assert!(matches!(parse_source("echo a ;; echo b"), Parsed::Error(_)));
        assert!(matches!(parse_source("| echo"), Parsed::Error(_)));
        // A stray closing keyword is a syntax error.
        assert!(matches!(parse_source("fi"), Parsed::Error(_)));
        assert!(matches!(parse_source("done"), Parsed::Error(_)));
        assert!(matches!(parse_source("echo a )"), Parsed::Error(_)));
    }

    // ---- Phase 4: compound commands & functions ----------------------------

    /// The single top-level command, asserting it is a compound of the given
    /// shape via a matcher closure.
    fn only_compound(list: &List) -> (&CompoundCommand, &[Redirect]) {
        assert_eq!(list.0.len(), 1, "expected a single list item");
        let ao = &list.0[0].and_or;
        assert!(ao.rest.is_empty(), "expected no &&/|| operators");
        assert_eq!(ao.first.commands.len(), 1, "expected a single command");
        match &ao.first.commands[0] {
            Command::Compound { kind, redirects } => (kind, redirects),
            other => panic!("expected a compound command, got {other:?}"),
        }
    }

    #[test]
    fn subshell_and_brace_group() {
        assert!(matches!(
            only_compound(&parse("(echo a)")).0,
            CompoundCommand::Subshell(_)
        ));
        assert!(matches!(
            only_compound(&parse("{ echo a; }")).0,
            CompoundCommand::Brace(_)
        ));
    }

    #[test]
    fn if_with_elif_else() {
        let list = parse("if a; then b; elif c; then d; else e; fi");
        match only_compound(&list).0 {
            CompoundCommand::If(c) => {
                assert_eq!(c.cond.0.len(), 1);
                assert_eq!(c.then_branch.0.len(), 1);
                assert_eq!(c.elifs.len(), 1);
                assert!(c.else_branch.is_some());
            }
            other => panic!("expected if, got {other:?}"),
        }
    }

    #[test]
    fn for_with_and_without_in() {
        match only_compound(&parse("for x in a b c; do echo $x; done")).0 {
            CompoundCommand::For(c) => {
                assert_eq!(c.var, "x");
                assert_eq!(c.words.as_ref().map(Vec::len), Some(3));
            }
            other => panic!("expected for, got {other:?}"),
        }
        // No `in` clause → iterate over "$@".
        match only_compound(&parse("for x do echo $x; done")).0 {
            CompoundCommand::For(c) => assert!(c.words.is_none()),
            other => panic!("expected for, got {other:?}"),
        }
    }

    #[test]
    fn while_and_until() {
        match only_compound(&parse("while a; do b; done")).0 {
            CompoundCommand::While(c) => assert!(!c.until),
            other => panic!("expected while, got {other:?}"),
        }
        match only_compound(&parse("until a; do b; done")).0 {
            CompoundCommand::While(c) => assert!(c.until),
            other => panic!("expected until, got {other:?}"),
        }
    }

    #[test]
    fn case_patterns() {
        let list = parse("case $x in a|b) echo one;; (*) echo other;; esac");
        match only_compound(&list).0 {
            CompoundCommand::Case(c) => {
                assert_eq!(c.items.len(), 2);
                assert_eq!(c.items[0].patterns.len(), 2);
                assert_eq!(c.items[1].patterns.len(), 1);
            }
            other => panic!("expected case, got {other:?}"),
        }
        // Empty case.
        match only_compound(&parse("case $x in esac")).0 {
            CompoundCommand::Case(c) => assert!(c.items.is_empty()),
            other => panic!("expected case, got {other:?}"),
        }
    }

    #[test]
    fn function_definition() {
        let list = parse("greet() { echo hi; }");
        assert_eq!(list.0.len(), 1);
        match &list.0[0].and_or.first.commands[0] {
            Command::Function { name, body } => {
                assert_eq!(name, "greet");
                assert!(matches!(body.body, CompoundCommand::Brace(_)));
            }
            other => panic!("expected a function definition, got {other:?}"),
        }
    }

    #[test]
    fn pipeline_negation() {
        let list = parse("! false");
        let ao = &list.0[0].and_or;
        assert!(ao.first.bang);
    }

    #[test]
    fn compound_with_trailing_redirect() {
        let list = parse("for i in 1 2; do echo $i; done > out");
        let (_, redirects) = only_compound(&list);
        assert_eq!(redirects.len(), 1);
    }

    #[test]
    fn reserved_words_are_plain_words_as_arguments() {
        // `if`/`then`/`done` after a command word are ordinary arguments.
        let list = parse("echo if then done");
        let s = only_simple(&list);
        assert_eq!(s.words.len(), 4);
    }

    #[test]
    fn multiline_compound_is_incomplete() {
        assert!(matches!(parse_source("if true; then"), Parsed::Incomplete));
        assert!(matches!(parse_source("for i in a b"), Parsed::Incomplete));
        assert!(matches!(parse_source("while x; do y"), Parsed::Incomplete));
        assert!(matches!(parse_source("case x in a)"), Parsed::Incomplete));
        assert!(matches!(parse_source("{ echo hi;"), Parsed::Incomplete));
        assert!(matches!(parse_source("f() {"), Parsed::Incomplete));
    }
}
