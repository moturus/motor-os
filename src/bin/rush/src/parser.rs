//! Recursive-descent parser (Phase 2): tokens → [`ast`].
//!
//! Grammar handled here (POSIX §2.9, non-compound subset):
//!
//! ```text
//! program  := linebreak (and_or (separator and_or)* separator?)?
//! and_or   := pipeline (('&&' | '||') linebreak pipeline)*
//! pipeline := command ('|' linebreak command)*
//! command  := simple_command                 // compound commands → Phase 4
//! simple   := (assignment | word | redirect)+ // assignment only before 1st word
//! ```
//!
//! [`parse_source`] is the single entry point used by both the interactive loop
//! and the `-c`/script paths: it lexes then parses, folding the lexer's
//! "incomplete input" and the parser's own "needs another operand" cases into
//! one [`Parsed::Incomplete`] result that drives PS2 continuation. Reserved
//! words (`if`, `for`, `{`, …) are *not* special-cased yet — they parse as plain
//! command words until Phase 4 wires in compound commands.

use crate::ast::{
    AndOr, AndOrOp, Assignment, Command, List, ListItem, Pipeline, RedirOp, Redirect, Separator,
    SimpleCommand,
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
        Token::Word(_) => "word".to_string(),
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

    fn parse_program(&mut self) -> PResult<List> {
        let mut items = Vec::new();
        self.skip_newlines();
        while self.peek().is_some() {
            let and_or = self.parse_and_or()?;
            let sep = match self.peek() {
                Some(Token::Op(Operator::Amp)) => {
                    self.advance();
                    Separator::Async
                }
                Some(Token::Op(Operator::Semi)) | Some(Token::Newline) => {
                    self.advance();
                    Separator::Seq
                }
                None => Separator::Seq,
                Some(other) => {
                    return Err(PErr::Syntax(format!(
                        "syntax error near unexpected token `{}`",
                        token_display(other)
                    )));
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
        // Leading `!` negation is recognized in Phase 4; for now `!` parses as
        // an ordinary command word.
        let mut commands = vec![self.parse_command()?];
        while matches!(self.peek(), Some(Token::Op(Operator::Pipe))) {
            self.advance();
            self.skip_newlines();
            if self.peek().is_none() {
                return Err(PErr::Incomplete);
            }
            commands.push(self.parse_command()?);
        }
        Ok(Pipeline {
            bang: false,
            commands,
        })
    }

    fn parse_command(&mut self) -> PResult<Command> {
        match self.peek() {
            None => Err(PErr::Incomplete),
            Some(Token::Op(Operator::LParen)) => Err(PErr::Syntax(
                "syntax error: subshells `( … )` are not yet supported (Phase 4)".to_string(),
            )),
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
}

#[cfg(test)]
mod tests {
    use super::{parse_source, Parsed};
    use crate::ast::{AndOrOp, Command, List, RedirOp, Redirect, Separator};
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
        // Subshell is deferred to Phase 4 and reported as a syntax error.
        assert!(matches!(parse_source("(echo a)"), Parsed::Error(_)));
    }
}
