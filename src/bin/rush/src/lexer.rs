//! POSIX token recognizer (Phase 1).
//!
//! `tokenize(input)` turns shell source into a `Vec<Token>` following the POSIX
//! token-recognition rules (§2.3, §2.10.1): operators, quoting, `$`-expansions
//! (captured opaquely), comments, line continuation, and here-documents.
//!
//! It reports [`LexError::Incomplete`] when the input ends in the middle of a
//! lexical construct (open quote/expansion, trailing backslash, or a here-doc
//! awaiting its terminator). The interactive loop uses this to prompt PS2 and
//! re-lex the accumulated buffer. Operator-level continuation (a line ending in
//! `|`, `&&`, …) is the parser's concern, not the lexer's.
//!
//! Not yet wired into execution — Phase 2's parser consumes this.
#![allow(dead_code)]

use crate::token::{ExpansionKind, HereDoc, Operator, Token, Word, WordPart};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexError {
    /// Input ended mid-construct; read more and re-lex (PS2 continuation).
    Incomplete(Incomplete),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incomplete {
    /// Unterminated `'…'` or `"…"` (the char is the opening quote).
    Quote(char),
    /// Unterminated `${…}`, `$(…)`, `$((…))`, or `` `…` ``.
    Expansion,
    /// A trailing backslash with no following character.
    Backslash,
    /// A here-document whose terminator (the delimiter) has not been seen.
    HereDoc(String),
}

fn inc(i: Incomplete) -> LexError {
    LexError::Incomplete(i)
}

/// Tokenize a (possibly multi-line) input string.
pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
    let mut lx = Lexer::new(input);
    lx.run()?;
    Ok(lx.tokens)
}

struct Pending {
    idx: usize, // index of the placeholder HereDoc token to fill
    strip: bool,
    delim: String,
}

struct Lexer {
    chars: Vec<char>,
    pos: usize,
    tokens: Vec<Token>,
    pending: Vec<Pending>,
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
fn is_special_param(c: char) -> bool {
    matches!(c, '@' | '*' | '#' | '?' | '-' | '$' | '!') || c.is_ascii_digit()
}
fn is_op_start(c: char) -> bool {
    matches!(c, '&' | '|' | ';' | '(' | ')' | '<' | '>')
}

/// Append a literal char to `parts`, merging with the trailing run when the
/// quoting matches so a word stays a compact list of parts.
fn push_lit(parts: &mut Vec<WordPart>, ch: char, quoted: bool) {
    if let Some(WordPart::Literal { text, quoted: q }) = parts.last_mut()
        && *q == quoted
    {
        text.push(ch);
        return;
    }
    parts.push(WordPart::Literal {
        text: ch.to_string(),
        quoted,
    });
}

impl Lexer {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            tokens: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn peek_nth(&self, n: usize) -> Option<char> {
        self.chars.get(self.pos + n).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn run(&mut self) -> Result<(), LexError> {
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' => {
                    self.pos += 1;
                }
                '\n' => {
                    self.pos += 1;
                    self.tokens.push(Token::Newline);
                    if !self.pending.is_empty() {
                        self.collect_heredocs()?;
                    }
                }
                '\\' if self.peek_nth(1) == Some('\n') => {
                    // Line continuation: the backslash-newline is removed.
                    self.pos += 2;
                }
                '#' => {
                    // A `#` at a token boundary starts a comment through EOL.
                    while let Some(ch) = self.peek() {
                        if ch == '\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                _ if is_op_start(c) => self.read_operator()?,
                _ => {
                    if c.is_ascii_digit()
                        && let Some(n) = self.try_io_number()
                    {
                        self.tokens.push(Token::IoNumber(n));
                        continue;
                    }
                    let w = self.read_word()?;
                    self.tokens.push(Token::Word(w));
                }
            }
        }

        if let Some(p) = self.pending.first() {
            // A `<<` was seen but its body/terminator never arrived.
            return Err(inc(Incomplete::HereDoc(p.delim.clone())));
        }
        Ok(())
    }

    /// A maximal run of digits immediately followed by `<` or `>` is an
    /// IO_NUMBER. Only consumes input when the rule matches.
    fn try_io_number(&mut self) -> Option<u32> {
        let start = self.pos;
        let mut end = start;
        while end < self.chars.len() && self.chars[end].is_ascii_digit() {
            end += 1;
        }
        if matches!(self.chars.get(end), Some('<') | Some('>')) {
            let s: String = self.chars[start..end].iter().collect();
            if let Ok(n) = s.parse::<u32>() {
                self.pos = end;
                return Some(n);
            }
        }
        None
    }

    fn read_operator(&mut self) -> Result<(), LexError> {
        let c = self.chars[self.pos];
        match c {
            '&' => {
                self.pos += 1;
                if self.peek() == Some('&') {
                    self.pos += 1;
                    self.tokens.push(Token::Op(Operator::AndAnd));
                } else {
                    self.tokens.push(Token::Op(Operator::Amp));
                }
            }
            '|' => {
                self.pos += 1;
                if self.peek() == Some('|') {
                    self.pos += 1;
                    self.tokens.push(Token::Op(Operator::OrOr));
                } else {
                    self.tokens.push(Token::Op(Operator::Pipe));
                }
            }
            ';' => {
                self.pos += 1;
                if self.peek() == Some(';') {
                    self.pos += 1;
                    self.tokens.push(Token::Op(Operator::DSemi));
                } else {
                    self.tokens.push(Token::Op(Operator::Semi));
                }
            }
            '(' => {
                self.pos += 1;
                self.tokens.push(Token::Op(Operator::LParen));
            }
            ')' => {
                self.pos += 1;
                self.tokens.push(Token::Op(Operator::RParen));
            }
            '>' => {
                self.pos += 1;
                let op = match self.peek() {
                    Some('>') => {
                        self.pos += 1;
                        Operator::DGreat
                    }
                    Some('&') => {
                        self.pos += 1;
                        Operator::GreatAnd
                    }
                    Some('|') => {
                        self.pos += 1;
                        Operator::Clobber
                    }
                    _ => Operator::Great,
                };
                self.tokens.push(Token::Op(op));
            }
            '<' => {
                self.pos += 1;
                match self.peek() {
                    Some('<') => {
                        self.pos += 1;
                        let strip = if self.peek() == Some('-') {
                            self.pos += 1;
                            true
                        } else {
                            false
                        };
                        self.start_heredoc(strip)?;
                    }
                    Some('&') => {
                        self.pos += 1;
                        self.tokens.push(Token::Op(Operator::LessAnd));
                    }
                    Some('>') => {
                        self.pos += 1;
                        self.tokens.push(Token::Op(Operator::LessGreat));
                    }
                    _ => self.tokens.push(Token::Op(Operator::Less)),
                }
            }
            _ => unreachable!("read_operator on non-operator char {c:?}"),
        }
        Ok(())
    }

    /// Handle `<<` / `<<-`: read the delimiter word, push a placeholder HereDoc
    /// token, and register the body to be collected at the next newline.
    fn start_heredoc(&mut self, strip: bool) -> Result<(), LexError> {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.pos += 1;
        }
        let w = self.read_word()?;
        let (delim, quoted) = heredoc_delim(&w);
        let idx = self.tokens.len();
        self.tokens.push(Token::HereDoc(HereDoc {
            strip_tabs: strip,
            quoted,
            delim: delim.clone(),
            body: String::new(),
        }));
        self.pending.push(Pending { idx, strip, delim });
        Ok(())
    }

    fn read_raw_line(&mut self) -> (String, bool) {
        let mut s = String::new();
        while let Some(c) = self.bump() {
            if c == '\n' {
                return (s, true);
            }
            s.push(c);
        }
        (s, false)
    }

    fn collect_heredocs(&mut self) -> Result<(), LexError> {
        let pendings = std::mem::take(&mut self.pending);
        for p in pendings {
            let mut body = String::new();
            loop {
                if self.pos >= self.chars.len() {
                    return Err(inc(Incomplete::HereDoc(p.delim)));
                }
                let (line, had_nl) = self.read_raw_line();
                let compare: &str = if p.strip {
                    line.trim_start_matches('\t')
                } else {
                    &line
                };
                if compare == p.delim {
                    break; // terminator line: consumed, not part of the body
                }
                body.push_str(compare);
                body.push('\n');
                if !had_nl {
                    return Err(inc(Incomplete::HereDoc(p.delim)));
                }
            }
            if let Some(Token::HereDoc(hd)) = self.tokens.get_mut(p.idx) {
                hd.body = body;
            }
        }
        Ok(())
    }

    /// Read one WORD, stopping at an unquoted blank, newline, or operator char.
    fn read_word(&mut self) -> Result<Word, LexError> {
        let mut parts: Vec<WordPart> = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\n' => break,
                _ if is_op_start(c) => break,
                '\'' => {
                    self.pos += 1;
                    self.read_single_quote(&mut parts)?;
                }
                '"' => {
                    self.pos += 1;
                    self.read_double_quote(&mut parts)?;
                }
                '\\' => {
                    self.pos += 1;
                    match self.peek() {
                        None => return Err(inc(Incomplete::Backslash)),
                        Some('\n') => {
                            // Line continuation inside a word.
                            self.pos += 1;
                        }
                        Some(ch) => {
                            self.pos += 1;
                            push_lit(&mut parts, ch, true);
                        }
                    }
                }
                '$' => self.read_dollar(&mut parts, false)?,
                '`' => {
                    self.pos += 1;
                    self.read_backtick(&mut parts, false)?;
                }
                _ => {
                    self.pos += 1;
                    push_lit(&mut parts, c, false);
                }
            }
        }
        Ok(Word(parts))
    }

    fn read_single_quote(&mut self, parts: &mut Vec<WordPart>) -> Result<(), LexError> {
        let mut added = false;
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Quote('\''))),
                Some('\'') => {
                    self.pos += 1;
                    if !added {
                        parts.push(WordPart::Literal {
                            text: String::new(),
                            quoted: true,
                        });
                    }
                    return Ok(());
                }
                Some(c) => {
                    self.pos += 1;
                    push_lit(parts, c, true);
                    added = true;
                }
            }
        }
    }

    fn read_double_quote(&mut self, parts: &mut Vec<WordPart>) -> Result<(), LexError> {
        let mut added = false;
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Quote('"'))),
                Some('"') => {
                    self.pos += 1;
                    if !added {
                        parts.push(WordPart::Literal {
                            text: String::new(),
                            quoted: true,
                        });
                    }
                    return Ok(());
                }
                Some('\\') => {
                    // Inside "...", backslash is special only before $ ` " \ and
                    // newline; otherwise it stays literal.
                    self.pos += 1;
                    match self.peek() {
                        None => return Err(inc(Incomplete::Quote('"'))),
                        Some(ch @ ('$' | '`' | '"' | '\\')) => {
                            self.pos += 1;
                            push_lit(parts, ch, true);
                            added = true;
                        }
                        Some('\n') => {
                            self.pos += 1; // line continuation
                        }
                        Some(_) => {
                            push_lit(parts, '\\', true);
                            added = true;
                        }
                    }
                }
                Some('$') => {
                    self.read_dollar(parts, true)?;
                    added = true;
                }
                Some('`') => {
                    self.pos += 1;
                    self.read_backtick(parts, true)?;
                    added = true;
                }
                Some(c) => {
                    self.pos += 1;
                    push_lit(parts, c, true);
                    added = true;
                }
            }
        }
    }

    /// Handle a `$`. `quoted` = we are inside double quotes.
    fn read_dollar(&mut self, parts: &mut Vec<WordPart>, quoted: bool) -> Result<(), LexError> {
        self.pos += 1; // consume '$'
        match self.peek() {
            Some('{') => {
                self.pos += 1;
                let raw = self.scan_braces()?;
                parts.push(WordPart::Expansion {
                    kind: ExpansionKind::Parameter,
                    raw,
                    quoted,
                });
            }
            Some('(') => {
                if self.peek_nth(1) == Some('(') {
                    self.pos += 2;
                    let raw = self.scan_arith()?;
                    parts.push(WordPart::Expansion {
                        kind: ExpansionKind::Arithmetic,
                        raw,
                        quoted,
                    });
                } else {
                    self.pos += 1;
                    let raw = self.scan_cmd_paren()?;
                    parts.push(WordPart::Expansion {
                        kind: ExpansionKind::Command,
                        raw,
                        quoted,
                    });
                }
            }
            // ANSI-C quoting is only recognized unquoted.
            Some('\'') if !quoted => {
                self.pos += 1;
                self.read_ansi_c(parts)?;
            }
            Some(c) if is_name_start(c) => {
                let name = self.read_name();
                parts.push(WordPart::Expansion {
                    kind: ExpansionKind::Parameter,
                    raw: name,
                    quoted,
                });
            }
            Some(c) if is_special_param(c) => {
                self.pos += 1;
                parts.push(WordPart::Expansion {
                    kind: ExpansionKind::Parameter,
                    raw: c.to_string(),
                    quoted,
                });
            }
            // A `$` not introducing an expansion is a literal `$`.
            _ => push_lit(parts, '$', quoted),
        }
        Ok(())
    }

    fn read_name(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if is_name_char(c) {
                s.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        s
    }

    fn read_backtick(&mut self, parts: &mut Vec<WordPart>, quoted: bool) -> Result<(), LexError> {
        // Opening backtick already consumed.
        let mut inner = String::new();
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Expansion)),
                Some('`') => {
                    self.pos += 1;
                    parts.push(WordPart::Expansion {
                        kind: ExpansionKind::Command,
                        raw: inner,
                        quoted,
                    });
                    return Ok(());
                }
                Some('\\') => {
                    self.pos += 1;
                    match self.peek() {
                        None => return Err(inc(Incomplete::Expansion)),
                        Some(n @ ('`' | '$' | '\\')) => {
                            self.pos += 1;
                            inner.push(n);
                        }
                        Some(_) => inner.push('\\'),
                    }
                }
                Some(c) => {
                    self.pos += 1;
                    inner.push(c);
                }
            }
        }
    }

    fn read_ansi_c(&mut self, parts: &mut Vec<WordPart>) -> Result<(), LexError> {
        // Opening `$'` already consumed.
        let mut s = String::new();
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Quote('\''))),
                Some('\'') => {
                    self.pos += 1;
                    parts.push(WordPart::Literal {
                        text: s,
                        quoted: true,
                    });
                    return Ok(());
                }
                Some('\\') => {
                    self.pos += 1;
                    let text = self.ansi_escape()?;
                    s.push_str(&text);
                }
                Some(c) => {
                    self.pos += 1;
                    s.push(c);
                }
            }
        }
    }

    fn ansi_escape(&mut self) -> Result<String, LexError> {
        let c = match self.bump() {
            None => return Err(inc(Incomplete::Quote('\''))),
            Some(c) => c,
        };
        let out = match c {
            'n' => "\n".to_string(),
            't' => "\t".to_string(),
            'r' => "\r".to_string(),
            'a' => "\u{07}".to_string(),
            'b' => "\u{08}".to_string(),
            'f' => "\u{0c}".to_string(),
            'v' => "\u{0b}".to_string(),
            'e' | 'E' => "\u{1b}".to_string(),
            '\\' => "\\".to_string(),
            '\'' => "'".to_string(),
            '"' => "\"".to_string(),
            '?' => "?".to_string(),
            '0'..='7' => {
                // Octal: up to three digits total (this one plus two more).
                let mut val = c.to_digit(8).unwrap();
                for _ in 0..2 {
                    match self.peek() {
                        Some(d) if d.is_digit(8) => {
                            val = val * 8 + d.to_digit(8).unwrap();
                            self.pos += 1;
                        }
                        _ => break,
                    }
                }
                ((val & 0xff) as u8 as char).to_string()
            }
            'x' => {
                // Hex: up to two hex digits.
                let mut val: u32 = 0;
                let mut n = 0;
                while n < 2 {
                    match self.peek() {
                        Some(d) if d.is_ascii_hexdigit() => {
                            val = val * 16 + d.to_digit(16).unwrap();
                            self.pos += 1;
                            n += 1;
                        }
                        _ => break,
                    }
                }
                if n == 0 {
                    "\\x".to_string() // no hex digits: keep literal
                } else {
                    (val as u8 as char).to_string()
                }
            }
            other => format!("\\{other}"), // unknown escape: keep the backslash
        };
        Ok(out)
    }

    // ---- opaque balanced-span scanners (quote-aware) ----------------------

    fn copy_squote(&mut self, buf: &mut String) -> Result<(), LexError> {
        buf.push('\'');
        self.pos += 1;
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Quote('\''))),
                Some('\'') => {
                    buf.push('\'');
                    self.pos += 1;
                    return Ok(());
                }
                Some(c) => {
                    buf.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn copy_dquote(&mut self, buf: &mut String) -> Result<(), LexError> {
        buf.push('"');
        self.pos += 1;
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Quote('"'))),
                Some('"') => {
                    buf.push('"');
                    self.pos += 1;
                    return Ok(());
                }
                Some('\\') => {
                    buf.push('\\');
                    self.pos += 1;
                    match self.bump() {
                        None => return Err(inc(Incomplete::Quote('"'))),
                        Some(n) => buf.push(n),
                    }
                }
                Some(c) => {
                    buf.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn copy_backtick(&mut self, buf: &mut String) -> Result<(), LexError> {
        buf.push('`');
        self.pos += 1;
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Expansion)),
                Some('`') => {
                    buf.push('`');
                    self.pos += 1;
                    return Ok(());
                }
                Some('\\') => {
                    buf.push('\\');
                    self.pos += 1;
                    match self.bump() {
                        None => return Err(inc(Incomplete::Expansion)),
                        Some(n) => buf.push(n),
                    }
                }
                Some(c) => {
                    buf.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    /// Capture `${...}` inner text (the opening `${` already consumed), tracking
    /// nested braces and skipping over quoted regions.
    fn scan_braces(&mut self) -> Result<String, LexError> {
        let mut depth = 1;
        let mut inner = String::new();
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Expansion)),
                Some('}') => {
                    self.pos += 1;
                    depth -= 1;
                    if depth == 0 {
                        return Ok(inner);
                    }
                    inner.push('}');
                }
                Some('{') => {
                    self.pos += 1;
                    depth += 1;
                    inner.push('{');
                }
                Some('\'') => self.copy_squote(&mut inner)?,
                Some('"') => self.copy_dquote(&mut inner)?,
                Some('`') => self.copy_backtick(&mut inner)?,
                Some('\\') => {
                    self.pos += 1;
                    inner.push('\\');
                    match self.bump() {
                        None => return Err(inc(Incomplete::Expansion)),
                        Some(n) => inner.push(n),
                    }
                }
                Some(c) => {
                    self.pos += 1;
                    inner.push(c);
                }
            }
        }
    }

    /// Capture `$(...)` inner text (the opening `$(` already consumed), tracking
    /// nested parens and skipping over quoted regions.
    ///
    /// Limitation: `#` comments inside the substitution are not special-cased,
    /// so an unbalanced `)` inside such a comment could close the span early.
    /// Phase 3 re-lexes the captured text, so this only affects delimiting.
    fn scan_cmd_paren(&mut self) -> Result<String, LexError> {
        let mut depth = 1;
        let mut inner = String::new();
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Expansion)),
                Some(')') => {
                    self.pos += 1;
                    depth -= 1;
                    if depth == 0 {
                        return Ok(inner);
                    }
                    inner.push(')');
                }
                Some('(') => {
                    self.pos += 1;
                    depth += 1;
                    inner.push('(');
                }
                Some('\'') => self.copy_squote(&mut inner)?,
                Some('"') => self.copy_dquote(&mut inner)?,
                Some('`') => self.copy_backtick(&mut inner)?,
                Some('\\') => {
                    self.pos += 1;
                    inner.push('\\');
                    match self.bump() {
                        None => return Err(inc(Incomplete::Expansion)),
                        Some(n) => inner.push(n),
                    }
                }
                Some(c) => {
                    self.pos += 1;
                    inner.push(c);
                }
            }
        }
    }

    /// Capture `$(( ... ))` inner text (the opening `$((` already consumed).
    /// Arithmetic has no quoting, so this is pure paren balancing; the closing
    /// `))` is recognized at the top level.
    fn scan_arith(&mut self) -> Result<String, LexError> {
        let mut depth = 2;
        let mut inner = String::new();
        loop {
            match self.peek() {
                None => return Err(inc(Incomplete::Expansion)),
                Some(')') => {
                    if depth == 2 && self.peek_nth(1) == Some(')') {
                        self.pos += 2;
                        return Ok(inner);
                    }
                    self.pos += 1;
                    depth -= 1;
                    inner.push(')');
                }
                Some('(') => {
                    self.pos += 1;
                    depth += 1;
                    inner.push('(');
                }
                Some(c) => {
                    self.pos += 1;
                    inner.push(c);
                }
            }
        }
    }
}

/// Compute a here-doc delimiter's literal value and whether it was quoted
/// (quoting disables expansion of the body).
fn heredoc_delim(w: &Word) -> (String, bool) {
    let mut s = String::new();
    let mut quoted = false;
    for p in &w.0 {
        match p {
            WordPart::Literal { text, quoted: q } => {
                s.push_str(text);
                if *q {
                    quoted = true;
                }
            }
            // Delimiters are only subject to quote removal; an expansion here is
            // degenerate — fold its raw text in literally.
            WordPart::Expansion { raw, .. } => s.push_str(raw),
        }
    }
    (s, quoted)
}

#[cfg(test)]
mod tests {
    use super::{tokenize, Incomplete, LexError};
    use crate::token::{ExpansionKind, HereDoc, Operator, Token, Word, WordPart};

    fn toks(s: &str) -> Vec<Token> {
        tokenize(s).unwrap_or_else(|e| panic!("expected complete, got {e:?} for {s:?}"))
    }
    fn err(s: &str) -> Incomplete {
        match tokenize(s) {
            Err(LexError::Incomplete(i)) => i,
            other => panic!("expected Incomplete, got {other:?} for {s:?}"),
        }
    }
    fn lit(s: &str, quoted: bool) -> WordPart {
        WordPart::Literal {
            text: s.into(),
            quoted,
        }
    }
    fn exp(kind: ExpansionKind, raw: &str, quoted: bool) -> WordPart {
        WordPart::Expansion {
            kind,
            raw: raw.into(),
            quoted,
        }
    }
    fn word(parts: Vec<WordPart>) -> Token {
        Token::Word(Word(parts))
    }
    fn uword(s: &str) -> Token {
        word(vec![lit(s, false)])
    }
    fn op(o: Operator) -> Token {
        Token::Op(o)
    }

    #[test]
    fn control_operators() {
        assert_eq!(toks("a;b"), vec![uword("a"), op(Operator::Semi), uword("b")]);
        assert_eq!(
            toks("a && b || c"),
            vec![
                uword("a"),
                op(Operator::AndAnd),
                uword("b"),
                op(Operator::OrOr),
                uword("c")
            ]
        );
        assert_eq!(toks("a|b"), vec![uword("a"), op(Operator::Pipe), uword("b")]);
        assert_eq!(toks("a & b"), vec![uword("a"), op(Operator::Amp), uword("b")]);
        assert_eq!(
            toks("( a )"),
            vec![op(Operator::LParen), uword("a"), op(Operator::RParen)]
        );
        assert_eq!(toks(";;"), vec![op(Operator::DSemi)]);
    }

    #[test]
    fn redirection_operators() {
        assert_eq!(toks("> f"), vec![op(Operator::Great), uword("f")]);
        assert_eq!(toks(">>f"), vec![op(Operator::DGreat), uword("f")]);
        assert_eq!(toks("<f"), vec![op(Operator::Less), uword("f")]);
        assert_eq!(toks("<>f"), vec![op(Operator::LessGreat), uword("f")]);
        assert_eq!(toks(">|f"), vec![op(Operator::Clobber), uword("f")]);
        assert_eq!(toks(">&2"), vec![op(Operator::GreatAnd), uword("2")]);
        assert_eq!(toks("<&-"), vec![op(Operator::LessAnd), uword("-")]);
    }

    #[test]
    fn io_number() {
        assert_eq!(
            toks("2>f"),
            vec![Token::IoNumber(2), op(Operator::Great), uword("f")]
        );
        assert_eq!(
            toks("2>>f"),
            vec![Token::IoNumber(2), op(Operator::DGreat), uword("f")]
        );
        assert_eq!(
            toks("10>f"),
            vec![Token::IoNumber(10), op(Operator::Great), uword("f")]
        );
        assert_eq!(
            toks("1>&2"),
            vec![Token::IoNumber(1), op(Operator::GreatAnd), uword("2")]
        );
        // A space breaks the IO_NUMBER rule: "2" is an ordinary word.
        assert_eq!(
            toks("2 > f"),
            vec![uword("2"), op(Operator::Great), uword("f")]
        );
        // Non-digit prefix: not an IO_NUMBER.
        assert_eq!(
            toks("a2>f"),
            vec![uword("a2"), op(Operator::Great), uword("f")]
        );
    }

    #[test]
    fn quoting() {
        assert_eq!(toks("'a b'"), vec![word(vec![lit("a b", true)])]);
        assert_eq!(toks("\"a b\""), vec![word(vec![lit("a b", true)])]);
        assert_eq!(toks("''"), vec![word(vec![lit("", true)])]);
        assert_eq!(toks("\"\""), vec![word(vec![lit("", true)])]);
        // Backslash-escaped space keeps it inside one (quoted) word.
        assert_eq!(
            toks("a\\ b"),
            vec![word(vec![lit("a", false), lit(" ", true), lit("b", false)])]
        );
        // Inside double quotes, \n is literal backslash-n (not a newline).
        assert_eq!(toks("\"\\n\""), vec![word(vec![lit("\\n", true)])]);
        // ...but \" is an escaped quote.
        assert_eq!(toks("\"\\\"\""), vec![word(vec![lit("\"", true)])]);
    }

    #[test]
    fn expansions_are_opaque() {
        use ExpansionKind::*;
        assert_eq!(toks("$foo"), vec![word(vec![exp(Parameter, "foo", false)])]);
        assert_eq!(
            toks("${foo:-bar}"),
            vec![word(vec![exp(Parameter, "foo:-bar", false)])]
        );
        assert_eq!(toks("$?"), vec![word(vec![exp(Parameter, "?", false)])]);
        assert_eq!(toks("$1"), vec![word(vec![exp(Parameter, "1", false)])]);
        assert_eq!(toks("$(cmd)"), vec![word(vec![exp(Command, "cmd", false)])]);
        assert_eq!(
            toks("$(a $(b) c)"),
            vec![word(vec![exp(Command, "a $(b) c", false)])]
        );
        assert_eq!(toks("`cmd`"), vec![word(vec![exp(Command, "cmd", false)])]);
        assert_eq!(
            toks("$((1+2))"),
            vec![word(vec![exp(Arithmetic, "1+2", false)])]
        );
        assert_eq!(
            toks("$(( (1+2)*3 ))"),
            vec![word(vec![exp(Arithmetic, " (1+2)*3 ", false)])]
        );
        // Quoted expansion + adjacency to literals.
        assert_eq!(
            toks("foo\"$bar\"baz"),
            vec![word(vec![
                lit("foo", false),
                exp(Parameter, "bar", true),
                lit("baz", false),
            ])]
        );
        // A lone `$` is a literal dollar sign.
        assert_eq!(toks("$"), vec![word(vec![lit("$", false)])]);
    }

    #[test]
    fn ansi_c_quoting() {
        assert_eq!(toks("$'a\\nb'"), vec![word(vec![lit("a\nb", true)])]);
        assert_eq!(toks("$'\\t\\\\'"), vec![word(vec![lit("\t\\", true)])]);
        assert_eq!(toks("$'\\x41'"), vec![word(vec![lit("A", true)])]);
        assert_eq!(toks("$'\\101'"), vec![word(vec![lit("A", true)])]);
    }

    #[test]
    fn comments() {
        assert_eq!(toks("echo hi # a comment"), vec![uword("echo"), uword("hi")]);
        assert_eq!(toks("# whole line"), vec![]);
        // `#` is literal inside a word and inside quotes.
        assert_eq!(toks("a#b"), vec![word(vec![lit("a#b", false)])]);
        assert_eq!(toks("'#x'"), vec![word(vec![lit("#x", true)])]);
    }

    #[test]
    fn newlines_and_continuation() {
        assert_eq!(
            toks("echo a\nb"),
            vec![uword("echo"), uword("a"), Token::Newline, uword("b")]
        );
        // Backslash-newline splices: "a\<nl>b" => one word "ab".
        assert_eq!(toks("echo a\\\nb"), vec![uword("echo"), uword("ab")]);
    }

    #[test]
    fn here_document() {
        assert_eq!(
            toks("cat <<EOF\nhello\nEOF\n"),
            vec![
                uword("cat"),
                Token::HereDoc(HereDoc {
                    strip_tabs: false,
                    quoted: false,
                    delim: "EOF".into(),
                    body: "hello\n".into(),
                }),
                Token::Newline,
            ]
        );
        // <<- strips leading tabs from body and delimiter lines.
        assert_eq!(
            toks("cat <<-EOF\n\t\tindented\n\tEOF\n"),
            vec![
                uword("cat"),
                Token::HereDoc(HereDoc {
                    strip_tabs: true,
                    quoted: false,
                    delim: "EOF".into(),
                    body: "indented\n".into(),
                }),
                Token::Newline,
            ]
        );
        // A quoted delimiter marks the body as non-expanding.
        assert_eq!(
            toks("cat <<'EOF'\n$x\nEOF\n"),
            vec![
                uword("cat"),
                Token::HereDoc(HereDoc {
                    strip_tabs: false,
                    quoted: true,
                    delim: "EOF".into(),
                    body: "$x\n".into(),
                }),
                Token::Newline,
            ]
        );
    }

    #[test]
    fn here_document_in_place_with_trailing_tokens() {
        // The HereDoc token sits where `<<EOF` appeared; the rest of the line
        // (`| wc`) follows, and the body is collected from later lines.
        assert_eq!(
            toks("cat <<EOF | wc\nbody\nEOF\n"),
            vec![
                uword("cat"),
                Token::HereDoc(HereDoc {
                    strip_tabs: false,
                    quoted: false,
                    delim: "EOF".into(),
                    body: "body\n".into(),
                }),
                op(Operator::Pipe),
                uword("wc"),
                Token::Newline,
            ]
        );
    }

    #[test]
    fn two_here_documents_on_one_line() {
        // Bodies are filled in order: first A, then B.
        assert_eq!(
            toks("cat <<A <<B\naaa\nA\nbbb\nB\n"),
            vec![
                uword("cat"),
                Token::HereDoc(HereDoc {
                    strip_tabs: false,
                    quoted: false,
                    delim: "A".into(),
                    body: "aaa\n".into(),
                }),
                Token::HereDoc(HereDoc {
                    strip_tabs: false,
                    quoted: false,
                    delim: "B".into(),
                    body: "bbb\n".into(),
                }),
                Token::Newline,
            ]
        );
    }

    #[test]
    fn incomplete_inputs() {
        assert_eq!(err("'abc"), Incomplete::Quote('\''));
        assert_eq!(err("\"abc"), Incomplete::Quote('"'));
        assert_eq!(err("echo \\"), Incomplete::Backslash);
        assert_eq!(err("${x"), Incomplete::Expansion);
        assert_eq!(err("$(cmd"), Incomplete::Expansion);
        assert_eq!(err("$((1+2"), Incomplete::Expansion);
        assert_eq!(err("`cmd"), Incomplete::Expansion);
        assert_eq!(err("cat <<EOF\nbody\n"), Incomplete::HereDoc("EOF".into()));
    }
}
