//! The word-expansion engine (Phase 3, POSIX §2.6).
//!
//! Applies the seven expansion steps in order:
//!   1. tilde expansion,
//!   2. parameter expansion (`$x`, `${x}`, with `:-` `:=` `:?` `:+`, `${#x}`,
//!      and `#`/`##`/`%`/`%%` trimming),
//!   3. command substitution (`$(…)`, `` `…` `` — delegated to [`crate::exec`]),
//!   4. arithmetic expansion (`$(( … ))` via [`crate::arith`]),
//!   5. field splitting on `IFS` (unquoted expansion results only),
//!   6. pathname expansion (globbing via [`crate::glob`], unless `set -f`),
//!   7. quote removal.
//!
//! Quoting is carried per-character through steps 5–6 so that only *unquoted*
//! expansion results are split, and only *unquoted* `*?[` are glob-magic. The
//! two entry points are [`to_fields`] (for command words/arguments — all seven
//! steps) and [`to_string`] (for assignment values, redirection targets, and
//! patterns — steps 1–4 and quote removal, no splitting or globbing).

use crate::arith;
use crate::glob;
use crate::lexer;
use crate::shell::Shell;
use crate::token::{Token, Word, WordPart};

/// The origin of an expanded character, controlling later steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    /// From quotes: protected from field splitting and pathname expansion.
    Quoted,
    /// Unquoted literal text: not split, but `*?[` are glob-magic.
    Literal,
    /// From an unquoted expansion: subject to splitting and globbing.
    Expand,
}

#[derive(Debug, Clone)]
enum Elem {
    Ch(char, Tag),
    /// A hard field boundary from `$@`/`"$@"` between positional parameters.
    Break,
    /// A zero-width marker that a (possibly empty) field exists here — from an
    /// empty quoted string such as `""` or `"$unset"`.
    Anchor,
}

/// Expand a command word/argument through all seven steps into zero or more
/// fields.
pub fn to_fields(word: &Word, shell: &mut Shell) -> Vec<String> {
    let elems = build(word, shell, true);
    let ifs = shell.ifs();
    let fields = split_fields(&elems, &ifs);
    let noglob = shell.noglob;

    let mut out = Vec::new();
    for field in fields {
        let pattern = build_glob_pattern(&field);
        if !noglob && glob::has_magic(&pattern) {
            let matches = glob::glob(&pattern);
            if matches.is_empty() {
                out.push(glob::unescape(&pattern)); // no match: word stays literal
            } else {
                out.extend(matches);
            }
        } else {
            out.push(glob::unescape(&pattern)); // unescape performs quote removal
        }
    }
    out
}

/// Expand a word to a single string (assignment RHS, redirection target, `case`
/// subject word): steps 1–4 and quote removal, without field splitting or
/// globbing.
pub fn to_string(word: &Word, shell: &mut Shell) -> String {
    let elems = build(word, shell, false);
    let mut s = String::new();
    for e in elems {
        if let Elem::Ch(c, _) = e {
            s.push(c);
        }
    }
    s
}

/// Expand a word into an [`crate::glob::fnmatch`] pattern (a `case` pattern):
/// steps 1–4 with no field splitting or pathname expansion, but with quoting
/// preserved as `\`-escapes so only *unquoted* `*?[` stay pattern-magic.
pub fn to_pattern(word: &Word, shell: &mut Shell) -> String {
    let elems = build(word, shell, false);
    let mut p = String::new();
    for e in elems {
        if let Elem::Ch(c, tag) = e {
            if tag == Tag::Quoted || c == '\\' {
                p.push('\\');
            }
            p.push(c);
        }
    }
    p
}

// ---- prefield construction (steps 1–4) -------------------------------------

fn build(word: &Word, shell: &mut Shell, splitting: bool) -> Vec<Elem> {
    let mut out = Vec::new();
    for (i, part) in word.0.iter().enumerate() {
        match part {
            WordPart::Literal { text, quoted } => {
                let text = if i == 0 && !quoted {
                    apply_tilde(text, shell)
                } else {
                    text.clone()
                };
                if *quoted && text.is_empty() && splitting {
                    out.push(Elem::Anchor);
                } else {
                    let tag = if *quoted { Tag::Quoted } else { Tag::Literal };
                    for c in text.chars() {
                        out.push(Elem::Ch(c, tag));
                    }
                }
            }
            WordPart::Expansion { kind, raw, quoted } => match kind {
                crate::token::ExpansionKind::Parameter => {
                    match param_eval(raw, shell) {
                        PVal::Scalar(s) => push_scalar(&mut out, &s, *quoted, splitting),
                        PVal::Fields(list) => push_fields(&mut out, &list, *quoted, splitting),
                    }
                }
                crate::token::ExpansionKind::Command => {
                    let s = crate::exec::command_substitution(raw, shell);
                    push_scalar(&mut out, &s, *quoted, splitting);
                }
                crate::token::ExpansionKind::Arithmetic => {
                    let s = eval_arith(raw, shell);
                    push_scalar(&mut out, &s, *quoted, splitting);
                }
            },
        }
    }
    out
}

fn push_scalar(out: &mut Vec<Elem>, s: &str, quoted: bool, splitting: bool) {
    if quoted && s.is_empty() && splitting {
        out.push(Elem::Anchor);
        return;
    }
    let tag = if quoted {
        Tag::Quoted
    } else if splitting {
        Tag::Expand
    } else {
        Tag::Literal
    };
    for c in s.chars() {
        out.push(Elem::Ch(c, tag));
    }
}

/// Push the positional parameters (`$@`/`"$@"`). Quoted keeps each parameter a
/// distinct field (empties preserved); unquoted drops empty parameters and
/// leaves the rest subject to further splitting.
fn push_fields(out: &mut Vec<Elem>, list: &[String], quoted: bool, splitting: bool) {
    if !splitting {
        // String context: join with a single space.
        let joined = list.join(" ");
        for c in joined.chars() {
            out.push(Elem::Ch(c, Tag::Literal));
        }
        return;
    }
    if quoted {
        for (i, p) in list.iter().enumerate() {
            if i > 0 {
                out.push(Elem::Break);
            }
            if p.is_empty() {
                out.push(Elem::Anchor);
            } else {
                for c in p.chars() {
                    out.push(Elem::Ch(c, Tag::Quoted));
                }
            }
        }
    } else {
        let mut first = true;
        for p in list {
            if p.is_empty() {
                continue; // unquoted empties disappear
            }
            if !first {
                out.push(Elem::Break);
            }
            for c in p.chars() {
                out.push(Elem::Ch(c, Tag::Expand));
            }
            first = false;
        }
    }
}

/// Tilde expansion of a leading unquoted `~` or `~/…` to `$HOME`. `~user` is
/// left literal (Motor OS may have no user database — see the plan).
fn apply_tilde(text: &str, shell: &Shell) -> String {
    if !text.starts_with('~') {
        return text.to_string();
    }
    let rest = &text[1..];
    let (user, tail) = match rest.find('/') {
        Some(p) => (&rest[..p], &rest[p..]),
        None => (rest, ""),
    };
    if user.is_empty()
        && let Some(home) = shell.get("HOME")
    {
        return format!("{home}{tail}");
    }
    text.to_string()
}

// ---- field splitting (step 5) ----------------------------------------------

fn split_fields(elems: &[Elem], ifs: &str) -> Vec<Vec<(char, Tag)>> {
    let mut fields: Vec<Vec<(char, Tag)>> = Vec::new();
    let mut cur: Vec<(char, Tag)> = Vec::new();
    let mut started = false;
    // Whether the previous separator was IFS whitespace, so an adjacent
    // non-whitespace IFS char merges into the same delimiter (no empty field).
    let mut prev_ws_delim = false;

    for e in elems {
        match e {
            Elem::Break => {
                fields.push(std::mem::take(&mut cur));
                started = false;
                prev_ws_delim = false;
            }
            Elem::Anchor => started = true,
            Elem::Ch(c, tag) => {
                let is_split = *tag == Tag::Expand && ifs.contains(*c);
                if !is_split {
                    cur.push((*c, *tag));
                    started = true;
                    prev_ws_delim = false;
                } else if c.is_whitespace() {
                    if started {
                        fields.push(std::mem::take(&mut cur));
                        started = false;
                    }
                    prev_ws_delim = true;
                } else {
                    // non-whitespace IFS delimiter
                    if started {
                        fields.push(std::mem::take(&mut cur));
                        started = false;
                    } else if !prev_ws_delim {
                        fields.push(Vec::new()); // empty field between delimiters
                    }
                    prev_ws_delim = false;
                }
            }
        }
    }
    if started {
        fields.push(cur);
    }
    fields
}

// ---- pathname expansion helpers (step 6) -----------------------------------

/// Turn a split field into a glob pattern: quoted characters (and any literal
/// backslash) are escaped so only unquoted `*?[` stay magic.
fn build_glob_pattern(field: &[(char, Tag)]) -> String {
    let mut p = String::new();
    for (c, tag) in field {
        if *tag == Tag::Quoted || *c == '\\' {
            p.push('\\');
        }
        p.push(*c);
    }
    p
}

// ---- parameter expansion (step 2) ------------------------------------------

enum PVal {
    Scalar(String),
    Fields(Vec<String>),
}

/// Evaluate a parameter expansion body (the text between `${` and `}`, or the
/// name after `$`) to a scalar or, for `$@`, a list of fields.
fn param_eval(raw: &str, shell: &mut Shell) -> PVal {
    // ${#…} length / $# count.
    if raw == "#" {
        return PVal::Scalar(shell.param_count().to_string());
    }
    if let Some(inner) = raw.strip_prefix('#')
        && !inner.is_empty()
        && !starts_with_modifier(inner)
    {
        let len = if inner == "@" || inner == "*" {
            shell.param_count()
        } else {
            resolve_scalar(inner, shell).unwrap_or_default().chars().count()
        };
        return PVal::Scalar(len.to_string());
    }

    let (head, modifier) = split_head_and_modifier(raw);

    if head == "@" || head == "*" {
        // Modifiers on `$@`/`$*` are unusual; Phase 3 ignores them.
        return if head == "@" {
            PVal::Fields(shell.params().to_vec())
        } else {
            PVal::Scalar(join_star(shell))
        };
    }

    let value = resolve_scalar(head, shell);
    PVal::Scalar(apply_modifier(head, value, modifier, shell))
}

/// Join the positional parameters for `$*`: with the first character of `IFS`
/// (space when `IFS` is unset, nothing when `IFS` is null).
fn join_star(shell: &Shell) -> String {
    match shell.get("IFS") {
        None => shell.params().join(" "),
        Some(ifs) => match ifs.chars().next() {
            Some(sep) => shell.params().join(&sep.to_string()),
            None => shell.params().concat(),
        },
    }
}

/// Resolve a plain parameter (name / positional / special) to its value, or
/// `None` if unset.
fn resolve_scalar(head: &str, shell: &Shell) -> Option<String> {
    if head.chars().all(|c| c.is_ascii_digit()) && !head.is_empty() {
        let n: usize = head.parse().unwrap_or(0);
        return shell.positional(n).map(str::to_string);
    }
    match head {
        "?" => Some(shell.status().to_string()),
        "$" => Some(shell.pid().to_string()),
        "!" => Some(String::new()), // last background pid — Phase 7
        "-" => Some(option_flags(shell)),
        "#" => Some(shell.param_count().to_string()),
        _ => shell.get(head),
    }
}

fn option_flags(shell: &Shell) -> String {
    // `$-`: currently only `set -f` is representable (Phase 6 adds the rest).
    let mut s = String::new();
    if shell.noglob {
        s.push('f');
    }
    s
}

#[derive(Clone, Copy)]
enum ModKind {
    UseDefault,
    AssignDefault,
    ErrorIfUnset,
    UseAlt,
    RemoveSmallestPrefix,
    RemoveLargestPrefix,
    RemoveSmallestSuffix,
    RemoveLargestSuffix,
}

fn starts_with_modifier(s: &str) -> bool {
    matches!(s.chars().next(), Some(':' | '-' | '=' | '?' | '+' | '#' | '%'))
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Split `${…}` body into the parameter head and an optional modifier.
fn split_head_and_modifier(raw: &str) -> (&str, Option<(ModKind, bool, String)>) {
    let first = match raw.chars().next() {
        Some(c) => c,
        None => return (raw, None),
    };
    let head_len = if first.is_ascii_alphabetic() || first == '_' {
        raw.find(|c: char| !is_name_char(c)).unwrap_or(raw.len())
    } else if first.is_ascii_digit() {
        raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len())
    } else {
        first.len_utf8()
    };
    let head = &raw[..head_len];
    let rest = &raw[head_len..];
    if rest.is_empty() {
        return (head, None);
    }

    let modifier = if let Some(w) = rest.strip_prefix("##") {
        Some((ModKind::RemoveLargestPrefix, false, w.to_string()))
    } else if let Some(w) = rest.strip_prefix('#') {
        Some((ModKind::RemoveSmallestPrefix, false, w.to_string()))
    } else if let Some(w) = rest.strip_prefix("%%") {
        Some((ModKind::RemoveLargestSuffix, false, w.to_string()))
    } else if let Some(w) = rest.strip_prefix('%') {
        Some((ModKind::RemoveSmallestSuffix, false, w.to_string()))
    } else {
        let (colon, r2) = match rest.strip_prefix(':') {
            Some(r) => (true, r),
            None => (false, rest),
        };
        match r2.chars().next() {
            Some('-') => Some((ModKind::UseDefault, colon, r2[1..].to_string())),
            Some('=') => Some((ModKind::AssignDefault, colon, r2[1..].to_string())),
            Some('?') => Some((ModKind::ErrorIfUnset, colon, r2[1..].to_string())),
            Some('+') => Some((ModKind::UseAlt, colon, r2[1..].to_string())),
            _ => None, // unrecognized: treat as a plain parameter
        }
    };
    (head, modifier)
}

fn apply_modifier(
    head: &str,
    value: Option<String>,
    modifier: Option<(ModKind, bool, String)>,
    shell: &mut Shell,
) -> String {
    let Some((kind, colon, word)) = modifier else {
        return value.unwrap_or_default();
    };
    let unset = value.is_none();
    // For `:`-variants "empty" (null) also triggers the default/alt.
    let empty = value.as_deref().is_none_or(str::is_empty);
    let trigger = if colon { empty } else { unset };

    match kind {
        ModKind::UseDefault => {
            if trigger {
                expand_raw_to_string(&word, shell)
            } else {
                value.unwrap_or_default()
            }
        }
        ModKind::UseAlt => {
            if trigger {
                String::new()
            } else {
                expand_raw_to_string(&word, shell)
            }
        }
        ModKind::AssignDefault => {
            if trigger {
                let v = expand_raw_to_string(&word, shell);
                if is_assignable_name(head) {
                    let _ = shell.set(head, v.clone());
                } else {
                    eprintln!("rush: ${{{head}}}: cannot assign in this way");
                }
                v
            } else {
                value.unwrap_or_default()
            }
        }
        ModKind::ErrorIfUnset => {
            if trigger {
                let msg = if word.is_empty() {
                    "parameter null or not set".to_string()
                } else {
                    expand_raw_to_string(&word, shell)
                };
                // POSIX exits a non-interactive shell here; deferred — we
                // diagnose and substitute nothing.
                eprintln!("rush: {head}: {msg}");
                String::new()
            } else {
                value.unwrap_or_default()
            }
        }
        ModKind::RemoveSmallestPrefix
        | ModKind::RemoveLargestPrefix
        | ModKind::RemoveSmallestSuffix
        | ModKind::RemoveLargestSuffix => {
            let subject = value.unwrap_or_default();
            let pattern = expand_raw_to_string(&word, shell);
            trim(&subject, &pattern, kind)
        }
    }
}

fn is_assignable_name(head: &str) -> bool {
    !head.is_empty() && (head.chars().next().unwrap().is_ascii_alphabetic() || head.starts_with('_'))
        && head.chars().all(is_name_char)
}

/// Remove the matching prefix/suffix from `subject` using `pattern` as a glob.
fn trim(subject: &str, pattern: &str, kind: ModKind) -> String {
    let chars: Vec<char> = subject.chars().collect();
    let n = chars.len();
    match kind {
        ModKind::RemoveSmallestPrefix | ModKind::RemoveLargestPrefix => {
            let range: Vec<usize> = match kind {
                ModKind::RemoveSmallestPrefix => (0..=n).collect(),
                _ => (0..=n).rev().collect(),
            };
            for i in range {
                let prefix: String = chars[..i].iter().collect();
                if glob::fnmatch(pattern, &prefix) {
                    return chars[i..].iter().collect();
                }
            }
            subject.to_string()
        }
        _ => {
            let range: Vec<usize> = match kind {
                ModKind::RemoveSmallestSuffix => (0..=n).rev().collect(),
                _ => (0..=n).collect(),
            };
            for i in range {
                let suffix: String = chars[i..].iter().collect();
                if glob::fnmatch(pattern, &suffix) {
                    return chars[..i].iter().collect();
                }
            }
            subject.to_string()
        }
    }
}

/// Expand a raw substring (a modifier word or pattern) to a string: lex it and
/// concatenate the expansion of each resulting word with single spaces.
fn expand_raw_to_string(raw: &str, shell: &mut Shell) -> String {
    match lexer::tokenize(raw) {
        Ok(tokens) => {
            let mut parts = Vec::new();
            for t in tokens {
                if let Token::Word(w) = t {
                    parts.push(to_string(&w, shell));
                }
            }
            parts.join(" ")
        }
        Err(_) => raw.to_string(),
    }
}

/// Evaluate an arithmetic expansion `$(( expr ))`. Per POSIX §2.6.4 the
/// expression is first expanded as if double-quoted (parameter expansion,
/// command substitution, nested arithmetic) — so `$1`, `$x`, `$(cmd)` work
/// inside it — then evaluated by [`crate::arith`].
pub fn eval_arith(raw: &str, shell: &mut Shell) -> String {
    let expr = expand_double_quoted(raw, shell);
    match arith::eval(&expr, shell) {
        Ok(n) => n.to_string(),
        Err(e) => {
            eprintln!("rush: arithmetic: {e}");
            String::new()
        }
    }
}

/// Expand a here-document body: double-quote rules (parameter/command/
/// arithmetic expansion, backslash special only before `$` `` ` `` `\`), no
/// field splitting or globbing.
pub fn expand_heredoc_body(body: &str, shell: &mut Shell) -> String {
    expand_double_quoted(body, shell)
}

/// The shared double-quote-context expander used by here-documents and by
/// arithmetic-expression pre-expansion.
fn expand_double_quoted(body: &str, shell: &mut Shell) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    let mut out = String::new();
    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() && matches!(chars[i + 1], '$' | '`' | '\\') => {
                out.push(chars[i + 1]);
                i += 2;
            }
            '$' => {
                let (val, next) = scan_dollar(&chars, i, shell);
                out.push_str(&val);
                i = next;
            }
            '`' => {
                let (inner, next) = scan_backtick(&chars, i);
                out.push_str(&crate::exec::command_substitution(&inner, shell));
                i = next;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Scan a `$…` at `chars[i]` (`chars[i] == '$'`) and return its expanded value
/// and the index past it.
fn scan_dollar(chars: &[char], i: usize, shell: &mut Shell) -> (String, usize) {
    let mut j = i + 1;
    if j >= chars.len() {
        return ("$".to_string(), j);
    }
    match chars[j] {
        '{' => {
            let (inner, next) = scan_balanced(chars, j + 1, '{', '}');
            (param_to_string(&inner, shell), next)
        }
        '(' if chars.get(j + 1) == Some(&'(') => {
            let (inner, next) = scan_balanced_arith(chars, j + 2);
            (eval_arith(&inner, shell), next)
        }
        '(' => {
            let (inner, next) = scan_balanced(chars, j + 1, '(', ')');
            (crate::exec::command_substitution(&inner, shell), next)
        }
        c if c.is_ascii_alphabetic() || c == '_' => {
            let start = j;
            while j < chars.len() && is_name_char(chars[j]) {
                j += 1;
            }
            let name: String = chars[start..j].iter().collect();
            (param_to_string(&name, shell), j)
        }
        c if c.is_ascii_digit() || matches!(c, '@' | '*' | '#' | '?' | '$' | '!' | '-') => {
            let name = c.to_string();
            (param_to_string(&name, shell), j + 1)
        }
        _ => ("$".to_string(), j),
    }
}

/// Evaluate a parameter body to a plain string (`$@`/`$*` join with a space).
fn param_to_string(raw: &str, shell: &mut Shell) -> String {
    match param_eval(raw, shell) {
        PVal::Scalar(s) => s,
        PVal::Fields(list) => list.join(" "),
    }
}

fn scan_backtick(chars: &[char], i: usize) -> (String, usize) {
    let mut j = i + 1;
    let mut inner = String::new();
    while j < chars.len() && chars[j] != '`' {
        if chars[j] == '\\' && j + 1 < chars.len() && matches!(chars[j + 1], '`' | '$' | '\\') {
            inner.push(chars[j + 1]);
            j += 2;
        } else {
            inner.push(chars[j]);
            j += 1;
        }
    }
    (inner, (j + 1).min(chars.len()))
}

fn scan_balanced(chars: &[char], start: usize, open: char, close: char) -> (String, usize) {
    let mut depth = 1;
    let mut j = start;
    let mut inner = String::new();
    while j < chars.len() {
        let c = chars[j];
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return (inner, j + 1);
            }
        }
        inner.push(c);
        j += 1;
    }
    (inner, j)
}

fn scan_balanced_arith(chars: &[char], start: usize) -> (String, usize) {
    let mut depth = 2;
    let mut j = start;
    let mut inner = String::new();
    while j < chars.len() {
        let c = chars[j];
        if c == ')' && depth == 2 && chars.get(j + 1) == Some(&')') {
            return (inner, j + 2);
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        }
        inner.push(c);
        j += 1;
    }
    (inner, j)
}

#[cfg(test)]
mod tests {
    use super::{to_fields, to_string};
    use crate::lexer;
    use crate::shell::Shell;
    use crate::token::{Token, Word};

    fn word(src: &str) -> Word {
        match lexer::tokenize(src).unwrap().into_iter().next() {
            Some(Token::Word(w)) => w,
            other => panic!("expected a single word, got {other:?}"),
        }
    }

    fn fields(src: &str, shell: &mut Shell) -> Vec<String> {
        to_fields(&word(src), shell)
    }

    #[test]
    fn plain_variable_and_braces() {
        let mut sh = Shell::new();
        sh.set("x", "hello".into()).unwrap();
        assert_eq!(fields("$x", &mut sh), vec!["hello"]);
        assert_eq!(fields("${x}", &mut sh), vec!["hello"]);
        assert_eq!(fields("a${x}b", &mut sh), vec!["ahellob"]);
        assert_eq!(fields("$undefined", &mut sh), Vec::<String>::new());
    }

    #[test]
    fn quoting_and_field_splitting() {
        let mut sh = Shell::new();
        sh.set("x", "a b c".into()).unwrap();
        // Unquoted: field-split into three.
        assert_eq!(fields("$x", &mut sh), vec!["a", "b", "c"]);
        // Quoted: one field.
        assert_eq!(fields("\"$x\"", &mut sh), vec!["a b c"]);
        // Empty quoted string is one empty field.
        assert_eq!(fields("\"\"", &mut sh), vec![""]);
        // Unquoted empty variable yields no field.
        assert_eq!(fields("$undefined", &mut sh), Vec::<String>::new());
    }

    #[test]
    fn custom_ifs() {
        let mut sh = Shell::new();
        sh.set("IFS", ":".into()).unwrap();
        sh.set("p", "a:b::c".into()).unwrap();
        assert_eq!(fields("$p", &mut sh), vec!["a", "b", "", "c"]);
    }

    #[test]
    fn parameter_modifiers() {
        let mut sh = Shell::new();
        assert_eq!(fields("${u:-default}", &mut sh), vec!["default"]);
        sh.set("u", "".into()).unwrap();
        assert_eq!(fields("${u:-default}", &mut sh), vec!["default"]); // null triggers :-
        assert_eq!(fields("${u-default}", &mut sh), Vec::<String>::new()); // set-but-null: - does not
        sh.set("u", "val".into()).unwrap();
        assert_eq!(fields("${u:-default}", &mut sh), vec!["val"]);
        assert_eq!(fields("${u:+set}", &mut sh), vec!["set"]);
        // := assigns.
        assert_eq!(fields("${w:=assigned}", &mut sh), vec!["assigned"]);
        assert_eq!(sh.get("w").as_deref(), Some("assigned"));
    }

    #[test]
    fn length_and_trimming() {
        let mut sh = Shell::new();
        sh.set("s", "hello".into()).unwrap();
        assert_eq!(fields("${#s}", &mut sh), vec!["5"]);
        sh.set("path", "/usr/local/bin".into()).unwrap();
        assert_eq!(fields("${path##*/}", &mut sh), vec!["bin"]);
        assert_eq!(fields("${path#*/}", &mut sh), vec!["usr/local/bin"]);
        sh.set("file", "archive.tar.gz".into()).unwrap();
        assert_eq!(fields("${file%.*}", &mut sh), vec!["archive.tar"]);
        assert_eq!(fields("${file%%.*}", &mut sh), vec!["archive"]);
    }

    #[test]
    fn positional_and_special() {
        let mut sh = Shell::new();
        sh.set_params(vec!["one".into(), "two three".into()]);
        sh.set_status(42);
        assert_eq!(fields("$1", &mut sh), vec!["one"]);
        assert_eq!(fields("$#", &mut sh), vec!["2"]);
        assert_eq!(fields("$?", &mut sh), vec!["42"]);
        // "$@" keeps each parameter a distinct field.
        assert_eq!(fields("\"$@\"", &mut sh), vec!["one", "two three"]);
        // Unquoted $@ splits the second parameter further.
        assert_eq!(fields("$@", &mut sh), vec!["one", "two", "three"]);
        // "$*" joins with the first IFS char (space by default).
        assert_eq!(fields("\"$*\"", &mut sh), vec!["one two three"]);
    }

    #[test]
    fn arithmetic_expansion() {
        let mut sh = Shell::new();
        sh.set("n", "6".into()).unwrap();
        assert_eq!(fields("$((n * 7))", &mut sh), vec!["42"]);
        assert_eq!(to_string(&word("$((1 + 2 * 3))"), &mut sh), "7");
    }

    #[test]
    fn tilde_expansion() {
        let mut sh = Shell::new();
        sh.set("HOME", "/home/u".into()).unwrap();
        // HOME is a shell var here, but tilde reads it via get().
        assert_eq!(fields("~/bin", &mut sh), vec!["/home/u/bin"]);
        // Quoted tilde is literal.
        assert_eq!(fields("\"~\"", &mut sh), vec!["~"]);
    }
}
