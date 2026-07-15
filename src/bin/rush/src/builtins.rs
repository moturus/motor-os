//! Shell builtins (Phase 5, milestone M2).
//!
//! POSIX splits builtins into *special* (§2.14) and *regular* ones. The
//! distinction matters for dispatch and semantics:
//!
//! - A **special** builtin (`:`, `.`, `eval`, `exec`, `exit`, `export`,
//!   `readonly`, `set`, `shift`, `unset`, `times`, `trap`, `break`/`continue`/
//!   `return`) is found *before* shell functions and cannot be shadowed by one;
//!   a variable assignment prefixed to it (`X=1 export …`) persists in the
//!   shell; and a syntax/usage error aborts a non-interactive shell.
//! - A **regular** builtin (`cd`, `pwd`, `echo`, `printf`, `test`/`[`, `read`,
//!   `true`, `false`, `getopts`, `command`, `type`, `hash`, `alias`, `unalias`,
//!   `umask`, and the Phase 7 job builtins `wait`, `jobs`, `fg`, `bg`, `kill`)
//!   is found *after* functions, so a like-named function shadows it, and a
//!   prefixed assignment is transient.
//!
//! This module owns the *pure* builtins — those that only need the [`Shell`] and
//! a place to write output. The executor ([`crate::exec`]) owns the ones coupled
//! to execution itself (`.`, `eval`, `exec`, `command name …`, `read`, and the
//! control-flow builtins), dispatches every builtin in the correct order, and
//! wires each builtin's stdout/stderr to the command's redirections via the
//! [`Io`] writers below (so `echo hi > f` and `pwd 2>err` behave).
//!
//! Documented limits: `umask` is bookkeeping-only (no Motor OS syscall); `times`
//! reports zeros; `hash` is a no-op cache. Phase 6 moved the shell options behind
//! [`crate::options`]: `set` parses them from that one table, and the executor
//! and expansion engine enforce them. Phase 7 gave `trap` real delivery via
//! [`crate::signal`] and added the job builtins over [`crate::jobs`] — where the
//! platform's limits live (Motor OS cannot deliver a signal, so a trap there
//! fires only for a `^C` rush spots itself).

use std::io::{Read, Write};
use std::path::Path;

use crate::jobs::{JobState, JobWait};
use crate::options::Options;
use crate::shell::Shell;
use crate::signal;
use crate::sys;

/// The writers a builtin sends its normal and error output to. They are derived
/// from the command's effective fd 1 / fd 2, so builtin output honors
/// redirections (`echo hi >f`, `type x 2>err`) without a `dup2`.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    /// Whether any write to `out` failed. A builtin has nowhere useful to return
    /// a per-write error to, but losing output silently is worse: the executor
    /// consumes this via [`Io::finish`] and reports it, the way dash does.
    out_failed: bool,
}

impl<'a> Io<'a> {
    pub fn new(out: &'a mut dyn Write, err: &'a mut dyn Write) -> Self {
        Self {
            out,
            err,
            out_failed: false,
        }
    }

    /// Flush `out` and report whether this builtin's output was written intact.
    /// A buffered writer can fail at flush time, so the flush counts too.
    pub fn finish(&mut self) -> bool {
        if self.out.flush().is_err() {
            self.out_failed = true;
        }
        !self.out_failed
    }

    fn out(&mut self, s: &str) {
        self.write_out(s.as_bytes());
    }
    fn outln(&mut self, s: &str) {
        self.write_out(s.as_bytes());
        self.write_out(b"\n");
    }
    fn write_out(&mut self, bytes: &[u8]) {
        if self.out.write_all(bytes).is_err() {
            self.out_failed = true;
        }
    }
    fn errln(&mut self, s: &str) {
        // A failed write to stderr has nowhere left to be reported.
        let _ = self.err.write_all(s.as_bytes());
        let _ = self.err.write_all(b"\n");
    }
}

/// Every builtin the shell recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    // ---- special ----
    Colon,
    Dot,
    Eval,
    Exec,
    Exit,
    Export,
    Readonly,
    Set,
    Shift,
    Unset,
    Times,
    Trap,
    Break,
    Continue,
    Return,
    // ---- regular ----
    Cd,
    Pwd,
    Echo,
    Printf,
    Test,
    Read,
    True,
    False,
    Getopts,
    Command,
    Type,
    Hash,
    Alias,
    Unalias,
    Umask,
    Wait,
    Jobs,
    Fg,
    Bg,
    Kill,
}

/// Map a command name to its builtin, if any.
pub fn lookup(name: &str) -> Option<Builtin> {
    Some(match name {
        ":" => Builtin::Colon,
        "." => Builtin::Dot,
        "eval" => Builtin::Eval,
        "exec" => Builtin::Exec,
        "exit" => Builtin::Exit,
        "export" => Builtin::Export,
        "readonly" => Builtin::Readonly,
        "set" => Builtin::Set,
        "shift" => Builtin::Shift,
        "unset" => Builtin::Unset,
        "times" => Builtin::Times,
        "trap" => Builtin::Trap,
        "break" => Builtin::Break,
        "continue" => Builtin::Continue,
        "return" => Builtin::Return,
        "cd" => Builtin::Cd,
        "pwd" => Builtin::Pwd,
        "echo" => Builtin::Echo,
        "printf" => Builtin::Printf,
        "test" | "[" => Builtin::Test,
        "read" => Builtin::Read,
        "true" => Builtin::True,
        "false" => Builtin::False,
        "getopts" => Builtin::Getopts,
        "command" => Builtin::Command,
        "type" => Builtin::Type,
        "hash" => Builtin::Hash,
        "alias" => Builtin::Alias,
        "unalias" => Builtin::Unalias,
        "umask" => Builtin::Umask,
        "wait" => Builtin::Wait,
        "jobs" => Builtin::Jobs,
        "fg" => Builtin::Fg,
        "bg" => Builtin::Bg,
        "kill" => Builtin::Kill,
        _ => return None,
    })
}

/// Whether a builtin is a POSIX *special* builtin (dispatched before functions;
/// prefixed assignments persist; usage errors are fatal to a script).
pub fn is_special(b: Builtin) -> bool {
    matches!(
        b,
        Builtin::Colon
            | Builtin::Dot
            | Builtin::Eval
            | Builtin::Exec
            | Builtin::Exit
            | Builtin::Export
            | Builtin::Readonly
            | Builtin::Set
            | Builtin::Shift
            | Builtin::Unset
            | Builtin::Times
            | Builtin::Trap
            | Builtin::Break
            | Builtin::Continue
            | Builtin::Return
    )
}

/// Run one of the *pure* builtins (those the executor does not intercept). The
/// executor handles `:`/`true`/`false` inline and the execution-coupled builtins
/// itself, so those are unreachable here.
pub fn dispatch(b: Builtin, args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    match b {
        Builtin::Echo => echo(args, io),
        Builtin::Printf => printf(args, io),
        Builtin::Pwd => pwd(args, io, shell),
        Builtin::Cd => cd(args, io, shell),
        Builtin::Set => set(args, io, shell),
        Builtin::Shift => shift(args, io, shell),
        Builtin::Unset => unset(args, io, shell),
        Builtin::Export => export(args, io, shell),
        Builtin::Readonly => readonly(args, io, shell),
        Builtin::Getopts => getopts(args, io, shell),
        Builtin::Type => type_cmd(args, io, shell),
        Builtin::Umask => umask(args, io, shell),
        Builtin::Wait => wait(args, io, shell),
        Builtin::Jobs => jobs_cmd(args, io, shell),
        Builtin::Fg => fg(args, io, shell),
        Builtin::Bg => bg(args, io, shell),
        Builtin::Kill => kill(args, io, shell),
        Builtin::Times => times(io),
        Builtin::Trap => trap(args, io, shell),
        Builtin::Hash => hash(args, io),
        Builtin::Alias => alias(args, io, shell),
        Builtin::Unalias => unalias(args, io, shell),
        Builtin::Test => test_main(args),
        // Handled by the executor; see module docs.
        Builtin::Colon | Builtin::True => 0,
        Builtin::False => 1,
        Builtin::Dot
        | Builtin::Eval
        | Builtin::Exec
        | Builtin::Exit
        | Builtin::Read
        | Builtin::Command
        | Builtin::Break
        | Builtin::Continue
        | Builtin::Return => {
            io.errln(&format!(
                "rush: internal: builtin {b:?} not dispatched here"
            ));
            2
        }
    }
}

// ---- quoting helper ---------------------------------------------------------

/// Single-quote `s` so it re-reads as one shell word, rendering embedded quotes
/// as `'\''`. Used by `export -p`, `readonly -p`, `set`, and `alias` listings —
/// dash always quotes these values, so we do too.
pub fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// ---- echo -------------------------------------------------------------------

/// `echo [-n] [args…]` — matches dash's XSI echo: backslash escapes are always
/// interpreted, and a leading `-n` suppresses the trailing newline. `\c` stops
/// output (and suppresses the newline).
fn echo(args: &[String], io: &mut Io) -> i32 {
    let mut newline = true;
    let mut start = 0;
    if args.first().map(String::as_str) == Some("-n") {
        newline = false;
        start = 1;
    }
    let mut out = String::new();
    let mut stop = false;
    for (i, arg) in args[start..].iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if escape_into(&mut out, arg) {
            stop = true;
            break;
        }
    }
    if stop {
        newline = false;
    }
    if newline {
        out.push('\n');
    }
    io.out(&out);
    0
}

/// Interpret backslash escapes from `s` into `out`; returns `true` if a `\c`
/// (stop output) was hit.
fn escape_into(out: &mut String, s: &str) -> bool {
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != '\\' || i + 1 >= bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1; // consume backslash
        match bytes[i] {
            'a' => out.push('\u{07}'),
            'b' => out.push('\u{08}'),
            'c' => return true,
            'f' => out.push('\u{0C}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'v' => out.push('\u{0B}'),
            '\\' => out.push('\\'),
            '0' => {
                // \0nnn: up to three octal digits.
                let mut val = 0u32;
                let mut k = 0;
                while k < 3 && i + 1 < bytes.len() && ('0'..='7').contains(&bytes[i + 1]) {
                    val = val * 8 + (bytes[i + 1] as u32 - '0' as u32);
                    i += 1;
                    k += 1;
                }
                if let Some(c) = char::from_u32(val) {
                    out.push(c);
                }
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
        i += 1;
    }
    false
}

// ---- printf -----------------------------------------------------------------

/// `printf format [args…]` — a solid subset: escape sequences in the format,
/// conversions `%d %i %o %u %x %X %c %s %b %%` with optional flags, width, and
/// precision, and format-string recycling until the arguments are consumed.
fn printf(args: &[String], io: &mut Io) -> i32 {
    if args.is_empty() {
        io.errln("rush: printf: usage: printf format [arguments]");
        return 2;
    }
    let format = &args[0];
    let operands = &args[1..];
    let mut out = String::new();
    let mut status = 0;
    let mut arg_idx = 0;

    loop {
        let used = format_once(format, operands, &mut arg_idx, &mut out, &mut status);
        // Recycle the format while it still consumes arguments; stop once a full
        // pass consumed none (either there were none, or the format has no
        // conversions).
        if !used || arg_idx >= operands.len() {
            break;
        }
    }
    io.out(&out);
    status
}

/// One pass over the format string. Returns whether it consumed any argument.
fn format_once(
    format: &str,
    operands: &[String],
    arg_idx: &mut usize,
    out: &mut String,
    status: &mut i32,
) -> bool {
    let chars: Vec<char> = format.chars().collect();
    let start_idx = *arg_idx;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            i += 1;
            if i < chars.len() {
                i = printf_backslash(&chars, i, out);
            }
            continue;
        }
        if c != '%' {
            out.push(c);
            i += 1;
            continue;
        }
        // A conversion specification: %[flags][width][.prec]conv
        i += 1;
        if i < chars.len() && chars[i] == '%' {
            out.push('%');
            i += 1;
            continue;
        }
        let spec_start = i;
        // flags
        while i < chars.len() && "-+ #0".contains(chars[i]) {
            i += 1;
        }
        // width
        while i < chars.len() && chars[i].is_ascii_digit() {
            i += 1;
        }
        // precision
        if i < chars.len() && chars[i] == '.' {
            i += 1;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
        }
        if i >= chars.len() {
            // Trailing bare '%': emit literally.
            out.push('%');
            out.extend(&chars[spec_start..i]);
            break;
        }
        let conv = chars[i];
        let spec: String = chars[spec_start..i].iter().collect();
        i += 1;
        let next_arg = |idx: &mut usize| -> Option<String> {
            let v = operands.get(*idx).cloned();
            if v.is_some() {
                *idx += 1;
            }
            v
        };
        match conv {
            'd' | 'i' | 'o' | 'u' | 'x' | 'X' => {
                let arg = next_arg(arg_idx).unwrap_or_default();
                let n = parse_printf_int(&arg, status);
                out.push_str(&render_int(&spec, conv, n));
            }
            'c' => {
                let arg = next_arg(arg_idx).unwrap_or_default();
                if let Some(ch) = arg.chars().next() {
                    out.push(ch);
                }
            }
            's' => {
                let arg = next_arg(arg_idx).unwrap_or_default();
                out.push_str(&render_str(&spec, &arg));
            }
            'b' => {
                let arg = next_arg(arg_idx).unwrap_or_default();
                escape_into(out, &arg);
            }
            other => {
                // Unknown conversion: emit verbatim (best effort).
                out.push('%');
                out.push_str(&spec);
                out.push(other);
            }
        }
    }
    *arg_idx > start_idx
}

fn printf_backslash(chars: &[char], mut i: usize, out: &mut String) -> usize {
    match chars[i] {
        'a' => out.push('\u{07}'),
        'b' => out.push('\u{08}'),
        'f' => out.push('\u{0C}'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'v' => out.push('\u{0B}'),
        '\\' => out.push('\\'),
        '"' => out.push('"'),
        '0'..='7' => {
            let mut val = 0u32;
            let mut k = 0;
            while k < 3 && i < chars.len() && ('0'..='7').contains(&chars[i]) {
                val = val * 8 + (chars[i] as u32 - '0' as u32);
                i += 1;
                k += 1;
            }
            if let Some(c) = char::from_u32(val) {
                out.push(c);
            }
            return i;
        }
        other => {
            out.push('\\');
            out.push(other);
        }
    }
    i + 1
}

/// Parse a printf integer operand. A leading `"` or `'` yields the next
/// character's code (POSIX). Bad numbers set status 1 and evaluate to 0.
fn parse_printf_int(arg: &str, status: &mut i32) -> i64 {
    let arg = arg.trim();
    if let Some(rest) = arg.strip_prefix(['"', '\'']) {
        return rest.chars().next().map(|c| c as i64).unwrap_or(0);
    }
    let parsed = if let Some(hex) = arg.strip_prefix("0x").or_else(|| arg.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else if let Some(neg) = arg.strip_prefix("-0x").or_else(|| arg.strip_prefix("-0X")) {
        i64::from_str_radix(neg, 16).map(|v| -v)
    } else if arg.len() > 1 && arg.starts_with('0') && arg[1..].bytes().all(|b| b.is_ascii_digit())
    {
        i64::from_str_radix(&arg[1..], 8)
    } else {
        arg.parse::<i64>()
    };
    match parsed {
        Ok(n) => n,
        Err(_) => {
            if !arg.is_empty() {
                *status = 1;
            }
            0
        }
    }
}

/// A parsed `%`-spec's width/precision/flags, enough for integer and string
/// rendering.
struct Spec {
    left: bool,
    zero: bool,
    plus: bool,
    space: bool,
    width: usize,
    prec: Option<usize>,
}

fn parse_spec(spec: &str) -> Spec {
    let chars: Vec<char> = spec.chars().collect();
    let mut i = 0;
    let (mut left, mut zero, mut plus, mut space) = (false, false, false, false);
    while i < chars.len() {
        match chars[i] {
            '-' => left = true,
            '0' => zero = true,
            '+' => plus = true,
            ' ' => space = true,
            '#' => {}
            _ => break,
        }
        i += 1;
    }
    let mut width = 0usize;
    while i < chars.len() && chars[i].is_ascii_digit() {
        width = width * 10 + (chars[i] as usize - '0' as usize);
        i += 1;
    }
    let mut prec = None;
    if i < chars.len() && chars[i] == '.' {
        i += 1;
        let mut p = 0usize;
        while i < chars.len() && chars[i].is_ascii_digit() {
            p = p * 10 + (chars[i] as usize - '0' as usize);
            i += 1;
        }
        prec = Some(p);
    }
    Spec {
        left,
        zero,
        plus,
        space,
        width,
        prec,
    }
}

fn render_int(spec_str: &str, conv: char, n: i64) -> String {
    let spec = parse_spec(spec_str);
    let (digits, neg) = match conv {
        'd' | 'i' => (n.unsigned_abs().to_string(), n < 0),
        'u' => ((n as u64).to_string(), false),
        'o' => (format!("{:o}", n as u64), false),
        'x' => (format!("{:x}", n as u64), false),
        'X' => (format!("{:X}", n as u64), false),
        _ => (n.to_string(), false),
    };
    let mut body = digits;
    if let Some(p) = spec.prec {
        while body.len() < p {
            body.insert(0, '0');
        }
    }
    let sign = if neg {
        "-"
    } else if spec.plus {
        "+"
    } else if spec.space {
        " "
    } else {
        ""
    };
    let mut s = format!("{sign}{body}");
    pad(&mut s, &spec, sign.len());
    s
}

fn render_str(spec_str: &str, arg: &str) -> String {
    let spec = parse_spec(spec_str);
    let mut body = arg.to_string();
    if let Some(p) = spec.prec
        && body.chars().count() > p
    {
        body = body.chars().take(p).collect();
    }
    let mut s = body;
    pad(&mut s, &spec, 0);
    s
}

/// Pad `s` to the spec's width. `sign_len` marks how many leading chars are a
/// sign, so zero-padding inserts after it.
fn pad(s: &mut String, spec: &Spec, sign_len: usize) {
    let len = s.chars().count();
    if len >= spec.width {
        return;
    }
    let fill = spec.width - len;
    if spec.left {
        s.extend(std::iter::repeat_n(' ', fill));
    } else if spec.zero && spec.prec.is_none() {
        let insert: String = std::iter::repeat_n('0', fill).collect();
        s.insert_str(sign_len, &insert);
    } else {
        let pad: String = std::iter::repeat_n(' ', fill).collect();
        s.insert_str(0, &pad);
    }
}

// ---- pwd --------------------------------------------------------------------

fn pwd(args: &[String], io: &mut Io, shell: &Shell) -> i32 {
    let mut physical = false;
    for a in args {
        match a.as_str() {
            "-P" => physical = true,
            "-L" => physical = false,
            other if other.starts_with('-') && other.len() > 1 => {
                io.errln(&format!("rush: pwd: {other}: invalid option"));
                return 2;
            }
            _ => break,
        }
    }
    let physical_path = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => {
            io.errln(&format!("rush: pwd: {e}"));
            return 1;
        }
    };
    // `pwd -L` prints `$PWD` only when it is absolute and actually names the
    // current directory (POSIX); otherwise it falls back to the physical path.
    // This keeps `pwd` correct even if an exported `$PWD` leaked from a subshell.
    let path = if !physical
        && let Some(p) = shell.get("PWD").filter(|p| p.starts_with('/'))
        && std::fs::canonicalize(&p).ok() == std::fs::canonicalize(&physical_path).ok()
    {
        p
    } else {
        physical_path.to_string_lossy().into_owned()
    };
    io.outln(&path);
    0
}

// ---- cd ---------------------------------------------------------------------

fn cd(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    let mut physical = false;
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "-P" => physical = true,
            "-L" => physical = false,
            "--" => {
                idx += 1;
                break;
            }
            "-" => break, // `cd -` operand
            other if other.starts_with('-') && other.len() > 1 => {
                io.errln(&format!("rush: cd: {other}: invalid option"));
                return 2;
            }
            _ => break,
        }
        idx += 1;
    }
    let operand = args.get(idx);
    if args.len() > idx + 1 {
        io.errln("rush: cd: too many arguments");
        return 1;
    }

    let mut announce = false;
    let target: String = match operand.map(String::as_str) {
        None | Some("") => match shell.get("HOME") {
            Some(h) => h,
            None => {
                io.errln("rush: cd: HOME not set");
                return 1;
            }
        },
        Some("-") => match shell.get("OLDPWD") {
            Some(p) => {
                announce = true;
                p
            }
            None => {
                io.errln("rush: cd: OLDPWD not set");
                return 1;
            }
        },
        Some(dir) => {
            // CDPATH search for a non-slash, non-dot relative operand.
            if !dir.starts_with('/') && !dir.starts_with('.') {
                if let Some(found) = cdpath_search(dir, shell) {
                    announce = true;
                    found
                } else {
                    dir.to_string()
                }
            } else {
                dir.to_string()
            }
        }
    };

    let old = shell.get("PWD").or_else(|| {
        std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    });

    if let Err(e) = std::env::set_current_dir(Path::new(&target)) {
        io.errln(&format!("rush: cd: {target}: {}", err_str(&e)));
        return 1;
    }

    // Recompute PWD. With no symlinks on Motor OS, the physical path is a fine
    // logical path too; `-L` would otherwise preserve the textual path.
    let new_pwd = if physical {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or(target.clone())
    } else {
        logical_pwd(&old, &target)
    };

    if let Some(old) = old {
        let _ = shell.export("OLDPWD", Some(old));
    }
    let _ = shell.export("PWD", Some(new_pwd.clone()));

    if announce {
        io.outln(&new_pwd);
    }
    0
}

/// Search `CDPATH` for a directory `dir`. Returns the resolved path if found in
/// a component other than the (implicit) current directory.
fn cdpath_search(dir: &str, shell: &Shell) -> Option<String> {
    let cdpath = shell.get("CDPATH")?;
    for base in cdpath.split(':') {
        if base.is_empty() || base == "." {
            continue;
        }
        let candidate = Path::new(base).join(dir);
        if candidate.is_dir() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Compute the logical `$PWD` after `cd target`, resolving `.`/`..` textually
/// against the old `$PWD` for a relative target.
fn logical_pwd(old: &Option<String>, target: &str) -> String {
    let base = if target.starts_with('/') {
        String::new()
    } else {
        old.clone().unwrap_or_default()
    };
    let combined = if base.is_empty() {
        target.to_string()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), target)
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in combined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    out
}

// ---- set --------------------------------------------------------------------

fn set(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    if args.is_empty() {
        for (name, value) in shell.vars_sorted() {
            io.outln(&format!("{name}={}", sh_quote(&value)));
        }
        return 0;
    }
    // Parse leading option arguments (`-f`, `+f`, `-eux`, `-o name`, …) against
    // the one option table; `--` or a non-option operand ends them.
    let mut i = 0;
    let mut saw_dashdash = false;
    let mut saw_operand = false;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            saw_dashdash = true;
            i += 1;
            break;
        }
        let (on, letters) = match a.as_str() {
            // A bare `-`/`+` is an operand, not an option cluster.
            s if s.starts_with('-') && s.len() > 1 => (true, &s[1..]),
            s if s.starts_with('+') && s.len() > 1 => (false, &s[1..]),
            _ => {
                saw_operand = true;
                break;
            }
        };
        for ch in letters.chars() {
            if ch == 'o' {
                // `-o [name]` / `+o [name]`: a bare `-o`/`+o` lists the options.
                match args.get(i + 1) {
                    None => {
                        if on {
                            io.outln("Current option settings");
                            for line in &shell.opts.listing() {
                                io.outln(line);
                            }
                        } else {
                            for line in &shell.opts.listing_reinput() {
                                io.outln(line);
                            }
                        }
                    }
                    Some(name) => {
                        i += 1;
                        match Options::by_name(name) {
                            Some(opt) => shell.opts.set(opt, on),
                            None => return illegal_option(&format!("o {name}"), on, io, shell),
                        }
                    }
                }
                continue;
            }
            match Options::by_letter(ch) {
                Some(opt) => shell.opts.set(opt, on),
                None => return illegal_option(&ch.to_string(), on, io, shell),
            }
        }
        i += 1;
    }
    // Positional parameters change only when operands (or a bare `--`) appear:
    // `set -e` must not wipe `$1`, but `set --` clears them.
    if saw_operand || saw_dashdash {
        shell.set_params(args[i..].to_vec());
    }
    0
}

/// An unknown `set` option: a *special* builtin usage error, so it is fatal to a
/// non-interactive shell.
fn illegal_option(what: &str, on: bool, io: &mut Io, shell: &mut Shell) -> i32 {
    let sign = if on { '-' } else { '+' };
    io.errln(&format!("rush: set: illegal option {sign}{what}"));
    shell.mark_fatal(2);
    2
}

// ---- shift ------------------------------------------------------------------

fn shift(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    let n = match args.first() {
        None => 1,
        Some(a) => match a.parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                io.errln(&format!("rush: shift: {a}: numeric argument required"));
                shell.mark_fatal(2);
                return 2;
            }
        },
    };
    let params = shell.params();
    if n > params.len() {
        io.errln("rush: shift: can't shift that many");
        shell.mark_fatal(2);
        return 2;
    }
    let rest = params[n..].to_vec();
    shell.set_params(rest);
    0
}

// ---- unset ------------------------------------------------------------------

fn unset(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    let mut want_func = false;
    let mut want_var = false;
    let mut names_start = 0;
    for (i, a) in args.iter().enumerate() {
        match a.as_str() {
            "-f" => want_func = true,
            "-v" => want_var = true,
            "--" => {
                names_start = i + 1;
                break;
            }
            s if s.starts_with('-') && s.len() > 1 => {
                io.errln(&format!("rush: unset: {s}: invalid option"));
                return 2;
            }
            _ => {
                names_start = i;
                break;
            }
        }
        names_start = i + 1;
    }
    let mut status = 0;
    for name in &args[names_start..] {
        if want_func {
            shell.unset_function(name);
            if !want_var {
                continue;
            }
        }
        // Variable unset: an invalid name or a readonly is a fatal error.
        if !crate::is_valid_var_name(name) {
            io.errln(&format!("rush: unset: {name}: bad variable name"));
            shell.mark_fatal(2);
            status = 2;
        } else if let Err(e) = shell.unset(name) {
            io.errln(&format!("rush: unset: {e}"));
            shell.mark_fatal(2);
            status = 2;
        }
    }
    status
}

// ---- export / readonly ------------------------------------------------------

fn export(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    declare(args, io, shell, false)
}

fn readonly(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    declare(args, io, shell, true)
}

/// Shared body of `export` and `readonly`: `[-p] [name[=value]]…`. With no
/// operands (or `-p`), list the exported / readonly set in re-readable form.
fn declare(args: &[String], io: &mut Io, shell: &mut Shell, readonly: bool) -> i32 {
    let keyword = if readonly { "readonly" } else { "export" };
    let operands: Vec<&String> = args.iter().filter(|a| a.as_str() != "-p").collect();
    if operands.is_empty() {
        if readonly {
            for name in shell.readonly_names() {
                match shell.get(&name) {
                    Some(v) => io.outln(&format!("readonly {name}={}", sh_quote(&v))),
                    None => io.outln(&format!("readonly {name}")),
                }
            }
        } else {
            for (name, value) in shell.vars_sorted() {
                if shell.is_exported(&name) {
                    io.outln(&format!("export {name}={}", sh_quote(&value)));
                }
            }
        }
        return 0;
    }

    let mut status = 0;
    for arg in operands {
        let (name, value) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        if !crate::is_valid_var_name(name) {
            io.errln(&format!("rush: {keyword}: {name}: bad variable name"));
            shell.mark_fatal(2);
            status = 2;
            continue;
        }
        if readonly {
            if let Some(v) = value
                && let Err(e) = shell.set(name, v)
            {
                io.errln(&format!("rush: {keyword}: {e}"));
                status = 1;
                continue;
            }
            shell.set_readonly(name);
        } else if let Err(e) = shell.export(name, value) {
            io.errln(&format!("rush: {keyword}: {e}"));
            status = 1;
        }
    }
    status
}

// ---- getopts ----------------------------------------------------------------

fn getopts(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    if args.len() < 2 {
        io.errln("rush: getopts: usage: getopts optstring name [arg…]");
        return 2;
    }
    let optstring = &args[0];
    let var = &args[1];
    let silent = optstring.starts_with(':');
    // Positional args to scan: explicit operands, else the shell's params.
    let scan: Vec<String> = if args.len() > 2 {
        args[2..].to_vec()
    } else {
        shell.params().to_vec()
    };

    let mut optind: usize = shell
        .get("OPTIND")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    if optind == 0 {
        optind = 1;
    }
    let mut charpos = shell.getopts_char();

    // The current argument index (0-based within `scan`) is optind-1.
    loop {
        let cur = optind.saturating_sub(1);
        let arg = match scan.get(cur) {
            Some(a) => a,
            None => return end_getopts(shell, var, optind, 0),
        };
        if charpos == 0 {
            // Positioned at the start of `arg`: must begin an option.
            if arg == "-" || !arg.starts_with('-') {
                return end_getopts(shell, var, optind, 0);
            }
            if arg == "--" {
                return end_getopts(shell, var, optind + 1, 0);
            }
            charpos = 1;
        }
        let arg_chars: Vec<char> = arg.chars().collect();
        if charpos >= arg_chars.len() {
            // Exhausted this argument; advance.
            optind += 1;
            charpos = 0;
            continue;
        }
        let opt = arg_chars[charpos];
        charpos += 1;
        // Look the option up in optstring (skipping a leading ':').
        let ostr: Vec<char> = optstring.chars().collect();
        let pos = ostr
            .iter()
            .enumerate()
            .position(|(i, &c)| c == opt && !(i == 0 && silent));
        match pos {
            None => {
                // Unknown option: still a processed option, so return success.
                let _ = shell.set(var, "?".to_string());
                if silent {
                    let _ = shell.set("OPTARG", opt.to_string());
                } else {
                    let _ = shell.unset("OPTARG");
                    io.errln(&format!("rush: getopts: illegal option -- {opt}"));
                }
                return persist_getopts(shell, optind, charpos, arg_chars.len());
            }
            Some(p) => {
                let takes_arg = ostr.get(p + 1) == Some(&':');
                if !takes_arg {
                    let _ = shell.set(var, opt.to_string());
                    let _ = shell.unset("OPTARG");
                    return persist_getopts(shell, optind, charpos, arg_chars.len());
                }
                // Option argument: rest of this arg, else the next argument.
                if charpos < arg_chars.len() {
                    let val: String = arg_chars[charpos..].iter().collect();
                    let _ = shell.set("OPTARG", val);
                    let _ = shell.set(var, opt.to_string());
                    return advance_getopts(shell, optind + 1);
                }
                if let Some(next) = scan.get(optind) {
                    let _ = shell.set("OPTARG", next.clone());
                    let _ = shell.set(var, opt.to_string());
                    return advance_getopts(shell, optind + 2);
                }
                // Missing argument (still returns success with `var` flagged).
                if silent {
                    let _ = shell.set(var, ":".to_string());
                    let _ = shell.set("OPTARG", opt.to_string());
                } else {
                    let _ = shell.set(var, "?".to_string());
                    let _ = shell.unset("OPTARG");
                    io.errln(&format!(
                        "rush: getopts: option requires an argument -- {opt}"
                    ));
                }
                return advance_getopts(shell, optind + 1);
            }
        }
    }
}

/// An option was processed: persist OPTIND / the intra-argument cursor. If the
/// current argument is exhausted, advance to the next. Returns 0 (success).
fn persist_getopts(
    shell: &mut Shell,
    mut optind: usize,
    mut charpos: usize,
    arg_len: usize,
) -> i32 {
    if charpos >= arg_len {
        optind += 1;
        charpos = 0;
    }
    let _ = shell.set("OPTIND", optind.to_string());
    shell.set_getopts_char(charpos);
    0
}

/// An option consuming a full argument (or its own argument) was processed:
/// jump OPTIND to `optind` and reset the cursor. Returns 0 (success).
fn advance_getopts(shell: &mut Shell, optind: usize) -> i32 {
    let _ = shell.set("OPTIND", optind.to_string());
    shell.set_getopts_char(0);
    0
}

/// The option scan is exhausted: set `var` to `?`, persist OPTIND, reset the
/// cursor, and return 1.
fn end_getopts(shell: &mut Shell, var: &str, optind: usize, charpos: usize) -> i32 {
    let _ = shell.set(var, "?".to_string());
    let _ = shell.set("OPTIND", optind.to_string());
    shell.set_getopts_char(charpos);
    1
}

// ---- type -------------------------------------------------------------------

fn type_cmd(args: &[String], io: &mut Io, shell: &Shell) -> i32 {
    let mut status = 0;
    for name in args.iter().filter(|a| a.as_str() != "--") {
        let line = describe(name, shell, false);
        if find_kind(name, shell).is_some() {
            io.outln(&line);
        } else {
            // dash reports the miss on stderr and returns 127 if any name is
            // unknown.
            io.errln(&line);
            status = 127;
        }
    }
    status
}

enum Kind {
    Keyword,
    Alias(String),
    Function,
    Builtin,
    File(String),
}

fn find_kind(name: &str, shell: &Shell) -> Option<Kind> {
    if crate::parser::is_reserved_word(name) {
        return Some(Kind::Keyword);
    }
    if let Some(v) = shell.get_alias(name) {
        return Some(Kind::Alias(v.to_string()));
    }
    if shell.get_function(name).is_some() {
        return Some(Kind::Function);
    }
    if lookup(name).is_some() {
        return Some(Kind::Builtin);
    }
    search_path(name, shell).map(Kind::File)
}

/// Build the `type name` / `command -V name` description line.
fn describe(name: &str, shell: &Shell, brief: bool) -> String {
    match find_kind(name, shell) {
        Some(Kind::Keyword) => format!("{name} is a shell keyword"),
        Some(Kind::Alias(v)) => format!("{name} is aliased to `{v}'"),
        Some(Kind::Function) => format!("{name} is a shell function"),
        Some(Kind::Builtin) => format!("{name} is a shell builtin"),
        Some(Kind::File(p)) => {
            if brief {
                p
            } else {
                format!("{name} is {p}")
            }
        }
        None => format!("{name}: not found"),
    }
}

/// Locate `name` on `PATH` (an executable regular file). A name containing `/`
/// resolves to itself if it exists.
pub fn search_path(name: &str, shell: &Shell) -> Option<String> {
    if name.contains('/') {
        return if Path::new(name).is_file() {
            Some(name.to_string())
        } else {
            None
        };
    }
    let path = shell.get("PATH")?;
    for dir in path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// `command -v`/`-V` describer, shared with the executor's `command` handling.
/// Returns (line, found).
pub fn command_describe(name: &str, shell: &Shell, verbose: bool) -> (Option<String>, bool) {
    match find_kind(name, shell) {
        None => (None, false),
        Some(kind) => {
            if verbose {
                (Some(describe(name, shell, false)), true)
            } else {
                let line = match kind {
                    Kind::File(p) => p,
                    Kind::Alias(v) => format!("alias {name}={}", sh_quote(&v)),
                    _ => name.to_string(),
                };
                (Some(line), true)
            }
        }
    }
}

// ---- umask ------------------------------------------------------------------

fn umask(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    let operands: Vec<&String> = args.iter().filter(|a| a.as_str() != "-S").collect();
    match operands.first() {
        None => {
            io.outln(&format!("{:04o}", shell.umask()));
            0
        }
        Some(mode) => match u32::from_str_radix(mode, 8) {
            Ok(m) if m <= 0o777 => {
                shell.set_umask(m);
                0
            }
            _ => {
                io.errln(&format!("rush: umask: {mode}: invalid mode"));
                1
            }
        },
    }
}

// ---- times ------------------------------------------------------------------

fn times(io: &mut Io) -> i32 {
    // Motor OS `std` exposes no resource-usage clock; report zeros (documented).
    io.outln("0m0.000s 0m0.000s");
    io.outln("0m0.000s 0m0.000s");
    0
}

// ---- trap -------------------------------------------------------------------

/// `trap [action] condition…` — POSIX §2.14.
///
/// With no operands, list the traps in a form the shell can re-read.
/// `trap - COND…` restores the default action, `trap '' COND…` ignores the
/// signal, and any other first operand is the action to run.
///
/// Setting a trap also establishes the platform disposition, which is what makes
/// the signal arrive at all — or, on Motor OS, what quietly cannot: a trap there
/// is stored and never fires unless rush itself synthesizes the signal (`^C`).
/// A trap on a signal no one may catch (`KILL`) is likewise accepted and inert,
/// as it is in dash. See [`crate::signal`].
fn trap(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    if args.is_empty() {
        for (cond, action) in shell.traps_sorted() {
            io.outln(&format!("trap -- {} {cond}", sh_quote(&action)));
        }
        return 0;
    }
    // Only a literal `-` resets; every other first operand is the action — so
    // `trap 2` runs the action `2` on no conditions, as in dash, rather than
    // resetting INT.
    let (action, conds) = if args[0] == "-" {
        (None, &args[1..])
    } else {
        (Some(args[0].as_str()), &args[1..])
    };
    if conds.is_empty() {
        io.errln("rush: trap: usage: trap [action] condition…");
        return 2;
    }
    let mut status = 0;
    for cond in conds {
        let Some(parsed) = signal::parse_condition(cond) else {
            io.errln(&format!("rush: trap: {cond}: bad trap"));
            status = 1;
            continue;
        };
        signal::apply_disposition(parsed, action);
        let name = signal::condition_name(parsed);
        match action {
            None => shell.clear_trap(&name),
            Some(a) => shell.set_trap(&name, a.to_string()),
        }
    }
    status
}

// ---- job control ------------------------------------------------------------

/// Wait for one job, running traps if a signal interrupts the wait.
///
/// Returns the job's exit status, or `128 + signo` if a trapped signal cut the
/// wait short — POSIX requires `wait` to return above 128 then, and dash reports
/// 138 for a `USR1` trap (verified).
fn wait_one(shell: &mut Shell, idx: usize) -> i32 {
    loop {
        match shell.jobs.wait_step(idx) {
            JobWait::Done(status) => return status,
            JobWait::Gone => return 127,
            JobWait::Interrupted => {
                if let Some(signo) = signal::run_pending_traps(shell) {
                    return 128 + signo;
                }
                // Nothing to run after all: resume waiting.
            }
        }
    }
}

/// `wait [pid|%job …]` — wait for background jobs.
///
/// With no operands, wait for all of them and report 0. With operands, report
/// the status of the last one waited for. A finished job's status stays
/// available to repeated `wait`s until `jobs` reports it (dash behaves the same;
/// see [`jobs_cmd`]).
fn wait(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    shell.jobs.poll();
    if args.is_empty() {
        while let Some(&idx) = shell.jobs.running_indices().first() {
            let status = wait_one(shell, idx);
            if status > 128 {
                return status; // a trap interrupted the wait
            }
        }
        return 0;
    }
    let mut status = 0;
    for spec in args {
        match shell.jobs.find(spec) {
            Some(idx) => status = wait_one(shell, idx),
            None => {
                if !spec.starts_with('%') && spec.parse::<u64>().is_err() {
                    io.errln(&format!("rush: wait: Illegal number: {spec}"));
                    return 2;
                }
                // A pid or job rush never started, or one already forgotten:
                // POSIX (and dash) report 127.
                status = 127;
            }
        }
    }
    status
}

/// `jobs [-l|-p]` — list background jobs, newest first (as dash does).
///
/// Reports each finished job once and then forgets it, which is what makes a
/// later `wait` on it report 127 — dash's rule, and the reason `wait` itself
/// does not discard anything.
fn jobs_cmd(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    let mut long = false;
    let mut pids_only = false;
    for arg in args {
        match arg.as_str() {
            "-l" => long = true,
            "-p" => pids_only = true,
            _ => {
                io.errln(&format!("rush: jobs: {arg}: invalid option"));
                return 2;
            }
        }
    }
    shell.jobs.poll();
    let count = shell.jobs.iter().count();
    let mut lines = Vec::new();
    for (i, job) in shell.jobs.iter().enumerate() {
        if pids_only {
            lines.push(job.pid.to_string());
            continue;
        }
        // `+` marks the most recent job, `-` the one before it.
        let marker = match count - i {
            1 => '+',
            2 => '-',
            _ => ' ',
        };
        let state = match job.state {
            JobState::Running => "Running".to_string(),
            JobState::Done(0) => "Done".to_string(),
            JobState::Done(status) => format!("Done({status})"),
        };
        let pid = if long {
            format!("{} ", job.pid)
        } else {
            String::new()
        };
        lines.push(format!("[{}] {marker} {pid}{state:<27}{}", job.id, job.cmd));
    }
    for line in lines.iter().rev() {
        io.outln(line.trim_end());
    }
    shell.jobs.retain_unfinished();
    0
}

/// `fg [job]` — run a job in the foreground.
///
/// Motor OS has no terminal process groups to hand a job (§0.1) and rush can
/// never suspend one, so "foreground" can only mean "wait for it and report its
/// status" — which is the half that still has meaning. dash instead refuses `fg`
/// unless job control is on; rush's version is a documented divergence, and a
/// useful one.
fn fg(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    shell.jobs.poll();
    let spec = args.first().map(String::as_str).unwrap_or("%%");
    let Some(idx) = shell.jobs.find(spec) else {
        io.errln(&format!("rush: fg: {spec}: no such job"));
        return 1;
    };
    // Echo the command, as a job control shell does when it resumes one.
    if let Some(cmd) = shell.jobs.get(idx).map(|job| job.cmd.clone()) {
        io.outln(&cmd);
    }
    wait_one(shell, idx)
}

/// `bg [job]` — resume a stopped job in the background.
///
/// Nothing can ever be stopped: with no termios there is no `^Z`, and neither
/// platform can deliver SIGTSTP (§0.1), so no job is ever in the one state `bg`
/// exists to leave. It therefore always fails — as dash's does without job
/// control — rather than pretending.
fn bg(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    let _ = (args, shell);
    io.errln("rush: bg: no job control: a job can never be stopped");
    2
}

/// `kill [-s sigspec | -sigspec] pid|%job …` and `kill -l`.
///
/// A `%job` — and, on Motor OS, any `$!` — is resolved through rush's own job
/// table (see [`crate::jobs`]); a bare pid the shell did not start goes to the
/// platform, which on Motor OS can only ever terminate it.
fn kill(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    const SIGTERM: i32 = 15;

    if args.is_empty() {
        io.errln("rush: kill: usage: kill [-s sigspec | -sigspec] pid | %job …");
        return 2;
    }
    if args[0] == "-l" {
        for signo in 1..(sys::NSIG as i32) {
            if let Some(name) = signal::signo_to_name(signo) {
                io.outln(name);
            }
        }
        return 0;
    }

    let mut signo = SIGTERM;
    let mut targets: &[String] = args;
    if args[0] == "-s" {
        let Some(spec) = args.get(1) else {
            io.errln("rush: kill: -s requires a signal name");
            return 2;
        };
        match signal_number(spec) {
            Some(n) => signo = n,
            None => {
                io.errln(&format!("rush: kill: {spec}: invalid signal specification"));
                return 2;
            }
        }
        targets = &args[2..];
    } else if let Some(spec) = args[0].strip_prefix('-') {
        match signal_number(spec) {
            Some(n) => signo = n,
            None => {
                io.errln(&format!("rush: kill: {spec}: invalid signal specification"));
                return 2;
            }
        }
        targets = &args[1..];
    }
    if targets.is_empty() {
        io.errln("rush: kill: usage: kill [-s sigspec | -sigspec] pid | %job …");
        return 2;
    }

    let mut status = 0;
    for target in targets {
        let result = match shell.jobs.find(target) {
            Some(idx) => shell.jobs.signal(idx, signo),
            None => match target.parse::<u64>() {
                Ok(pid) => Some(sys::kill(pid, signo)),
                Err(_) => {
                    io.errln(&format!("rush: kill: {target}: no such job"));
                    status = 1;
                    continue;
                }
            },
        };
        match result {
            None | Some(Ok(())) => {}
            Some(Err(err)) => {
                io.errln(&format!("rush: kill: {target}: {}", kill_error(err)));
                status = 1;
            }
        }
    }
    status
}

/// A signal number from a `kill` sigspec: a name (`TERM`, `SIGTERM`) or a number.
/// Unlike a trap condition, `0` is the "check only" signal rather than `EXIT`.
fn signal_number(spec: &str) -> Option<i32> {
    if spec == "0" {
        return Some(0);
    }
    match signal::parse_condition(spec) {
        Some(signal::Condition::Signal(signo)) => Some(signo),
        // `EXIT` is not a signal one can send.
        Some(signal::Condition::Exit) | None => None,
    }
}

fn kill_error(err: sys::KillError) -> &'static str {
    match err {
        sys::KillError::NoSuchProcess => "no such process",
        sys::KillError::PermissionDenied => "operation not permitted",
        // Reached on Motor OS for every signal but KILL/TERM: there is no signal
        // delivery to degrade to, so say so rather than killing something.
        sys::KillError::Unsupported => "signal not supported on this platform",
    }
}

// ---- hash -------------------------------------------------------------------

fn hash(args: &[String], _io: &mut Io) -> i32 {
    // rush does not cache command locations, so `hash` and `hash -r` are no-ops
    // and `hash name…` simply succeeds (documented stub).
    let _ = args;
    0
}

// ---- alias / unalias --------------------------------------------------------

fn alias(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    if args.is_empty() {
        // dash lists as `name='value'` (no `alias ` prefix).
        for (name, value) in shell.aliases_sorted() {
            io.outln(&format!("{name}={}", sh_quote(&value)));
        }
        return 0;
    }
    let mut status = 0;
    for arg in args {
        match arg.split_once('=') {
            Some((name, value)) => shell.set_alias(name, value.to_string()),
            None => match shell.get_alias(arg) {
                Some(v) => io.outln(&format!("{arg}={}", sh_quote(v))),
                None => {
                    io.errln(&format!("rush: alias: {arg}: not found"));
                    status = 1;
                }
            },
        }
    }
    status
}

fn unalias(args: &[String], io: &mut Io, shell: &mut Shell) -> i32 {
    if args.first().map(String::as_str) == Some("-a") {
        for (name, _) in shell.aliases_sorted() {
            shell.unset_alias(&name);
        }
        return 0;
    }
    let mut status = 0;
    for name in args {
        if !shell.unset_alias(name) {
            io.errln(&format!("rush: unalias: {name}: not found"));
            status = 1;
        }
    }
    status
}

// ---- read (input-coupled; called by the executor with a reader) -------------

/// `read [-r] var…` — read one logical line from `input`, split it on `IFS`, and
/// assign the fields to the variables (the last variable absorbs the remainder).
/// Without `-r`, backslash escapes the next character and a backslash-newline
/// continues the line. Returns 1 at end of input with nothing read.
pub fn read(args: &[String], input: &mut dyn Read, io: &mut Io, shell: &mut Shell) -> i32 {
    let mut raw = false;
    let mut vars: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "-r" => raw = true,
            "--" => {}
            s if s.starts_with('-') && s.len() > 1 => {
                io.errln(&format!("rush: read: {s}: invalid option"));
                return 2;
            }
            s => vars.push(s.to_string()),
        }
    }
    if vars.is_empty() {
        io.errln("rush: read: arg count");
        return 2;
    }

    let (line, got) = match read_logical_line(input, raw) {
        Some(pair) => pair,
        None => {
            // EOF with no data: clear the variables and fail.
            for v in &vars {
                let _ = shell.set(v, String::new());
            }
            return 1;
        }
    };

    let ifs = shell.ifs();
    let fields = split_read_fields(&line, &ifs, vars.len());
    for (v, f) in vars.iter().zip(fields.iter()) {
        let _ = shell.set(v, f.clone());
    }
    if got { 0 } else { 1 }
}

/// One character of a `read` line together with whether it was backslash-escaped
/// (and so must be treated literally, never as an `IFS` delimiter).
type ReadChar = (char, bool);

/// Read one logical line as `(char, escaped)` pairs, handling backslash
/// continuation and escaping unless `raw`. Returns the characters and whether a
/// newline actually terminated the line (`false` = trailing data at EOF, still a
/// successful read).
fn read_logical_line(input: &mut dyn Read, raw: bool) -> Option<(Vec<ReadChar>, bool)> {
    let mut line: Vec<ReadChar> = Vec::new();
    let mut byte = [0u8; 1];
    let mut any = false;
    loop {
        match input.read(&mut byte) {
            Ok(0) => return if any { Some((line, true)) } else { None },
            Ok(_) => {}
            Err(_) => return if any { Some((line, true)) } else { None },
        }
        any = true;
        let c = byte[0] as char;
        if c == '\n' {
            return Some((line, true));
        }
        if !raw && c == '\\' {
            // Escape the next byte; a backslash-newline continues the line.
            let mut nb = [0u8; 1];
            match input.read(&mut nb) {
                Ok(0) => {
                    line.push(('\\', true));
                    return Some((line, true));
                }
                Ok(_) => {
                    let nc = nb[0] as char;
                    if nc != '\n' {
                        line.push((nc, true));
                    }
                }
                Err(_) => {
                    line.push(('\\', true));
                    return Some((line, true));
                }
            }
            continue;
        }
        line.push((c, false));
    }
}

/// Split a `read` input line into at most `nvars` fields on `IFS`, with the last
/// field absorbing the unsplit remainder (trailing IFS whitespace trimmed). An
/// escaped character is always literal, never a delimiter.
fn split_read_fields(line: &[ReadChar], ifs: &str, nvars: usize) -> Vec<String> {
    let ws: Vec<char> = ifs.chars().filter(|c| " \t\n".contains(*c)).collect();
    let other: Vec<char> = ifs.chars().filter(|c| !" \t\n".contains(*c)).collect();
    let is_ws = |ch: ReadChar| !ch.1 && ws.contains(&ch.0);
    let is_other = |ch: ReadChar| !ch.1 && other.contains(&ch.0);
    let is_ifs = |ch: ReadChar| is_ws(ch) || is_other(ch);
    let text = |slice: &[ReadChar]| -> String { slice.iter().map(|(c, _)| *c).collect() };

    let n = line.len();
    let mut fields: Vec<String> = Vec::new();

    if ifs.is_empty() {
        // No splitting: the whole line is the first field.
        fields.push(text(line));
        while fields.len() < nvars {
            fields.push(String::new());
        }
        return fields;
    }

    let mut i = 0;
    // Leading IFS whitespace is stripped.
    while i < n && is_ws(line[i]) {
        i += 1;
    }
    while fields.len() < nvars {
        if fields.len() == nvars - 1 {
            // Last variable: the remainder, minus trailing IFS whitespace.
            let mut end = n;
            while end > i && is_ws(line[end - 1]) {
                end -= 1;
            }
            fields.push(text(&line[i..end]));
            return fields;
        }
        if i >= n {
            fields.push(String::new());
            continue;
        }
        let start = i;
        while i < n && !is_ifs(line[i]) {
            i += 1;
        }
        fields.push(text(&line[start..i]));
        // Consume one delimiter: surrounding IFS whitespace and at most one
        // IFS non-whitespace character.
        while i < n && is_ws(line[i]) {
            i += 1;
        }
        if i < n && is_other(line[i]) {
            i += 1;
            while i < n && is_ws(line[i]) {
                i += 1;
            }
        }
    }
    fields
}

// ---- test / [ ---------------------------------------------------------------

/// `test expr` / `[ expr ]` — evaluate a POSIX conditional expression. Returns
/// 0 (true), 1 (false), or 2 (usage error).
fn test_main(args: &[String]) -> i32 {
    let mut argv: Vec<&str> = args.iter().map(String::as_str).collect();
    // `[` requires a trailing `]`.
    // (The executor passes argv without argv[0]; the bracket form's `]` is the
    // final argument.)
    if argv.last() == Some(&"]") {
        argv.pop();
    }
    match eval_test(&argv) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(msg) => {
            eprintln!("rush: test: {msg}");
            2
        }
    }
}

/// Evaluate the test argument vector using POSIX's arg-count special cases for
/// 0–4 arguments, then a general recursive-descent grammar for more.
fn eval_test(argv: &[&str]) -> Result<bool, String> {
    match argv.len() {
        0 => Ok(false),
        1 => Ok(!argv[0].is_empty()),
        2 => {
            if argv[0] == "!" {
                return Ok(argv[1].is_empty());
            }
            if is_unary_op(argv[0]) {
                return unary(argv[0], argv[1]);
            }
            Err(format!("unexpected operator: {}", argv[0]))
        }
        3 => {
            if is_binary_op(argv[1]) {
                return binary(argv[0], argv[1], argv[2]);
            }
            if argv[0] == "!" {
                return eval_test(&argv[1..]).map(|b| !b);
            }
            if argv[0] == "(" && argv[2] == ")" {
                return eval_test(&argv[1..2]);
            }
            Err(format!("unexpected operator: {}", argv[1]))
        }
        4 => {
            if argv[0] == "!" {
                return eval_test(&argv[1..]).map(|b| !b);
            }
            if argv[0] == "(" && argv[3] == ")" {
                return eval_test(&argv[1..3]);
            }
            general_test(argv)
        }
        _ => general_test(argv),
    }
}

/// The general test grammar for >4 arguments: `-o` (or) over `-a` (and) over
/// negation over primaries and `( … )`.
fn general_test(argv: &[&str]) -> Result<bool, String> {
    let mut p = TestParser { argv, pos: 0 };
    let v = p.or_expr()?;
    if p.pos != argv.len() {
        return Err(format!("unexpected argument: {}", argv[p.pos]));
    }
    Ok(v)
}

struct TestParser<'a> {
    argv: &'a [&'a str],
    pos: usize,
}

impl<'a> TestParser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.argv.get(self.pos).copied()
    }
    fn next(&mut self) -> Option<&'a str> {
        let v = self.argv.get(self.pos).copied();
        if v.is_some() {
            self.pos += 1;
        }
        v
    }

    fn or_expr(&mut self) -> Result<bool, String> {
        let mut v = self.and_expr()?;
        while self.peek() == Some("-o") {
            self.pos += 1;
            let rhs = self.and_expr()?;
            v = v || rhs;
        }
        Ok(v)
    }

    fn and_expr(&mut self) -> Result<bool, String> {
        let mut v = self.neg_expr()?;
        while self.peek() == Some("-a") {
            self.pos += 1;
            let rhs = self.neg_expr()?;
            v = v && rhs;
        }
        Ok(v)
    }

    fn neg_expr(&mut self) -> Result<bool, String> {
        if self.peek() == Some("!") {
            self.pos += 1;
            return self.neg_expr().map(|b| !b);
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<bool, String> {
        if self.peek() == Some("(") {
            self.pos += 1;
            let v = self.or_expr()?;
            if self.next() != Some(")") {
                return Err("missing )".to_string());
            }
            return Ok(v);
        }
        // Binary: operand OP operand.
        if let (Some(a), Some(op)) = (self.peek(), self.argv.get(self.pos + 1).copied())
            && is_binary_op(op)
        {
            let c = self.argv.get(self.pos + 2).copied();
            match c {
                Some(c) => {
                    self.pos += 3;
                    return binary(a, op, c);
                }
                None => return Err("missing operand".to_string()),
            }
        }
        // Unary: OP operand.
        if let Some(op) = self.peek()
            && is_unary_op(op)
        {
            match self.argv.get(self.pos + 1).copied() {
                Some(operand) => {
                    self.pos += 2;
                    return unary(op, operand);
                }
                None => return Err("missing operand".to_string()),
            }
        }
        // Bare string: true iff non-empty.
        match self.next() {
            Some(s) => Ok(!s.is_empty()),
            None => Err("missing operand".to_string()),
        }
    }
}

fn is_unary_op(op: &str) -> bool {
    matches!(
        op,
        "-z" | "-n"
            | "-e"
            | "-f"
            | "-d"
            | "-r"
            | "-w"
            | "-x"
            | "-s"
            | "-h"
            | "-L"
            | "-p"
            | "-S"
            | "-b"
            | "-c"
            | "-t"
            | "-g"
            | "-u"
            | "-k"
            | "-O"
            | "-G"
    )
}

fn is_binary_op(op: &str) -> bool {
    matches!(
        op,
        "=" | "=="
            | "!="
            | "<"
            | ">"
            | "-eq"
            | "-ne"
            | "-lt"
            | "-le"
            | "-gt"
            | "-ge"
            | "-ef"
            | "-nt"
            | "-ot"
    )
}

fn unary(op: &str, s: &str) -> Result<bool, String> {
    Ok(match op {
        "-z" => s.is_empty(),
        "-n" => !s.is_empty(),
        "-t" => false, // no reliable fd→tty query on the portable path
        _ => file_test(op, s),
    })
}

fn binary(a: &str, op: &str, b: &str) -> Result<bool, String> {
    Ok(match op {
        "=" | "==" => a == b,
        "!=" => a != b,
        "<" => a < b,
        ">" => a > b,
        "-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge" => {
            let x = parse_test_int(a)?;
            let y = parse_test_int(b)?;
            match op {
                "-eq" => x == y,
                "-ne" => x != y,
                "-lt" => x < y,
                "-le" => x <= y,
                "-gt" => x > y,
                "-ge" => x >= y,
                _ => unreachable!(),
            }
        }
        "-nt" => file_mtime(a) > file_mtime(b),
        "-ot" => file_mtime(a) < file_mtime(b),
        "-ef" => {
            // Same file: compare canonical paths (portable stand-in for dev/ino).
            match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
                (Ok(x), Ok(y)) => x == y,
                _ => false,
            }
        }
        _ => return Err(format!("unknown operator: {op}")),
    })
}

fn parse_test_int(s: &str) -> Result<i64, String> {
    s.trim()
        .parse::<i64>()
        .map_err(|_| format!("{s}: integer expression expected"))
}

fn file_mtime(path: &str) -> std::time::SystemTime {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH)
}

fn file_test(op: &str, path: &str) -> bool {
    let meta = std::fs::metadata(path);
    let lmeta = std::fs::symlink_metadata(path);
    match op {
        "-e" => meta.is_ok(),
        "-f" => meta.as_ref().map(|m| m.is_file()).unwrap_or(false),
        "-d" => meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
        "-s" => meta.as_ref().map(|m| m.len() > 0).unwrap_or(false),
        "-h" | "-L" => lmeta.map(|m| m.file_type().is_symlink()).unwrap_or(false),
        "-r" => can_access(path, Access::Read),
        "-w" => can_access(path, Access::Write),
        "-x" => is_executable(path),
        "-p" | "-S" | "-b" | "-c" => special_file(op, path),
        // Ownership/setuid bits: not meaningful on the portable path.
        "-g" | "-u" | "-k" | "-O" | "-G" => false,
        _ => false,
    }
}

enum Access {
    Read,
    Write,
}

fn can_access(path: &str, mode: Access) -> bool {
    match mode {
        Access::Read => std::fs::File::open(path).is_ok(),
        Access::Write => std::fs::OpenOptions::new().write(true).open(path).is_ok(),
    }
}

#[cfg(unix)]
fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &str) -> bool {
    // Motor OS has no execute permission bit; treat any existing file as
    // executable (matching how command resolution accepts it).
    std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
}

#[cfg(unix)]
fn special_file(op: &str, path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::metadata(path) {
        Ok(m) => {
            let ft = m.file_type();
            match op {
                "-p" => ft.is_fifo(),
                "-S" => ft.is_socket(),
                "-b" => ft.is_block_device(),
                "-c" => ft.is_char_device(),
                _ => false,
            }
        }
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn special_file(_op: &str, _path: &str) -> bool {
    false
}

/// A short, portable rendering of an I/O error for user-facing messages.
fn err_str(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "Permission denied".to_string(),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_forms() {
        assert_eq!(sh_quote("simple"), "'simple'");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn echo_escapes_and_n() {
        let mut o = Vec::new();
        let mut e = Vec::new();
        let mut io = Io::new(&mut o, &mut e);
        echo(&["-n".into(), "a\\tb".into()], &mut io);
        assert_eq!(String::from_utf8(o).unwrap(), "a\tb");
    }

    #[test]
    fn printf_basic() {
        let mut o = Vec::new();
        let mut e = Vec::new();
        let mut io = Io::new(&mut o, &mut e);
        printf(&["%s=%d\n".into(), "x".into(), "42".into()], &mut io);
        assert_eq!(String::from_utf8(o).unwrap(), "x=42\n");
    }

    #[test]
    fn printf_recycles_format() {
        let mut o = Vec::new();
        let mut e = Vec::new();
        let mut io = Io::new(&mut o, &mut e);
        printf(
            &["[%s]".into(), "a".into(), "b".into(), "c".into()],
            &mut io,
        );
        assert_eq!(String::from_utf8(o).unwrap(), "[a][b][c]");
    }

    #[test]
    fn printf_width_and_pad() {
        let mut o = Vec::new();
        let mut e = Vec::new();
        let mut io = Io::new(&mut o, &mut e);
        printf(
            &["%5d|%-5d|%05d\n".into(), "7".into(), "7".into(), "7".into()],
            &mut io,
        );
        assert_eq!(String::from_utf8(o).unwrap(), "    7|7    |00007\n");
    }

    #[test]
    fn test_expr_cases() {
        assert_eq!(eval_test(&["-z", ""]), Ok(true));
        assert_eq!(eval_test(&["-n", "x"]), Ok(true));
        assert_eq!(eval_test(&["a", "=", "a"]), Ok(true));
        assert_eq!(eval_test(&["1", "-lt", "2"]), Ok(true));
        assert_eq!(eval_test(&["2", "-lt", "2"]), Ok(false));
        assert_eq!(eval_test(&["!", "a", "=", "a"]), Ok(false));
        assert_eq!(eval_test(&["(", "a", "=", "a", ")"]), Ok(true));
        assert_eq!(
            eval_test(&["1", "-eq", "1", "-a", "2", "-eq", "2"]),
            Ok(true)
        );
        assert_eq!(
            eval_test(&["1", "-eq", "1", "-o", "2", "-eq", "3"]),
            Ok(true)
        );
    }

    #[test]
    fn read_field_split() {
        let plain = |s: &str| -> Vec<ReadChar> { s.chars().map(|c| (c, false)).collect() };
        assert_eq!(
            split_read_fields(&plain("a b c"), " \t\n", 2),
            vec!["a".to_string(), "b c".to_string()]
        );
        assert_eq!(
            split_read_fields(&plain("  1   2   3  "), " \t\n", 3),
            vec!["1".to_string(), "2".to_string(), "3".to_string()]
        );
        assert_eq!(
            split_read_fields(&plain("1:2:3"), ":", 2),
            vec!["1".to_string(), "2:3".to_string()]
        );
        assert_eq!(
            split_read_fields(&plain("a"), " ", 3),
            vec!["a".to_string(), "".to_string(), "".to_string()]
        );
        // An escaped space is literal, not a field delimiter: `a\ b c` → 2 fields.
        let escaped: Vec<ReadChar> = vec![
            ('a', false),
            (' ', true),
            ('b', false),
            (' ', false),
            ('c', false),
        ];
        assert_eq!(
            split_read_fields(&escaped, " \t\n", 2),
            vec!["a b".to_string(), "c".to_string()]
        );
    }
}
