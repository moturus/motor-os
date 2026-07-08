//! AST executor (Phase 2 — deliberately minimal).
//!
//! This walks the [`crate::ast`] tree: it runs `List`s (`;`/`&`/newline
//! separators), `AndOr` lists (`&&`/`||` short-circuiting), pipelines, and
//! simple commands with assignments and file redirections. It is intentionally
//! a bootstrap: the real executor — full word expansion (variables, command
//! substitution, arithmetic, field splitting, globbing, tilde), multi-stage
//! pipelines wired with real pipes, fd duplication, here-document delivery, and
//! subshells — lands in Phase 3.
//!
//! Phase 2 limitations, all reported cleanly (never a panic) and revisited in
//! Phase 3:
//! - `$`-expansions flatten to the empty string (the sole exception is a bare
//!   unquoted `$@`/`$*`, which still splices the positional parameters, matching
//!   the previous behavior).
//! - multi-stage pipelines (`a | b`) are refused;
//! - here-document and fd-duplication (`<&`, `>&`) redirections are refused;
//! - background `&` runs synchronously.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::ast::{AndOr, AndOrOp, Command, List, RedirOp, Redirect, SimpleCommand};
use crate::parser::{self, Parsed};
use crate::token::{ExpansionKind, Word, WordPart};

/// Last command's exit status, i.e. the value `$?` will eventually expose.
/// This is a placeholder; Phase 3 moves it into the `Shell` state object. For
/// now it is enough to make a bare `exit` use the previous command's status.
static LAST_STATUS: AtomicI32 = AtomicI32::new(0);

fn set_last_status(code: i32) {
    LAST_STATUS.store(code, Ordering::Relaxed);
}

fn last_status() -> i32 {
    LAST_STATUS.load(Ordering::Relaxed)
}

// ---- source-string entry points -------------------------------------------

/// Parse and execute a whole source buffer, returning its exit status. Used by
/// the `-c` and script paths, which — unlike the interactive loop — treat
/// incomplete input as a syntax error rather than prompting for more.
fn exec_source(src: &str, global: bool, args: &[String]) -> i32 {
    match parser::parse_source(src) {
        Parsed::Complete(list) => exec_list(&list, global, args),
        Parsed::Empty => 0,
        Parsed::Incomplete => {
            eprintln!("rush: syntax error: unexpected end of input");
            2
        }
        Parsed::Error(msg) => {
            eprintln!("rush: {msg}");
            2
        }
    }
}

pub fn run_command(args: Vec<String>) {
    let line = args.join(" ");
    let status = exec_source(&line, true, &[]);
    crate::exit(status);
}

pub fn run_script(fname: &str, args: Vec<String>, global: bool) -> i32 {
    let script = match std::fs::read_to_string(Path::new(fname)) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("Error reading '{fname}': {err:?}");
            std::process::exit(1);
        }
    };
    exec_source(&script, global, &args)
}

// ---- AST walk --------------------------------------------------------------

/// Run a complete command list, returning the status of the last and-or list.
/// Records `$?` after each one so a subsequent bare `exit` sees it.
pub fn exec_list(list: &List, global: bool, args: &[String]) -> i32 {
    let mut status = 0;
    for item in &list.0 {
        // `Separator::Async` (`&`) is honored in Phase 7; for now everything
        // runs synchronously.
        status = exec_and_or(&item.and_or, global, args);
        set_last_status(status);
    }
    status
}

fn exec_and_or(and_or: &AndOr, global: bool, args: &[String]) -> i32 {
    let mut status = exec_pipeline(&and_or.first, global, args);
    for (op, pipeline) in &and_or.rest {
        let run = match op {
            AndOrOp::And => status == 0,
            AndOrOp::Or => status != 0,
        };
        if run {
            status = exec_pipeline(pipeline, global, args);
        }
    }
    status
}

fn exec_pipeline(pipeline: &crate::ast::Pipeline, global: bool, args: &[String]) -> i32 {
    // Pipeline negation (`!`) is finalized in Phase 4.
    match pipeline.commands.as_slice() {
        [single] => exec_command(single, global, args),
        _ => {
            // Real multi-stage pipelines need pipe/dup fd wiring (and builtins
            // as stages), which arrives in Phase 3. Refuse cleanly rather than
            // panic.
            eprintln!("rush: multi-stage pipelines are not yet supported (Phase 3)");
            1
        }
    }
}

fn exec_command(command: &Command, global: bool, args: &[String]) -> i32 {
    match command {
        Command::Simple(simple) => exec_simple(simple, global, args),
    }
}

fn exec_simple(simple: &SimpleCommand, global: bool, args: &[String]) -> i32 {
    let assigns: Vec<(String, String)> = simple
        .assigns
        .iter()
        .map(|a| (a.name.clone(), flatten_word(&a.value)))
        .collect();
    let argv = build_argv(&simple.words, args);

    if argv.is_empty() {
        // Assignment-only (and/or redirect-only) command. In "global" contexts
        // (config scripts, `-c`) a bare assignment updates the process
        // environment; interactively it is a no-op until shell variables land
        // in Phase 3.
        if global {
            for (k, v) in &assigns {
                // SAFETY: single-threaded shell control flow; TBD in Phase 3.
                unsafe { std::env::set_var(k, v) };
            }
        }
        return noword_redirects(&simple.redirects);
    }

    match argv[0].as_str() {
        "cd" => builtin_cd(&argv[1..]),
        "quit" => crate::exit(0),
        "exit" => process_exit(&argv[1..]),
        _ => spawn_external(&argv, &assigns, &simple.redirects),
    }
}

// ---- builtins --------------------------------------------------------------

fn builtin_cd(args: &[String]) -> i32 {
    // Full `cd` (no-arg → $HOME, `cd -`, CDPATH, PWD/OLDPWD) is Phase 5.
    if args.len() != 1 {
        eprintln!("rush: cd: expected a single argument.");
        return 1;
    }
    match std::env::set_current_dir(Path::new(&args[0])) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("rush: cd: {}: {e}", args[0]);
            1
        }
    }
}

fn process_exit(args: &[String]) -> ! {
    let code = if args.is_empty() {
        // Bare `exit` exits with the status of the last command ($?).
        last_status()
    } else if let Ok(exit_val) = args[0].as_str().parse::<i32>() {
        // POSIX: the exit status is the argument taken modulo 256.
        exit_val & 0xff
    } else {
        // Behavior (error to stderr, exit 2) is the universal POSIX-shell
        // convention; wording follows the common "numeric argument required"
        // phrasing rather than dash's shell-specific "Illegal number".
        eprintln!("rush: exit: {}: numeric argument required", args[0]);
        2
    };
    crate::exit(code);
}

// ---- external commands & redirections --------------------------------------

fn spawn_external(argv: &[String], env: &[(String, String)], redirects: &[Redirect]) -> i32 {
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (k, v) in env {
        cmd.env(k, v);
    }

    for redirect in redirects {
        if let Err(code) = apply_redirect(&mut cmd, redirect) {
            return code;
        }
    }

    match cmd.spawn() {
        Ok(mut child) => match child.wait() {
            // A signal-terminated child has no exit code. POSIX reports
            // 128 + signum; without a portable signal accessor here we use a
            // generic non-zero status.
            Ok(status) => status.code().unwrap_or(128),
            Err(err) => {
                eprintln!("rush: {err}");
                126
            }
        },
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidFilename => {
                // POSIX: a command that cannot be found exits 127.
                eprintln!("rush: {}: command not found", argv[0]);
                127
            }
            std::io::ErrorKind::PermissionDenied => {
                // POSIX: found but not executable exits 126.
                eprintln!("rush: {}: permission denied", argv[0]);
                126
            }
            _ => {
                eprintln!("rush: {}: {e}", argv[0]);
                126
            }
        },
    }
}

/// Wire one redirection onto a to-be-spawned command. Only fd 0/1/2 file
/// redirections are supported in Phase 2; fd duplication and here-documents
/// (and fds > 2) return `Err(status)` after a diagnostic — Phase 3.
fn apply_redirect(cmd: &mut std::process::Command, redirect: &Redirect) -> Result<(), i32> {
    let (fd, op, target) = match redirect {
        Redirect::File { fd, op, target } => (*fd, *op, target),
        Redirect::Heredoc { .. } => {
            eprintln!("rush: here-documents are not yet supported (Phase 3)");
            return Err(1);
        }
    };

    let file = match op {
        RedirOp::Read => open_read(target)?,
        RedirOp::Write | RedirOp::Clobber => open_create(target)?,
        RedirOp::Append => open_append(target)?,
        RedirOp::ReadWrite => open_read_write(target)?,
        RedirOp::DupRead | RedirOp::DupWrite => {
            eprintln!("rush: fd duplication (`<&`, `>&`) is not yet supported (Phase 3)");
            return Err(1);
        }
    };

    let fd = fd.unwrap_or_else(|| default_fd(op));
    match fd {
        0 => {
            cmd.stdin(file);
        }
        1 => {
            cmd.stdout(file);
        }
        2 => {
            cmd.stderr(file);
        }
        other => {
            eprintln!("rush: redirection to fd {other} is not yet supported (Phase 3)");
            return Err(1);
        }
    }
    Ok(())
}

/// Perform the side effects of a command that has redirections but no command
/// word (e.g. `> file` truncates it). Input/dup/here-doc redirections have no
/// standalone effect worth emulating in Phase 2 and are ignored.
fn noword_redirects(redirects: &[Redirect]) -> i32 {
    for redirect in redirects {
        if let Redirect::File { op, target, .. } = redirect {
            let result = match op {
                RedirOp::Write | RedirOp::Clobber => open_create(target).map(drop),
                RedirOp::Append => open_append(target).map(drop),
                _ => Ok(()),
            };
            if let Err(code) = result {
                return code;
            }
        }
    }
    0
}

fn default_fd(op: RedirOp) -> u32 {
    match op {
        RedirOp::Read | RedirOp::ReadWrite | RedirOp::DupRead => 0,
        RedirOp::Write | RedirOp::Append | RedirOp::Clobber | RedirOp::DupWrite => 1,
    }
}

fn open_read(target: &Word) -> Result<File, i32> {
    open_with(target, |p| File::open(p))
}
fn open_create(target: &Word) -> Result<File, i32> {
    open_with(target, |p| File::create(p))
}
fn open_append(target: &Word) -> Result<File, i32> {
    open_with(target, |p| OpenOptions::new().create(true).append(true).open(p))
}
fn open_read_write(target: &Word) -> Result<File, i32> {
    open_with(target, |p| {
        // POSIX `<>` opens for read+write without truncating.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(p)
    })
}

fn open_with(
    target: &Word,
    open: impl FnOnce(&Path) -> std::io::Result<File>,
) -> Result<File, i32> {
    let path = flatten_word(target);
    open(Path::new(&path)).map_err(|e| {
        eprintln!("rush: {path}: {e}");
        1
    })
}

// ---- minimal word flattening (Phase 3 replaces this with real expansion) ---

/// Build the argument vector from the command words. Each word yields exactly
/// one field (no field splitting yet — Phase 3), except a bare unquoted `$@` /
/// `$*`, which splices the positional parameters.
fn build_argv(words: &[Word], args: &[String]) -> Vec<String> {
    let mut argv = Vec::new();
    for word in words {
        if is_at_or_star(word) {
            argv.extend(args.iter().skip(1).cloned());
        } else {
            argv.push(flatten_word(word));
        }
    }
    argv
}

/// A word that is exactly a single unquoted `$@` or `$*` expansion.
fn is_at_or_star(word: &Word) -> bool {
    matches!(
        word.0.as_slice(),
        [WordPart::Expansion { kind: ExpansionKind::Parameter, raw, quoted: false }]
            if raw == "@" || raw == "*"
    )
}

/// Flatten a word to a string: concatenate literal parts (quote removal).
/// `$`-expansions are not evaluated in Phase 2 — they contribute nothing. The
/// full expansion engine replaces this in Phase 3.
fn flatten_word(word: &Word) -> String {
    let mut s = String::new();
    for part in &word.0 {
        match part {
            WordPart::Literal { text, .. } => s.push_str(text),
            WordPart::Expansion { .. } => { /* Phase 3: expand. */ }
        }
    }
    s
}
