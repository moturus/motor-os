//! AST executor (Phase 3, extended in Phase 4).
//!
//! Walks the [`crate::ast`] tree over a persistent [`Shell`], driving the
//! [`crate::expand`] engine for every word: it runs lists (`;`/`&`/newline),
//! and-or lists (`&&`/`||`), pipelines (with `!` negation), simple commands with
//! variable assignments and the full redirection set (files, `2>&1`-style fd
//! duplication, and here-documents), and — from Phase 4 — compound commands
//! (`if`, `for`, `while`/`until`, `case`, `{ … }`, `( … )`), shell functions,
//! and the `break`/`continue`/`return` control-flow builtins. Command
//! substitution and `( … )` subshells run the inner script in an in-process
//! subshell whose variable/cwd/function mutations are rolled back.
//!
//! Portability: everything is built on `std::process` + `std::fs` — pipelines
//! chain child stdio, redirections open files, here-docs feed a pipe, and
//! command substitution captures through a temp file. No `fork`/`dup2` syscalls,
//! keeping the executor portable to Motor OS.
//!
//! Documented limits: multi-stage pipeline stages must be external commands
//! (builtins/compound commands mid-pipeline are not wired); per-stage `<&` `>&`
//! and here-docs inside a pipeline, and redirections to fds > 2, are not wired;
//! background `&` runs synchronously (Phase 7); `${x:?}` diagnoses but does not
//! abort; `exit` inside an emulated `( … )` subshell exits the whole shell.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ast::{
    AndOr, AndOrOp, CaseClause, Command as AstCommand, CompoundCommand, ForClause, FunctionBody,
    IfClause, List, Pipeline, RedirOp, Redirect, SimpleCommand, WhileClause,
};
use crate::expand;
use crate::parser::{self, Parsed};
use crate::shell::{Flow, Shell};

// ---- source-string entry points --------------------------------------------

pub fn run_command(args: Vec<String>, shell: &mut Shell) {
    let line = args.join(" ");
    let status = run_source(&line, shell);
    crate::exit(status);
}

pub fn run_script(fname: &str, shell: &mut Shell) -> i32 {
    let script = match std::fs::read_to_string(Path::new(fname)) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("Error reading '{fname}': {err:?}");
            std::process::exit(1);
        }
    };
    run_source(&script, shell)
}

/// Parse and execute a source buffer with the default (inherited) I/O
/// environment. Incomplete input is a syntax error here (unlike the interactive
/// loop, which reads more).
pub fn run_source(src: &str, shell: &mut Shell) -> i32 {
    match parser::parse_source(src) {
        Parsed::Complete(list) => run_list(&list, shell),
        Parsed::Empty => 0,
        Parsed::Incomplete => {
            eprintln!("rush: syntax error: unexpected end of input");
            shell.set_status(2);
            2
        }
        Parsed::Error(msg) => {
            eprintln!("rush: {msg}");
            shell.set_status(2);
            2
        }
    }
}

/// Execute a parsed list with inherited I/O (used by the interactive loop).
pub fn run_list(list: &List, shell: &mut Shell) -> i32 {
    let status = exec_list(list, shell, &IoEnv::inherit());
    // Any `break`/`continue`/`return` that escaped to the top level is discarded.
    shell.clear_flow();
    status
}

// ---- I/O environment --------------------------------------------------------

/// The ambient file descriptors a command inherits (fd 0/1/2). Each source is
/// cheaply cloneable (a `File` is shared behind an `Arc` and materialized with
/// `try_clone`), so the same target can be handed to several children.
#[derive(Clone)]
enum FdSource {
    Inherit,
    File(Arc<File>),
    /// stdin fed from a here-document body via a pipe (written after spawn).
    Heredoc(Arc<String>),
}

impl FdSource {
    fn to_stdio(&self) -> std::io::Result<Stdio> {
        Ok(match self {
            FdSource::Inherit => Stdio::inherit(),
            FdSource::File(f) => Stdio::from(f.try_clone()?),
            FdSource::Heredoc(_) => Stdio::piped(),
        })
    }
    fn heredoc_body(&self) -> Option<Arc<String>> {
        match self {
            FdSource::Heredoc(b) => Some(b.clone()),
            _ => None,
        }
    }
}

struct IoEnv {
    fds: [FdSource; 3],
}

impl IoEnv {
    fn inherit() -> Self {
        Self {
            fds: [FdSource::Inherit, FdSource::Inherit, FdSource::Inherit],
        }
    }
}

// ---- AST walk ---------------------------------------------------------------

fn exec_list(list: &List, shell: &mut Shell, io: &IoEnv) -> i32 {
    let mut status = 0;
    for item in &list.0 {
        // `Separator::Async` (`&`) is honored in Phase 7; runs synchronously now.
        status = exec_and_or(&item.and_or, shell, io);
        shell.set_status(status);
        // A pending `break`/`continue`/`return` stops the rest of the list.
        if shell.flow() != Flow::Normal {
            break;
        }
    }
    status
}

fn exec_and_or(and_or: &AndOr, shell: &mut Shell, io: &IoEnv) -> i32 {
    let mut status = exec_pipeline(&and_or.first, shell, io);
    shell.set_status(status);
    if shell.flow() != Flow::Normal {
        return status;
    }
    for (op, pipeline) in &and_or.rest {
        let run = match op {
            AndOrOp::And => status == 0,
            AndOrOp::Or => status != 0,
        };
        if run {
            status = exec_pipeline(pipeline, shell, io);
            shell.set_status(status);
            if shell.flow() != Flow::Normal {
                return status;
            }
        }
    }
    status
}

fn exec_pipeline(pipeline: &Pipeline, shell: &mut Shell, io: &IoEnv) -> i32 {
    let status = match pipeline.commands.as_slice() {
        [single] => exec_command(single, shell, io),
        cmds => run_pipeline(cmds, shell, io),
    };
    // `! pipeline` inverts the final exit status (0 ⇄ 1).
    if pipeline.bang {
        i32::from(status == 0)
    } else {
        status
    }
}

fn exec_command(command: &AstCommand, shell: &mut Shell, io: &IoEnv) -> i32 {
    match command {
        AstCommand::Simple(simple) => exec_simple(simple, shell, io),
        AstCommand::Compound { kind, redirects } => exec_compound_cmd(kind, redirects, shell, io),
        AstCommand::Function { name, body } => {
            shell.define_function(name, Rc::new(body.clone()));
            0
        }
    }
}

fn exec_simple(simple: &SimpleCommand, shell: &mut Shell, io: &IoEnv) -> i32 {
    let assigns: Vec<(String, String)> = simple
        .assigns
        .iter()
        .map(|a| (a.name.clone(), expand::to_string(&a.value, shell)))
        .collect();

    let mut argv = Vec::new();
    for word in &simple.words {
        argv.extend(expand::to_fields(word, shell));
    }

    if argv.is_empty() {
        // Assignment-only command: assignments persist in the shell.
        let mut status = 0;
        for (k, v) in &assigns {
            if let Err(e) = shell.set(k, v.clone()) {
                eprintln!("rush: {e}");
                status = 1;
            }
        }
        if !simple.redirects.is_empty() {
            // Opening the targets is the observable effect (e.g. `> file`).
            if let Err(code) = build_fds(io, &simple.redirects, shell) {
                status = code;
            }
        }
        return status;
    }

    // Redirections apply to every command, builtin or external; build them once
    // (this also gives the file-creation side effect for output-less builtins).
    let fds = match build_fds(io, &simple.redirects, shell) {
        Ok(fds) => fds,
        Err(code) => return code,
    };

    // Special built-ins that touch the shell process or its control flow; these
    // cannot be shadowed by a function.
    match argv[0].as_str() {
        "exit" => process_exit(&argv[1..], shell),
        "quit" => crate::exit(0),
        "return" => return builtin_return(&argv[1..], shell),
        "break" => return builtin_break(&argv[1..], shell),
        "continue" => return builtin_continue(&argv[1..], shell),
        "export" => return builtin_export(&argv[1..], shell),
        _ => {}
    }

    // A function shadows regular builtins and external commands.
    if let Some(body) = shell.get_function(&argv[0]) {
        return exec_function_call(&body, &argv, &assigns, &fds, shell);
    }

    match argv[0].as_str() {
        "cd" => builtin_cd(&argv[1..]),
        ":" | "true" => 0,
        "false" => 1,
        _ => match resolve_program(&argv[0], shell) {
            Some(program) => spawn_external(&program, &argv[1..], &assigns, &fds),
            None => {
                eprintln!("rush: {}: command not found", argv[0]);
                127
            }
        },
    }
}

/// Resolve a command name to the program path to execute (POSIX §2.9.1.1 command
/// search). A name containing `/` is used verbatim; a bare name is looked up in
/// the shell's `PATH` — reading the shell variable directly, so it resolves even
/// when `PATH` is not exported (matching dash). This keeps command resolution
/// working on Motor OS, whose own resolver consults only the *process*
/// environment and has no default-PATH fallback.
///
/// Returns `None` when `PATH` is set but the command is not found (→ 127); when
/// `PATH` is unset, the bare name is passed through for the OS to resolve.
fn resolve_program(name: &str, shell: &Shell) -> Option<String> {
    if name.contains('/') {
        return Some(name.to_string());
    }
    let path = match shell.get("PATH") {
        Some(p) => p,
        None => return Some(name.to_string()),
    };
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

// ---- function invocation ----------------------------------------------------

/// Invoke a shell function: rebind the positional parameters to the call's
/// arguments (`$0` is unchanged), apply the definition's own redirections over
/// the call-site fds, run the body, then restore the parameters. `return`
/// terminates the function; `break`/`continue` do not cross the boundary.
fn exec_function_call(
    body: &FunctionBody,
    argv: &[String],
    assigns: &[(String, String)],
    fds: &[FdSource; 3],
    shell: &mut Shell,
) -> i32 {
    // Prefix assignments (`VAR=x func`) persist in the shell — proper per-call
    // scoping arrives with the builtin/options work of later phases.
    for (k, v) in assigns {
        if let Err(e) = shell.set(k, v.clone()) {
            eprintln!("rush: {e}");
        }
    }

    let saved_params = shell.params().to_vec();
    shell.set_params(argv[1..].to_vec());
    // A function is a boundary for `break`/`continue`: they see only loops
    // defined within it, not the caller's.
    let saved_loop_depth = shell.take_loop_depth();

    let status = match build_fds(&IoEnv { fds: fds.clone() }, &body.redirects, shell) {
        Ok(f) => exec_compound(&body.body, shell, &IoEnv { fds: f }),
        Err(code) => code,
    };
    shell.set_loop_depth(saved_loop_depth);

    let status = match shell.flow() {
        Flow::Return(n) => {
            shell.clear_flow();
            n
        }
        // A loop-control signal that reached the function top has no loop to act
        // on; it is discarded at the boundary.
        Flow::Break(_) | Flow::Continue(_) => {
            shell.clear_flow();
            status
        }
        Flow::Normal => status,
    };

    shell.set_params(saved_params);
    status
}

// ---- builtins ---------------------------------------------------------------

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

/// `export [-p] [name[=value]]...` — mark each `name` for export to the
/// environment of subsequently executed commands (moving it out of the shell's
/// unexported variable map into the real process environment), optionally
/// assigning `value` first. This is what lets a config's `export PATH=/bin`
/// reach children like `printenv`, whose command resolution consults only the
/// process environment. With no operands (or `-p`), the current exported set is
/// listed in a form that can be re-read as shell input.
///
/// `export` is a POSIX special built-in, so it is dispatched before function
/// name resolution and cannot be shadowed. (Assignment field-splitting on the
/// value — `export X=$y` — follows the same word-expansion path as any other
/// argument for now; declaration-utility assignment semantics are a later
/// refinement.)
fn builtin_export(args: &[String], shell: &mut Shell) -> i32 {
    // No operands, or the lone `-p` flag: list the exported variables.
    if args.iter().all(|a| a == "-p") {
        for (name, value) in std::env::vars() {
            println!("export {name}={}", single_quote(&value));
        }
        return 0;
    }

    let mut status = 0;
    for arg in args {
        if arg == "-p" {
            continue;
        }
        // `name=value` assigns then exports; a bare `name` exports whatever
        // value the name currently holds (if any).
        let (name, value) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        if !crate::is_valid_var_name(name) {
            eprintln!("rush: export: `{arg}': not a valid identifier");
            status = 1;
            continue;
        }
        if let Err(e) = shell.export(name, value) {
            eprintln!("rush: export: {e}");
            status = 1;
        }
    }
    status
}

/// Single-quote a value so `export -p` output round-trips as shell input:
/// wrap in `'…'` and render any embedded quote as the `'\''` escape.
fn single_quote(s: &str) -> String {
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

fn process_exit(args: &[String], shell: &Shell) -> ! {
    let code = if args.is_empty() {
        shell.status()
    } else if let Ok(exit_val) = args[0].as_str().parse::<i32>() {
        exit_val & 0xff
    } else {
        eprintln!("rush: exit: {}: numeric argument required", args[0]);
        2
    };
    crate::exit(code);
}

/// `return [n]` — leave the current function with status `n` (default: `$?`).
fn builtin_return(args: &[String], shell: &mut Shell) -> i32 {
    let code = match args.first() {
        None => shell.status(),
        Some(a) => match a.parse::<i32>() {
            Ok(n) => n & 0xff,
            Err(_) => {
                eprintln!("rush: return: {a}: numeric argument required");
                return 2;
            }
        },
    };
    shell.set_flow(Flow::Return(code));
    code
}

/// `break [n]` — stop the innermost `n` enclosing loops (default 1). Outside a
/// loop it is a silent no-op (matching dash).
fn builtin_break(args: &[String], shell: &mut Shell) -> i32 {
    match loop_count(args, "break") {
        Some(n) => {
            if shell.in_loop() {
                shell.set_flow(Flow::Break(n));
            }
            0
        }
        None => 2,
    }
}

/// `continue [n]` — resume the `n`-th enclosing loop's next iteration (default
/// 1). Outside a loop it is a silent no-op (matching dash).
fn builtin_continue(args: &[String], shell: &mut Shell) -> i32 {
    match loop_count(args, "continue") {
        Some(n) => {
            if shell.in_loop() {
                shell.set_flow(Flow::Continue(n));
            }
            0
        }
        None => 2,
    }
}

/// Parse the optional count for `break`/`continue` (a positive integer,
/// default 1), or `None` on a bad argument (already diagnosed).
fn loop_count(args: &[String], name: &str) -> Option<u32> {
    match args.first() {
        None => Some(1),
        Some(a) => match a.parse::<u32>() {
            Ok(0) => {
                eprintln!("rush: {name}: 0: loop count out of range");
                None
            }
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("rush: {name}: {a}: numeric argument required");
                None
            }
        },
    }
}

// ---- external commands ------------------------------------------------------

fn spawn_external(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    fds: &[FdSource; 3],
) -> i32 {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }

    let stdin = match fds[0].to_stdio() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rush: {e}");
            return 1;
        }
    };
    let stdout = match fds[1].to_stdio() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rush: {e}");
            return 1;
        }
    };
    let stderr = match fds[2].to_stdio() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rush: {e}");
            return 1;
        }
    };
    cmd.stdin(stdin).stdout(stdout).stderr(stderr);
    let heredoc = fds[0].heredoc_body();

    match cmd.spawn() {
        Ok(mut child) => {
            if let Some(body) = heredoc
                && let Some(mut sink) = child.stdin.take()
            {
                // Feeding the whole body then closing the pipe is deadlock-free
                // for a lone command: its stdout drains concurrently.
                let _ = sink.write_all(body.as_bytes());
            }
            match child.wait() {
                Ok(status) => status.code().unwrap_or(128),
                Err(err) => {
                    eprintln!("rush: {err}");
                    126
                }
            }
        }
        Err(e) => spawn_error(program, e),
    }
}

fn spawn_error(program: &str, e: std::io::Error) -> i32 {
    match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidFilename => {
            eprintln!("rush: {program}: command not found");
            127
        }
        std::io::ErrorKind::PermissionDenied => {
            eprintln!("rush: {program}: permission denied");
            126
        }
        _ => {
            eprintln!("rush: {program}: {e}");
            126
        }
    }
}

// ---- redirections -----------------------------------------------------------

/// Resolve a command's redirections into the effective fd 0/1/2 sources,
/// starting from the ambient environment and applying each redirect in order.
fn build_fds(io: &IoEnv, redirects: &[Redirect], shell: &mut Shell) -> Result<[FdSource; 3], i32> {
    let mut fds = io.fds.clone();
    for redirect in redirects {
        match redirect {
            Redirect::File { fd, op, target } => {
                let fd_num = fd.unwrap_or(default_fd(*op)) as usize;
                if fd_num > 2 {
                    eprintln!("rush: redirection to fd {fd_num} is not yet supported (Phase 3)");
                    return Err(1);
                }
                match op {
                    RedirOp::DupRead | RedirOp::DupWrite => {
                        let t = expand::to_string(target, shell);
                        if t == "-" {
                            // Close: approximated by /dev/null. `Stdio::null` is
                            // the closest portable stand-in for closing an fd.
                            fds[fd_num] = FdSource::File(Arc::new(dev_null()?));
                        } else if let Ok(m) = t.parse::<usize>() {
                            if m > 2 {
                                eprintln!("rush: fd {m}: duplication of fds > 2 is not yet supported (Phase 3)");
                                return Err(1);
                            }
                            fds[fd_num] = fds[m].clone();
                        } else {
                            eprintln!("rush: {t}: ambiguous redirect");
                            return Err(1);
                        }
                    }
                    _ => {
                        let path = expand::to_string(target, shell);
                        let file = open_for(*op, &path)?;
                        fds[fd_num] = FdSource::File(Arc::new(file));
                    }
                }
            }
            Redirect::Heredoc { fd, doc } => {
                let fd_num = fd.unwrap_or(0) as usize;
                if fd_num > 2 {
                    eprintln!("rush: here-document on fd {fd_num} is not yet supported (Phase 3)");
                    return Err(1);
                }
                let body = if doc.quoted {
                    doc.body.clone()
                } else {
                    expand::expand_heredoc_body(&doc.body, shell)
                };
                fds[fd_num] = FdSource::Heredoc(Arc::new(body));
            }
        }
    }
    Ok(fds)
}

fn default_fd(op: RedirOp) -> u32 {
    match op {
        RedirOp::Read | RedirOp::ReadWrite | RedirOp::DupRead => 0,
        RedirOp::Write | RedirOp::Append | RedirOp::Clobber | RedirOp::DupWrite => 1,
    }
}

fn open_for(op: RedirOp, path: &str) -> Result<File, i32> {
    let result = match op {
        RedirOp::Read => File::open(path),
        // `>|` ignores noclobber, which is not implemented until Phase 6, so it
        // behaves like `>` for now.
        RedirOp::Write | RedirOp::Clobber => File::create(path),
        RedirOp::Append => OpenOptions::new().create(true).append(true).open(path),
        RedirOp::ReadWrite => OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path),
        RedirOp::DupRead | RedirOp::DupWrite => unreachable!("dup handled by caller"),
    };
    result.map_err(|e| {
        eprintln!("rush: {path}: {e}");
        1
    })
}

fn dev_null() -> Result<File, i32> {
    // Approximates closing an fd (`>&-`); Motor OS may expose a different sink.
    File::create("/dev/null").map_err(|e| {
        eprintln!("rush: /dev/null: {e}");
        1
    })
}

// ---- pipelines --------------------------------------------------------------

/// Run a multi-stage pipeline. Stages are external commands wired together with
/// `std::process` pipes; the pipeline status is the last stage's.
fn run_pipeline(cmds: &[AstCommand], shell: &mut Shell, io: &IoEnv) -> i32 {
    let n = cmds.len();
    let mut children: Vec<Option<Child>> = Vec::with_capacity(n);
    let mut prev: Option<ChildStdout> = None;

    for (i, command) in cmds.iter().enumerate() {
        let is_last = i == n - 1;
        let simple = match command {
            AstCommand::Simple(s) => s,
            // Compound commands and function calls as pipeline stages need real
            // fd wiring (a subshell writing to a pipe); not yet supported.
            _ => {
                eprintln!(
                    "rush: compound commands / functions inside a multi-stage pipeline are not yet supported"
                );
                children.push(None);
                prev = None;
                continue;
            }
        };

        let assigns: Vec<(String, String)> = simple
            .assigns
            .iter()
            .map(|a| (a.name.clone(), expand::to_string(&a.value, shell)))
            .collect();
        let mut argv = Vec::new();
        for word in &simple.words {
            argv.extend(expand::to_fields(word, shell));
        }
        if argv.is_empty() {
            eprintln!("rush: pipeline stage {}: no command", i + 1);
            children.push(None);
            prev = None;
            continue;
        }
        let program = match resolve_program(&argv[0], shell) {
            Some(p) => p,
            None => {
                eprintln!("rush: {}: command not found", argv[0]);
                children.push(None);
                prev = None;
                continue;
            }
        };

        let stdin = match prev.take() {
            Some(out) => Stdio::from(out),
            None => io.fds[0].to_stdio().unwrap_or_else(|_| Stdio::inherit()),
        };
        let stdout = if is_last {
            io.fds[1].to_stdio().unwrap_or_else(|_| Stdio::inherit())
        } else {
            Stdio::piped()
        };
        let stderr = io.fds[2].to_stdio().unwrap_or_else(|_| Stdio::inherit());

        let mut cmd = Command::new(&program);
        cmd.args(&argv[1..]).stdin(stdin).stdout(stdout).stderr(stderr);
        for (k, v) in &assigns {
            cmd.env(k, v);
        }
        // A stage's own file redirections override the pipe wiring (dup/heredoc
        // inside a pipeline are a documented Phase 3 gap).
        if let Err(code) = apply_stage_redirects(&mut cmd, &simple.redirects, shell) {
            children.push(None);
            prev = None;
            let _ = code;
            continue;
        }

        match cmd.spawn() {
            Ok(mut child) => {
                if !is_last {
                    prev = child.stdout.take();
                }
                children.push(Some(child));
            }
            Err(e) => {
                let _ = spawn_error(&program, e);
                children.push(None);
                prev = None;
            }
        }
    }

    // Wait for every stage; the pipeline's status is the last stage's.
    let mut status = 127;
    for (i, child) in children.into_iter().enumerate() {
        let is_last = i == n - 1;
        let stage_status = match child {
            Some(mut c) => match c.wait() {
                Ok(s) => s.code().unwrap_or(128),
                Err(_) => 126,
            },
            None => 127,
        };
        if is_last {
            status = stage_status;
        }
    }
    status
}

/// Apply a pipeline stage's file redirections over its base stdio.
fn apply_stage_redirects(
    cmd: &mut Command,
    redirects: &[Redirect],
    shell: &mut Shell,
) -> Result<(), i32> {
    for redirect in redirects {
        match redirect {
            Redirect::File {
                fd,
                op: op @ (RedirOp::Read | RedirOp::Write | RedirOp::Clobber | RedirOp::Append | RedirOp::ReadWrite),
                target,
            } => {
                let fd_num = fd.unwrap_or(default_fd(*op));
                let path = expand::to_string(target, shell);
                let file = open_for(*op, &path)?;
                match fd_num {
                    0 => cmd.stdin(file),
                    1 => cmd.stdout(file),
                    2 => cmd.stderr(file),
                    other => {
                        eprintln!("rush: redirection to fd {other} is not yet supported (Phase 3)");
                        return Err(1);
                    }
                };
            }
            _ => {
                eprintln!("rush: fd duplication / here-documents inside a pipeline are not yet supported (Phase 3)");
                return Err(1);
            }
        }
    }
    Ok(())
}

// ---- compound commands ------------------------------------------------------

/// A compound command with its own redirections applied (`if …; fi > out`): the
/// redirects wrap the whole construct.
fn exec_compound_cmd(
    kind: &CompoundCommand,
    redirects: &[Redirect],
    shell: &mut Shell,
    io: &IoEnv,
) -> i32 {
    let fds = match build_fds(io, redirects, shell) {
        Ok(fds) => fds,
        Err(code) => return code,
    };
    exec_compound(kind, shell, &IoEnv { fds })
}

fn exec_compound(kind: &CompoundCommand, shell: &mut Shell, io: &IoEnv) -> i32 {
    match kind {
        CompoundCommand::Brace(list) => exec_list(list, shell, io),
        CompoundCommand::Subshell(list) => exec_subshell(list, shell, io),
        CompoundCommand::If(clause) => exec_if(clause, shell, io),
        CompoundCommand::For(clause) => exec_for(clause, shell, io),
        CompoundCommand::While(clause) => exec_while(clause, shell, io),
        CompoundCommand::Case(clause) => exec_case(clause, shell, io),
    }
}

/// `( list )` — run in an emulated subshell: variable/cwd/function mutations and
/// any pending control flow are rolled back afterwards. (`exit` still exits the
/// whole shell — a documented emulation limit.)
fn exec_subshell(list: &List, shell: &mut Shell, io: &IoEnv) -> i32 {
    let snapshot = shell.snapshot();
    let status = exec_list(list, shell, io);
    shell.restore(snapshot);
    shell.clear_flow();
    status
}

fn exec_if(clause: &IfClause, shell: &mut Shell, io: &IoEnv) -> i32 {
    exec_list(&clause.cond, shell, io);
    if shell.flow() != Flow::Normal {
        return shell.status();
    }
    if shell.status() == 0 {
        return exec_list(&clause.then_branch, shell, io);
    }
    for (cond, then) in &clause.elifs {
        exec_list(cond, shell, io);
        if shell.flow() != Flow::Normal {
            return shell.status();
        }
        if shell.status() == 0 {
            return exec_list(then, shell, io);
        }
    }
    if let Some(else_branch) = &clause.else_branch {
        return exec_list(else_branch, shell, io);
    }
    // No branch ran: POSIX makes the status 0.
    shell.set_status(0);
    0
}

fn exec_for(clause: &ForClause, shell: &mut Shell, io: &IoEnv) -> i32 {
    let items: Vec<String> = match &clause.words {
        Some(words) => {
            let mut v = Vec::new();
            for w in words {
                v.extend(expand::to_fields(w, shell));
            }
            v
        }
        // No `in` clause: iterate over the positional parameters.
        None => shell.params().to_vec(),
    };
    let mut status = 0;
    shell.enter_loop();
    for item in items {
        if let Err(e) = shell.set(&clause.var, item) {
            eprintln!("rush: {e}");
        }
        status = exec_list(&clause.body, shell, io);
        if loop_should_break(shell) {
            break;
        }
    }
    shell.exit_loop();
    status
}

fn exec_while(clause: &WhileClause, shell: &mut Shell, io: &IoEnv) -> i32 {
    let mut status = 0;
    shell.enter_loop();
    loop {
        exec_list(&clause.cond, shell, io);
        if shell.flow() != Flow::Normal {
            break;
        }
        // `while` runs the body while the condition is true (status 0); `until`
        // runs it while the condition is false.
        if (shell.status() == 0) == clause.until {
            break;
        }
        status = exec_list(&clause.body, shell, io);
        if loop_should_break(shell) {
            break;
        }
    }
    shell.exit_loop();
    status
}

fn exec_case(clause: &CaseClause, shell: &mut Shell, io: &IoEnv) -> i32 {
    let subject = expand::to_string(&clause.word, shell);
    for item in &clause.items {
        for pat in &item.patterns {
            let pattern = expand::to_pattern(pat, shell);
            if crate::glob::fnmatch(&pattern, &subject) {
                return exec_list(&item.body, shell, io);
            }
        }
    }
    // No pattern matched: status 0.
    shell.set_status(0);
    0
}

/// Consume a pending loop-control signal after a loop body. Returns `true` when
/// the enclosing loop should stop iterating (a `break`, an outer-targeted
/// `continue`/`break n`, or a `return`); `false` to keep looping.
fn loop_should_break(shell: &mut Shell) -> bool {
    match shell.flow() {
        Flow::Normal => false,
        Flow::Break(1) => {
            shell.clear_flow();
            true
        }
        Flow::Break(n) => {
            shell.set_flow(Flow::Break(n - 1));
            true
        }
        Flow::Continue(1) => {
            shell.clear_flow();
            false
        }
        Flow::Continue(n) => {
            shell.set_flow(Flow::Continue(n - 1));
            true
        }
        Flow::Return(_) => true,
    }
}

// ---- command substitution ---------------------------------------------------

/// Run `src` as a subshell and capture its standard output, with trailing
/// newlines stripped (POSIX §2.6.3). Variable and working-directory mutations
/// are rolled back so the substitution does not affect the parent.
pub fn command_substitution(src: &str, shell: &mut Shell) -> String {
    let snapshot = shell.snapshot();
    let saved_flow = shell.flow();
    let output = capture(src, shell);
    shell.restore(snapshot);
    // A subshell's control flow does not escape into the parent.
    shell.set_flow(saved_flow);
    let trimmed = output.trim_end_matches('\n');
    trimmed.to_string()
}

fn capture(src: &str, shell: &mut Shell) -> String {
    let list = match parser::parse_source(src) {
        Parsed::Complete(list) => list,
        Parsed::Empty => return String::new(),
        Parsed::Incomplete => {
            eprintln!("rush: command substitution: unexpected end of input");
            return String::new();
        }
        Parsed::Error(msg) => {
            eprintln!("rush: {msg}");
            return String::new();
        }
    };

    let path = temp_path("cmdsub");
    let file = match File::create(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("rush: command substitution: {e}");
            return String::new();
        }
    };
    let io = IoEnv {
        fds: [FdSource::Inherit, FdSource::File(Arc::new(file)), FdSource::Inherit],
    };
    exec_list(&list, shell, &io);
    // All stages have exited; re-read the captured output from the start.
    let output = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    output
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(tag: &str) -> PathBuf {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    // `crate::sys::pid()` rather than `std::process::id()`, which panics on
    // Motor OS.
    std::env::temp_dir().join(format!("rush_{}_{}_{}", crate::sys::pid(), tag, n))
}
