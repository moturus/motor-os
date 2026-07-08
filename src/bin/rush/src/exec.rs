//! AST executor (Phase 3).
//!
//! Walks the [`crate::ast`] tree over a persistent [`Shell`], driving the
//! [`crate::expand`] engine for every word: it runs lists (`;`/`&`/newline),
//! and-or lists (`&&`/`||`), multi-stage pipelines, and simple commands with
//! variable assignments and the full redirection set (files, `2>&1`-style fd
//! duplication, and here-documents). Command substitution runs the inner script
//! in an in-process subshell whose variable/cwd mutations are rolled back.
//!
//! Portability: everything is built on `std::process` + `std::fs` — pipelines
//! chain child stdio, redirections open files, here-docs feed a pipe, and
//! command substitution captures through a temp file. No `fork`/`dup2` syscalls,
//! keeping the executor portable to Motor OS.
//!
//! Documented Phase 3 limits: pipeline stages are external commands (the only
//! builtins — `cd`/`exit`/`quit` — are nonsensical mid-pipeline); per-stage `<&`
//! `>&` and here-docs inside a pipeline, and redirections to fds > 2, are not
//! wired; background `&` runs synchronously (Phase 7); `${x:?}` diagnoses but
//! does not abort the shell.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ast::{AndOr, AndOrOp, Command as AstCommand, List, Pipeline, RedirOp, Redirect, SimpleCommand};
use crate::expand;
use crate::parser::{self, Parsed};
use crate::shell::Shell;

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
    exec_list(list, shell, &IoEnv::inherit())
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
    }
    status
}

fn exec_and_or(and_or: &AndOr, shell: &mut Shell, io: &IoEnv) -> i32 {
    let mut status = exec_pipeline(&and_or.first, shell, io);
    shell.set_status(status);
    for (op, pipeline) in &and_or.rest {
        let run = match op {
            AndOrOp::And => status == 0,
            AndOrOp::Or => status != 0,
        };
        if run {
            status = exec_pipeline(pipeline, shell, io);
            shell.set_status(status);
        }
    }
    status
}

fn exec_pipeline(pipeline: &Pipeline, shell: &mut Shell, io: &IoEnv) -> i32 {
    // Pipeline negation (`!`) is finalized in Phase 4.
    match pipeline.commands.as_slice() {
        [single] => exec_command(single, shell, io),
        cmds => run_pipeline(cmds, shell, io),
    }
}

fn exec_command(command: &AstCommand, shell: &mut Shell, io: &IoEnv) -> i32 {
    match command {
        AstCommand::Simple(simple) => exec_simple(simple, shell, io),
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

    match argv[0].as_str() {
        "cd" => builtin_cd(&argv[1..]),
        "quit" => crate::exit(0),
        "exit" => process_exit(&argv[1..], shell),
        _ => {
            let fds = match build_fds(io, &simple.redirects, shell) {
                Ok(fds) => fds,
                Err(code) => return code,
            };
            spawn_external(&argv, &assigns, &fds)
        }
    }
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

// ---- external commands ------------------------------------------------------

fn spawn_external(argv: &[String], env: &[(String, String)], fds: &[FdSource; 3]) -> i32 {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
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
        Err(e) => spawn_error(&argv[0], e),
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
        let AstCommand::Simple(simple) = command;

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

        let mut cmd = Command::new(&argv[0]);
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
                let _ = spawn_error(&argv[0], e);
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

// ---- command substitution ---------------------------------------------------

/// Run `src` as a subshell and capture its standard output, with trailing
/// newlines stripped (POSIX §2.6.3). Variable and working-directory mutations
/// are rolled back so the substitution does not affect the parent.
pub fn command_substitution(src: &str, shell: &mut Shell) -> String {
    let snapshot = shell.snapshot();
    let output = capture(src, shell);
    shell.restore(snapshot);
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
