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
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ast::{
    AndOr, AndOrOp, CaseClause, Command as AstCommand, CompoundCommand, ForClause, FunctionBody,
    IfClause, List, Pipeline, RedirOp, Redirect, SimpleCommand, WhileClause,
};
use crate::builtins::{self, Builtin};
use crate::expand;
use crate::parser::{self, Parsed};
use crate::shell::{Flow, Shell};

// ---- source-string entry points --------------------------------------------

pub fn run_command(args: Vec<String>, shell: &mut Shell) {
    let line = args.join(" ");
    let status = run_source(&line, shell);
    fire_exit_trap(shell);
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

/// Run the `EXIT` trap action, if any, and clear it so it fires exactly once.
/// Called when the shell itself is about to terminate (the `exit` builtin, the
/// end of `-c`/script execution). Signal traps await Phase 7.
pub fn fire_exit_trap(shell: &mut Shell) {
    if let Some(action) = shell.get_trap("EXIT").map(String::from) {
        shell.clear_trap("EXIT");
        if !action.is_empty() {
            run_source(&action, shell);
        }
    }
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
    /// A writer for this fd used as *standard output*: `Inherit` → the process's
    /// stdout. Backs builtin output so `echo hi > f` and `pwd` honor redirects.
    fn out_writer(&self) -> Box<dyn Write> {
        match self {
            FdSource::Inherit => Box::new(std::io::stdout()),
            FdSource::File(f) => f
                .try_clone()
                .map(|x| Box::new(x) as Box<dyn Write>)
                .unwrap_or_else(|_| Box::new(std::io::stdout())),
            FdSource::Heredoc(_) => Box::new(std::io::sink()),
        }
    }

    /// A writer for this fd used as *standard error*: `Inherit` → stderr.
    fn err_writer(&self) -> Box<dyn Write> {
        match self {
            FdSource::Inherit => Box::new(std::io::stderr()),
            FdSource::File(f) => f
                .try_clone()
                .map(|x| Box::new(x) as Box<dyn Write>)
                .unwrap_or_else(|_| Box::new(std::io::stderr())),
            FdSource::Heredoc(_) => Box::new(std::io::sink()),
        }
    }

    /// A reader for this fd used as *standard input* (for `read`): `Inherit` →
    /// stdin, a file → the file, a here-document → its body.
    fn reader(&self) -> Box<dyn Read> {
        match self {
            FdSource::Inherit => Box::new(std::io::stdin()),
            FdSource::File(f) => f
                .try_clone()
                .map(|x| Box::new(x) as Box<dyn Read>)
                .unwrap_or_else(|_| Box::new(std::io::empty())),
            FdSource::Heredoc(b) => Box::new(std::io::Cursor::new(b.as_bytes().to_vec())),
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
                // A variable assignment error aborts a non-interactive shell.
                eprintln!("rush: {e}");
                status = 2;
                shell.mark_fatal(2);
            }
        }
        if !simple.redirects.is_empty() {
            // Opening the targets is the observable effect (e.g. `> file`).
            if let Err(code) = build_fds(io, &simple.redirects, shell) {
                status = code;
            }
        }
        maybe_die_fatal(shell);
        return status;
    }

    // Alias expansion in command position (a documented-limits approximation:
    // the value is whitespace-split into words, without re-quoting or `$`
    // re-expansion, and a name is expanded at most once to avoid loops).
    expand_aliases(&mut argv, shell);

    // Redirections apply to every command, builtin or external; build them once
    // (this also gives the file-creation side effect for output-less builtins).
    let fds = match build_fds(io, &simple.redirects, shell) {
        Ok(fds) => fds,
        Err(code) => return code,
    };

    // `quit` is a rush convenience, not POSIX; keep it.
    if argv[0] == "quit" {
        crate::exit(0);
    }

    // Dispatch order (POSIX §2.9.1): a *special* builtin is found before any
    // function and cannot be shadowed; a *regular* builtin is found after
    // functions, so a like-named function shadows it.
    if let Some(b) = builtins::lookup(&argv[0]) {
        if builtins::is_special(b) {
            // A prefix assignment on a special builtin persists in the shell; an
            // assignment error there is fatal to a non-interactive shell.
            for (k, v) in &assigns {
                if let Err(e) = shell.set(k, v.clone()) {
                    eprintln!("rush: {e}");
                    shell.mark_fatal(2);
                }
            }
            maybe_die_fatal(shell);
            let status = exec_builtin(b, &argv, &fds, shell);
            maybe_die_fatal(shell);
            return status;
        }
        if let Some(body) = shell.get_function(&argv[0]) {
            return exec_function_call(&body, &argv, &assigns, &fds, shell);
        }
        // A regular builtin's prefix assignments are transient: visible to the
        // builtin, then restored.
        let saved = apply_temp_assigns(&assigns, shell);
        let status = exec_builtin(b, &argv, &fds, shell);
        restore_temp_assigns(saved, shell);
        return status;
    }

    if let Some(body) = shell.get_function(&argv[0]) {
        return exec_function_call(&body, &argv, &assigns, &fds, shell);
    }

    match resolve_program(&argv[0], shell) {
        Some(program) => spawn_external(&program, &argv[1..], &assigns, &fds),
        None => {
            let mut err = fds[2].err_writer();
            let _ = writeln!(err, "rush: {}: command not found", argv[0]);
            127
        }
    }
}

/// If a special builtin or a variable assignment flagged a fatal error, a
/// *non-interactive* shell exits (POSIX §2.8.1); an interactive one continues.
fn maybe_die_fatal(shell: &mut Shell) {
    if let Some(code) = shell.take_fatal()
        && !shell.is_interactive()
        && !shell.in_subshell()
    {
        fire_exit_trap(shell);
        crate::exit(code);
    }
}

/// Expand a leading command-position alias in place. See [`exec_simple`] for the
/// documented approximation.
fn expand_aliases(argv: &mut Vec<String>, shell: &Shell) {
    let mut seen: Vec<String> = Vec::new();
    while let Some(value) = shell.get_alias(&argv[0]) {
        if seen.iter().any(|n| n == &argv[0]) {
            break;
        }
        seen.push(argv[0].clone());
        let words: Vec<String> = value.split_whitespace().map(String::from).collect();
        if words.is_empty() {
            break;
        }
        let rest: Vec<String> = argv.split_off(1);
        *argv = words;
        argv.extend(rest);
    }
}

/// Save the pre-existing values of names about to be temporarily assigned (for a
/// regular builtin), so [`restore_temp_assigns`] can undo them.
fn apply_temp_assigns(
    assigns: &[(String, String)],
    shell: &mut Shell,
) -> Vec<(String, Option<String>, bool)> {
    let mut saved = Vec::with_capacity(assigns.len());
    for (k, v) in assigns {
        let prev = shell.get(k);
        let exported = shell.is_exported(k);
        saved.push((k.clone(), prev, exported));
        let _ = shell.set(k, v.clone());
    }
    saved
}

fn restore_temp_assigns(saved: Vec<(String, Option<String>, bool)>, shell: &mut Shell) {
    for (k, prev, exported) in saved.into_iter().rev() {
        match prev {
            Some(v) => {
                let _ = shell.set(&k, v);
                if exported {
                    let _ = shell.export(&k, None);
                }
            }
            None => {
                let _ = shell.unset(&k);
            }
        }
    }
}

// ---- builtin dispatch -------------------------------------------------------

/// Run a builtin as a simple command with its redirections resolved into `fds`.
/// The execution-coupled builtins (`.`, `eval`, `exec`, `command`, `read`) and
/// the divergent ones (`exit`) are handled here; the rest go to
/// [`builtins::dispatch`] with writers wired to fd 1 / fd 2.
fn exec_builtin(b: Builtin, argv: &[String], fds: &[FdSource; 3], shell: &mut Shell) -> i32 {
    let args = &argv[1..];
    match b {
        Builtin::Exit => {
            fire_exit_trap(shell);
            process_exit(args, shell)
        }
        Builtin::Return => builtin_return(args, shell),
        Builtin::Break => builtin_break(args, shell),
        Builtin::Continue => builtin_continue(args, shell),
        Builtin::Dot => builtin_dot(args, fds, shell),
        Builtin::Eval => builtin_eval(args, fds, shell),
        Builtin::Exec => builtin_exec(args, fds, shell),
        Builtin::Command => builtin_command(args, fds, shell),
        Builtin::Read => {
            let mut out = fds[1].out_writer();
            let mut err = fds[2].err_writer();
            let mut reader = fds[0].reader();
            let mut io = builtins::Io {
                out: &mut out,
                err: &mut err,
            };
            let status = builtins::read(args, &mut *reader, &mut io, shell);
            let _ = io.out.flush();
            status
        }
        _ => {
            let mut out = fds[1].out_writer();
            let mut err = fds[2].err_writer();
            let mut io = builtins::Io {
                out: &mut out,
                err: &mut err,
            };
            let status = builtins::dispatch(b, args, &mut io, shell);
            let _ = io.out.flush();
            status
        }
    }
}

/// `. file` (source): read `file`, parse it, and execute it in the current
/// shell. A `return` inside the sourced file returns from the `.`.
fn builtin_dot(args: &[String], fds: &[FdSource; 3], shell: &mut Shell) -> i32 {
    let file = match args.first() {
        Some(f) => f,
        None => {
            let mut err = fds[2].err_writer();
            let _ = writeln!(err, "rush: .: filename argument required");
            return 2;
        }
    };
    let path = if file.contains('/') {
        file.clone()
    } else {
        builtins::search_path(file, shell).unwrap_or_else(|| file.clone())
    };
    let src = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            let mut err = fds[2].err_writer();
            let _ = writeln!(err, "rush: .: cannot open {file}: {e}");
            // Failing to open the sourced file is fatal to a non-interactive shell.
            shell.mark_fatal(2);
            return 2;
        }
    };
    let status = source_string(&src, shell, &IoEnv { fds: fds.clone() });
    // A `return` unwinds to the `.` boundary.
    if let Flow::Return(n) = shell.flow() {
        shell.clear_flow();
        return n;
    }
    status
}

/// `eval [args…]` — concatenate the arguments and execute the result in the
/// current shell (control flow propagates outward: `eval return` returns).
fn builtin_eval(args: &[String], fds: &[FdSource; 3], shell: &mut Shell) -> i32 {
    if args.is_empty() {
        return 0;
    }
    let joined = args.join(" ");
    source_string(&joined, shell, &IoEnv { fds: fds.clone() })
}

/// `exec [command [args…]]` — with a command, replace the shell: Motor OS has no
/// `execve`, so this spawns the command with the current fds and exits with its
/// status (a documented emulation). With only redirections, the fds were already
/// opened by `build_fds`; persistent redirection of the shell is not supported.
fn builtin_exec(args: &[String], fds: &[FdSource; 3], shell: &mut Shell) -> ! {
    if args.is_empty() {
        // Redirection-only exec: no persistent effect (no dup2). The file
        // side-effects already happened when the redirects were built.
        crate::exit(shell.status());
    }
    match resolve_program(&args[0], shell) {
        Some(program) => crate::exit(spawn_external(&program, &args[1..], &[], fds)),
        None => {
            let mut err = fds[2].err_writer();
            let _ = writeln!(err, "rush: exec: {}: not found", args[0]);
            crate::exit(127);
        }
    }
}

/// `command [-v|-V] [-p] name [args…]` — run `name` ignoring shell functions, or
/// (with `-v`/`-V`) describe it.
fn builtin_command(args: &[String], fds: &[FdSource; 3], shell: &mut Shell) -> i32 {
    let mut verbose = false;
    let mut describe = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-v" => describe = true,
            "-V" => {
                describe = true;
                verbose = true;
            }
            "-p" => {} // use the default PATH; we do not special-case it
            "--" => {
                i += 1;
                break;
            }
            s if s.starts_with('-') && s.len() > 1 => {
                let mut err = fds[2].err_writer();
                let _ = writeln!(err, "rush: command: {s}: invalid option");
                return 2;
            }
            _ => break,
        }
        i += 1;
    }
    let rest = &args[i..];
    if describe {
        let mut out = fds[1].out_writer();
        let mut err = fds[2].err_writer();
        let mut status = 0;
        for name in rest {
            let (line, found) = builtins::command_describe(name, shell, verbose);
            if let Some(l) = line {
                let _ = writeln!(out, "{l}");
            }
            if !found {
                // dash returns 127 for an unresolved name.
                status = 127;
                if verbose {
                    let _ = writeln!(err, "rush: {name}: not found");
                }
            }
        }
        let _ = out.flush();
        return status;
    }
    if rest.is_empty() {
        return 0;
    }
    // Run `name`: a builtin (bypassing functions) or an external program.
    if let Some(b) = builtins::lookup(&rest[0]) {
        return exec_builtin(b, rest, fds, shell);
    }
    match resolve_program(&rest[0], shell) {
        Some(program) => spawn_external(&program, &rest[1..], &[], fds),
        None => {
            let mut err = fds[2].err_writer();
            let _ = writeln!(err, "rush: {}: command not found", rest[0]);
            127
        }
    }
}

/// Parse and execute `src` in the current shell with the given I/O environment.
/// Used by `.` (source) and `eval`.
fn source_string(src: &str, shell: &mut Shell, io: &IoEnv) -> i32 {
    match parser::parse_source(src) {
        Parsed::Complete(list) => exec_list(&list, shell, io),
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

/// Spawn an external command with the given fd sources and return its status.
///
/// Motor OS's process spawn only accepts `INHERIT` / `NULL` / `MAKE_PIPE` for a
/// child's stdio — a real file descriptor cannot be handed to a child. So any
/// file-backed or here-document stdio is wired as a pipe and *pumped by this
/// process* on a thread (copying between the file/body and the child's pipe).
/// `Inherit` stays a true inherit. Portable to the Unix host, which also accepts
/// this.
fn spawn_external(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    fds: &[FdSource; 3],
) -> i32 {
    let stdin = ExtIn::from_fd(&fds[0]);
    let stdout = ExtOut::from_fd(&fds[1]);
    let stderr = ExtOut::from_fd(&fds[2]);
    run_external(program, args, env, stdin, stdout, stderr)
}

/// A child's standard input on Motor OS: inherited, or piped and fed by us.
enum ExtIn {
    Inherit,
    File(Arc<File>),
    Heredoc(Arc<String>),
}

/// A child's standard output/error on Motor OS: inherited, or pumped into a
/// file (a captured pipeline stage's output is a temp file, so it is `File` too).
enum ExtOut {
    Inherit,
    File(Arc<File>),
}

impl ExtIn {
    fn from_fd(fd: &FdSource) -> Self {
        match fd {
            FdSource::Inherit => ExtIn::Inherit,
            FdSource::File(f) => ExtIn::File(f.clone()),
            FdSource::Heredoc(b) => ExtIn::Heredoc(b.clone()),
        }
    }
}

impl ExtOut {
    fn from_fd(fd: &FdSource) -> Self {
        match fd {
            FdSource::Inherit => ExtOut::Inherit,
            FdSource::File(f) => ExtOut::File(f.clone()),
            // A here-document as *output* is meaningless; behave like inherit.
            FdSource::Heredoc(_) => ExtOut::Inherit,
        }
    }
}

/// Spawn `program`, pumping any non-inherited stdio through pipes on helper
/// threads (Motor OS children accept only inherit/null/pipe stdio). Returns the
/// exit status.
fn run_external(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    stdin: ExtIn,
    stdout: ExtOut,
    stderr: ExtOut,
) -> i32 {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    // Motor OS's sys-io is not reentrant under concurrent filesystem access from
    // one process, so rush keeps all of its own FS I/O on this thread: read any
    // file-backed input into memory *before* the child runs, and write captured
    // output to files *after* it exits. The helper threads below touch only
    // pipes while the child is running.
    let feed: Option<Vec<u8>> = match &stdin {
        ExtIn::Inherit => None,
        ExtIn::Heredoc(b) => Some(b.as_bytes().to_vec()),
        ExtIn::File(f) => Some(read_all(f)),
    };
    let capture_out = matches!(stdout, ExtOut::File(_));
    let capture_err = matches!(stderr, ExtOut::File(_));

    cmd.stdin(if feed.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    cmd.stdout(if capture_out {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    cmd.stderr(if capture_err {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return spawn_error(program, e),
    };

    // Feed stdin bytes on a thread (pipe writes only).
    let feed_thread = match (feed, child.stdin.take()) {
        (Some(bytes), Some(mut sink)) => Some(std::thread::spawn(move || {
            let _ = sink.write_all(&bytes);
        })),
        _ => None,
    };
    // Capture stdout / stderr on threads (pipe reads only).
    let out_thread = child
        .stdout
        .take()
        .filter(|_| capture_out)
        .map(|mut o| std::thread::spawn(move || read_stream(&mut o)));
    let err_thread = child
        .stderr
        .take()
        .filter(|_| capture_err)
        .map(|mut e| std::thread::spawn(move || read_stream(&mut e)));

    let status = match child.wait() {
        Ok(s) => s.code().unwrap_or(128),
        Err(err) => {
            eprintln!("rush: {err}");
            126
        }
    };
    if let Some(t) = feed_thread {
        let _ = t.join();
    }
    let out_bytes = out_thread.map(|t| t.join().unwrap_or_default());
    let err_bytes = err_thread.map(|t| t.join().unwrap_or_default());

    // Now (child gone, no other FS in flight) write the captured output.
    if let (ExtOut::File(f), Some(bytes)) = (stdout, out_bytes) {
        write_all(&f, &bytes);
    }
    if let (ExtOut::File(f), Some(bytes)) = (stderr, err_bytes) {
        write_all(&f, &bytes);
    }
    status
}

/// Read an entire file into memory (single-threaded FS access).
fn read_all(f: &Arc<File>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Ok(mut c) = f.try_clone() {
        let _ = c.read_to_end(&mut buf);
    }
    buf
}

/// Read a pipe to end (no FS).
fn read_stream(r: &mut dyn Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = r.read_to_end(&mut buf);
    buf
}

/// Append `bytes` to a file (single-threaded FS access).
fn write_all(f: &Arc<File>, bytes: &[u8]) {
    if let Ok(mut c) = f.try_clone() {
        let _ = c.write_all(bytes);
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

/// What feeds a pipeline stage's standard input.
enum StageInput {
    /// The pipeline's own stdin (first stage).
    Ambient,
    /// Bytes produced by an upstream stage (captured through a temp file).
    Buffer(Vec<u8>),
}

/// Run a multi-stage pipeline. Every stage runs in an emulated subshell whose
/// stdin is staged through a temp file (so `read` in a `while` loop advances)
/// and whose stdout is captured for the next stage — or the real fd 1 when it is
/// last. External stages spawn the program (with file-backed stdio pumped
/// through pipes, per Motor OS's constraints); builtins/compounds/functions run
/// in-process. The pipeline's status is the last stage's.
fn run_pipeline(cmds: &[AstCommand], shell: &mut Shell, io: &IoEnv) -> i32 {
    let n = cmds.len();
    let mut prev = StageInput::Ambient;
    let mut last_status = 0;

    for (i, command) in cmds.iter().enumerate() {
        let is_last = i == n - 1;
        let taken = std::mem::replace(&mut prev, StageInput::Ambient);

        let (status, next) = match command {
            AstCommand::Simple(simple) => {
                let assigns: Vec<(String, String)> = simple
                    .assigns
                    .iter()
                    .map(|a| (a.name.clone(), expand::to_string(&a.value, shell)))
                    .collect();
                let mut argv = Vec::new();
                for word in &simple.words {
                    argv.extend(expand::to_fields(word, shell));
                }
                expand_aliases(&mut argv, shell);

                let external = !argv.is_empty()
                    && builtins::lookup(&argv[0]).is_none()
                    && shell.get_function(&argv[0]).is_none();
                let program = if external {
                    resolve_program(&argv[0], shell)
                } else {
                    None
                };

                run_inproc_stage(taken, is_last, io, shell, |shell, sio| {
                    if external {
                        match &program {
                            Some(p) => {
                                let fds = match build_fds(sio, &simple.redirects, shell) {
                                    Ok(f) => f,
                                    Err(code) => return code,
                                };
                                spawn_external(p, &argv[1..], &assigns, &fds)
                            }
                            None => {
                                eprintln!("rush: {}: command not found", argv[0]);
                                127
                            }
                        }
                    } else {
                        run_simple_inproc(simple, &argv, &assigns, sio, shell)
                    }
                })
            }
            // A compound command as a pipeline stage.
            _ => run_inproc_stage(taken, is_last, io, shell, |shell, sio| {
                exec_command(command, shell, sio)
            }),
        };

        prev = next;
        if is_last {
            last_status = status;
        }
    }
    last_status
}

/// Run one simple command (a builtin, function, or assignment-only) as an
/// in-process pipeline stage, over the stage's I/O environment `sio`.
fn run_simple_inproc(
    simple: &SimpleCommand,
    argv: &[String],
    assigns: &[(String, String)],
    sio: &IoEnv,
    shell: &mut Shell,
) -> i32 {
    if argv.is_empty() {
        // Assignment-only stage (subshell: discarded by the caller's restore).
        for (k, v) in assigns {
            let _ = shell.set(k, v.clone());
        }
        return 0;
    }
    let fds = match build_fds(sio, &simple.redirects, shell) {
        Ok(f) => f,
        Err(code) => return code,
    };
    if let Some(b) = builtins::lookup(&argv[0]) {
        return run_builtin_pipeline_safe(b, argv, assigns, &fds, shell);
    }
    if let Some(body) = shell.get_function(&argv[0]) {
        return exec_function_call(&body, argv, assigns, &fds, shell);
    }
    // Unreachable: run_pipeline only routes builtins/functions here.
    127
}

/// Run a builtin as a pipeline-stage subshell, taming the builtins that would
/// otherwise diverge or escape: `exit` yields the subshell's status without
/// killing the shell; loop/function control is contained; and the
/// execution-coupled `.`/`eval`/`exec`/`command` are refused (documented gap).
fn run_builtin_pipeline_safe(
    b: Builtin,
    argv: &[String],
    assigns: &[(String, String)],
    fds: &[FdSource; 3],
    shell: &mut Shell,
) -> i32 {
    match b {
        Builtin::Exit => argv
            .get(1)
            .and_then(|a| a.parse::<i32>().ok())
            .map(|n| n & 0xff)
            .unwrap_or_else(|| shell.status()),
        Builtin::Return | Builtin::Break | Builtin::Continue => 0,
        Builtin::Dot | Builtin::Eval | Builtin::Exec | Builtin::Command => {
            let mut err = fds[2].err_writer();
            let _ = writeln!(err, "rush: {}: not supported as a pipeline stage", argv[0]);
            2
        }
        _ => {
            let saved = apply_temp_assigns(assigns, shell);
            let status = exec_builtin(b, argv, fds, shell);
            restore_temp_assigns(saved, shell);
            status
        }
    }
}

/// Drive an in-process pipeline stage: materialize its upstream input into a
/// temp file (a real file so successive `read`s share an advancing offset),
/// capture its stdout for the next stage (or send it to the real fd 1 when
/// last), and run `body` in an emulated subshell (state snapshot/restore so the
/// stage cannot leak). Returns (status, input-for-next-stage).
fn run_inproc_stage(
    input: StageInput,
    is_last: bool,
    io: &IoEnv,
    shell: &mut Shell,
    body: impl FnOnce(&mut Shell, &IoEnv) -> i32,
) -> (i32, StageInput) {
    // Standard input: the ambient fd for the first stage, else the upstream
    // bytes staged through a temp file.
    let (stdin_fd, in_path) = match input {
        StageInput::Ambient => (io.fds[0].clone(), None),
        StageInput::Buffer(bytes) => bytes_to_fd(bytes),
    };
    // Standard output: the real fd 1 when last, else a capture temp file.
    let (stdout_fd, out_path) = if is_last {
        (io.fds[1].clone(), None)
    } else {
        match temp_capture_file() {
            Some((fd, path)) => (fd, Some(path)),
            None => (io.fds[1].clone(), None),
        }
    };
    let sio = IoEnv {
        fds: [stdin_fd, stdout_fd, io.fds[2].clone()],
    };

    let snapshot = shell.snapshot();
    let saved_flow = shell.flow();
    shell.enter_subshell();
    let status = body(shell, &sio);
    shell.exit_subshell();
    shell.take_fatal(); // a fatal error stays inside the pipeline-stage subshell
    shell.restore(snapshot);
    shell.set_flow(saved_flow);
    drop(sio); // close the temp-file handles before reading/removing them

    if let Some(p) = in_path {
        let _ = std::fs::remove_file(&p);
    }
    let next = match out_path {
        Some(p) => {
            let bytes = std::fs::read(&p).unwrap_or_default();
            let _ = std::fs::remove_file(&p);
            StageInput::Buffer(bytes)
        }
        None => StageInput::Ambient,
    };
    (status, next)
}

/// Stage `bytes` through a temp file opened for reading. Returns a file-backed
/// [`FdSource`] (whose successive `try_clone`s share the read offset) and the
/// path to clean up. Falls back to an empty here-doc reader on failure.
fn bytes_to_fd(bytes: Vec<u8>) -> (FdSource, Option<PathBuf>) {
    let path = temp_path("pin");
    if std::fs::write(&path, &bytes).is_ok()
        && let Ok(f) = File::open(&path)
    {
        return (FdSource::File(Arc::new(f)), Some(path));
    }
    (FdSource::Heredoc(Arc::new(String::new())), None)
}

/// Create a temp file to capture a stage's stdout, returning a writable
/// [`FdSource`] and its path.
fn temp_capture_file() -> Option<(FdSource, PathBuf)> {
    let path = temp_path("pout");
    File::create(&path)
        .ok()
        .map(|f| (FdSource::File(Arc::new(f)), path))
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
    shell.enter_subshell();
    let status = exec_list(list, shell, io);
    shell.exit_subshell();
    shell.take_fatal(); // a fatal error stays inside the subshell
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
    shell.enter_subshell();
    let output = capture(src, shell);
    shell.exit_subshell();
    shell.take_fatal(); // a fatal error stays inside the substitution subshell
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
