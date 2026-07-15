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
//! Phase 7 adds asynchronous execution: `&` starts a background job (see
//! [`exec_background`] and [`crate::jobs`]), and a trap runs at the safe points
//! between commands (see [`crate::signal`]).
//!
//! Portability: everything is built on `std::process` + `std::fs` — pipelines
//! chain child stdio, redirections open files, here-docs feed a pipe, and
//! command substitution captures through a temp file. No `fork`/`dup2` syscalls,
//! keeping the executor portable to Motor OS.
//!
//! Phase 9 made the emulated subshell a real boundary for `exit`: with no `fork`
//! there is no process to end, so `exit` inside one unwinds to that boundary
//! ([`Flow::Exit`]) and becomes the subshell's status — `(exit 42)` reports 42
//! rather than killing the shell.
//!
//! Documented limits: per-stage `<&` `>&` and here-docs inside a pipeline, and
//! redirections to fds > 2, are not wired (Motor OS cannot hand a child an
//! arbitrary fd at all); `&` on anything but a lone external command delivers
//! isolation but not concurrency (there is no `fork` — see
//! [`exec_background`]).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ast::{
    AndOr, AndOrOp, CaseClause, Command as AstCommand, CompoundCommand, ForClause, FunctionBody,
    IfClause, List, ListItem, Pipeline, RedirOp, Redirect, Separator, SimpleCommand, WhileClause,
};
use crate::builtins::{self, Builtin};
use crate::expand;
use crate::jobs::{self, ChildIn, ChildOut, JobState};
use crate::options::Opt;
use crate::parser::{self, Parsed};
use crate::shell::{Flow, Shell};
use crate::signal;
use crate::sys::WaitOutcome;
use crate::token::{ExpansionKind, WordPart};

// ---- source-string entry points --------------------------------------------

pub fn run_script(fname: &str, shell: &mut Shell) -> i32 {
    let script = match std::fs::read_to_string(Path::new(fname)) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("rush: cannot open {fname}: {err}");
            // dash exits 2 when it cannot read its script operand.
            crate::exit(2);
        }
    };
    crate::verbose_echo(&script, shell);
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
        status = match item.sep {
            Separator::Seq => exec_and_or(&item.and_or, shell, io),
            Separator::Async => exec_background(&item.and_or, shell, io),
        };
        shell.set_status(status);
        // A pending `break`/`continue`/`return` stops the rest of the list.
        if shell.flow() != Flow::Normal {
            break;
        }
        // A safe point: run the trap for any signal that arrived while the
        // command ran (a handler can only set a flag — see `crate::signal`).
        signal::run_pending_traps(shell);
    }
    status
}

/// Run an and-or list asynchronously (`&`). Its status is 0 regardless, since
/// the shell does not wait for it (POSIX §2.9.3).
///
/// Only a lone external command can genuinely run in the background. Anything
/// else — a builtin, function, compound command, pipeline, or `&&` chain — would
/// have to keep executing shell code concurrently with the shell itself, which
/// needs a `fork` to isolate; rush has none (§3.4). Those run to completion
/// *here*, in an emulated subshell, and are then recorded as an already-finished
/// job. So on such a command `&` delivers isolation but not concurrency: a
/// documented degradation, and the reason `{ sleep 5; } &` blocks where
/// `sleep 5 &` does not.
fn exec_background(and_or: &AndOr, shell: &mut Shell, io: &IoEnv) -> i32 {
    let started = shell.jobs.started();
    let status = match lone_simple(and_or) {
        Some(simple) => {
            // POSIX §2.9.3: `&` runs the command in a subshell. For a lone
            // external command that subshell is a real child; for a builtin or
            // function rush runs it right here — but it is still marked as a
            // subshell, so an `exit` ends *that* and not the whole shell
            // (`exit 3 & echo hi` prints hi, as in dash).
            shell.enter_subshell();
            let mut status = exec_simple(simple, shell, io, Background::Yes);
            if let Flow::Exit(code) = shell.flow() {
                shell.clear_flow();
                status = code;
            }
            shell.exit_subshell();
            status
        }
        None => {
            let list = List(vec![ListItem {
                and_or: and_or.clone(),
                sep: Separator::Seq,
            }]);
            exec_subshell(&list, shell, io)
        }
    };
    // The spawn path registers its own job; this counter is how we tell that it
    // did, since the command may have turned out to be a builtin or a function
    // and run in place. Whatever ran in place is recorded as a finished job, so
    // that `$!` and `wait` still have something to name.
    if shell.jobs.started() == started {
        shell
            .jobs
            .add(describe(and_or), None, JobState::Done(status));
    }
    announce_job(shell);
    0
}

/// The lone simple command of an and-or list, if that is all it is — the only
/// shape [`exec_background`] can start asynchronously.
fn lone_simple(and_or: &AndOr) -> Option<&SimpleCommand> {
    if !and_or.rest.is_empty() || and_or.first.bang {
        return None;
    }
    match and_or.first.commands.as_slice() {
        [AstCommand::Simple(simple)] => Some(simple),
        _ => None,
    }
}

/// An interactive shell reports a job as it starts: `[1] 12345`.
fn announce_job(shell: &mut Shell) {
    if !shell.is_interactive() {
        return;
    }
    if let Some(job) = shell.jobs.iter().last() {
        println!("[{}] {}", job.id, job.pid);
    }
}

/// A short label for a backgrounded command, for `jobs` to print.
///
/// Reconstructed from the AST rather than kept as source text, which rush does
/// not retain: quoting is gone and an expansion is shown in its unexpanded form.
/// dash prints the real source text — but only when interactive, and rush's
/// approximation is more useful than dash's non-interactive blank.
fn describe(and_or: &AndOr) -> String {
    let Some(simple) = lone_simple(and_or) else {
        return "(subshell)".to_string();
    };
    simple
        .words
        .iter()
        .map(|word| {
            word.0
                .iter()
                .map(|part| match part {
                    WordPart::Literal { text, .. } => text.clone(),
                    WordPart::Expansion { kind, raw, .. } => match kind {
                        ExpansionKind::Parameter => format!("${raw}"),
                        ExpansionKind::Command => format!("$({raw})"),
                        ExpansionKind::Arithmetic => format!("$(({raw}))"),
                    },
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn exec_and_or(and_or: &AndOr, shell: &mut Shell, io: &IoEnv) -> i32 {
    // `set -e` applies only to the *last* command of an and-or list: in
    // `false && echo x` the `false` is a condition, so it must not exit the
    // shell (POSIX §2.8.1). `last` is the index of the final operand, with 0
    // meaning `first` is it.
    let last = and_or.rest.len();
    let mut status = exec_operand(&and_or.first, shell, io, last == 0);
    shell.set_status(status);
    if shell.flow() != Flow::Normal {
        return status;
    }
    for (i, (op, pipeline)) in and_or.rest.iter().enumerate() {
        let run = match op {
            AndOrOp::And => status == 0,
            AndOrOp::Or => status != 0,
        };
        if run {
            status = exec_operand(pipeline, shell, io, i + 1 == last);
            shell.set_status(status);
            if shell.flow() != Flow::Normal {
                return status;
            }
        }
    }
    status
}

/// Run one operand of an and-or list. A non-final operand — and any `!`-negated
/// pipeline, wherever it sits — is a condition context: `set -e` is suppressed
/// throughout it, including inside a compound operand such as `{ false; } && x`.
/// The final, un-negated operand is the one `set -e` acts on.
fn exec_operand(pipeline: &Pipeline, shell: &mut Shell, io: &IoEnv, is_last: bool) -> i32 {
    if !is_last || pipeline.bang {
        shell.enter_condition();
        let status = exec_pipeline(pipeline, shell, io);
        shell.exit_condition();
        return status;
    }
    let status = exec_pipeline(pipeline, shell, io);
    check_errexit(status, shell);
    status
}

/// Under `set -e`, a command that fails outside a condition context exits the
/// shell (running the `EXIT` trap first). Suppressed inside an emulated subshell,
/// where there is no `fork` to confine the exit to: the subshell's status
/// surfaces in the parent, whose own check then fires — so `(false)` and
/// `x=$(false)` still exit, while `echo $(false)` correctly does not.
fn check_errexit(status: i32, shell: &mut Shell) {
    if status != 0 && shell.errexit_applies() && !shell.in_subshell() {
        shell.set_status(status);
        signal::fire_exit_trap(shell);
        crate::exit(status);
    }
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
    // `set -n`: read and parse commands without executing them. An interactive
    // shell ignores it (POSIX), otherwise a typo would wedge the session — and
    // since `set +n` would itself not run, nothing could turn it back off.
    if shell.opts.get(Opt::NoExec) && !shell.is_interactive() {
        return 0;
    }
    match command {
        AstCommand::Simple(simple) => exec_simple(simple, shell, io, Background::No),
        AstCommand::Compound { kind, redirects } => exec_compound_cmd(kind, redirects, shell, io),
        AstCommand::Function { name, body } => {
            shell.define_function(name, Rc::new(body.clone()));
            0
        }
    }
}

/// Whether a simple command is being started in the background (`&`). Only
/// reaches as far as the external-command spawn: everything else runs the same
/// either way, and [`exec_background`] deals with the difference afterwards.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Background {
    No,
    Yes,
}

fn exec_simple(
    simple: &SimpleCommand,
    shell: &mut Shell,
    io: &IoEnv,
    background: Background,
) -> i32 {
    // POSIX §2.9.1: with no command name, the command's status is that of the
    // last command substitution it performed (`x=$(false)` fails), so watch for
    // one across this command's expansions.
    shell.clear_cmdsub_status();
    let assigns: Vec<(String, String)> = simple
        .assigns
        .iter()
        .map(|a| (a.name.clone(), expand::to_string(&a.value, shell)))
        .collect();

    let mut argv = Vec::new();
    for word in &simple.words {
        argv.extend(expand::to_fields(word, shell));
    }

    // An expansion error (`set -u`, `${x?}`) aborts the command before it runs.
    if shell.fatal_pending() {
        maybe_die_fatal(shell);
        return 2;
    }

    if argv.is_empty() {
        let mut status = shell.cmdsub_status().unwrap_or(0);
        trace(shell, &assigns, &[]);
        // Assignment-only command: assignments persist in the shell.
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

    trace(shell, &assigns, &argv);

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

    match (resolve_program(&argv[0], shell), background) {
        (Some(program), Background::Yes) => {
            spawn_background(&program, &argv, &assigns, &fds, shell);
            0
        }
        (Some(program), Background::No) => {
            spawn_external(&program, &argv[1..], &assigns, &fds, shell)
        }
        (None, _) => {
            let mut err = fds[2].err_writer();
            let _ = writeln!(err, "rush: {}: command not found", argv[0]);
            127
        }
    }
}

/// Start an external command as a background job, registering it so `$!`,
/// `jobs` and `wait` can see it.
fn spawn_background(
    program: &str,
    argv: &[String],
    env: &[(String, String)],
    fds: &[FdSource; 3],
    shell: &mut Shell,
) {
    let cmd = argv.join(" ");
    match jobs::spawn(
        program,
        &argv[1..],
        env,
        child_in(&fds[0], true),
        child_out(&fds[1]),
        child_out(&fds[2]),
    ) {
        Ok(child) => shell.jobs.add(cmd, Some(child), JobState::Running),
        // dash forks before it discovers the command is missing, so `$!` is set
        // and `wait` reports 127. Record the same, already-finished, job rather
        // than losing `$!` entirely.
        Err(e) => {
            let status = report_spawn_error(program, e, &fds[2]);
            shell.jobs.add(cmd, None, JobState::Done(status))
        }
    };
}

/// `set -x`: write the expanded command to stderr, prefixed by the expanded
/// `PS4` (default `+ `). Like dash, the words are printed unquoted and only
/// *simple* commands are traced — which covers loop and `if` bodies, since those
/// are made of simple commands.
fn trace(shell: &mut Shell, assigns: &[(String, String)], argv: &[String]) {
    if !shell.opts.get(Opt::XTrace) {
        return;
    }
    let ps4 = match shell.get("PS4") {
        Some(raw) => expand::expand_prompt(&raw, shell),
        None => "+ ".to_string(),
    };
    let words: Vec<String> = assigns
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .chain(argv.iter().cloned())
        .collect();
    eprintln!("{ps4}{}", words.join(" "));
}

/// If a special builtin or a variable assignment flagged a fatal error, a
/// *non-interactive* shell exits (POSIX §2.8.1); an interactive one continues.
fn maybe_die_fatal(shell: &mut Shell) {
    if let Some(code) = shell.take_fatal()
        && !shell.is_interactive()
        && !shell.in_subshell()
    {
        signal::fire_exit_trap(shell);
        crate::exit(code);
    }
}

/// Expand a leading command-position alias in place. See [`exec_simple`] for the
/// documented approximation.
fn expand_aliases(argv: &mut Vec<String>, shell: &Shell) {
    // A command whose words all expanded to nothing (`$unset | cat`) has no
    // name to look an alias up by. The caller then treats it as the empty
    // command it is; reaching in for `argv[0]` here would panic — as it did,
    // until Phase 9's fuzzer typed `$x|*&-};~` at it.
    if argv.is_empty() {
        return;
    }
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
            // The EXIT trap fires for the shell this ends — which, inside an
            // emulated subshell, is that subshell (its boundary fires the trap
            // it set for itself; see `fire_subshell_exit_trap`).
            if !shell.in_subshell() {
                signal::fire_exit_trap(shell);
            }
            builtin_exit(args, shell)
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
            let mut io = builtins::Io::new(&mut out, &mut err);
            let status = builtins::read(args, &mut *reader, &mut io, shell);
            io_status(&mut io, &argv[0], status)
        }
        _ => {
            let mut out = fds[1].out_writer();
            let mut err = fds[2].err_writer();
            let mut io = builtins::Io::new(&mut out, &mut err);
            let status = builtins::dispatch(b, args, &mut io, shell);
            io_status(&mut io, &argv[0], status)
        }
    }
}

/// Finish a builtin's output and fold an I/O failure into its exit status: a
/// builtin whose output could not be written has *not* succeeded, however happy
/// its own return value was (dash reports the same way). Without this, a broken
/// redirection target loses the output and still reports success.
fn io_status(io: &mut builtins::Io, name: &str, status: i32) -> i32 {
    if io.finish() {
        return status;
    }
    let _ = writeln!(io.err, "rush: {name}: I/O error");
    1
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
    crate::verbose_echo(&src, shell); // `set -v` echoes a sourced file too
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
        Some(program) => crate::exit(spawn_external(&program, &args[1..], &[], fds, shell)),
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
        Some(program) => spawn_external(&program, &rest[1..], &[], fds, shell),
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
        // An `exit` is not the function's to catch — it ends the shell, or the
        // emulated subshell standing in for one — so it passes straight through.
        Flow::Exit(n) => n,
        Flow::Normal => status,
    };

    shell.set_params(saved_params);
    status
}

// ---- builtins ---------------------------------------------------------------

/// `exit [n]` — end the shell with status `n` (default: `$?`).
///
/// Inside an emulated subshell it ends *that*, via [`Flow::Exit`]: with no
/// `fork`, the subshell has no process of its own to end, but its boundary is
/// standing in for one and can turn the unwind back into an exit status. This is
/// what makes `(exit 42); echo $?` print 42 instead of killing the shell, and
/// `x=$(exit 7)` set `$?` to 7 — both of which rush got wrong until Phase 9's
/// corpus put it next to dash.
fn builtin_exit(args: &[String], shell: &mut Shell) -> i32 {
    let code = if args.is_empty() {
        shell.status()
    } else if let Ok(exit_val) = args[0].as_str().parse::<i32>() {
        exit_val & 0xff
    } else {
        eprintln!("rush: exit: {}: numeric argument required", args[0]);
        2
    };
    if shell.in_subshell() {
        shell.set_flow(Flow::Exit(code));
        return code;
    }
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

/// Spawn an external command with the given fd sources, wait for it, and return
/// its status. Pending traps run if a signal interrupts the wait.
///
/// The spawning itself — and the stdio pumping Motor OS forces — lives in
/// [`crate::jobs`], which a background job shares.
fn spawn_external(
    program: &str,
    args: &[String],
    env: &[(String, String)],
    fds: &[FdSource; 3],
    shell: &mut Shell,
) -> i32 {
    let mut child = match jobs::spawn(
        program,
        args,
        env,
        child_in(&fds[0], false),
        child_out(&fds[1]),
        child_out(&fds[2]),
    ) {
        Ok(child) => child,
        Err(e) => return report_spawn_error(program, e, &fds[2]),
    };
    let status = loop {
        match child.wait() {
            WaitOutcome::Exited(status) => break status,
            // A trapped signal arrived; run it and resume waiting, so a trap
            // does not have to wait out a long-running foreground command.
            // (Only `wait` reports the interruption itself, per POSIX.)
            WaitOutcome::Interrupted => {
                signal::run_pending_traps(shell);
            }
        }
    };
    child.finish();
    status
}

/// Report a command that could not be started, to *its* standard error — which
/// `2>/dev/null` may well have pointed elsewhere — and give the status POSIX
/// §2.8.2 asks for: 127 when the command was not found, 126 when it was found
/// but could not be run.
fn report_spawn_error(program: &str, e: std::io::Error, err_fd: &FdSource) -> i32 {
    let mut err = err_fd.err_writer();
    match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidFilename => {
            let _ = writeln!(err, "rush: {program}: command not found");
            127
        }
        std::io::ErrorKind::PermissionDenied => {
            let _ = writeln!(err, "rush: {program}: permission denied");
            126
        }
        _ => {
            let _ = writeln!(err, "rush: {program}: {e}");
            126
        }
    }
}

/// The child stdin for an fd source. Background jobs read from nothing rather
/// than competing with the shell for the terminal (POSIX §2.9.3).
fn child_in(fd: &FdSource, background: bool) -> ChildIn {
    match fd {
        FdSource::Inherit if background => ChildIn::Null,
        FdSource::Inherit => ChildIn::Inherit,
        FdSource::File(f) => ChildIn::File(f.clone()),
        FdSource::Heredoc(b) => ChildIn::Heredoc(b.clone()),
    }
}

fn child_out(fd: &FdSource) -> ChildOut {
    match fd {
        FdSource::Inherit => ChildOut::Inherit,
        FdSource::File(f) => ChildOut::File(f.clone()),
        // A here-document as *output* is meaningless; behave like inherit.
        FdSource::Heredoc(_) => ChildOut::Inherit,
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
                                eprintln!(
                                    "rush: fd {m}: duplication of fds > 2 is not yet supported (Phase 3)"
                                );
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
                        let file = open_for(*op, &path, shell)?;
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

fn open_for(op: RedirOp, path: &str, shell: &Shell) -> Result<File, i32> {
    // `set -C` (noclobber): `>` must not truncate an existing *regular* file,
    // while `>|` overrides it. Non-regular targets (`> /dev/null`) are exempt,
    // so this checks the file type rather than mere existence.
    if op == RedirOp::Write
        && shell.opts.get(Opt::NoClobber)
        && std::fs::metadata(path).is_ok_and(|m| m.is_file())
    {
        eprintln!("rush: cannot create {path}: File exists");
        return Err(2);
    }
    let result = match op {
        RedirOp::Read => File::open(path),
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
        2
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
/// in-process. The pipeline's status is the last stage's — or, under
/// `set -o pipefail`, the last *failing* stage's.
fn run_pipeline(cmds: &[AstCommand], shell: &mut Shell, io: &IoEnv) -> i32 {
    let n = cmds.len();
    let mut prev = StageInput::Ambient;
    let mut last_status = 0;
    let mut pipefail_status = 0;

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
                trace(shell, &assigns, &argv);

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
                                spawn_external(p, &argv[1..], &assigns, &fds, shell)
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
        if status != 0 {
            pipefail_status = status;
        }
        if is_last {
            last_status = status;
        }
    }
    if shell.opts.get(Opt::PipeFail) {
        return pipefail_status;
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
/// any pending control flow are rolled back afterwards.
///
/// This boundary stands in for the process a `fork` would have made, which is
/// what lets an `exit` inside it be the *subshell's* exit: `(exit 42)` reports
/// 42 and the shell lives on, as in dash.
fn exec_subshell(list: &List, shell: &mut Shell, io: &IoEnv) -> i32 {
    let snapshot = shell.snapshot();
    shell.enter_subshell();
    let mut status = exec_list(list, shell, io);
    if let Flow::Exit(code) = shell.flow() {
        status = code;
    }
    fire_subshell_exit_trap(shell, io);
    shell.exit_subshell();
    shell.take_fatal(); // a fatal error stays inside the subshell
    shell.restore(snapshot);
    shell.clear_flow();
    status
}

/// Run an `EXIT` trap that a subshell set for itself, at the subshell's
/// boundary and with the subshell's own I/O environment — so
/// `x=$(trap 'echo t' EXIT; echo v)` captures both lines, as dash does.
///
/// A trap merely *inherited* from the parent is left alone: it is the parent's
/// to run when the parent exits (see [`Shell::exit_trap_set_here`]). Call this
/// while still inside the subshell, before its snapshot is restored.
fn fire_subshell_exit_trap(shell: &mut Shell, io: &IoEnv) {
    if !shell.exit_trap_set_here() {
        return;
    }
    let Some(action) = shell.get_trap("EXIT").map(String::from) else {
        return;
    };
    shell.clear_trap("EXIT");
    if action.is_empty() {
        return;
    }
    // The action sees, and cannot change, the status the subshell is ending with.
    let saved = shell.status();
    if let Parsed::Complete(list) = parser::parse_source(&action) {
        exec_list(&list, shell, io);
    }
    shell.set_status(saved);
}

fn exec_if(clause: &IfClause, shell: &mut Shell, io: &IoEnv) -> i32 {
    exec_condition(&clause.cond, shell, io);
    if shell.flow() != Flow::Normal {
        return shell.status();
    }
    if shell.status() == 0 {
        return exec_list(&clause.then_branch, shell, io);
    }
    for (cond, then) in &clause.elifs {
        exec_condition(cond, shell, io);
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
        exec_condition(&clause.cond, shell, io);
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

/// Run an `if`/`while`/`until` condition list. `set -e` is ignored throughout it
/// — including inside a compound condition like `if { false; }; then` — because
/// the whole point of the condition is to test a status.
fn exec_condition(list: &List, shell: &mut Shell, io: &IoEnv) -> i32 {
    shell.enter_condition();
    let status = exec_list(list, shell, io);
    shell.exit_condition();
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
        // Neither is the loop's to act on: leave them pending for the function
        // call / subshell boundary above, and stop iterating.
        Flow::Return(_) | Flow::Exit(_) => true,
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
    if let Flow::Exit(code) = shell.flow() {
        // `x=$(exit 7)`: the substitution's shell exited, and its status is what
        // the substitution reports.
        shell.set_status(code);
    }
    shell.exit_subshell();
    shell.take_fatal(); // a fatal error stays inside the substitution subshell
    shell.restore(snapshot);
    // A subshell's control flow does not escape into the parent, but its status
    // does: it becomes `$?` for a command that has no name of its own.
    shell.set_flow(saved_flow);
    shell.set_cmdsub_status(shell.status());
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
        fds: [
            FdSource::Inherit,
            FdSource::File(Arc::new(file)),
            FdSource::Inherit,
        ],
    };
    exec_list(&list, shell, &io);
    fire_subshell_exit_trap(shell, &io);
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
