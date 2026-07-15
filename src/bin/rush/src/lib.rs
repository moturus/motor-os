//! rush — a POSIX-ish shell.
//!
//! This module owns *invocation*: turning `argv` into a [`Mode`] plus the
//! [`Shell`] state it runs over, and driving the interactive read-parse-execute
//! loop. POSIX §2.5.1 gives three shapes, all supported here:
//!
//! ```text
//! rush [options] [command_file [argument…]]     # run a script
//! rush [options] -c command_string [name [argument…]]
//! rush [options] -s [argument…]                 # read commands from stdin
//! ```
//!
//! Options are parsed against the one table in [`crate::options`]: clustered
//! (`-ex`), `+`-form (`+x`), `-o name` / `+o name`, and `--` to end them.
//!
//! rush extensions, deliberately outside POSIX and documented as such:
//! `--piped` (an internal mode: the interactive loop over a pipe, with no
//! terminal control) and the colored default `PS1`.

mod arith;
mod ast;
mod builtins;
mod exec;
mod expand;
mod glob;
mod jobs;
mod lexer;
mod options;
mod parser;
mod shell;
mod signal;
mod sys;
mod term;
mod token;

use options::{Opt, Options};
use shell::Shell;

/// Whether `name` is a valid shell variable name (POSIX "name": an underscore or
/// alphabetic first character, then alphanumerics/underscores).
pub(crate) fn is_valid_var_name(name: &str) -> bool {
    if name.is_empty() || !name.is_ascii() {
        return false;
    }
    let first: char = name.as_bytes()[0].into();
    if !(first.is_alphabetic() || first == '_') {
        return false;
    }
    name[1..]
        .bytes()
        .all(|b| (b as char).is_alphanumeric() || b == b'_')
}

struct Cleanup {}
impl Drop for Cleanup {
    fn drop(&mut self) {
        term::on_exit();
    }
}

/// What the shell was asked to run.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    /// `-c string`: run the string and exit.
    Command(String),
    /// A `command_file` operand: run the script and exit.
    Script(String),
    /// `-s`, or no operands: read commands from standard input. Interactive when
    /// stdin is a terminal or `-i` was given.
    Stdin,
}

/// The result of parsing `argv`: everything needed to start the shell.
pub struct Invocation {
    pub mode: Mode,
    /// `$0`.
    pub name: String,
    /// `$1`, `$2`, …
    pub params: Vec<String>,
    opts: Options,
    /// `--piped`: run the interactive loop without terminal control.
    piped: bool,
}

fn exit(code: i32) -> ! {
    term::on_exit();
    std::process::exit(code)
}

/// A fatal invocation error: report it and exit 2, before any shell state exists.
fn usage_error(msg: &str) -> ! {
    eprintln!("rush: {msg}");
    eprintln!("usage: rush [options] [command_file [argument...]]");
    eprintln!("       rush [options] -c command_string [name [argument...]]");
    eprintln!("       rush [options] -s [argument...]");
    std::process::exit(2)
}

/// Parse `argv` per POSIX §2.5.1.
///
/// The five documented breaks from rush's pre-Phase-6 parsing, each of which
/// made it diverge from every other `sh`: `-c` no longer joins extra operands
/// into the command string (they become `$0`/`$1`…); script operands now set the
/// positional parameters; `-h` is no longer "print usage" (POSIX reserves the
/// letter for command hashing); `-i script` is gone (an interactive shell now
/// sources `$ENV` instead); and a leading `VAR=val` operand no longer switches
/// the shell into command mode (it names a *file*, as POSIX says).
pub fn parse_args(argv: Vec<String>) -> Invocation {
    let mut opts = Options::new();
    let mut piped = false;
    let mut want_command = false;
    let mut i = 1;

    // ---- options ----
    while i < argv.len() {
        let arg = argv[i].clone();
        if arg == "--" {
            i += 1;
            break;
        }
        // A rush-internal extension, spelled as a long option so it cannot be
        // mistaken for a POSIX option cluster — which is exactly why the old
        // `-piped` had to be renamed: it now parses as `-p -i -p -e -d`.
        if arg == "--piped" {
            piped = true;
            i += 1;
            continue;
        }
        let on = match arg.chars().next() {
            Some('-') if arg.len() > 1 => true,
            Some('+') if arg.len() > 1 => false,
            // A bare `-`/`+`, or anything else: this is the first operand.
            _ => break,
        };
        for ch in arg[1..].chars() {
            match ch {
                'o' => {
                    // `-o name`: the name is the next argv element. (A bare `-o`
                    // lists options, but at invocation there is nothing to list
                    // to yet, so the name is required here.)
                    i += 1;
                    match argv.get(i) {
                        Some(name) => match Options::by_name(name) {
                            Some(opt) => opts.set(opt, on),
                            None => usage_error(&format!("illegal option -o {name}")),
                        },
                        None => usage_error("-o requires an option name"),
                    }
                }
                // `-c` only *marks* that the first operand is the command
                // string; it does not consume the next argv element itself.
                // That is what makes `rush -c -- 'echo hi'` — the form libc's
                // system()/popen() emit — parse correctly.
                'c' => want_command = true,
                _ => match Options::by_letter(ch) {
                    Some(opt) => opts.set(opt, on),
                    None => {
                        let sign = if on { '-' } else { '+' };
                        usage_error(&format!("illegal option {sign}{ch}"));
                    }
                },
            }
        }
        i += 1;
    }
    let mut operands = argv[i.min(argv.len())..].to_vec();

    // ---- mode and positional parameters ----
    // `$0` is the command name for `-c` (operand 2), the script path for a
    // command_file, and the shell's own name otherwise.
    let self_name = argv.first().cloned().unwrap_or_else(|| "rush".to_string());
    if want_command {
        if operands.is_empty() {
            usage_error("-c requires an argument");
        }
        // `-c string [name [args…]]`: the string is operand 1, and the rest name
        // the shell and its positional parameters.
        let string = operands.remove(0);
        let mut rest = operands.into_iter();
        let name = rest.next().unwrap_or(self_name);
        return Invocation {
            mode: Mode::Command(string),
            name,
            params: rest.collect(),
            opts,
            piped,
        };
    }
    if opts.get(Opt::Stdin) || operands.is_empty() {
        // "If there are no operands and -c is not specified, -s is assumed."
        opts.set(Opt::Stdin, true);
        return Invocation {
            mode: Mode::Stdin,
            name: self_name,
            params: operands,
            opts,
            piped,
        };
    }
    // `command_file [args…]`: the script names the shell (`$0`) too.
    let script = operands.remove(0);
    Invocation {
        mode: Mode::Script(script.clone()),
        name: script,
        params: operands,
        opts,
        piped,
    }
}

pub fn execute(inv: Invocation) {
    if std::env::current_dir().is_err() {
        std::env::set_current_dir(std::path::Path::new("/")).unwrap();
    }

    // The single persistent shell state, carried across the whole session.
    let mut sh = Shell::new();
    sh.set_name(inv.name);
    sh.set_params(inv.params);
    sh.opts = inv.opts;
    sh.init_environment();

    // A shell is interactive when asked to be (`-i`), or when it would read
    // commands from a terminal (POSIX §2.5.1) — which `--piped` stands in for.
    // An interactive shell reports and continues where a script would abort.
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let interactive =
        sh.opts.get(Opt::Interactive) || (inv.mode == Mode::Stdin && (inv.piped || stdin_is_tty));
    sh.set_interactive(interactive);

    if interactive {
        source_startup_files(&mut sh);
    }

    let status = match inv.mode {
        Mode::Command(string) => exec::run_source(&string, &mut sh),
        Mode::Script(script) => exec::run_script(&script, &mut sh),
        Mode::Stdin if interactive => {
            // `--piped`, and `-i` over a pipe, run the interactive loop without
            // terminal control: there is no cursor to query or line to redraw.
            interactive_loop(&mut sh, inv.piped || !stdin_is_tty);
        }
        // Non-interactive stdin: read the whole script, then run it.
        Mode::Stdin => {
            let mut src = String::new();
            match std::io::Read::read_to_string(&mut std::io::stdin(), &mut src) {
                Ok(_) => {
                    verbose_echo(&src, &sh);
                    exec::run_source(&src, &mut sh)
                }
                Err(e) => {
                    eprintln!("rush: cannot read standard input: {e}");
                    2
                }
            }
        }
    };
    signal::fire_exit_trap(&mut sh);
    exit(status);
}

/// `set -v`: echo shell input to stderr as it is read.
///
/// rush reads a whole script before parsing it (it has no incremental reader),
/// so it echoes the text in one piece where dash interleaves line-by-line with
/// the output. The interactive loop, which *does* read a line at a time, echoes
/// each line as dash does. A documented divergence.
pub(crate) fn verbose_echo(src: &str, sh: &Shell) {
    if sh.opts.get(Opt::Verbose) {
        eprint!("{src}");
        if !src.ends_with('\n') {
            eprintln!();
        }
    }
}

/// An interactive shell expands `$ENV` and sources the file it names (POSIX
/// §2.5.3); a *login* shell (conventionally, `$0` starting with `-`) first reads
/// the system and user profiles. Missing files are not an error.
///
/// This replaces rush's old `-i <script>` flag: `ENV=/sys/cfg/rush.cfg rush -i`
/// is the portable spelling of what that flag did.
fn source_startup_files(sh: &mut Shell) {
    if sh.name().starts_with('-') {
        for profile in ["/etc/profile", "$HOME/.profile"] {
            source_if_present(profile, sh);
        }
    }
    if let Some(env) = sh.get("ENV") {
        source_if_present(&env, sh);
    }
}

fn source_if_present(raw: &str, sh: &mut Shell) {
    let path = expand::expand_prompt(raw, sh); // parameter expansion, per POSIX
    if path.is_empty() || !std::path::Path::new(&path).is_file() {
        return;
    }
    exec::run_script(&path, sh);
}

/// The read-parse-execute loop.
///
/// Input is accumulated across lines so the lexer sees whole multi-line
/// constructs (here-docs, continuations): when the buffer neither lexes nor
/// parses to completion, another line is read with the `PS2` prompt.
fn interactive_loop(sh: &mut Shell, piped: bool) -> ! {
    let _cleanup = Cleanup {}; // On panic, restore the terminal state.
    term::init(piped);

    let mut buf = String::new();
    loop {
        // A safe point: run the trap for a `^C` at the prompt, or for a signal
        // that arrived while the last command ran.
        signal::run_pending_traps(sh);
        // Collect any background job that finished while we were busy. Nothing
        // else reaps in an interactive session — `wait`/`jobs` might never be
        // run — and an unreaped child costs a process slot until the shell
        // exits (on Motor OS, also its handle and pump threads).
        sh.jobs.poll();

        let prompt = prompt_string(if buf.is_empty() { "PS1" } else { "PS2" }, sh);
        let line = if buf.is_empty() {
            term::readline(&prompt)
        } else {
            term::readline_continuation(&prompt)
        };
        let Some(line) = line else {
            // `^C`. Abandon the whole command being typed, not just the line it
            // was on, and report the status a shell gives an interrupted
            // command (128 + SIGINT). The trap runs at the top of the loop.
            buf.clear();
            sh.set_status(128 + signal::SIGINT);
            continue;
        };
        verbose_echo(&line, sh);
        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(line.as_str());

        match parser::parse_source(&buf) {
            parser::Parsed::Incomplete => continue, // read a PS2 line
            parser::Parsed::Empty => buf.clear(),
            parser::Parsed::Error(msg) => {
                eprintln!("rush: {msg}");
                buf.clear();
            }
            parser::Parsed::Complete(list) => {
                if buf.contains('\n') {
                    // Multi-line command: readline only recorded the first line,
                    // so add the merged command to history.
                    term::add_to_history(buf.as_str());
                }
                // Interactive mode ignores the overall status.
                exec::run_list(&list, sh);
                buf.clear();
            }
        }
    }
}

/// Expand `PS1`/`PS2` for display, falling back to rush's default if the
/// variable was unset (e.g. by `unset PS1`).
fn prompt_string(name: &str, sh: &mut Shell) -> String {
    let raw = sh
        .get(name)
        .unwrap_or_else(|| shell::default_prompt(name).to_string());
    expand::expand_prompt(&raw, sh)
}
