use std::sync::Mutex;

mod arith;
mod ast;
mod builtins;
mod exec;
mod expand;
mod glob;
mod lexer;
mod parser;
mod shell;
mod sys;
mod term;
mod token;

fn is_valid_var_name(name: &str) -> bool {
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

#[derive(Clone, PartialEq, Eq)]
enum Mode {
    Command,
    Script, // Run a script and exit.
    Terminal,
    Piped, // Internal/hidden mode.
}

static MODE: Mutex<Mode> = Mutex::new(Mode::Script);

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!("(rush) usage:");
    eprintln!("    -h: print this message");
    eprintln!("    -c: read commands from the command string (stdin is ignored)");
    eprintln!("    -i: terminal mode + init script");
    std::process::exit(code);
}

fn assert_terminal() {
    let is_terminal = std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::io::IsTerminal::is_terminal(&std::io::stdout())
        && std::io::IsTerminal::is_terminal(&std::io::stderr());

    if !is_terminal {
        eprintln!("rush: terminal not detected. Exiting.");
        std::process::exit(1)
    }
}

fn exit(code: i32) -> ! {
    term::on_exit();
    std::process::exit(code)
}

fn prompt() -> String {
    let mode = MODE.lock().unwrap().clone();
    match mode {
        Mode::Terminal | Mode::Piped => std::env::current_dir()
            .unwrap()
            .as_path()
            .to_str()
            .unwrap()
            .to_owned(),
        _ => panic!(),
    }
}

pub fn parse_args(args_raw: Vec<String>) -> (Vec<String>, Option<String>) {
    let mut args = Vec::new();
    let mut script = None;

    for idx in 1..args_raw.len() {
        let arg = args_raw[idx].clone();
        if idx == 1 {
            if arg.as_str() == "-i" {
                *MODE.lock().unwrap() = Mode::Terminal;
                continue;
            }
            if arg.as_str() == "-c" {
                *MODE.lock().unwrap() = Mode::Command;
                continue;
            }
            if arg.as_str() == "-h" {
                print_usage_and_exit(0);
            }

            if arg.as_str() == "-piped" {
                assert_eq!(args_raw.len(), 2);
                *MODE.lock().unwrap() = Mode::Piped;
                break;
            }
            if arg.as_str().starts_with('-') {
                print_usage_and_exit(1);
            }
        }

        // POSIX `sh -c -- command`: "--" terminates option parsing; libc
        // system()/popen() pass it before the command string. Skip it.
        if *MODE.lock().unwrap() == Mode::Command && args.is_empty() && arg == "--" {
            continue;
        }

        if script.is_none() && *MODE.lock().unwrap() != Mode::Command {
            // If the first positional arg looks like VAR=val, treat all
            // args as a command rather than interpreting it as a script name.
            if let Some((k, _)) = arg.split_once('=')
                && is_valid_var_name(k)
            {
                *MODE.lock().unwrap() = Mode::Command;
                args.push(arg);
                continue;
            }
            script = Some(arg.clone());
        }
        args.push(arg);
    }

    (args, script)
}

pub fn execute(args: Vec<String>, script: Option<String>) {
    if std::env::current_dir().is_err() {
        std::env::set_current_dir(std::path::Path::new("/")).unwrap();
    }

    let mut mode = MODE.lock().unwrap().clone();
    if mode == Mode::Script && script.is_none() {
        // Try running in a terminal.
        *MODE.lock().unwrap() = Mode::Terminal;
        mode = Mode::Terminal;
    }

    // The single persistent shell state, carried across the whole session.
    let mut sh = shell::Shell::new();

    match mode {
        Mode::Command => crate::exec::run_command(args, &mut sh),

        Mode::Script => {
            if let Some(script) = script {
                // Positional parameters: $0 is the script name, $1.. the rest.
                // (Full invocation parsing lands in Phase 6.)
                if let Some((name, rest)) = args.split_first() {
                    sh.set_name(name.clone());
                    sh.set_params(rest.to_vec());
                }
                // Running a script file: its exit status is the last command's.
                crate::exit(exec::run_script(script.as_str(), &mut sh));
            }
        }
        Mode::Terminal | Mode::Piped => {
            // Interactive: a special-builtin usage error reports and continues
            // rather than aborting the shell.
            sh.set_interactive(true);
            if let Some(script) = script {
                // This is usually config, setting PATH and such.
                exec::run_script(script.as_str(), &mut sh);
            }
            if mode == Mode::Terminal {
                assert_terminal();
            }
            let _cleanup = Cleanup {}; // On panic, restore the terminal state.
            term::init(mode == Mode::Piped);

            // Accumulate raw input across lines so the lexer sees whole
            // multi-line constructs (here-docs, continuations). When the
            // accumulated buffer neither lexes nor parses to completion we read
            // another line (PS2); otherwise we execute and reset.
            let mut buf = String::new();
            loop {
                let line = if buf.is_empty() {
                    term::readline()
                } else {
                    buf.push('\n');
                    term::readline_continuation()
                };
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
                            // Multi-line command: readline only recorded the
                            // first line, so add the merged command to history.
                            term::add_to_history(buf.as_str());
                        }
                        // Interactive mode ignores the overall status.
                        exec::run_list(&list, &mut sh);
                        buf.clear();
                    }
                }
            }
            // unreachable
        }
    }
}
