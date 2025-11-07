use std::sync::Mutex;

mod exec;
mod line_parser;
mod redirect;
mod term;

#[cfg(unix)]
mod term_impl_unix;

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

        if script.is_none() && *MODE.lock().unwrap() != Mode::Command {
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
    match mode {
        Mode::Command => crate::exec::run_command(args),

        Mode::Script => {
            if let Some(script) = script {
                // This is usually config, setting PATH and such.
                exec::run_script(script.as_str(), args, true);
            }
        }
        Mode::Terminal | Mode::Piped => {
            if let Some(script) = script {
                // This is usually config, setting PATH and such.
                exec::run_script(script.as_str(), args, true);
            }
            if mode == Mode::Terminal {
                assert_terminal();
            }
            let _cleanup = Cleanup {}; // On panic, restore the terminal state.
            term::init(mode == Mode::Piped);
            let mut parser = line_parser::LineParser::new();

            let args = vec![];
            loop {
                if let Some(commands) = parser.parse_line(term::readline().as_str()) {
                    exec::run(commands, false, &args).ok(); // Ignore results in the interactive mode.
                }
            }
            // unreachable
        }
    }
}
