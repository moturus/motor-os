#![feature(io_error_more)]

use std::sync::Mutex;

use exec::run_script;

mod client_relay;
mod exec;
mod line_parser;
mod listener;
mod redirect;
mod term;

#[cfg(unix)]
mod term_impl_unix;

const RUSH_HANDSHAKE: &str = "RUSH_001";

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
    Listener(u16),
    ClientRelay(String),
}

static MODE: Mutex<Mode> = Mutex::new(Mode::Script);

fn print_usage_and_exit(code: i32) -> ! {
    eprintln!("(rush) usage:");
    eprintln!("    -h: print this message");
    eprintln!("    -c: read commands from the command string (stdin is ignored)");
    eprintln!("    -i: terminal mode + init script");
    eprintln!("    -r $HOST:$PORT: connect to a remote listener");
    eprintln!("    -l $PORT: listen on a local port");
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
fn main() {
    let mut args = Vec::new();
    let mut script = None;

    let args_raw: Vec<_> = std::env::args().collect();

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
            if arg.as_str() == "-r" {
                if args_raw.len() != 3 {
                    print_usage_and_exit(1);
                }
                *MODE.lock().unwrap() = Mode::ClientRelay(args_raw[2].clone());
                break;
            }
            if arg.as_str() == "-l" {
                if args_raw.len() != 3 {
                    print_usage_and_exit(1);
                }
                if let Ok(port) = args_raw[2].parse::<u16>() {
                    *MODE.lock().unwrap() = Mode::Listener(port);
                    break;
                } else {
                    print_usage_and_exit(1);
                }
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
                run_script(script.as_str(), args, true);
            }
        }
        Mode::Terminal | Mode::Piped => {
            if let Some(script) = script {
                // This is usually config, setting PATH and such.
                run_script(script.as_str(), args, true);
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
        Mode::Listener(port) => {
            assert!(script.is_none());
            listener::run(port)
            // unreachable
        }
        Mode::ClientRelay(host_port) => {
            assert_terminal();
            assert!(script.is_none());
            let _cleanup = Cleanup {}; // On panic, restore the terminal state.
            term::init(false);
            client_relay::connect_to(host_port.as_str()).run()
            // unreachable
        }
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
