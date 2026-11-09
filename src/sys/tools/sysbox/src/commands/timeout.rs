//! `timeout DURATION COMMAND`: run COMMAND and kill it after DURATION.
//!
//! Motor OS has no signals: TERM and KILL are both an unconditional native
//! kill of the direct child, and nothing is forwarded to grandchildren.
use std::os::motor::process::ChildExt;
use std::process::{Child, Command};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

const HELP: &str = "Usage: timeout [OPTION]... DURATION COMMAND [ARG]...
Run COMMAND, terminating it after DURATION.
DURATION is a nonnegative floating point number, optionally followed by
s (seconds, default), m (minutes), h (hours), or d (days). Zero disables it.
  -f, --foreground       accepted; only the direct child is ever managed
  -k, --kill-after TIME  kill TIME after the initial timeout; 0 disables
  -p, --preserve-status  return COMMAND's status even after a timeout
  -s, --signal SIGNAL    TERM (default), KILL, or 0 (report only, no kill)
  -v, --verbose          report timeout actions on stderr
  -h, --help             show this help
  -V, --version          show version
TERM and KILL both kill the child outright; TERM cannot be caught.
Exit status: 124 on timeout, 125 on timeout errors, 126 if COMMAND cannot be
invoked, 127 if COMMAND is missing, 137 after --kill-after, or COMMAND's status.
With --preserve-status a killed COMMAND reports 143 (TERM) or 137 (KILL).";

const TERM: i32 = 15;
const KILL: i32 = 9;

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("timeout: {message}");
    std::process::exit(125)
}

// None disables the timer: zero, or a duration too large to represent. Any
// other positive value fires, even one that rounds below a nanosecond.
fn duration(text: &str) -> Option<Duration> {
    let (number, scale) = match text.as_bytes().last() {
        Some(b's') => (&text[..text.len() - 1], 1.0),
        Some(b'm') => (&text[..text.len() - 1], 60.0),
        Some(b'h') => (&text[..text.len() - 1], 3600.0),
        Some(b'd') => (&text[..text.len() - 1], 86400.0),
        _ => (text, 1.0),
    };
    let seconds = number
        .parse::<f64>()
        .ok()
        .filter(|seconds| *seconds >= 0.0)
        .unwrap_or_else(|| fail(format!("invalid time interval '{text}'")));
    if seconds == 0.0 {
        return None;
    }
    Duration::try_from_secs_f64(seconds * scale)
        .ok()
        .map(|duration| duration.max(Duration::from_nanos(1)))
}

fn signal(text: &str) -> i32 {
    let upper = text.to_ascii_uppercase();
    if let Some(n) = upper.parse::<u32>().ok().filter(|n| [0, 9, 15].contains(n)) {
        return n as i32;
    }
    match upper.strip_prefix("SIG").unwrap_or(&upper) {
        "TERM" => TERM,
        "KILL" => KILL,
        _ => fail(format!("unsupported signal '{text}'; use TERM, KILL, or 0")),
    }
}

#[derive(Clone)]
struct Options {
    preserve: bool,
    verbose: bool,
    signal: i32,
    kill_after: Option<Duration>,
}

fn parse(args: &[String]) -> (Options, Option<Duration>, &[String]) {
    let mut options = Options {
        preserve: false,
        verbose: false,
        signal: TERM,
        kill_after: None,
    };
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if arg == "--" {
            index += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        index += 1;
        let (flags, attached) = if arg.starts_with("--") {
            let (name, value) = arg
                .split_once('=')
                .map_or((arg, None), |(n, v)| (n, Some(v)));
            let flags = match name {
                "--foreground" if value.is_none() => "f",
                "--preserve-status" if value.is_none() => "p",
                "--verbose" if value.is_none() => "v",
                "--help" if value.is_none() => "h",
                "--version" if value.is_none() => "V",
                "--signal" => "s",
                "--kill-after" => "k",
                _ => fail(format!("unrecognized option '{arg}'")),
            };
            (flags, value)
        } else {
            (&arg[1..], None)
        };
        for (position, flag) in flags.char_indices() {
            match flag {
                'f' => {}
                'p' => options.preserve = true,
                'v' => options.verbose = true,
                'h' => {
                    println!("{HELP}");
                    std::process::exit(0);
                }
                'V' => {
                    println!("timeout (Motor OS sysbox) {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                's' | 'k' => {
                    // The value is attached (-k5, --kill-after=5) or the next argument.
                    let rest = &flags[position + 1..];
                    let value = attached.or_else(|| (!rest.is_empty()).then_some(rest));
                    let value = value.unwrap_or_else(|| {
                        let value = args.get(index).unwrap_or_else(|| {
                            fail(format!("option '{arg}' requires an argument"))
                        });
                        index += 1;
                        value
                    });
                    if flag == 's' {
                        options.signal = signal(value);
                    } else {
                        options.kill_after = duration(value);
                    }
                    break;
                }
                _ => fail(format!("unrecognized option '-{flag}'")),
            }
        }
    }
    let timeout = args
        .get(index)
        .unwrap_or_else(|| fail("missing duration; see --help"));
    let timeout = duration(timeout);
    let command = &args[index + 1..];
    if command.is_empty() {
        fail("missing command; see --help");
    }
    (options, timeout, command)
}

#[derive(Default)]
struct Outcome {
    timed_out: bool,
    escalated: bool,
    // The signal a kill was issued for, if any.
    killed_with: Option<i32>,
}

fn kill(handle: u64, signal: i32, name: &str, verbose: bool) -> Option<i32> {
    if verbose {
        let signal_name = match signal {
            TERM => "TERM",
            KILL => "KILL",
            _ => "0",
        };
        eprintln!("timeout: sending signal {signal_name} to command '{name}'");
    }
    if signal == 0 {
        return None;
    }
    if let Err(error) = moto_rt::process::kill(handle) {
        eprintln!("timeout: failed to kill command '{name}': {error:?}");
    }
    Some(signal)
}

// Blocks until the child exits (the sender is dropped) or the deadline passes.
fn watchdog(
    exited: mpsc::Receiver<()>,
    handle: u64,
    timeout: Duration,
    options: Options,
    name: String,
) -> Outcome {
    let mut outcome = Outcome::default();
    if exited.recv_timeout(timeout) != Err(RecvTimeoutError::Timeout) {
        return outcome;
    }
    outcome.timed_out = true;
    outcome.killed_with = kill(handle, options.signal, &name, options.verbose);
    if let Some(kill_after) = options.kill_after {
        if exited.recv_timeout(kill_after) == Err(RecvTimeoutError::Timeout) {
            outcome.escalated = true;
            outcome.killed_with = kill(handle, KILL, &name, options.verbose);
        }
    }
    outcome
}

fn spawn(command: &[String]) -> Child {
    Command::new(&command[0])
        .args(&command[1..])
        .spawn()
        .unwrap_or_else(|error| {
            eprintln!("timeout: failed to run command '{}': {error}", command[0]);
            let missing = matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidFilename
            );
            std::process::exit(if missing { 127 } else { 126 });
        })
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "timeout");
    let (options, timeout, command) = parse(&args[1..]);
    let mut child = spawn(command);
    let handle = child.sys_handle();

    let (exited, receiver) = mpsc::channel();
    let watchdog = timeout.map(|timeout| {
        let options = options.clone();
        let name = command[0].clone();
        std::thread::spawn(move || watchdog(receiver, handle, timeout, options, name))
    });
    let status = child.wait().unwrap_or_else(|error| {
        let _ = moto_rt::process::kill(handle);
        fail(format!("waiting for the command failed: {error}"))
    });
    drop(exited);
    let outcome = watchdog
        .map(|watchdog| watchdog.join().unwrap_or_default())
        .unwrap_or_default();

    // A killed child reports -1; a normal exit reports its own code.
    let mut code = status.code().unwrap_or(-1);
    if code == -1 {
        if let Some(signal) = outcome.killed_with {
            code = 128 + signal;
        }
    }
    std::process::exit(if outcome.escalated {
        137
    } else if outcome.timed_out && !options.preserve {
        124
    } else {
        code
    });
}
