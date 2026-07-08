use std::sync::atomic::{AtomicI32, Ordering};
use std::{path::Path, process::Stdio};

/// Last command's exit status, i.e. the value `$?` will eventually expose.
/// This is a Phase-0 placeholder; Phase 3 moves it into the `Shell` state
/// object. For now it is enough to make a bare `exit` use the previous
/// command's status.
static LAST_STATUS: AtomicI32 = AtomicI32::new(0);

fn set_last_status(code: i32) {
    LAST_STATUS.store(code, Ordering::Relaxed);
}

fn last_status() -> i32 {
    LAST_STATUS.load(Ordering::Relaxed)
}

fn take_env(command: &[String]) -> Option<(&str, &str)> {
    if command.is_empty() {
        return None;
    }

    let cmd = command[0].as_str().trim();
    if let Some((k, v)) = cmd.split_once('=') {
        if super::is_valid_var_name(k) {
            Some((k, v))
        } else {
            None
        }
    } else {
        None
    }
}

fn apply_global_env(env: &Vec<(&str, &str)>) {
    for (k, v) in env {
        // SAFETY: TBD.
        unsafe { std::env::set_var(k, v) };
    }
}

fn process_vars(tokens: &[String], _env: &[(&str, &str)], args: &[String]) -> Vec<String> {
    // We should do a proper language interpreter with AST later.
    // For now we have something simple to bootstrap things.

    let mut result = Vec::new();
    for token in tokens {
        if token.as_str() == "$@" {
            for arg in &args[1..] {
                result.push(arg.clone());
            }
        } else {
            result.push(token.clone());
        }
    }

    result
}

/// Run a sequence of &&-separated pipelines, short-circuiting on failure.
pub fn run_sequence(
    pipelines: Vec<Vec<Vec<String>>>,
    global: bool,
    args: &[String],
) -> Result<(), i32> {
    for pipeline in pipelines {
        match run(pipeline, global, args) {
            Ok(()) => set_last_status(0),
            Err(code) => {
                set_last_status(code);
                return Err(code);
            }
        }
    }
    Ok(())
}

pub fn run(commands: Vec<Vec<String>>, global: bool, args: &[String]) -> Result<(), i32> {
    let mut prev_child = None;

    if commands.len() > 1 {
        todo!("piping needs better stdio treatment");
    }

    for idx in 0..commands.len() {
        let mut command = commands[idx].as_slice();

        // We should do a proper language interpreter with AST later.
        // For now we have something simple to bootstrap things.

        // Process commands like `A=B do_something`.
        let mut env: Vec<(&str, &str)> = vec![];
        while let Some(k_v) = take_env(command) {
            env.push(k_v);
            command = &command[1..];
        }

        if command.is_empty() {
            if global {
                if idx == 0 && commands.len() == 1 {
                    apply_global_env(&env);
                } else {
                    eprintln!("rush: cannot set an environment variable in a pipeline.");
                    return Err(1);
                }
            }
            continue;
        }

        // Process inline vars.
        let command = process_vars(command, &env, args);
        if command.is_empty() {
            continue;
        }

        let cmd = command[0].clone();
        let args = &command[1..];
        match cmd.as_str() {
            "cd" => {
                if args.len() != 1 {
                    eprintln!("rush: cd: expected a single argument.");
                    prev_child = None;
                    continue;
                }
                let new_dir = args[0].as_str();
                let root = Path::new(new_dir);
                if let Err(e) = std::env::set_current_dir(root) {
                    eprintln!("rush: cd: {new_dir}: {e}");
                }

                prev_child = None;
            }
            "quit" => crate::exit(0),
            "exit" => process_exit(args),
            command => {
                let stdin = prev_child.map_or(Stdio::inherit(), |output: std::process::Child| {
                    Stdio::from(output.stdout.unwrap())
                });

                let redirect_to_file = super::redirect::parse_args(args);
                if redirect_to_file.is_err() {
                    // parse_args() eprints the error message.
                    return Err(-1);
                }
                let (args, maybe_redirect) = redirect_to_file.unwrap();

                let stdout = if (idx < (commands.len() - 1)) || maybe_redirect.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::inherit()
                };

                let stderr = if idx < (commands.len() - 1) {
                    Stdio::piped()
                } else {
                    Stdio::inherit()
                };

                let child = std::process::Command::new(command)
                    .args(args)
                    .stdin(stdin)
                    .stdout(stdout)
                    .stderr(stderr)
                    .envs(env)
                    .spawn();

                match child {
                    Ok(mut child) => {
                        if let Some(mut redirect_to_file) = maybe_redirect
                            && let Some(child_stdout) = &mut child.stdout
                        {
                            redirect_to_file.consume_stdout(child_stdout);
                        }
                        prev_child = Some(child);
                    }
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidFilename => {
                            // POSIX: a command that cannot be found exits 127.
                            eprintln!("rush: {command}: command not found");
                            return Err(127);
                        }
                        std::io::ErrorKind::PermissionDenied => {
                            // POSIX: found but not executable exits 126.
                            eprintln!("rush: {command}: permission denied");
                            return Err(126);
                        }
                        _ => {
                            eprintln!("rush: {command}: {e}");
                            return Err(126);
                        }
                    },
                };
            }
        }
    }

    if let Some(mut last) = prev_child {
        match last.wait() {
            Ok(status) => {
                if let Some(code) = status.code() {
                    if code == 0 { Ok(()) } else { Err(code) }
                } else {
                    // Terminated by a signal (no exit code). POSIX reports
                    // 128 + signum; without a portable signal accessor here we
                    // use a generic non-zero status.
                    Err(128)
                }
            }
            Err(err) => {
                eprintln!("rush: {err}");
                Err(126)
            }
        }
    } else {
        Ok(())
    }
}

pub fn run_script(fname: &str, args: Vec<String>, global: bool) {
    let script = {
        match std::fs::read_to_string(std::path::Path::new(fname)) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("Error reading '{fname}': {err:?}");
                std::process::exit(1);
            }
        }
    };

    let mut parser = crate::line_parser::LineParser::new();
    for line in script.lines() {
        // When the parser is mid-continuation (previous line ended with `\`),
        // don't skip any lines — the continuation must be fed to the parser.
        if !parser.is_continuation() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.as_bytes()[0] == b'#' {
                continue;
            }
        }
        if let Some(pipelines) = parser.parse_line(line)
            && let Err(err) = run_sequence(pipelines, global, &args)
        {
            std::process::exit(err);
        }
    }
}

pub fn run_command(args: Vec<String>) {
    let line = args.join(" ");
    let mut parser = crate::line_parser::LineParser::new();
    if let Some(pipelines) = parser.parse_line(&line)
        && let Err(err) = run_sequence(pipelines, true, &[])
    {
        std::process::exit(err);
    }
    std::process::exit(0);
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
