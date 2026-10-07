//! Run commands directly with bounded batches of arguments read from stdin.
#[path = "xargs_tokens.rs"]
mod tokens;
use std::process::{Command, Stdio};
const LIMIT: usize = 128 * 1024;
fn fail(message: &str) -> ! {
    eprintln!("xargs: {message}");
    std::process::exit(1)
}
#[derive(Default)]
struct Options {
    delimiter: Option<u8>,
    empty: bool,
}
fn parse(args: &[String]) -> (Options, Vec<String>) {
    let mut options = Options::default();
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            break;
        }
        if !argument.starts_with('-') || argument == "-" {
            return (
                options,
                std::iter::once(argument.clone())
                    .chain(arguments.cloned())
                    .collect(),
            );
        }
        if argument == "--help" {
            println!("usage: xargs [-0r] [COMMAND [ARG]...]\nRead UTF-8 arguments from stdin and run COMMAND directly.\nDefault input recognizes quotes and backslashes; -0 reads literal NUL-delimited arguments.\n-r skips empty input. With no command, run sysbox echo. Command lines are bounded to 128 KiB.");
            std::process::exit(0);
        }
        let flags = match argument.as_str() {
            "--null" => "0",
            "--no-run-if-empty" => "r",
            name if !name.starts_with("--") => &argument[1..],
            _ => fail(&format!("unsupported option '{argument}'")),
        };
        for flag in flags.chars() {
            match flag {
                '0' => options.delimiter = Some(0),
                'r' => options.empty = true,
                _ => fail(&format!("unsupported option '{argument}'")),
            }
        }
    }
    (options, arguments.cloned().collect())
}
fn execute(command: &[String]) -> i32 {
    let status = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::null())
        .status()
        .unwrap_or_else(|error| {
            // Motor's PATH lookup reports InvalidFilename when no candidate exists.
            #[cfg(target_os = "motor")]
            let error = if error.raw_os_error() == Some(i32::from(moto_rt::E_INVALID_FILENAME)) {
                std::io::Error::from(std::io::ErrorKind::NotFound)
            } else {
                error
            };
            eprintln!("xargs: {}: {}", command[0], super::wc::strerror(&error));
            std::process::exit(if error.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            });
        });
    match status.code() {
        Some(0) => 0,
        Some(255) => {
            eprintln!("xargs: {}: exited with status 255; aborting", command[0]);
            std::process::exit(124);
        }
        Some(_) => 123,
        None => {
            eprintln!("xargs: {}: terminated by a signal", command[0]);
            std::process::exit(125);
        }
    }
}
pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "xargs");
    let (options, mut initial) = parse(&args[1..]);
    if initial.is_empty() {
        let program = std::env::current_exe()
            .unwrap_or_else(|error| fail(&format!("cannot locate sysbox: {error}")))
            .into_os_string()
            .into_string()
            .unwrap_or_else(|_| fail("sysbox path is not valid UTF-8"));
        initial = vec![program, "echo".into()];
    }
    let base = initial
        .iter()
        .try_fold(0usize, |size, arg| {
            size.checked_add(arg.len() + 1).filter(|size| *size < LIMIT)
        })
        .unwrap_or_else(|| fail("command line too long"));
    let mut batch = initial.clone();
    let mut bytes = base;
    let mut ran = false;
    let mut result = 0;
    tokens::arguments(std::io::stdin().lock(), options.delimiter, |argument| {
        let size = argument.len() + 1;
        if base + size >= LIMIT {
            fail("argument line too long");
        }
        if bytes + size >= LIMIT {
            result = result.max(execute(&batch));
            ran = true;
            batch.truncate(initial.len());
            bytes = base;
        }
        bytes += size;
        batch.push(argument);
    });
    if batch.len() > initial.len() || (!ran && !options.empty) {
        result = result.max(execute(&batch));
    }
    if result != 0 {
        std::process::exit(result);
    }
}
