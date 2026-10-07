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
    maximum: Option<usize>,
    replacement: Option<String>,
    empty: bool,
    verbose: bool,
}
fn delimiter(text: &str) -> u8 {
    let bytes = text.as_bytes();
    if let [byte] = bytes {
        return *byte;
    }
    if let [b'\\', byte] = bytes {
        match byte {
            b'a' => return 7,
            b'b' => return 8,
            b'f' => return 12,
            b'n' => return 10,
            b'r' => return 13,
            b't' => return 9,
            b'v' => return 11,
            b'\\' => return b'\\',
            _ => {}
        }
    }
    if let Some(octal) = text
        .strip_prefix('\\')
        .filter(|s| s.len() <= 3 && !s.is_empty() && s.bytes().all(|b| (b'0'..=b'7').contains(&b)))
    {
        return u8::from_str_radix(octal, 8)
            .unwrap_or_else(|_| fail("delimiter value is too large"));
    }
    if let Some(hex) = text
        .strip_prefix("\\x")
        .filter(|s| s.len() <= 2 && !s.is_empty())
    {
        return u8::from_str_radix(hex, 16)
            .unwrap_or_else(|_| fail("invalid hexadecimal delimiter"));
    }
    fail("delimiter must be one byte or a backslash escape")
}
fn maximum(text: &str) -> usize {
    let text = text.trim_start_matches(|character| matches!(character, ' ' | '\t'..='\r'));
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        fail("max-args must be a positive integer");
    }
    let number = digits.bytes().fold(0usize, |number, digit| {
        number
            .saturating_mul(10)
            .saturating_add((digit - b'0') as usize)
    });
    if number == 0 {
        fail("max-args must be a positive integer");
    }
    number
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
            println!("usage: xargs [-0rt] [-d BYTE] [-n COUNT] [-I REPLACE] [COMMAND [ARG]...]\nRead UTF-8 arguments from stdin and run COMMAND directly, without a shell.\nDefault input recognizes quotes and backslashes; -0/-d are literal.\n-I replaces the marker in initial arguments, once per input record.\n-n limits each batch; -r skips empty input; -t prints commands.\nWith no command, run sysbox echo.\nCommand lines are bounded to 128 KiB.");
            std::process::exit(0);
        }
        let (name, value) = if argument.starts_with("--") {
            argument
                .split_once('=')
                .map_or((argument.as_str(), None), |(n, v)| (n, Some(v)))
        } else {
            (argument.as_str(), None)
        };
        let flags = match name {
            "--null" if value.is_none() => "0",
            "--no-run-if-empty" if value.is_none() => "r",
            "--verbose" if value.is_none() => "t",
            "--delimiter" => "d",
            "--max-args" => "n",
            "--replace" => "I",
            name if !name.starts_with("--") => &argument[1..],
            _ => fail(&format!("unsupported option '{argument}'")),
        };
        for (position, flag) in flags.char_indices() {
            match flag {
                '0' => options.delimiter = Some(0),
                'r' => options.empty = true,
                't' => options.verbose = true,
                'd' | 'n' | 'I' => {
                    let rest = &flags[position + 1..];
                    let value = value.unwrap_or_else(|| {
                        if !rest.is_empty() {
                            rest
                        } else if argument == "--replace" {
                            "{}"
                        } else {
                            arguments.next().unwrap_or_else(|| {
                                fail(&format!("option requires an argument -- '{flag}'"))
                            })
                        }
                    });
                    match flag {
                        'd' => options.delimiter = Some(delimiter(value)),
                        'n' => {
                            let number = maximum(value);
                            if options.replacement.is_some() && number != 1 {
                                eprintln!("xargs: warning: options --replace and --max-args/-n are mutually exclusive, ignoring previous --replace value");
                                options.replacement = None;
                            }
                            options.maximum = Some(number);
                        }
                        _ => {
                            if options.maximum.take().is_some() {
                                eprintln!("xargs: warning: options --max-args and --replace/-I/-i are mutually exclusive, ignoring previous --max-args value");
                            }
                            options.replacement = Some(value.to_owned());
                        }
                    }
                    break;
                }
                _ => fail(&format!("unsupported option '{argument}'")),
            }
        }
    }
    (options, arguments.cloned().collect())
}
fn trace(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}
fn execute(command: &[String], options: &Options) -> i32 {
    if options.verbose {
        eprintln!(
            "{}",
            command
                .iter()
                .map(|argument| trace(argument))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
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
    let default = initial.is_empty();
    if default {
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
    tokens::arguments(
        std::io::stdin().lock(),
        options.delimiter,
        options.replacement.is_some(),
        |argument| {
            if let Some(marker) = &options.replacement {
                if marker.is_empty() {
                    fail("command too long");
                }
                let mut command = Vec::with_capacity(initial.len());
                let mut size = 0usize;
                for (index, arg) in initial.iter().enumerate() {
                    let literal = index == 0 || (default && index == 1);
                    let matches = if literal {
                        0
                    } else {
                        arg.matches(marker).count()
                    };
                    let length = argument
                        .len()
                        .checked_mul(matches)
                        .and_then(|replacements| {
                            replacements.checked_add(arg.len() - matches * marker.len())
                        })
                        .unwrap_or_else(|| fail("argument list too long"));
                    size = size
                        .checked_add(length + 1)
                        .filter(|size| *size < LIMIT)
                        .unwrap_or_else(|| fail("argument list too long"));
                    command.push(if literal {
                        arg.clone()
                    } else {
                        arg.replace(marker, &argument)
                    });
                }
                result = result.max(execute(&command, &options));
                ran = true;
            } else {
                let size = argument.len() + 1;
                if base + size >= LIMIT {
                    fail("argument line too long");
                }
                if bytes + size >= LIMIT {
                    result = result.max(execute(&batch, &options));
                    ran = true;
                    batch.truncate(initial.len());
                    bytes = base;
                }
                bytes += size;
                batch.push(argument);
                if batch.len() - initial.len() == options.maximum.unwrap_or(usize::MAX) {
                    result = result.max(execute(&batch, &options));
                    ran = true;
                    batch.truncate(initial.len());
                    bytes = base;
                }
            }
        },
    );
    if batch.len() > initial.len() || (!ran && !options.empty && options.replacement.is_none()) {
        result = result.max(execute(&batch, &options));
    }
    if result != 0 {
        std::process::exit(result);
    }
}
