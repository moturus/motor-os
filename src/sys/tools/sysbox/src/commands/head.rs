//! `head`: print the first part of files.
//!
//! The options, headers and messages follow GNU `head` (coreutils 9.7), which
//! this was checked against; uutils `head` differs only in its usage errors.

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};
use std::path::Path;

use super::wc::strerror;

const USAGE: &str = "\
Print the first 10 lines of each FILE to standard output.
With more than one FILE, precede each with a header giving the file name.

usage:
\thead [OPTION]... [FILE]...

With no FILE, or when FILE is -, read standard input.

  -c, --bytes=[-]NUM       print the first NUM bytes of each file;
                           with the leading '-', print all but the last
                           NUM bytes of each file
  -n, --lines=[-]NUM       print the first NUM lines instead of the first 10;
                           with the leading '-', print all but the last
                           NUM lines of each file
  -q, --quiet, --silent    never print headers giving file names
  -v, --verbose            always print headers giving file names
  -z, --zero-terminated    line delimiter is NUL, not newline
  -h, --help               print this help
  -V, --version            print version

NUM may have a multiplier suffix: b 512, kB 1000, K 1024, MB 1000*1000,
M 1024*1024, GB 1000*1000*1000, G 1024*1024*1024, and so on for T, P, E.
Binary prefixes can be used, too: KiB=K, MiB=M, and so on.";

const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq)]
enum Unit {
    Lines,
    Bytes,
}

#[derive(Clone, Copy, PartialEq)]
enum Headers {
    Auto,
    Never,
    Always,
}

struct Options {
    unit: Unit,
    count: u64,
    /// `-n -NUM` and `-c -NUM`: everything except the last `count` units.
    all_but_last: bool,
    headers: Headers,
    delimiter: u8,
}

/// Why one input could not be printed. A failed write ends the command: there
/// is nowhere left to print to.
enum Failure {
    Read(std::io::Error),
    Write(std::io::Error),
}

fn fail(message: &str) -> ! {
    eprintln!("head: {message}");
    eprintln!("Try 'head --help' for more information.");
    std::process::exit(1);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "head");

    let (options, mut operands) = parse_args(&args[1..]);
    if operands.is_empty() {
        operands.push("-".to_owned());
    }
    let headers = match options.headers {
        Headers::Auto => operands.len() > 1,
        Headers::Never => false,
        Headers::Always => true,
    };

    let mut out = std::io::BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout().lock());
    let mut first = true;
    let mut failed = false;

    for operand in &operands {
        let name = display_name(operand);
        let result = if operand == "-" {
            print_header(&mut out, headers, &mut first, name)
                .and_then(|_| head(&mut std::io::stdin().lock(), &mut out, &options))
        } else {
            match std::fs::File::open(Path::new(operand)) {
                Ok(file) => print_header(&mut out, headers, &mut first, name).and_then(|_| {
                    let mut file = std::io::BufReader::with_capacity(BUFFER_SIZE, file);
                    head(&mut file, &mut out, &options)
                }),
                // Motor OS refuses to open a directory at all; Linux opens it
                // and fails the read, which is what gets reported.
                Err(_) if is_directory(operand) => {
                    print_header(&mut out, headers, &mut first, name).and(Err(Failure::Read(
                        std::io::Error::from(std::io::ErrorKind::IsADirectory),
                    )))
                }
                Err(err) => {
                    let _ = out.flush();
                    eprintln!(
                        "head: cannot open '{operand}' for reading: {}",
                        strerror(&err)
                    );
                    failed = true;
                    continue;
                }
            }
        };

        match result {
            Ok(()) => {}
            Err(Failure::Read(err)) => {
                let _ = out.flush();
                eprintln!("head: error reading '{name}': {}", strerror(&err));
                failed = true;
            }
            Err(Failure::Write(err)) => write_failed(&err),
        }
    }

    if let Err(err) = out.flush() {
        write_failed(&err);
    }
    if failed {
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> (Options, Vec<String>) {
    let mut options = Options {
        unit: Unit::Lines,
        count: 10,
        all_but_last: false,
        headers: Headers::Auto,
        delimiter: b'\n',
    };
    let mut operands = Vec::new();
    let mut args = args.iter();

    // `head -5` is the obsolete spelling of `head -n 5`, still common in
    // scripts. As on Linux, it is recognized only as the first argument.
    if let Some(first) = args.as_slice().first() {
        if parse_obsolete(first, &mut options) {
            args.next();
        }
    }

    let mut options_done = false;
    while let Some(arg) = args.next() {
        if options_done || arg == "-" || !arg.starts_with('-') {
            operands.push(arg.clone());
            continue;
        }

        if arg == "--" {
            options_done = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match name {
                "bytes" | "lines" => {
                    let unit = if name == "bytes" {
                        Unit::Bytes
                    } else {
                        Unit::Lines
                    };
                    let value = match value {
                        Some(value) => value,
                        None => args.next().map(String::as_str).unwrap_or_else(|| {
                            fail(&format!("option '--{name}' requires an argument"))
                        }),
                    };
                    set_count(&mut options, unit, value);
                }
                "quiet" | "silent" | "verbose" | "zero-terminated" | "help" | "version"
                    if value.is_some() =>
                {
                    fail(&format!("option '--{name}' doesn't allow an argument"))
                }
                "quiet" | "silent" => options.headers = Headers::Never,
                "verbose" => options.headers = Headers::Always,
                "zero-terminated" => options.delimiter = 0,
                "help" => print_usage_and_exit(0),
                "version" => print_version_and_exit(),
                _ => fail(&format!("unrecognized option '--{name}'")),
            }
        } else {
            for (idx, short) in arg.char_indices().skip(1) {
                match short {
                    'c' | 'n' => {
                        let unit = if short == 'c' {
                            Unit::Bytes
                        } else {
                            Unit::Lines
                        };
                        // The count is the rest of this argument, or the next.
                        let rest = &arg[idx + 1..];
                        let value = if rest.is_empty() {
                            args.next().map(String::as_str).unwrap_or_else(|| {
                                fail(&format!("option requires an argument -- '{short}'"))
                            })
                        } else {
                            rest
                        };
                        set_count(&mut options, unit, value);
                        break;
                    }
                    'q' => options.headers = Headers::Never,
                    'v' => options.headers = Headers::Always,
                    'z' => options.delimiter = 0,
                    'h' => print_usage_and_exit(0),
                    'V' => print_version_and_exit(),
                    _ => fail(&format!("invalid option -- '{short}'")),
                }
            }
        }
    }

    (options, operands)
}

/// `-NUM`, optionally followed by a multiplier (`b`, `k`, `m`) and by `c`
/// (bytes), `l` (lines), `q`, `v` or `z`, the way GNU `head` reads it.
fn parse_obsolete(arg: &str, options: &mut Options) -> bool {
    let Some(rest) = arg.strip_prefix('-') else {
        return false;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }

    let mut count = rest[..digits].parse::<u64>().unwrap_or(u64::MAX);
    let mut unit = Unit::Lines;
    let mut flags = rest[digits..].chars().peekable();
    let multiplier = match flags.peek() {
        Some('b') => 512,
        Some('k') => 1024,
        Some('m') => 1024 * 1024,
        _ => 1,
    };
    if multiplier != 1 {
        flags.next();
        unit = Unit::Bytes;
        count = count.saturating_mul(multiplier);
    }
    for flag in flags {
        match flag {
            'c' => unit = Unit::Bytes,
            'l' => unit = Unit::Lines,
            'q' => options.headers = Headers::Never,
            'v' => options.headers = Headers::Always,
            'z' => options.delimiter = 0,
            _ => fail(&format!("invalid trailing option -- {flag}")),
        }
    }

    options.unit = unit;
    options.count = count;
    options.all_but_last = false;
    true
}

fn set_count(options: &mut Options, unit: Unit, value: &str) {
    let (all_but_last, number) = match value.strip_prefix('-') {
        Some(number) => (true, number),
        None => (false, value.strip_prefix('+').unwrap_or(value)),
    };
    let Some(count) = parse_size(number) else {
        let what = match unit {
            Unit::Lines => "lines",
            Unit::Bytes => "bytes",
        };
        // A bad value is not a usage mistake, so there is no hint to follow.
        eprintln!("head: invalid number of {what}: '{value}'");
        std::process::exit(1);
    };

    options.unit = unit;
    options.count = count;
    options.all_but_last = all_but_last;
}

/// A count as `head` and `tail` take it: digits, then an optional multiplier.
/// A count too large to hold means "all of it", as it does on Linux.
fn parse_size(text: &str) -> Option<u64> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let number = text[..digits].parse::<u64>().unwrap_or(u64::MAX);

    let suffix = &text[digits..];
    let multiplier: u64 = if suffix.is_empty() {
        1
    } else if suffix == "b" {
        512
    } else {
        let mut chars = suffix.chars();
        let power = match chars.next().map(|c| c.to_ascii_uppercase()) {
            Some('K') => 1,
            Some('M') => 2,
            Some('G') => 3,
            Some('T') => 4,
            Some('P') => 5,
            Some('E') => 6,
            _ => return None,
        };
        let base: u64 = match chars.as_str() {
            "" | "iB" => 1024,
            "B" => 1000,
            _ => return None,
        };
        base.pow(power)
    };

    Some(number.saturating_mul(multiplier))
}

fn print_usage_and_exit(exit_code: i32) -> ! {
    println!("{USAGE}");
    std::process::exit(exit_code);
}

fn print_version_and_exit() -> ! {
    println!("head (sysbox) {}", env!("CARGO_PKG_VERSION"));
    std::process::exit(0);
}

/// The name an operand goes by in headers and messages.
fn display_name(operand: &str) -> &str {
    if operand == "-" {
        "standard input"
    } else {
        operand
    }
}

/// Motor OS refuses to open a directory with a plain `InvalidArgument`, so
/// the question has to be asked to say what Linux says.
fn is_directory(path: &str) -> bool {
    std::fs::metadata(Path::new(path)).is_ok_and(|meta| meta.is_dir())
}

/// `==> NAME <==`, separated from the previous file's output by a blank line.
fn print_header(
    out: &mut impl Write,
    headers: bool,
    first: &mut bool,
    name: &str,
) -> Result<(), Failure> {
    if !headers {
        return Ok(());
    }
    let separator = if *first { "" } else { "\n" };
    *first = false;
    writeln!(out, "{separator}==> {name} <==").map_err(Failure::Write)
}

/// A broken pipe is the reader having seen enough, as `head file | head -1`
/// does: that ends the command quietly. Anything else is worth a word.
fn write_failed(err: &std::io::Error) -> ! {
    if err.kind() != std::io::ErrorKind::BrokenPipe {
        eprintln!("head: error writing 'standard output': {}", strerror(err));
    }
    std::process::exit(1);
}

fn read_chunk(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize, Failure> {
    loop {
        match input.read(buffer) {
            Ok(read) => return Ok(read),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(Failure::Read(err)),
        }
    }
}

/// Copies everything that is left of `input`.
fn copy_rest(input: &mut impl Read, out: &mut impl Write) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let read = read_chunk(input, &mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        out.write_all(&buffer[..read]).map_err(Failure::Write)?;
    }
}

/// Takes buffered input so that `head -n` need take no more of it than it prints:
/// standard input's buffer is the process's, and outlives this operand.
fn head(input: &mut impl BufRead, out: &mut impl Write, options: &Options) -> Result<(), Failure> {
    match (options.unit, options.all_but_last) {
        // Withholding nothing is copying it all, as it comes: no line has to
        // end first.
        (_, true) if options.count == 0 => copy_rest(input, out),
        (Unit::Bytes, false) => first_bytes(input, out, options.count),
        (Unit::Lines, false) => first_lines(input, out, options.count, options.delimiter),
        (Unit::Bytes, true) => all_but_last_bytes(input, out, options.count),
        (Unit::Lines, true) => all_but_last_lines(input, out, options.count, options.delimiter),
    }
}

fn first_bytes(input: &mut impl Read, out: &mut impl Write, count: u64) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut remaining = count;
    while remaining > 0 {
        let wanted = remaining.min(BUFFER_SIZE as u64) as usize;
        let read = read_chunk(input, &mut buffer[..wanted])?;
        if read == 0 {
            break;
        }
        out.write_all(&buffer[..read]).map_err(Failure::Write)?;
        remaining -= read as u64;
    }
    Ok(())
}

/// The first `count` lines, taking no more from `input` than it prints: what
/// follows stays buffered in it, so that a second `-` operand reads on from
/// there. (GNU `head` seeks back instead, which leaves a pipe short.)
fn first_lines(
    input: &mut impl BufRead,
    out: &mut impl Write,
    count: u64,
    delimiter: u8,
) -> Result<(), Failure> {
    let mut remaining = count;
    while remaining > 0 {
        let chunk = match input.fill_buf() {
            Ok(chunk) => chunk,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(Failure::Read(err)),
        };
        if chunk.is_empty() {
            break;
        }
        let mut end = chunk.len();
        for (idx, _) in chunk.iter().enumerate().filter(|(_, b)| **b == delimiter) {
            remaining -= 1;
            if remaining == 0 {
                end = idx + 1;
                break;
            }
        }
        out.write_all(&chunk[..end]).map_err(Failure::Write)?;
        input.consume(end);
    }
    Ok(())
}

/// Holds back the last `count` bytes seen, printing whatever falls out of
/// that window, so that what is left at the end is exactly what to skip.
fn all_but_last_bytes(
    input: &mut impl Read,
    out: &mut impl Write,
    count: u64,
) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut held = VecDeque::new();
    loop {
        let read = read_chunk(input, &mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        held.extend(&buffer[..read]);
        if held.len() as u64 > count {
            let excess = (held.len() as u64 - count) as usize;
            let (front, back) = held.as_slices();
            let from_front = excess.min(front.len());
            out.write_all(&front[..from_front])
                .and_then(|_| out.write_all(&back[..excess - from_front]))
                .map_err(Failure::Write)?;
            held.drain(..excess);
        }
    }
}

/// The same for lines: a last line with no delimiter is a line too.
fn all_but_last_lines(
    input: &mut impl Read,
    out: &mut impl Write,
    count: u64,
    delimiter: u8,
) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut held: VecDeque<Vec<u8>> = VecDeque::new();
    let mut line = Vec::new();
    let mut hold = |line: Vec<u8>, out: &mut dyn Write| -> Result<(), Failure> {
        held.push_back(line);
        if held.len() as u64 > count {
            let line = held.pop_front().unwrap();
            out.write_all(&line).map_err(Failure::Write)?;
        }
        Ok(())
    };

    loop {
        let read = read_chunk(input, &mut buffer)?;
        if read == 0 {
            break;
        }
        for piece in buffer[..read].split_inclusive(|b| *b == delimiter) {
            line.extend_from_slice(piece);
            if piece.last() == Some(&delimiter) {
                hold(std::mem::take(&mut line), out)?;
            }
        }
    }
    if !line.is_empty() {
        hold(line, out)?;
    }
    Ok(())
}
