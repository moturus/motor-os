//! `head`: print the first part of files.
//!
//! The options, headers and messages follow GNU `head` (coreutils 9.7), which
//! this was checked against; uutils `head` differs only in its usage errors.
//!
//! `tail` takes the same options and prints its inputs the same way, so the
//! option parser and the loop over inputs here are shared with it.

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

pub(super) const BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Unit {
    Lines,
    Bytes,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Headers {
    Auto,
    Never,
    Always,
}

/// The options `head` and `tail` share. What a sign on the count means is
/// each command's own business.
pub(super) struct Options {
    pub unit: Unit,
    pub count: u64,
    pub sign: Option<char>,
    pub headers: Headers,
    pub delimiter: u8,
}

/// A command's view of its options: its name, and the forms of them it alone
/// has (its help text, and its obsolete `-NUM` spelling).
pub(super) struct Command {
    pub name: &'static str,
    pub usage: &'static str,
    /// Applies the obsolete option at the start of `args`, if there is one
    /// there, and says whether there was.
    pub parse_obsolete: fn(&Command, &[String], &mut Options) -> bool,
    /// Reports a digit among the options anywhere the obsolete form is not.
    pub misplaced_digit: fn(&Command, char) -> !,
}

impl Command {
    pub fn fail(&self, message: &str) -> ! {
        eprintln!("{}: {message}", self.name);
        eprintln!("Try '{} --help' for more information.", self.name);
        std::process::exit(1);
    }
}

/// Why one input could not be printed. A failed write ends the command: there
/// is nowhere left to print to.
pub(super) enum Failure {
    Read(std::io::Error),
    Write(std::io::Error),
}

pub(super) type Output = std::io::BufWriter<std::io::StdoutLock<'static>>;

/// An operand, opened.
pub(super) enum Input {
    Stdin(std::io::StdinLock<'static>),
    File(std::fs::File),
}

impl Read for Input {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Stdin(stdin) => stdin.read(buffer),
            Self::File(file) => file.read(buffer),
        }
    }
}

const HEAD: Command = Command {
    name: "head",
    usage: USAGE,
    parse_obsolete,
    misplaced_digit: |command, digit| command.fail(&format!("invalid trailing option -- {digit}")),
};

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "head");

    let (options, operands) = parse_args(&HEAD, &args[1..]);
    let all_but_last = options.sign == Some('-');
    let print = |input: &mut Input, out: &mut Output| match (options.unit, all_but_last) {
        // Withholding nothing is copying it all, as it comes: no line has to
        // end first.
        (_, true) if options.count == 0 => copy_rest(input, out),
        (Unit::Bytes, false) => first_bytes(input, out, options.count),
        (Unit::Lines, false) => match input {
            // Standard input's own buffer is the process's, and outlives
            // this operand.
            Input::Stdin(stdin) => first_lines(stdin, out, options.count, options.delimiter),
            Input::File(file) => {
                let mut file = std::io::BufReader::with_capacity(BUFFER_SIZE, file);
                first_lines(&mut file, out, options.count, options.delimiter)
            }
        },
        (Unit::Bytes, true) => all_but_last_bytes(input, out, options.count),
        (Unit::Lines, true) => all_but_last_lines(input, out, options.count, options.delimiter),
    };

    if !print_inputs(&HEAD, &operands, options.headers, print) {
        std::process::exit(1);
    }
}

/// Parses the options and returns them with the operands: standard input when
/// there are none.
pub(super) fn parse_args(command: &Command, args: &[String]) -> (Options, Vec<String>) {
    let mut options = Options {
        unit: Unit::Lines,
        count: 10,
        sign: None,
        headers: Headers::Auto,
        delimiter: b'\n',
    };
    let mut operands = Vec::new();
    let mut args = args.iter();

    if (command.parse_obsolete)(command, args.as_slice(), &mut options) {
        args.next();
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
                            command.fail(&format!("option '--{name}' requires an argument"))
                        }),
                    };
                    set_count(command, &mut options, unit, value);
                }
                "quiet" | "silent" | "verbose" | "zero-terminated" | "help" | "version"
                    if value.is_some() =>
                {
                    command.fail(&format!("option '--{name}' doesn't allow an argument"))
                }
                "quiet" | "silent" => options.headers = Headers::Never,
                "verbose" => options.headers = Headers::Always,
                "zero-terminated" => options.delimiter = 0,
                "help" => print_usage_and_exit(command),
                "version" => print_version_and_exit(command),
                _ => command.fail(&format!("unrecognized option '--{name}'")),
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
                                command.fail(&format!("option requires an argument -- '{short}'"))
                            })
                        } else {
                            rest
                        };
                        set_count(command, &mut options, unit, value);
                        break;
                    }
                    'q' => options.headers = Headers::Never,
                    'v' => options.headers = Headers::Always,
                    'z' => options.delimiter = 0,
                    'h' => print_usage_and_exit(command),
                    'V' => print_version_and_exit(command),
                    '0'..='9' => (command.misplaced_digit)(command, short),
                    _ => command.fail(&format!("invalid option -- '{short}'")),
                }
            }
        }
    }

    if operands.is_empty() {
        operands.push("-".to_owned());
    }
    (options, operands)
}

/// `-NUM`, optionally followed by a multiplier (`b`, `k`, `m`) and by `c`
/// (bytes), `l` (lines), `q`, `v` or `z`, the way GNU `head` reads it. As on
/// Linux, it is recognized only as the first argument.
fn parse_obsolete(command: &Command, args: &[String], options: &mut Options) -> bool {
    let Some(rest) = args.first().and_then(|arg| arg.strip_prefix('-')) else {
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
            _ => command.fail(&format!("invalid trailing option -- {flag}")),
        }
    }

    options.unit = unit;
    options.count = count;
    options.sign = None;
    true
}

fn set_count(command: &Command, options: &mut Options, unit: Unit, value: &str) {
    let sign = value.chars().next().filter(|c| *c == '-' || *c == '+');
    let number = &value[sign.map_or(0, char::len_utf8)..];
    let Some(count) = parse_size(number) else {
        let what = match unit {
            Unit::Lines => "lines",
            Unit::Bytes => "bytes",
        };
        // A bad value is not a usage mistake, so there is no hint to follow.
        eprintln!("{}: invalid number of {what}: '{value}'", command.name);
        std::process::exit(1);
    };

    options.unit = unit;
    options.count = count;
    options.sign = sign;
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

fn print_usage_and_exit(command: &Command) -> ! {
    println!("{}", command.usage);
    std::process::exit(0);
}

fn print_version_and_exit(command: &Command) -> ! {
    println!("{} (sysbox) {}", command.name, env!("CARGO_PKG_VERSION"));
    std::process::exit(0);
}

/// Prints each operand with `print`, under a header when `headers` asks for
/// one, and reports the ones that fail. Returns whether none did.
pub(super) fn print_inputs(
    command: &Command,
    operands: &[String],
    headers: Headers,
    mut print: impl FnMut(&mut Input, &mut Output) -> Result<(), Failure>,
) -> bool {
    let headers = match headers {
        Headers::Auto => operands.len() > 1,
        Headers::Never => false,
        Headers::Always => true,
    };
    let mut out = std::io::BufWriter::with_capacity(BUFFER_SIZE, std::io::stdout().lock());
    let mut first = true;
    let mut ok = true;

    for operand in operands {
        let name = if operand == "-" {
            "standard input"
        } else {
            operand.as_str()
        };
        let input = if operand == "-" {
            Ok(Input::Stdin(std::io::stdin().lock()))
        } else {
            std::fs::File::open(Path::new(operand)).map(Input::File)
        };

        let result = match input {
            Ok(mut input) => print_header(&mut out, headers, &mut first, name)
                .and_then(|_| print(&mut input, &mut out)),
            // Motor OS refuses to open a directory at all; Linux opens it and
            // fails the read, which is what gets reported.
            Err(_) if std::fs::metadata(Path::new(operand)).is_ok_and(|meta| meta.is_dir()) => {
                print_header(&mut out, headers, &mut first, name).and(Err(Failure::Read(
                    std::io::Error::from(std::io::ErrorKind::IsADirectory),
                )))
            }
            Err(err) => {
                let _ = out.flush();
                eprintln!(
                    "{}: cannot open '{operand}' for reading: {}",
                    command.name,
                    strerror(&err)
                );
                ok = false;
                continue;
            }
        };

        match result {
            Ok(()) => {}
            Err(Failure::Read(err)) => {
                let _ = out.flush();
                eprintln!(
                    "{}: error reading '{name}': {}",
                    command.name,
                    strerror(&err)
                );
                ok = false;
            }
            Err(Failure::Write(err)) => write_failed(command, &err),
        }
    }

    if let Err(err) = out.flush() {
        write_failed(command, &err);
    }
    ok
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
fn write_failed(command: &Command, err: &std::io::Error) -> ! {
    if err.kind() != std::io::ErrorKind::BrokenPipe {
        eprintln!(
            "{}: error writing 'standard output': {}",
            command.name,
            strerror(err)
        );
    }
    std::process::exit(1);
}

pub(super) fn read_chunk(input: &mut impl Read, buffer: &mut [u8]) -> Result<usize, Failure> {
    loop {
        match input.read(buffer) {
            Ok(read) => return Ok(read),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(Failure::Read(err)),
        }
    }
}

/// Copies everything that is left of `input`.
pub(super) fn copy_rest(input: &mut impl Read, out: &mut impl Write) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        let read = read_chunk(input, &mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        out.write_all(&buffer[..read]).map_err(Failure::Write)?;
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
    let mut held = VecDeque::new();
    for_each_line(input, delimiter, |line| {
        held.push_back(line);
        if held.len() as u64 > count {
            let line = held.pop_front().unwrap();
            out.write_all(&line).map_err(Failure::Write)?;
        }
        Ok(())
    })
}

/// Calls `take` with each line of `input`, delimiter included.
pub(super) fn for_each_line(
    input: &mut impl Read,
    delimiter: u8,
    mut take: impl FnMut(Vec<u8>) -> Result<(), Failure>,
) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut line = Vec::new();
    loop {
        let read = read_chunk(input, &mut buffer)?;
        if read == 0 {
            break;
        }
        for piece in buffer[..read].split_inclusive(|b| *b == delimiter) {
            line.extend_from_slice(piece);
            if piece.last() == Some(&delimiter) {
                take(std::mem::take(&mut line))?;
            }
        }
    }
    if !line.is_empty() {
        take(line)?;
    }
    Ok(())
}
