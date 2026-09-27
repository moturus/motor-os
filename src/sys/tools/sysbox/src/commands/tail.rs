//! `tail`: print the last part of files.
//!
//! The options, headers and messages follow GNU `tail` (coreutils 9.7), which
//! this was checked against. Following a file as it grows (`-f`, `-F`) is not
//! supported.

use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom, Write};

use super::head::{
    copy_rest, for_each_line, parse_args, print_inputs, read_chunk, Command, Failure, Input,
    Options, Output, Unit, BUFFER_SIZE,
};

const USAGE: &str = "\
Print the last 10 lines of each FILE to standard output.
With more than one FILE, precede each with a header giving the file name.

usage:
\ttail [OPTION]... [FILE]...

With no FILE, or when FILE is -, read standard input.

  -c, --bytes=[+]NUM       output the last NUM bytes; or use -c +NUM to
                           output starting with byte NUM of each file
  -n, --lines=[+]NUM       output the last NUM lines, instead of the last 10;
                           or use -n +NUM to skip NUM-1 lines at the start
  -q, --quiet, --silent    never output headers giving file names
  -v, --verbose            always output headers giving file names
  -z, --zero-terminated    line delimiter is NUL, not newline
  -h, --help               print this help
  -V, --version            print version

NUM may have a multiplier suffix: b 512, kB 1000, K 1024, MB 1000*1000,
M 1024*1024, GB 1000*1000*1000, G 1024*1024*1024, and so on for T, P, E.
Binary prefixes can be used, too: KiB=K, MiB=M, and so on.

Following growing files (-f, -F) is not supported.";

const TAIL: Command = Command {
    name: "tail",
    usage: USAGE,
    parse_obsolete,
    misplaced_digit: |command, digit| {
        eprintln!(
            "{}: option used in invalid context -- {digit}",
            command.name
        );
        std::process::exit(1);
    },
};

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "tail");

    let (options, operands) = parse_args(&TAIL, &args[1..]);
    // Nothing from the end prints nothing at all, so there is nothing to
    // open or wait for (a pipe's writer may never close it): what GNU does.
    if options.count == 0 && options.sign != Some('+') {
        return;
    }
    let print = |input: &mut Input, out: &mut Output| {
        if options.sign == Some('+') {
            // Line or byte 0 is where line or byte 1 is.
            let skip = options.count.saturating_sub(1);
            return match options.unit {
                Unit::Bytes => skip_bytes(input, skip).and_then(|_| copy_rest(input, out)),
                Unit::Lines => skip_lines(input, out, skip, options.delimiter),
            };
        }
        let regular_size = match input {
            Input::File(file) => file
                .metadata()
                .ok()
                .filter(|m| m.is_file())
                .map(|m| m.len()),
            Input::Stdin(_) => None,
        };
        match (input, regular_size) {
            (Input::File(file), Some(size)) => tail_file(file, size, out, &options),
            (input, _) => match options.unit {
                Unit::Bytes => last_bytes(input, out, options.count),
                Unit::Lines => last_lines(input, out, options.count, options.delimiter),
            },
        }
    };

    if !print_inputs(&TAIL, &operands, options.headers, print) {
        std::process::exit(1);
    }
}

/// `-NUM` or `+NUM`, optionally followed by `b` (512-byte blocks), `c` (bytes)
/// or `l` (lines), the way GNU `tail` reads it: as the first argument, and
/// followed by one file at most.
fn parse_obsolete(command: &Command, args: &[String], options: &mut Options) -> bool {
    let one_file = match args {
        [_] => true,
        [_, dashes] | [_, dashes, _] if dashes == "--" => true,
        [_, file] => !(file.starts_with('-') && file.len() > 1),
        _ => false,
    };
    let Some(arg) = args.first().filter(|_| one_file) else {
        return false;
    };
    // "-" is standard input and "-c" wants a count: neither is this form.
    let (sign, rest) = match arg.split_at_checked(1) {
        Some(("-", rest)) if !matches!(rest, "" | "c") => ('-', rest),
        Some(("+", rest)) => ('+', rest),
        _ => return false,
    };

    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let (number, suffix) = rest.split_at(digits);
    let (unit, multiplier, suffix) = match suffix.as_bytes().first() {
        Some(b'b') => (Unit::Bytes, 512, &suffix[1..]),
        Some(b'c') => (Unit::Bytes, 1, &suffix[1..]),
        Some(b'l') => (Unit::Lines, 1, &suffix[1..]),
        _ => (Unit::Lines, 1, suffix),
    };
    match suffix {
        "" => {}
        "f" => command.fail("invalid option -- 'f'"),
        _ => return false,
    }

    let count = if number.is_empty() {
        10
    } else {
        number.parse::<u64>().unwrap_or(u64::MAX)
    };
    options.unit = unit;
    options.count = count.saturating_mul(multiplier);
    options.sign = Some(sign);
    true
}

/// The last lines or bytes of a regular file, found from its end rather than
/// by reading all of it.
fn tail_file(
    file: &mut std::fs::File,
    size: u64,
    out: &mut Output,
    options: &Options,
) -> Result<(), Failure> {
    let start = match options.unit {
        Unit::Bytes => size.saturating_sub(options.count),
        Unit::Lines => last_lines_start(file, size, options.count, options.delimiter)?,
    };
    file.seek(SeekFrom::Start(start)).map_err(Failure::Read)?;
    copy_rest(file, out)
}

/// Where the last `count` lines of the file begin, reading back from its end.
fn last_lines_start(
    file: &mut std::fs::File,
    size: u64,
    count: u64,
    delimiter: u8,
) -> Result<u64, Failure> {
    if count == 0 {
        return Ok(size);
    }
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut seen = 0;
    let mut end = size;
    while end > 0 {
        let start = end.saturating_sub(BUFFER_SIZE as u64);
        let chunk = &mut buffer[..(end - start) as usize];
        file.seek(SeekFrom::Start(start))
            .and_then(|_| file.read_exact(chunk))
            .map_err(Failure::Read)?;
        // The delimiter at the very end ends the last line; it starts none.
        let chunk = match chunk.split_last() {
            Some((last, init)) if end == size && *last == delimiter => init,
            _ => chunk,
        };
        for (idx, _) in chunk
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, b)| **b == delimiter)
        {
            seen += 1;
            if seen == count {
                return Ok(start + idx as u64 + 1);
            }
        }
        end = start;
    }
    Ok(0)
}

/// The last `count` bytes of a stream: hold that many, and print them at
/// its end.
fn last_bytes(input: &mut impl Read, out: &mut impl Write, count: u64) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut held = VecDeque::new();
    loop {
        let read = read_chunk(input, &mut buffer)?;
        if read == 0 {
            break;
        }
        held.extend(&buffer[..read]);
        if held.len() as u64 > count {
            held.drain(..(held.len() as u64 - count) as usize);
        }
    }
    let (front, back) = held.as_slices();
    out.write_all(front)
        .and_then(|_| out.write_all(back))
        .map_err(Failure::Write)
}

/// The same for lines: a last line with no delimiter is a line too.
fn last_lines(
    input: &mut impl Read,
    out: &mut impl Write,
    count: u64,
    delimiter: u8,
) -> Result<(), Failure> {
    let mut held = VecDeque::new();
    for_each_line(input, delimiter, |line| {
        held.push_back(line);
        if held.len() as u64 > count {
            held.pop_front();
        }
        Ok(())
    })?;
    for line in held {
        out.write_all(&line).map_err(Failure::Write)?;
    }
    Ok(())
}

fn skip_bytes(input: &mut impl Read, count: u64) -> Result<(), Failure> {
    std::io::copy(&mut input.by_ref().take(count), &mut std::io::sink())
        .map(|_| ())
        .map_err(Failure::Read)
}

/// Skips `count` lines, then prints the rest.
fn skip_lines(
    input: &mut impl Read,
    out: &mut impl Write,
    count: u64,
    delimiter: u8,
) -> Result<(), Failure> {
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    let mut remaining = count;
    while remaining > 0 {
        let read = read_chunk(input, &mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        let chunk = &buffer[..read];
        for (idx, _) in chunk.iter().enumerate().filter(|(_, b)| **b == delimiter) {
            remaining -= 1;
            if remaining == 0 {
                out.write_all(&chunk[idx + 1..]).map_err(Failure::Write)?;
                break;
            }
        }
    }
    copy_rest(input, out)
}
