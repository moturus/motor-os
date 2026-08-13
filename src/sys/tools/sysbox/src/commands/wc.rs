//! `wc`: newline, word, character, byte and maximum-line-length counts.
//!
//! The counts, the column widths, the total line and the option set follow the
//! Linux `wc` this was checked against (uutils coreutils 0.8.0), so that a
//! script written elsewhere reads the same numbers here.
//!
//! One deliberate divergence, in input that is not valid UTF-8: an undecodable
//! byte counts as one character here, always. The reference counts it as one
//! when `-m` is asked for alone and as none when `-m` comes with `-w` or `-L`,
//! which are two answers for one file; this is the first of them, and the one
//! GNU `wc` gives.

use std::io::Read;
use std::path::Path;

const USAGE: &str = "\
Print newline, word, and byte counts for each FILE, and a total line if more
than one FILE is specified.

usage:
\twc [OPTION]... [FILE]...

With no FILE, or when FILE is -, read standard input.

  -c, --bytes            print the byte counts
  -m, --chars            print the character counts
      --files0-from F    read input from the files specified by
                         NUL-terminated names in file F;
                         If F is - then read names from standard input
  -l, --lines            print the newline counts
  -L, --max-line-length  print the length of the longest line
      --total WHEN       when to print a line with total counts;
                         WHEN can be: auto, always, only, never
  -w, --words            print the word counts
  -h, --help             print this help
  -V, --version          print version";

/// Tab stops, as everywhere else: the next multiple of eight.
const TAB_WIDTH: u64 = 8;

/// The width the counts are printed in when an input's size cannot be known
/// ahead of the count -- standard input, or anything that is not a plain file.
const UNKNOWN_SIZE_WIDTH: usize = 7;

#[derive(Clone, Copy, PartialEq)]
enum Total {
    Auto,
    Always,
    Only,
    Never,
}

struct Flags {
    lines: bool,
    words: bool,
    chars: bool,
    bytes: bool,
    max_line_length: bool,
    total: Total,
}

impl Flags {
    /// Which counts to print when none were asked for.
    fn defaults(&mut self) {
        if !(self.lines || self.words || self.chars || self.bytes || self.max_line_length) {
            self.lines = true;
            self.words = true;
            self.bytes = true;
        }
    }

    fn printed(&self) -> usize {
        usize::from(self.lines)
            + usize::from(self.words)
            + usize::from(self.chars)
            + usize::from(self.bytes)
            + usize::from(self.max_line_length)
    }

    /// Whether counting has to decode the input rather than just weigh it.
    /// Characters do not: a character is a byte that is not a continuation
    /// byte, which needs no decoding and holds for undecodable bytes too.
    fn decodes(&self) -> bool {
        self.words || self.max_line_length
    }
}

/// An operand: a file, or standard input — named `-` when the reader asked for
/// it by name, and nameless when there were no operands at all.
enum Input {
    File(String),
    Stdin { named: bool },
}

impl Input {
    fn name(&self) -> Option<&str> {
        match self {
            Self::File(path) => Some(path.as_str()),
            Self::Stdin { named: true } => Some("-"),
            Self::Stdin { named: false } => None,
        }
    }

    /// Whether this is a directory, which Motor OS refuses to open with a
    /// plain `InvalidArgument` rather than a kind of its own — so the question
    /// gets asked here, and `wc` says what Linux says either way.
    fn is_directory(&self) -> bool {
        match self {
            Self::File(path) => std::fs::metadata(Path::new(path)).is_ok_and(|meta| meta.is_dir()),
            Self::Stdin { .. } => false,
        }
    }

    /// The size the counts cannot exceed, or `None` where it cannot be known
    /// before reading. What cannot even be opened counts as nothing rather
    /// than as unknown: it will contribute no counts either.
    fn size(&self) -> Option<u64> {
        match self {
            Self::File(path) => match std::fs::metadata(Path::new(path)) {
                Ok(meta) if meta.is_file() => Some(meta.len()),
                Ok(_) => None,
                Err(_) => Some(0),
            },
            Self::Stdin { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Counts {
    lines: u64,
    words: u64,
    chars: u64,
    bytes: u64,
    max_line_length: u64,
}

impl Counts {
    /// The total of a longest line is the longest of them, not their sum.
    fn add(&mut self, other: &Counts) {
        self.lines += other.lines;
        self.words += other.words;
        self.chars += other.chars;
        self.bytes += other.bytes;
        self.max_line_length = self.max_line_length.max(other.max_line_length);
    }
}

fn fail(message: &str) -> ! {
    eprintln!("wc: {message}");
    eprintln!("Try 'wc --help' for more information.");
    std::process::exit(1);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "wc");

    let (mut flags, operands, files0_from) = parse_args(&args[1..]);
    flags.defaults();

    let inputs = match files0_from {
        Some(source) => {
            if let Some(extra) = operands.first() {
                eprintln!("wc: extra operand '{}'", extra.name().unwrap_or("-"));
                eprintln!("file operands cannot be combined with --files0-from");
                eprintln!("Try 'wc --help' for more information.");
                std::process::exit(1);
            }
            read_names(&source)
        }
        None if operands.is_empty() => vec![Input::Stdin { named: false }],
        None => operands,
    };

    let width = number_width(&flags, &inputs);
    let mut total = Counts::default();
    let mut failed = false;

    for input in &inputs {
        match count_input(input, &flags) {
            Ok(counts) => {
                total.add(&counts);
                if flags.total != Total::Only {
                    print_counts(&counts, &flags, width, input.name());
                }
            }
            Err(err) => {
                failed = true;
                let directory = input.is_directory();
                // What opened and then failed to read still has a row, as it
                // does on Linux: the file was there, its contents were not.
                // A directory is that case wherever the platform notices it.
                if (err.opened || directory) && flags.total != Total::Only {
                    print_counts(&Counts::default(), &flags, width, input.name());
                }

                let name = input.name().unwrap_or("-");
                if directory {
                    eprintln!("wc: {name}: Is a directory");
                } else {
                    report(name, &err.error);
                }
            }
        }
    }

    let print_total = match flags.total {
        Total::Auto => inputs.len() > 1,
        Total::Always | Total::Only => true,
        Total::Never => false,
    };
    if print_total {
        let name = (flags.total != Total::Only).then_some("total");
        print_counts(&total, &flags, width, name);
    }

    if failed {
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> (Flags, Vec<Input>, Option<String>) {
    let mut flags = Flags {
        lines: false,
        words: false,
        chars: false,
        bytes: false,
        max_line_length: false,
        total: Total::Auto,
    };
    let mut operands = Vec::new();
    let mut files0_from = None;

    // A long option's argument may follow it or be glued on with '='; either
    // way it is the next thing this loop must consume rather than parse.
    let mut pending: Option<&str> = None;
    let mut options_done = false;

    for arg in args {
        if let Some(option) = pending.take() {
            match option {
                "--files0-from" => files0_from = Some(arg.clone()),
                _ => flags.total = parse_total(option, arg),
            }
            continue;
        }

        if options_done || arg == "-" || !arg.starts_with('-') {
            operands.push(operand(arg));
            continue;
        }

        if arg == "--" {
            options_done = true;
        } else if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match parse_long(name, value, &mut flags, &mut files0_from) {
                Some(needs_value) => pending = needs_value,
                None => fail(&format!("unrecognized option '--{name}'")),
            }
        } else {
            for short in arg[1..].chars() {
                parse_short(short, &mut flags);
            }
        }
    }

    if let Some(option) = pending {
        fail(&format!("option '{option}' requires an argument"));
    }

    (flags, operands, files0_from)
}

fn operand(arg: &str) -> Input {
    if arg == "-" {
        Input::Stdin { named: true }
    } else {
        Input::File(arg.to_owned())
    }
}

/// Applies one long option. `None` is an option `wc` does not have; `Some` is
/// the option, carrying whichever one still needs the next argument.
fn parse_long<'a>(
    name: &'a str,
    value: Option<&str>,
    flags: &mut Flags,
    files0_from: &mut Option<String>,
) -> Option<Option<&'a str>> {
    match name {
        "lines" => flags.lines = true,
        "words" => flags.words = true,
        "chars" => flags.chars = true,
        "bytes" => flags.bytes = true,
        "max-line-length" => flags.max_line_length = true,
        "help" => print_usage_and_exit(0),
        "version" => print_version_and_exit(),
        "files0-from" => match value {
            Some(value) => *files0_from = Some(value.to_owned()),
            None => return Some(Some("--files0-from")),
        },
        "total" => match value {
            Some(value) => flags.total = parse_total("--total", value),
            None => return Some(Some("--total")),
        },
        _ => return None,
    }
    Some(None)
}

fn parse_short(short: char, flags: &mut Flags) {
    match short {
        'l' => flags.lines = true,
        'w' => flags.words = true,
        'm' => flags.chars = true,
        'c' => flags.bytes = true,
        'L' => flags.max_line_length = true,
        'h' => print_usage_and_exit(0),
        'V' => print_version_and_exit(),
        _ => fail(&format!("invalid option -- '{short}'")),
    }
}

fn parse_total(option: &str, value: &str) -> Total {
    match value {
        "auto" => Total::Auto,
        "always" => Total::Always,
        "only" => Total::Only,
        "never" => Total::Never,
        _ => fail(&format!(
            "invalid argument '{value}' for '{option}'\n\
             Valid arguments are: 'auto', 'always', 'only', 'never'"
        )),
    }
}

fn print_usage_and_exit(exit_code: i32) -> ! {
    println!("{USAGE}");
    std::process::exit(exit_code);
}

fn print_version_and_exit() -> ! {
    println!("wc (sysbox) {}", env!("CARGO_PKG_VERSION"));
    std::process::exit(0);
}

/// The classic message for the errors that have one, so that a failure reads
/// the same as it does on Linux.
fn strerror(err: &std::io::Error) -> String {
    match err.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory".to_owned(),
        std::io::ErrorKind::IsADirectory => "Is a directory".to_owned(),
        std::io::ErrorKind::PermissionDenied => "Permission denied".to_owned(),
        _ => format!("{err}"),
    }
}

fn report(name: &str, err: &std::io::Error) {
    eprintln!("wc: {name}: {}", strerror(err));
}

/// The NUL-terminated names in `--files0-from`'s file.
fn read_names(source: &str) -> Vec<Input> {
    let bytes = if source == "-" {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).map(|_| bytes)
    } else {
        std::fs::read(Path::new(source))
    };

    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("wc: cannot open '{source}' for reading: {}", strerror(&err));
            std::process::exit(1);
        }
    };

    let mut names: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    // The NUL after the last name terminates it rather than starting another.
    if names.last().is_some_and(|name| name.is_empty()) {
        names.pop();
    }

    names
        .iter()
        .enumerate()
        .map(|(idx, name)| match std::str::from_utf8(name) {
            Ok("") => bad_name(source, idx + 1, "invalid zero-length file name"),
            Ok(name) => operand(name),
            Err(_) => bad_name(source, idx + 1, "invalid file name"),
        })
        .collect()
}

/// A name the list itself got wrong, reported against its position in the
/// list. This is the list's error, not an option's, so there is no usage hint.
fn bad_name(source: &str, position: usize, problem: &str) -> ! {
    eprintln!("wc: {source}:{position}: {problem}");
    std::process::exit(1);
}

/// How wide the count columns are.
///
/// One count of one input needs no padding at all, and a total on its own is
/// printed the same way. Otherwise every count is padded to the width of the
/// largest one there could be — the sizes of the inputs added up, since no
/// count can exceed the bytes it was taken from.
fn number_width(flags: &Flags, inputs: &[Input]) -> usize {
    if flags.total == Total::Only || (flags.printed() == 1 && inputs.len() == 1) {
        return 1;
    }

    let mut known = 0_u64;
    let mut unknown = false;
    for input in inputs {
        match input.size() {
            Some(size) => known = known.saturating_add(size),
            None => unknown = true,
        }
    }

    let width = known.to_string().len();
    if unknown {
        width.max(UNKNOWN_SIZE_WIDTH)
    } else {
        width
    }
}

fn print_counts(counts: &Counts, flags: &Flags, width: usize, name: Option<&str>) {
    let mut line = String::new();
    let mut column = |count: u64| {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&format!("{count:>width$}"));
    };

    if flags.lines {
        column(counts.lines);
    }
    if flags.words {
        column(counts.words);
    }
    if flags.chars {
        column(counts.chars);
    }
    if flags.bytes {
        column(counts.bytes);
    }
    if flags.max_line_length {
        column(counts.max_line_length);
    }

    if let Some(name) = name {
        line.push(' ');
        line.push_str(name);
    }

    println!("{line}");
}

/// A failure to count, and whether the input had opened before it happened.
struct CountError {
    error: std::io::Error,
    opened: bool,
}

fn count_input(input: &Input, flags: &Flags) -> Result<Counts, CountError> {
    let opened = |error| CountError {
        error,
        opened: true,
    };

    match input {
        Input::File(path) => {
            let mut file = std::fs::File::open(Path::new(path)).map_err(|error| CountError {
                error,
                opened: false,
            })?;
            count(&mut file, flags).map_err(opened)
        }
        Input::Stdin { .. } => count(&mut std::io::stdin().lock(), flags).map_err(opened),
    }
}

fn count(source: &mut impl Read, flags: &Flags) -> std::io::Result<Counts> {
    const BUFFER_SIZE: usize = 64 * 1024;

    let mut counter = Counter::new(flags);
    let mut buffer = vec![0_u8; BUFFER_SIZE];
    loop {
        match source.read(&mut buffer) {
            Ok(0) => return Ok(counter.finish()),
            Ok(read) => counter.feed(&buffer[..read]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => (),
            Err(err) => return Err(err),
        }
    }
}

/// The counts as they accumulate over a stream that arrives in pieces.
struct Counter<'a> {
    flags: &'a Flags,
    counts: Counts,
    in_word: bool,
    /// The display width of the line being read.
    width: u64,
    /// A UTF-8 sequence split across two reads.
    carry: Vec<u8>,
}

impl<'a> Counter<'a> {
    fn new(flags: &'a Flags) -> Self {
        Self {
            flags,
            counts: Counts::default(),
            in_word: false,
            width: 0,
            carry: Vec::new(),
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        self.counts.bytes += chunk.len() as u64;
        if self.flags.lines {
            self.counts.lines += chunk.iter().filter(|byte| **byte == b'\n').count() as u64;
        }
        if self.flags.chars {
            self.counts.chars += chunk.iter().filter(|byte| (**byte & 0xc0) != 0x80).count() as u64;
        }
        if !self.flags.decodes() {
            return;
        }

        // Complete whatever the last chunk ended in the middle of, then hold
        // back this chunk's own tail if it ends the same way.
        let chunk = if self.carry.is_empty() {
            chunk
        } else {
            let wanted = utf8_len(self.carry[0]) - self.carry.len();
            let (head, rest) = chunk.split_at(wanted.min(chunk.len()));
            self.carry.extend_from_slice(head);
            if self.carry.len() < utf8_len(self.carry[0]) {
                return; // Still incomplete: a two-byte character, byte by byte.
            }
            let carry = core::mem::take(&mut self.carry);
            self.decode(&carry);
            rest
        };

        let (chunk, tail) = chunk.split_at(chunk.len() - incomplete_tail(chunk));
        self.decode(chunk);
        self.carry.extend_from_slice(tail);
    }

    fn finish(&mut self) -> Counts {
        // Whatever is left was never going to be a character.
        self.carry.clear();
        self.counts.max_line_length = self.counts.max_line_length.max(self.width);
        self.counts
    }

    /// Counts a run of bytes that ends on a character boundary. Bytes that are
    /// not decodable text are neither characters nor columns, which is what
    /// the reference `wc` makes of them.
    fn decode(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            match core::str::from_utf8(bytes) {
                Ok(text) => {
                    self.count_str(text);
                    return;
                }
                Err(err) => {
                    let (valid, invalid) = bytes.split_at(err.valid_up_to());
                    self.count_str(core::str::from_utf8(valid).unwrap());
                    // Undecodable bytes are no character and no column, and
                    // they end whatever word they interrupted: what is on
                    // either side of one is not one word.
                    self.in_word = false;
                    let skip = err.error_len().unwrap_or(invalid.len());
                    bytes = &invalid[skip..];
                }
            }
        }
    }

    fn count_str(&mut self, text: &str) {
        for ch in text.chars() {
            if self.flags.words {
                if ch.is_whitespace() {
                    self.in_word = false;
                } else if !self.in_word {
                    self.in_word = true;
                    self.counts.words += 1;
                }
            }
            if self.flags.max_line_length {
                if ch == '\n' {
                    self.counts.max_line_length = self.counts.max_line_length.max(self.width);
                    self.width = 0;
                } else if ch == '\t' {
                    self.width += TAB_WIDTH - (self.width % TAB_WIDTH);
                } else {
                    self.width += char_width(ch);
                }
            }
        }
    }
}

/// How many bytes the sequence starting with `lead` has. A byte that starts no
/// sequence stands for itself, and is dropped as undecodable further down.
fn utf8_len(lead: u8) -> usize {
    match lead {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

/// How many bytes at the end of `bytes` begin a character that has not all
/// arrived yet.
fn incomplete_tail(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(3) {
        let byte = bytes[bytes.len() - back];
        if !(0x80..0xc0).contains(&byte) {
            // A lead byte (or ASCII): the tail is incomplete only if the
            // sequence it starts runs past the end of what arrived.
            return if back < utf8_len(byte) { back } else { 0 };
        }
    }
    0
}

/// The columns a character occupies, as `wcwidth` counts them: nothing for a
/// control character or a combining mark, two for the East Asian wide and
/// fullwidth ranges, one for everything else. The zero-width ranges below are
/// the common ones rather than all of them — a rarer combining mark counts as
/// one column here and as none on Linux.
fn char_width(ch: char) -> u64 {
    const ZERO_WIDTH: [core::ops::RangeInclusive<u32>; 5] = [
        0x0300..=0x036f, // Combining diacritical marks.
        0x200b..=0x200f, // Zero-width spaces, directional marks.
        0x20d0..=0x20f0, // Combining marks for symbols.
        0xfe00..=0xfe0f, // Variation selectors.
        0xfe20..=0xfe2f, // Combining half marks.
    ];
    const WIDE: [core::ops::RangeInclusive<u32>; 12] = [
        0x1100..=0x115f,   // Hangul Jamo.
        0x2e80..=0x303e,   // CJK radicals, Kangxi, CJK symbols.
        0x3041..=0x33ff,   // Kana, Hangul compatibility Jamo, CJK letters.
        0x3400..=0x4dbf,   // CJK unified ideographs extension A.
        0x4e00..=0x9fff,   // CJK unified ideographs.
        0xa000..=0xa4cf,   // Yi.
        0xac00..=0xd7a3,   // Hangul syllables.
        0xf900..=0xfaff,   // CJK compatibility ideographs.
        0xfe30..=0xfe6f,   // CJK compatibility forms, small form variants.
        0xff00..=0xff60,   // Fullwidth forms.
        0xffe0..=0xffe6,   // Fullwidth signs.
        0x1f300..=0x3fffd, // Emoji, and the supplementary ideographic planes.
    ];

    let code = ch as u32;
    if code < 0x20 || code == 0x7f {
        return 0;
    }
    if ZERO_WIDTH.iter().any(|range| range.contains(&code)) {
        return 0;
    }
    if WIDE.iter().any(|range| range.contains(&code)) {
        return 2;
    }
    1
}
