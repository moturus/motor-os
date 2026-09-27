//! `diff`: compare files line by line.
//!
//! The options, output formats, messages and exit status follow GNU `diff`
//! (diffutils 3.12), which this was checked against. So does the edit script
//! itself: `analyze` finds the one GNU `diff` finds, so that the same two
//! files give the same hunks. Not supported: side-by-side and ed output, and
//! skipping blank lines, or lines or files that match a pattern (-B, -I, -x).

mod analyze;

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::time::SystemTime;

use super::wc::strerror;
use analyze::Change;

const USAGE: &str = "\
Compare FILES line by line.

usage:
\tdiff [OPTION]... FILE1 FILE2

  -q, --brief                   report only when files differ
  -s, --report-identical-files  report when two files are the same
  -c, -C NUM, --context[=NUM]   output NUM (default 3) lines of copied context
  -u, -U NUM, --unified[=NUM]   output NUM (default 3) lines of unified context
      --normal                  output a normal diff (the default)
  -r, --recursive               recursively compare any subdirectories found
  -N, --new-file                treat absent files as empty
      --label LABEL             use LABEL instead of file name and timestamp
                                (can be repeated)
  -i, --ignore-case             ignore case differences in file contents
  -b, --ignore-space-change     ignore changes in the amount of white space
  -w, --ignore-all-space        ignore all white space
  -a, --text                    treat all files as text
  -d, --minimal                 try hard to find a smaller set of changes
      --help                    display this help and exit
  -v, --version                 output version information and exit

FILES are 'FILE1 FILE2' or 'DIR1 DIR2' or 'DIR FILE' or 'FILE DIR'.
If a FILE is '-', read standard input.
Exit status is 0 if inputs are the same, 1 if different, 2 if trouble.";

const SAME: i32 = 0;
const DIFFERENT: i32 = 1;
const TROUBLE: i32 = 2;

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Normal,
    Unified,
    Context,
}

struct Options {
    /// The output format asked for; the normal one when none was.
    format: Option<Format>,
    context: usize,
    brief: bool,
    report_identical: bool,
    ignore_case: bool,
    ignore_space_change: bool,
    ignore_all_space: bool,
    text: bool,
    recursive: bool,
    new_file: bool,
    minimal: bool,
    labels: Vec<String>,
    /// The options as given, which name each pair of files compared in
    /// directories: "diff -r -u a/x b/x".
    switches: String,
}

fn fail(message: &str) -> ! {
    eprintln!("diff: {message}");
    eprintln!("diff: Try 'diff --help' for more information.");
    std::process::exit(TROUBLE);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "diff");

    let (options, operands) = parse_args(&args[1..]);
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let status = compare_operands(&options, &operands[0], &operands[1], &mut out);
    if let Err(err) = out.flush() {
        write_failed(&err);
    }
    std::process::exit(status);
}

/// A broken pipe is the reader having seen enough; that ends `diff` quietly.
fn write_failed(err: &std::io::Error) -> ! {
    if err.kind() != std::io::ErrorKind::BrokenPipe {
        eprintln!("diff: standard output: {}", strerror(err));
    }
    std::process::exit(TROUBLE);
}

fn parse_args(args: &[String]) -> (Options, Vec<String>) {
    let mut options = Options {
        format: None,
        context: 0,
        brief: false,
        report_identical: false,
        ignore_case: false,
        ignore_space_change: false,
        ignore_all_space: false,
        text: false,
        recursive: false,
        new_file: false,
        minimal: false,
        labels: Vec::new(),
        switches: String::new(),
    };
    let mut operands = Vec::new();
    let mut rest = args.iter();
    let mut options_done = false;

    while let Some(arg) = rest.next() {
        if options_done || arg == "-" || !arg.starts_with('-') {
            operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            options_done = true;
            continue;
        }
        options.switches.push(' ');
        options.switches.push_str(arg);

        if let Some(long) = arg.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            match name {
                "context" | "unified" => {
                    let style = if name == "context" {
                        Format::Context
                    } else {
                        Format::Unified
                    };
                    set_format(&mut options, style, attached.map_or(3, parse_context));
                }
                "label" => {
                    let label = take_value(name, attached, &mut rest, &mut options.switches);
                    options.labels.push(label);
                }
                _ => match (long_flag(name), attached) {
                    (Some(apply), None) => apply(&mut options),
                    (Some(_), Some(_)) => {
                        fail(&format!("option '--{name}' doesn't allow an argument"))
                    }
                    (None, _) => fail(&format!("unrecognized option '--{name}'")),
                },
            }
            continue;
        }

        for (idx, short) in arg.char_indices().skip(1) {
            let attached = Some(&arg[idx + short.len_utf8()..]).filter(|value| !value.is_empty());
            let option = short.to_string();
            match short {
                'c' => set_format(&mut options, Format::Context, 3),
                'u' => set_format(&mut options, Format::Unified, 3),
                'C' | 'U' => {
                    let value = take_value(&option, attached, &mut rest, &mut options.switches);
                    let style = if short == 'C' {
                        Format::Context
                    } else {
                        Format::Unified
                    };
                    set_format(&mut options, style, parse_context(&value));
                    break;
                }
                'L' => {
                    let label = take_value(&option, attached, &mut rest, &mut options.switches);
                    options.labels.push(label);
                    break;
                }
                'q' => options.brief = true,
                's' => options.report_identical = true,
                'r' => options.recursive = true,
                'N' => options.new_file = true,
                'i' => options.ignore_case = true,
                'b' => options.ignore_space_change = true,
                'w' => options.ignore_all_space = true,
                'a' => options.text = true,
                'd' => options.minimal = true,
                'v' => print_version_and_exit(),
                _ => fail(&format!("invalid option -- '{short}'")),
            }
        }
    }

    if options.labels.len() > 2 {
        eprintln!("diff: too many file label options");
        std::process::exit(TROUBLE);
    }
    match operands.len() {
        0 | 1 => {
            let last = args.last().map_or("diff", String::as_str);
            fail(&format!("missing operand after '{last}'"))
        }
        2 => {}
        _ => fail(&format!("extra operand '{}'", operands[2])),
    }
    (options, operands)
}

/// An option's value: the rest of its argument, or the next argument.
fn take_value(
    option: &str,
    attached: Option<&str>,
    rest: &mut std::slice::Iter<String>,
    switches: &mut String,
) -> String {
    if let Some(value) = attached {
        return value.to_owned();
    }
    let Some(value) = rest.next() else {
        if option.len() == 1 {
            fail(&format!("option requires an argument -- '{option}'"))
        }
        fail(&format!("option '--{option}' requires an argument"))
    };
    switches.push(' ');
    switches.push_str(value);
    value.clone()
}

/// The long options that take no value, and what each does.
fn long_flag(name: &str) -> Option<fn(&mut Options)> {
    Some(match name {
        "normal" => |options| set_format(options, Format::Normal, 0),
        "brief" => |options| options.brief = true,
        "report-identical-files" => |options| options.report_identical = true,
        "recursive" => |options| options.recursive = true,
        "new-file" => |options| options.new_file = true,
        "ignore-case" => |options| options.ignore_case = true,
        "ignore-space-change" => |options| options.ignore_space_change = true,
        "ignore-all-space" => |options| options.ignore_all_space = true,
        "text" => |options| options.text = true,
        "minimal" => |options| options.minimal = true,
        "help" => |_| {
            println!("{USAGE}");
            std::process::exit(SAME)
        },
        "version" => |_| print_version_and_exit(),
        _ => return None,
    })
}

/// Picks the output format. Asking for two different ones is an error; the
/// context is the widest asked for, as with GNU `diff`.
fn set_format(options: &mut Options, style: Format, lines: usize) {
    if options.format.is_some_and(|format| format != style) {
        fail("conflicting output style options");
    }
    options.format = Some(style);
    options.context = options.context.max(lines);
}

/// More context than this changes nothing (a hunk cannot outgrow its files),
/// and keeps the arithmetic on it well clear of overflow.
const CONTEXT_MAX: usize = isize::MAX as usize / 4;

fn parse_context(value: &str) -> usize {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        fail(&format!("invalid context length '{value}'"));
    }
    // Only overflow fails to parse: as GNU does, take that as the most.
    value
        .parse::<usize>()
        .unwrap_or(usize::MAX)
        .min(CONTEXT_MAX)
}

fn print_version_and_exit() -> ! {
    println!("diff (sysbox) {}", env!("CARGO_PKG_VERSION"));
    std::process::exit(SAME);
}

/// A file's contents, and what its header says about it.
struct Contents {
    data: Vec<u8>,
    modified: Option<SystemTime>,
}

fn is_dir(path: &str) -> bool {
    path != "-" && std::fs::metadata(Path::new(path)).is_ok_and(|meta| meta.is_dir())
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// The top-level operands: two files, two directories, or a file and the
/// directory to look for a file of the same name in.
fn compare_operands(options: &Options, path0: &str, path1: &str, out: &mut impl Write) -> i32 {
    // Whether each is a directory; `None` for one that is absent under -N,
    // which is then an empty one of the other's kind.
    let mut kinds = [None, None];
    let mut failed = false;
    for (kind, path) in kinds.iter_mut().zip([path0, path1]) {
        let found = match path {
            "-" => Ok(false),
            _ => std::fs::metadata(Path::new(path)).map(|meta| meta.is_dir()),
        };
        match found {
            Ok(dir) => *kind = Some(dir),
            Err(err) if options.new_file && err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                eprintln!("diff: {path}: {}", strerror(&err));
                failed = true;
            }
        }
    }
    let kinds = match kinds {
        _ if failed => return TROUBLE,
        [Some(dir0), Some(dir1)] => (dir0, dir1),
        [Some(dir), None] | [None, Some(dir)] => (dir, dir),
        [None, None] => {
            // -N makes an absent file empty, but not both of them.
            for path in [path0, path1] {
                eprintln!("diff: {path}: No such file or directory");
            }
            return TROUBLE;
        }
    };

    match kinds {
        (true, true) => compare_dirs(options, path0, path1, out),
        (true, false) | (false, true) if path0 == "-" || path1 == "-" => {
            eprintln!("diff: cannot compare '-' to a directory");
            TROUBLE
        }
        (true, false) => {
            let name = Path::new(path1).file_name().map(|n| n.to_string_lossy());
            let inner = join(path0, &name.unwrap_or_default());
            compare_files(options, &inner, path1, false, out)
        }
        (false, true) => {
            let name = Path::new(path0).file_name().map(|n| n.to_string_lossy());
            let inner = join(path1, &name.unwrap_or_default());
            compare_files(options, path0, &inner, false, out)
        }
        (false, false) => compare_files(options, path0, path1, false, out),
    }
}

/// The names in a directory, sorted; an absent directory is empty under -N.
fn read_dir(path: &str, options: &Options) -> Result<Vec<String>, std::io::Error> {
    let entries = match std::fs::read_dir(Path::new(path)) {
        Ok(entries) => entries,
        Err(err) if options.new_file && err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new())
        }
        Err(err) => return Err(err),
    };
    let mut names = Vec::new();
    for entry in entries {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Ok(names)
}

fn compare_dirs(options: &Options, dir0: &str, dir1: &str, out: &mut impl Write) -> i32 {
    let mut names = Vec::new();
    for dir in [dir0, dir1] {
        match read_dir(dir, options) {
            Ok(list) => names.push(list),
            Err(err) => {
                let _ = out.flush();
                eprintln!("diff: {dir}: {}", strerror(&err));
                return TROUBLE;
            }
        }
    }
    let (names0, names1) = (&names[0], &names[1]);

    let mut status = SAME;
    let (mut i0, mut i1) = (0, 0);
    while i0 < names0.len() || i1 < names1.len() {
        let order = match (names0.get(i0), names1.get(i1)) {
            (Some(name0), Some(name1)) => name0.cmp(name1),
            (Some(_), None) => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Greater,
        };
        let name = match order {
            std::cmp::Ordering::Greater => &names1[i1],
            _ => &names0[i0],
        };
        let (path0, path1) = (join(dir0, name), join(dir1, name));
        let result = if order != std::cmp::Ordering::Equal && !options.new_file {
            let dir = if order == std::cmp::Ordering::Less {
                dir0
            } else {
                dir1
            };
            writeln!(out, "Only in {dir}: {name}").map(|_| DIFFERENT)
        } else {
            compare_entries(options, &path0, &path1, out)
        };
        status = status.max(result.unwrap_or_else(|err| write_failed(&err)));

        match order {
            std::cmp::Ordering::Less => i0 += 1,
            std::cmp::Ordering::Greater => i1 += 1,
            std::cmp::Ordering::Equal => (i0, i1) = (i0 + 1, i1 + 1),
        }
    }
    status
}

/// Two entries of the same name in directories being compared; one of them
/// may be absent, under -N, and is then taken to be of the other's kind.
fn compare_entries(
    options: &Options,
    path0: &str,
    path1: &str,
    out: &mut impl Write,
) -> std::io::Result<i32> {
    let kind = |path: &str| std::fs::metadata(Path::new(path)).ok().map(|m| m.is_dir());
    let (dir0, dir1) = match (kind(path0), kind(path1)) {
        (Some(dir0), Some(dir1)) => (dir0, dir1),
        (Some(dir), None) | (None, Some(dir)) => (dir, dir),
        (None, None) => (false, false),
    };

    match (dir0, dir1) {
        (true, true) if options.recursive => Ok(compare_dirs(options, path0, path1, out)),
        (true, true) => {
            writeln!(out, "Common subdirectories: {path0} and {path1}")?;
            Ok(SAME)
        }
        (false, false) => Ok(compare_files(options, path0, path1, true, out)),
        _ => {
            let what = |dir| if dir { "directory" } else { "regular file" };
            let [name0, name1] = names(options, [path0, path1]);
            writeln!(
                out,
                "File {name0} is a {} while file {name1} is a {}",
                what(dir0),
                what(dir1)
            )?;
            Ok(DIFFERENT)
        }
    }
}

fn read_contents(path: &str, options: &Options) -> Result<Contents, std::io::Error> {
    if path == "-" {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        return Ok(Contents {
            data,
            modified: Some(SystemTime::now()),
        });
    }
    match std::fs::read(Path::new(path)) {
        Ok(data) => Ok(Contents {
            data,
            modified: std::fs::metadata(Path::new(path))
                .and_then(|meta| meta.modified())
                .ok(),
        }),
        Err(err) if options.new_file && err.kind() == std::io::ErrorKind::NotFound => {
            Ok(Contents {
                data: Vec::new(),
                modified: Some(SystemTime::UNIX_EPOCH),
            })
        }
        // Motor OS refuses to open a directory with a plain InvalidArgument.
        Err(_) if is_dir(path) => Err(std::io::Error::from(std::io::ErrorKind::IsADirectory)),
        Err(err) => Err(err),
    }
}

/// Compares two files, printing their differences; `in_dirs` is whether they
/// were found in directories, which names each pair before its differences.
fn compare_files(
    options: &Options,
    path0: &str,
    path1: &str,
    in_dirs: bool,
    out: &mut impl Write,
) -> i32 {
    // Standard input named twice is one input, the same as itself, and GNU
    // says so without reading it: an open pipe need not end first.
    if path0 == "-" && path1 == "-" {
        return report_identical(options, [path0, path1], out)
            .unwrap_or_else(|err| write_failed(&err));
    }
    let mut files = Vec::new();
    for path in [path0, path1] {
        match read_contents(path, options) {
            Ok(contents) => files.push(contents),
            Err(err) => {
                let _ = out.flush();
                eprintln!("diff: {path}: {}", strerror(&err));
                return TROUBLE;
            }
        }
    }

    print_differences(options, [path0, path1], &files, in_dirs, out)
        .unwrap_or_else(|err| write_failed(&err))
}

/// What a pair of files is called when they are reported on: the labels
/// given, where there are any. Errors and directory listings use the paths.
fn names<'a>(options: &'a Options, paths: [&'a str; 2]) -> [&'a str; 2] {
    [0, 1].map(|index| {
        options
            .labels
            .get(index)
            .map_or(paths[index], String::as_str)
    })
}

fn report_identical(
    options: &Options,
    paths: [&str; 2],
    out: &mut impl Write,
) -> std::io::Result<i32> {
    if options.report_identical {
        let [name0, name1] = names(options, paths);
        writeln!(out, "Files {name0} and {name1} are identical")?;
    }
    Ok(SAME)
}

fn print_differences(
    options: &Options,
    paths: [&str; 2],
    files: &[Contents],
    in_dirs: bool,
    out: &mut impl Write,
) -> std::io::Result<i32> {
    let [path0, path1] = paths;
    let [name0, name1] = names(options, paths);
    let (data0, data1) = (&files[0].data, &files[1].data);
    let differ = |out: &mut dyn Write, what: &str| {
        writeln!(out, "{what} {name0} and {name1} differ")?;
        Ok(DIFFERENT)
    };

    if data0 == data1 {
        return report_identical(options, paths, out);
    }
    if !options.text && (data0.contains(&0) || data1.contains(&0)) {
        return differ(
            out,
            if options.brief {
                "Files"
            } else {
                "Binary files"
            },
        );
    }
    let ignoring = options.ignore_case || options.ignore_space_change || options.ignore_all_space;
    if options.brief && !ignoring {
        return differ(out, "Files");
    }

    let lines = [split_lines(data0), split_lines(data1)];
    let script = diff_lines(options, &lines);
    if script.is_empty() {
        return report_identical(options, paths, out);
    }
    if options.brief {
        return differ(out, "Files");
    }

    if in_dirs {
        writeln!(out, "diff{} {name0} {name1}", options.switches)?;
    }
    let printer = Printer {
        options,
        lines: &lines,
        script: &script,
    };
    match options.format.unwrap_or(Format::Normal) {
        Format::Normal => printer.normal(out)?,
        Format::Unified => {
            print_header(out, "---", options, 0, path0, &files[0])?;
            print_header(out, "+++", options, 1, path1, &files[1])?;
            printer.unified(out)?;
        }
        Format::Context => {
            print_header(out, "***", options, 0, path0, &files[0])?;
            print_header(out, "---", options, 1, path1, &files[1])?;
            printer.context(out)?;
        }
    }
    Ok(DIFFERENT)
}

/// "--- NAME\tTIME", or the label given for the file instead.
fn print_header(
    out: &mut impl Write,
    marker: &str,
    options: &Options,
    index: usize,
    path: &str,
    file: &Contents,
) -> std::io::Result<()> {
    if let Some(label) = options.labels.get(index) {
        return writeln!(out, "{marker} {label}");
    }
    let Some(modified) = file.modified else {
        return writeln!(out, "{marker} {path}");
    };
    // Motor OS keeps time in UTC.
    let time = time::OffsetDateTime::from(modified);
    if options.format == Some(Format::Unified) {
        writeln!(
            out,
            "{marker} {path}\t{}-{:02}-{:02} {:02}:{:02}:{:02}.{:09} +0000",
            time.year(),
            time.month() as u8,
            time.day(),
            time.hour(),
            time.minute(),
            time.second(),
            time.nanosecond()
        )
    } else {
        let weekday = &format!("{}", time.weekday())[..3];
        let month = &format!("{}", time.month())[..3];
        writeln!(
            out,
            "{marker} {path}\t{weekday} {month} {:2} {:02}:{:02}:{:02} {}",
            time.day(),
            time.hour(),
            time.minute(),
            time.second(),
            time.year()
        )
    }
}

/// The lines of `data`, each with its newline; the last may have none.
fn split_lines(data: &[u8]) -> Vec<&[u8]> {
    data.split_inclusive(|b| *b == b'\n').collect()
}

fn diff_lines(options: &Options, lines: &[Vec<&[u8]>; 2]) -> Vec<Change> {
    // Leading and trailing lines the files share byte for byte are set aside
    // first, as GNU does: no change can move into them. GNU keeps as many of
    // them as there are lines of context in play, and so does this.
    let [lines0, lines1] = lines;
    let horizon = options.context;
    let prefix = lines0
        .iter()
        .zip(lines1)
        .take_while(|(l0, l1)| l0 == l1)
        .count();
    let suffix = lines0[prefix..]
        .iter()
        .rev()
        .zip(lines1[prefix..].iter().rev())
        .take_while(|(l0, l1)| l0 == l1)
        .count();
    let (prefix, suffix) = (
        prefix.saturating_sub(horizon),
        suffix.saturating_sub(horizon),
    );
    let middle = [
        &lines0[prefix..lines0.len() - suffix],
        &lines1[prefix..lines1.len() - suffix],
    ];

    // Number the lines by what they compare equal to, so that the search
    // compares numbers rather than text.
    let mut classes: HashMap<Cow<[u8]>, usize> = HashMap::new();
    let mut numbered = [Vec::new(), Vec::new()];
    for (file, lines) in middle.iter().enumerate() {
        for line in lines.iter() {
            let next = classes.len();
            numbered[file].push(*classes.entry(line_key(line, options)).or_insert(next));
        }
    }

    let mut script = analyze::edit_script(&numbered[0], &numbered[1], options.minimal);
    for change in &mut script {
        change.line0 += prefix;
        change.line1 += prefix;
    }
    script
}

/// What a line is compared as. Under -b and -w a missing last newline does
/// not count either: it is white space, too.
fn line_key<'a>(line: &'a [u8], options: &Options) -> Cow<'a, [u8]> {
    let spaces = options.ignore_space_change || options.ignore_all_space;
    if !options.ignore_case && !spaces {
        return Cow::Borrowed(line);
    }
    let text = if spaces {
        line.strip_suffix(b"\n").unwrap_or(line)
    } else {
        line
    };

    let mut key = Vec::with_capacity(text.len());
    let mut in_space = false;
    for &byte in text {
        if spaces && matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
            // -b makes any run of white space one space, and none at the end.
            in_space = !options.ignore_all_space;
            continue;
        }
        if in_space {
            key.push(b' ');
            in_space = false;
        }
        key.push(if options.ignore_case {
            byte.to_ascii_lowercase()
        } else {
            byte
        });
    }
    Cow::Owned(key)
}

struct Printer<'a> {
    options: &'a Options,
    lines: &'a [Vec<&'a [u8]>; 2],
    script: &'a [Change],
}

/// A hunk: the lines it spans in each file, first to last inclusive (last is
/// first - 1 where it spans none), and the changes in it.
struct Hunk<'a> {
    first: [isize; 2],
    last: [isize; 2],
    changes: &'a [Change],
}

impl Hunk<'_> {
    fn deletes(&self) -> bool {
        self.changes.iter().any(|change| change.deleted > 0)
    }

    fn inserts(&self) -> bool {
        self.changes.iter().any(|change| change.inserted > 0)
    }
}

impl<'a> Printer<'a> {
    /// Groups the changes into hunks, those at most 2 * `context` lines
    /// apart sharing one, and widens each by `context` lines on either side.
    fn hunks(&self, context: usize) -> Vec<Hunk<'a>> {
        let mut hunks = Vec::new();
        let mut rest = self.script;
        while let Some(first) = rest.first() {
            let mut len = 1;
            while let Some(next) = rest.get(len) {
                let prev = &rest[len - 1];
                if next.line0 - (prev.line0 + prev.deleted) > 2 * context {
                    break;
                }
                len += 1;
            }
            let (changes, tail) = rest.split_at(len);
            rest = tail;

            let last = &changes[len - 1];
            let context = context as isize;
            let mut hunk = Hunk {
                first: [first.line0 as isize, first.line1 as isize],
                last: [
                    (last.line0 + last.deleted) as isize - 1,
                    (last.line1 + last.inserted) as isize - 1,
                ],
                changes,
            };
            for file in 0..2 {
                let lines = self.lines[file].len() as isize;
                hunk.first[file] = (hunk.first[file] - context).max(0);
                hunk.last[file] = (hunk.last[file] + context).min(lines - 1);
            }
            hunks.push(hunk);
        }
        hunks
    }

    fn line(
        &self,
        out: &mut impl Write,
        prefix: &str,
        file: usize,
        line: isize,
    ) -> std::io::Result<()> {
        let text = self.lines[file][line as usize];
        out.write_all(prefix.as_bytes())?;
        out.write_all(text)?;
        if text.last() != Some(&b'\n') {
            out.write_all(b"\n\\ No newline at end of file\n")?;
        }
        Ok(())
    }

    fn normal(&self, out: &mut impl Write) -> std::io::Result<()> {
        for change in self.script {
            let first = [change.line0 as isize, change.line1 as isize];
            let last = [
                first[0] + change.deleted as isize - 1,
                first[1] + change.inserted as isize - 1,
            ];
            let letter = match (change.deleted > 0, change.inserted > 0) {
                (true, true) => 'c',
                (true, false) => 'd',
                _ => 'a',
            };
            writeln!(
                out,
                "{}{letter}{}",
                line_range(first[0], last[0]),
                line_range(first[1], last[1])
            )?;
            for line in first[0]..=last[0] {
                self.line(out, "< ", 0, line)?;
            }
            if letter == 'c' {
                writeln!(out, "---")?;
            }
            for line in first[1]..=last[1] {
                self.line(out, "> ", 1, line)?;
            }
        }
        Ok(())
    }

    fn unified(&self, out: &mut impl Write) -> std::io::Result<()> {
        for hunk in self.hunks(self.options.context) {
            writeln!(
                out,
                "@@ -{} +{} @@",
                unified_range(hunk.first[0], hunk.last[0]),
                unified_range(hunk.first[1], hunk.last[1])
            )?;
            let (mut i, mut j) = (hunk.first[0], hunk.first[1]);
            let mut changes = hunk.changes.iter().peekable();
            while i <= hunk.last[0] || j <= hunk.last[1] {
                match changes.peek() {
                    Some(change) if i >= change.line0 as isize => {
                        for _ in 0..change.deleted {
                            self.line(out, "-", 0, i)?;
                            i += 1;
                        }
                        for _ in 0..change.inserted {
                            self.line(out, "+", 1, j)?;
                            j += 1;
                        }
                        changes.next();
                    }
                    _ => {
                        self.line(out, " ", 0, i)?;
                        i += 1;
                        j += 1;
                    }
                }
            }
        }
        Ok(())
    }

    fn context(&self, out: &mut impl Write) -> std::io::Result<()> {
        for hunk in self.hunks(self.options.context) {
            writeln!(out, "***************")?;
            writeln!(out, "*** {} ****", line_range(hunk.first[0], hunk.last[0]))?;
            if hunk.deletes() {
                self.context_side(out, &hunk, 0)?;
            }
            writeln!(out, "--- {} ----", line_range(hunk.first[1], hunk.last[1]))?;
            if hunk.inserts() {
                self.context_side(out, &hunk, 1)?;
            }
        }
        Ok(())
    }

    /// One file's lines of a context hunk: "- " deleted or "+ " inserted,
    /// "! " where lines were both, and "  " around them.
    fn context_side(&self, out: &mut impl Write, hunk: &Hunk, file: usize) -> std::io::Result<()> {
        let span = |change: &Change| {
            if file == 0 {
                (change.line0, change.deleted, change.inserted)
            } else {
                (change.line1, change.inserted, change.deleted)
            }
        };
        let mut changes = hunk.changes.iter().map(span).peekable();
        for line in hunk.first[file]..=hunk.last[file] {
            while changes
                .peek()
                .is_some_and(|(start, len, _)| ((start + len) as isize) <= line)
            {
                changes.next();
            }
            let prefix = match changes.peek() {
                Some((start, _, other)) if *start as isize <= line => match (*other > 0, file) {
                    (true, _) => "! ",
                    (false, 0) => "- ",
                    (false, _) => "+ ",
                },
                _ => "  ",
            };
            self.line(out, prefix, file, line)?;
        }
        Ok(())
    }
}

/// Line numbers for the normal and context formats: "3", "3,5", or for no
/// lines the one before them.
fn line_range(first: isize, last: isize) -> String {
    if last > first {
        format!("{},{}", first + 1, last + 1)
    } else {
        format!("{}", last + 1)
    }
}

/// "3,5" for the unified format is the first line and how many; "3" is one
/// line, and "2,0" is none, after line 2.
fn unified_range(first: isize, last: isize) -> String {
    match last - first {
        0 => format!("{}", first + 1),
        ..0 => format!("{},0", last + 1),
        _ => format!("{},{}", first + 1, last - first + 1),
    }
}
