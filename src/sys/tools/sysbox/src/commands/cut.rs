//! Selected byte positions in the C locale, without locale-dependent character counts.
use std::io::{BufRead, Write};

#[derive(Default)]
struct Options {
    ranges: Vec<(u64, u64)>,
    complement: bool,
}
fn fail(message: &str) -> ! {
    eprintln!("cut: {message}\nTry 'cut --help' for more information.");
    std::process::exit(1)
}
fn ranges(list: &str) -> Vec<(u64, u64)> {
    let number = |text: &str| {
        if text.is_empty() {
            fail("byte/character positions are numbered from 1");
        }
        if !text.bytes().all(|b| b.is_ascii_digit()) {
            fail("invalid byte or character range");
        }
        text.parse::<u64>()
            .ok()
            .filter(|n| *n < u64::MAX)
            .unwrap_or_else(|| fail(&format!("byte/character offset '{text}' is too large")))
    };
    let mut ranges = Vec::new();
    for part in list.split([',', ' ', '\t']) {
        let (low, high) = if let Some((low, high)) = part.split_once('-') {
            if low.is_empty() && high.is_empty() {
                fail("invalid range with no endpoint: -");
            }
            let low = if low.is_empty() { 1 } else { number(low) };
            let high = if high.is_empty() {
                u64::MAX
            } else {
                number(high)
            };
            (low, high)
        } else {
            let n = number(part);
            (n, n)
        };
        if low == 0 {
            fail("byte/character positions are numbered from 1");
        }
        if high < low {
            fail("invalid decreasing range");
        }
        ranges.push((low, high));
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for range in ranges {
        if let Some(last) = merged
            .last_mut()
            .filter(|last| range.0 <= last.1.saturating_add(1))
        {
            last.1 = last.1.max(range.1);
        } else {
            merged.push(range);
        }
    }
    merged
}
fn parse(args: &[String]) -> (Options, Vec<String>) {
    let mut options = Options::default();
    let mut files = Vec::new();
    let mut arguments = args.iter();
    let mut done = false;
    let mut list = None;
    while let Some(argument) = arguments.next() {
        if done || argument == "-" || !argument.starts_with('-') {
            files.push(argument.clone());
            continue;
        }
        if argument == "--" {
            done = true;
            continue;
        }
        if argument == "--help" {
            println!("usage: cut (-b LIST | -c LIST) [--complement] [--] [FILE]...\nLists use one-based positions, N-M, -M, or N-, separated by commas.\n-b and -c select bytes in the C locale.");
            std::process::exit(0);
        }
        if argument == "--complement" {
            options.complement = true;
            continue;
        }
        let (name, value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(n, v)| (n, Some(v)));
        let flags = match name {
            "--bytes" => "b",
            "--characters" => "c",
            name if !name.starts_with("--") => &argument[1..],
            _ => fail(&format!("unsupported option '{argument}'")),
        };
        if let Some((position, flag)) = flags.char_indices().next() {
            if !matches!(flag, 'b' | 'c') {
                fail(&format!("unsupported option '{argument}'"));
            }
            let rest = &flags[position + 1..];
            let value = value.unwrap_or_else(|| {
                if !rest.is_empty() {
                    rest
                } else {
                    arguments.next().unwrap_or_else(|| {
                        fail(&format!("option requires an argument -- '{flag}'"))
                    })
                }
            });
            if list.is_some() {
                fail("only one list may be specified");
            }
            list = Some(());
            options.ranges = ranges(value);
        }
    }
    if list.is_none() {
        fail("you must specify a list of bytes, characters, or fields");
    }
    if files.is_empty() {
        files.push("-".into());
    }
    (options, files)
}
impl Options {
    fn selected(&self, position: usize) -> bool {
        let position = position as u64 + 1;
        let index = self.ranges.partition_point(|range| range.1 < position);
        let selected = self
            .ranges
            .get(index)
            .is_some_and(|range| range.0 <= position);
        selected != self.complement
    }
    fn line(&self, line: &[u8], output: &mut dyn Write) -> std::io::Result<()> {
        for (index, byte) in line.iter().enumerate() {
            if self.selected(index) {
                output.write_all(&[*byte])?;
            }
        }
        output.write_all(b"\n")
    }
    fn input(&self, input: &mut dyn BufRead, output: &mut dyn Write) -> std::io::Result<()> {
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            if input.read_until(b'\n', &mut bytes)? == 0 {
                return Ok(());
            }
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            self.line(&bytes, output).unwrap_or_else(|error| {
                fail(&format!("write error: {}", super::wc::strerror(&error)))
            });
        }
    }
}
pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "cut");
    let (options, files) = parse(&args[1..]);
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    let mut failed = false;
    for file in files {
        let input: std::io::Result<Box<dyn BufRead>> = if file == "-" {
            Ok(Box::new(std::io::stdin().lock()))
        } else {
            std::fs::File::open(&file)
                .map(|file| Box::new(std::io::BufReader::new(file)) as Box<dyn BufRead>)
        };
        let result = input
            .and_then(|mut input| options.input(input.as_mut(), &mut output))
            .map_err(|error| {
                if file != "-"
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::IsADirectory
                    )
                    && std::fs::metadata(&file).is_ok_and(|metadata| metadata.is_dir())
                {
                    std::io::Error::from(std::io::ErrorKind::IsADirectory)
                } else {
                    error
                }
            });
        if let Err(error) = result {
            eprintln!("cut: {file}: {}", super::wc::strerror(&error));
            failed = true;
        }
    }
    output
        .flush()
        .unwrap_or_else(|error| fail(&format!("write error: {}", super::wc::strerror(&error))));
    if failed {
        std::process::exit(1);
    }
}
