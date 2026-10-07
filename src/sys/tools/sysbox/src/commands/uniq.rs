//! Consecutive byte-line groups, keeping the first line's spelling.

use std::io::{BufRead, Write};

#[derive(Default)]
struct Options {
    count: bool,
    duplicates: bool,
    unique: bool,
    ignore_case: bool,
}

fn fail(message: &str) -> ! {
    eprintln!("uniq: {message}");
    std::process::exit(1);
}

fn parse(args: &[String]) -> (Options, Vec<String>) {
    let mut options = Options::default();
    let mut files = Vec::new();
    let mut done = false;
    for argument in args {
        if done || argument == "-" || !argument.starts_with('-') {
            files.push(argument.clone());
            continue;
        }
        if argument == "--" {
            done = true;
            continue;
        }
        if argument == "--help" {
            println!(
                "usage: uniq [-cdui] [--] [INPUT [OUTPUT]]\n\
                      Report consecutive equal lines; '-' means standard input/output.\n\
                      -c count; -d repeated lines only; -u single lines only;\n\
                      -i ignore ASCII case. Sort first to group nonadjacent equal lines."
            );
            std::process::exit(0);
        }
        let flags = match argument.as_str() {
            "--count" => "c",
            "--repeated" => "d",
            "--unique" => "u",
            "--ignore-case" => "i",
            flag if !flag.starts_with("--") => &flag[1..],
            flag => fail(&format!("unsupported option '{flag}'")),
        };
        for flag in flags.chars() {
            match flag {
                'c' => options.count = true,
                'd' => options.duplicates = true,
                'u' => options.unique = true,
                'i' => options.ignore_case = true,
                _ => fail(&format!("unsupported option '{argument}'")),
            }
        }
    }
    if files.len() > 2 {
        eprintln!("uniq: extra operand '{}'", files[2]);
        eprintln!("Try 'uniq --help' for more information.");
        std::process::exit(1);
    }
    (options, files)
}

impl Options {
    fn equal(&self, left: &[u8], right: &[u8]) -> bool {
        if self.ignore_case {
            left.iter()
                .map(u8::to_ascii_uppercase)
                .eq(right.iter().map(u8::to_ascii_uppercase))
        } else {
            left == right
        }
    }

    fn write_group(&self, output: &mut dyn Write, line: &[u8], count: usize) {
        if count == 0 || (self.duplicates && count == 1) || (self.unique && count > 1) {
            return;
        }
        let result = (|| {
            if self.count {
                write!(output, "{count:7} ")?;
            }
            output.write_all(line)?;
            output.write_all(b"\n")
        })();
        write_result(result);
    }
}

fn write_result(result: std::io::Result<()>) {
    if let Err(error) = result {
        fail(&format!("write error: {}", super::wc::strerror(&error)));
    }
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "uniq");
    let (options, files) = parse(&args[1..]);
    let input = files.first().map_or("-", String::as_str);
    let standard_input = input == "-";
    let input_name = if standard_input {
        "standard input"
    } else {
        input
    };
    let mut input: Box<dyn BufRead> = if input == "-" {
        Box::new(std::io::stdin().lock())
    } else {
        Box::new(std::io::BufReader::new(
            std::fs::File::open(input).unwrap_or_else(|error| {
                // Motor file handles reject directories during open.
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::InvalidInput | std::io::ErrorKind::IsADirectory
                ) && std::fs::metadata(input).is_ok_and(|metadata| metadata.is_dir())
                {
                    fail(&format!("error reading '{input}': Is a directory"));
                }
                fail(&format!("{input}: {}", super::wc::strerror(&error)))
            }),
        ))
    };
    let output = files.get(1).map_or("-", String::as_str);
    let output: Box<dyn Write> =
        if output == "-" {
            Box::new(std::io::stdout().lock())
        } else {
            Box::new(std::fs::File::create(output).unwrap_or_else(|error| {
                fail(&format!("{output}: {}", super::wc::strerror(&error)))
            }))
        };
    let mut output = std::io::BufWriter::new(output);
    let (mut previous, mut current) = (Vec::new(), Vec::new());
    let mut count = 0usize;
    loop {
        current.clear();
        let length = input
            .read_until(b'\n', &mut current)
            .unwrap_or_else(|error| {
                let error = if !standard_input
                    && std::fs::metadata(input_name).is_ok_and(|metadata| metadata.is_dir())
                {
                    std::io::Error::from(std::io::ErrorKind::IsADirectory)
                } else {
                    error
                };
                fail(&format!(
                    "error reading '{input_name}': {}",
                    super::wc::strerror(&error)
                ))
            });
        if length == 0 {
            options.write_group(&mut output, &previous, count);
            break;
        }
        if current.last() == Some(&b'\n') {
            current.pop();
        }
        if count != 0 && options.equal(&previous, &current) {
            count = count
                .checked_add(1)
                .unwrap_or_else(|| fail("line count overflow"));
        } else {
            options.write_group(&mut output, &previous, count);
            std::mem::swap(&mut previous, &mut current);
            count = 1;
        }
    }
    write_result(output.flush());
}
