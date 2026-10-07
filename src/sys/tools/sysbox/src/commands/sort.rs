//! Byte, exact decimal and human-size sorting in the C locale.

#[path = "sort_keys.rs"]
mod keys;
#[path = "sort_numeric.rs"]
mod numeric;

use std::cmp::Ordering;
use std::io::{Read, Write};

#[derive(Default)]
struct Options {
    keys: Vec<keys::Key>,
    delimiter: Option<u8>,
    numeric: bool,
    human: bool,
    reverse: bool,
    unique: bool,
    fold: bool,
    stable: bool,
    check: bool,
    output: Option<String>,
}

fn fail(message: &str) -> ! {
    eprintln!("sort: {message}");
    std::process::exit(2);
}

fn parse(args: &[String]) -> (Options, Vec<String>) {
    let mut options = Options::default();
    let mut files = Vec::new();
    let mut arguments = args.iter();
    let mut done = false;
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
            println!(
                "usage: sort [-nhrufsc] [-k KEY] [-t BYTE] [-o FILE] [--] [FILE]...\n\
                      Sort lines (byte order by default); no files or '-' reads standard input.\n\
                      -k FIELD[.BYTE][FLAGS][,FIELD[.BYTE][FLAGS]] select a key; -t BYTE separate fields.\n\
                      -n decimal prefix; -h human sizes; key flags b/n/h/f/r override global ordering;\n\
                      -r reverse; -u unique; -f fold ASCII case; -s stable;\n\
                      -c check order without output; -o FILE write sorted lines to FILE."
            );
            std::process::exit(0);
        }
        let (name, value) = argument
            .split_once('=')
            .filter(|(name, _)| matches!(*name, "--key" | "--field-separator" | "--output"))
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        let flags = match name {
            "--key" => "k",
            "--field-separator" => "t",
            "--numeric-sort" => "n",
            "--human-numeric-sort" => "h",
            "--reverse" => "r",
            "--unique" => "u",
            "--ignore-case" => "f",
            "--stable" => "s",
            "--check" | "--check=diagnose-first" => "c",
            "--output" => "o",
            flag if !flag.starts_with("--") => &flag[1..],
            flag => fail(&format!("unsupported option '{flag}'")),
        };
        for (position, flag) in flags.char_indices() {
            match flag {
                'n' => options.numeric = true,
                'h' => options.human = true,
                'r' => options.reverse = true,
                'u' => options.unique = true,
                'f' => options.fold = true,
                's' => options.stable = true,
                'c' => options.check = true,
                'o' | 'k' | 't' => {
                    let rest = &flags[position + 1..];
                    let file = if let Some(value) = value {
                        value
                    } else if rest.is_empty() {
                        arguments.next().unwrap_or_else(|| {
                            let message = if argument.starts_with("--") {
                                format!("option '{argument}' requires an argument")
                            } else {
                                format!("option requires an argument -- '{flag}'")
                            };
                            fail(&format!(
                                "{message}\nTry 'sort --help' for more information."
                            ))
                        })
                    } else {
                        rest
                    };
                    match flag {
                        'k' => options
                            .keys
                            .push(keys::Key::parse(file).unwrap_or_else(|error| fail(&error))),
                        't' => {
                            let delimiter = match file.as_bytes() {
                                [delimiter] => *delimiter,
                                b"\\0" => 0,
                                [] => fail("empty tab"),
                                _ => fail(&format!("multi-character tab '{file}'")),
                            };
                            if options
                                .delimiter
                                .is_some_and(|previous| previous != delimiter)
                            {
                                fail("incompatible tabs");
                            }
                            options.delimiter = Some(delimiter);
                        }
                        _ => {
                            if options
                                .output
                                .as_ref()
                                .is_some_and(|previous| previous != file)
                            {
                                fail("multiple output files specified");
                            }
                            options.output = Some(file.to_owned());
                        }
                    }
                    break;
                }
                _ => fail(&format!("unsupported option '{argument}'")),
            }
        }
    }
    if options.numeric
        && options.human
        && (options.keys.is_empty() || options.keys.iter().any(|key| key.flags.is_none()))
    {
        fail("options '-hn' are incompatible");
    }
    if files.is_empty() {
        files.push("-".into());
    }
    if options.check && files.len() > 1 {
        fail(&format!("extra operand '{}' not allowed with -c", files[1]));
    }
    if options.check && options.output.is_some() {
        fail("options '-co' are incompatible");
    }
    (options, files)
}

impl Options {
    fn compare(&self, left: &[u8], right: &[u8]) -> Ordering {
        let global = keys::Flags {
            reverse: self.reverse,
            fold: self.fold,
            numeric: self.numeric,
            human: self.human,
        };
        let mut order = if self.keys.is_empty() {
            global.compare(left, right)
        } else {
            self.keys
                .iter()
                .map(|key| {
                    key.flags.unwrap_or(global).compare(
                        key.slice(left, self.delimiter),
                        key.slice(right, self.delimiter),
                    )
                })
                .find(|order| *order != Ordering::Equal)
                .unwrap_or(Ordering::Equal)
        };
        if order == Ordering::Equal && !self.stable && !self.unique {
            order = left.cmp(right);
            if self.reverse {
                order = order.reverse();
            }
        }
        order
    }
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "sort");
    let (options, files) = parse(&args[1..]);
    let mut lines = Vec::new();
    for file in &files {
        let mut bytes = Vec::new();
        let result = if file == "-" {
            std::io::stdin().lock().read_to_end(&mut bytes)
        } else {
            std::fs::File::open(file).and_then(|mut input| input.read_to_end(&mut bytes))
        };
        if let Err(error) = result {
            let error = if std::fs::metadata(file).is_ok_and(|metadata| metadata.is_dir()) {
                std::io::Error::from(std::io::ErrorKind::IsADirectory)
            } else {
                error
            };
            fail(&format!(
                "cannot read: {file}: {}",
                super::wc::strerror(&error)
            ));
        }
        // Split inputs separately: each missing final newline ends its own line.
        lines.extend(
            bytes
                .split_inclusive(|byte| *byte == b'\n')
                .map(|line| line.strip_suffix(b"\n").unwrap_or(line).to_vec()),
        );
    }
    if options.check {
        for (position, pair) in lines.windows(2).enumerate() {
            let order = options.compare(&pair[0], &pair[1]);
            if order == Ordering::Greater || (options.unique && order == Ordering::Equal) {
                let name = &files[0];
                let mut error = std::io::stderr().lock();
                let result = write!(error, "sort: {name}:{}: disorder: ", position + 2)
                    .and_then(|_| error.write_all(&pair[1]))
                    .and_then(|_| error.write_all(b"\n"));
                if let Err(error) = result {
                    fail(&format!("write failed: {}", super::wc::strerror(&error)));
                }
                std::process::exit(1);
            }
        }
        return;
    }
    lines.sort_by(|left, right| options.compare(left, right));
    if options.unique {
        lines.dedup_by(|left, right| options.compare(left, right) == Ordering::Equal);
    }
    // Read every input before opening output, including when output is an input.
    let output: Box<dyn Write> = if let Some(file) = options.output {
        Box::new(std::fs::File::create(&file).unwrap_or_else(|error| {
            fail(&format!(
                "open failed: {file}: {}",
                super::wc::strerror(&error)
            ))
        }))
    } else {
        Box::new(std::io::stdout().lock())
    };
    let mut output = std::io::BufWriter::new(output);
    let result = lines
        .iter()
        .try_for_each(|line| output.write_all(line).and_then(|_| output.write_all(b"\n")))
        .and_then(|_| output.flush());
    if let Err(error) = result {
        fail(&format!("write failed: {}", super::wc::strerror(&error)));
    }
}
