//! Streaming byte translation, deletion and squeezing in the C locale.
#[path = "tr_sets.rs"]
mod charset;
use std::io::{Read, Write};
fn fail(message: &str) -> ! {
    eprintln!("tr: {message}");
    std::process::exit(1)
}
pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "tr");
    let (mut delete, mut squeeze, mut complement) = (false, false, false);
    let mut operands = Vec::new();
    let mut done = false;
    for argument in &args[1..] {
        if done || argument == "-" || !argument.starts_with('-') {
            operands.push(argument.as_str());
            done = true;
            continue;
        }
        if argument == "--" {
            done = true;
            continue;
        }
        if argument == "--help" {
            println!("usage: tr (-d | -s) [-c] [--] SET\nDelete (-d) or squeeze (-s) bytes; -c complements SET.\nSets support byte ranges, backslash escapes and C-locale POSIX classes.\nEquivalence and repetition constructs are unsupported.");
            std::process::exit(0);
        }
        let flags = match argument.as_str() {
            "--delete" => "d",
            "--squeeze-repeats" => "s",
            "--complement" => "c",
            name if !name.starts_with("--") => &argument[1..],
            _ => fail(&format!("unsupported option '{argument}'")),
        };
        for flag in flags.chars() {
            match flag {
                'd' => delete = true,
                's' => squeeze = true,
                'c' | 'C' => complement = true,
                _ => fail(&format!("unsupported option '{argument}'")),
            }
        }
    }
    if delete == squeeze {
        fail("specify either --delete or --squeeze-repeats");
    }
    if operands.is_empty() {
        fail("missing operand");
    }
    if operands.len() > 1 {
        fail(&format!("extra operand '{}'", operands[1]));
    }
    let first = charset::Array::parse(operands[0]);
    let mut selected = first.members();
    if complement {
        for member in &mut selected {
            *member = !*member;
        }
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    let mut buffer = [0; 32 * 1024];
    let mut transformed = Vec::with_capacity(buffer.len());
    let mut previous = None;
    loop {
        let length = input
            .read(&mut buffer)
            .unwrap_or_else(|error| fail(&format!("read error: {}", super::wc::strerror(&error))));
        if length == 0 {
            break;
        }
        transformed.clear();
        for byte in &buffer[..length] {
            if delete && selected[*byte as usize] {
                continue;
            }
            let byte = *byte;
            if !squeeze || !selected[byte as usize] || previous != Some(byte) {
                transformed.push(byte);
            }
            previous = Some(byte);
        }
        output
            .write_all(&transformed)
            .unwrap_or_else(|error| fail(&format!("write error: {}", super::wc::strerror(&error))));
    }
    output
        .flush()
        .unwrap_or_else(|error| fail(&format!("write error: {}", super::wc::strerror(&error))));
}
