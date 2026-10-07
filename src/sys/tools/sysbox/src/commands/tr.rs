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
            println!("usage: tr [-dsc] [--] SET1 [SET2]\nTranslate bytes, delete (-d), or squeeze (-s); -c complements SET1.\nSets support byte ranges, backslash escapes and C-locale POSIX classes.\nEquivalence and repetition constructs are unsupported.");
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
    let expected = if delete && !squeeze {
        1
    } else if delete || !squeeze {
        2
    } else {
        operands.len().clamp(1, 2)
    };
    if operands.len() < expected || operands.is_empty() {
        fail("missing operand");
    }
    if operands.len() > expected {
        fail(&format!("extra operand '{}'", operands[expected]));
    }
    let first = charset::Array::parse(operands[0]);
    let second = operands.get(1).map(|text| charset::Array::parse(text));
    let mut selected = first.members();
    if complement {
        for member in &mut selected {
            *member = !*member;
        }
    }
    let squeeze_set = second.as_ref().map_or(selected, |array| array.members());
    let mut mapping = std::array::from_fn::<_, 256, _>(|index| index as u8);
    if !delete {
        if let Some(second) = &second {
            if second.bytes.is_empty() && selected.iter().any(|member| *member) {
                fail("when not truncating set1, string2 must be non-empty");
            }
            if second
                .classes
                .last()
                .is_some_and(|(offset, _)| offset + 26 == second.bytes.len())
                && (if complement {
                    selected.iter().filter(|member| **member).count()
                } else {
                    first.bytes.len()
                }) > second.bytes.len()
            {
                fail("when translating with string1 longer than string2,\nthe latter string must not end with a character class");
            }
            if complement
                && !first.classes.is_empty()
                && second
                    .bytes
                    .iter()
                    .any(|byte| Some(byte) != second.bytes.first())
            {
                fail("when translating with complemented character classes,\nstring2 must map all characters in the domain to one");
            }
            for (position, class) in &second.classes {
                if !matches!(class.as_str(), "upper" | "lower") {
                    fail("when translating, the only character classes that may appear in\nstring2 are 'upper' and 'lower'");
                }
                if !complement
                    && first.bytes.len() >= *position
                    && !first.classes.iter().any(|(offset, name)| {
                        offset == position && matches!(name.as_str(), "upper" | "lower")
                    })
                {
                    fail("misaligned [:upper:] and/or [:lower:] construct");
                }
            }
            let bytes = if complement {
                (0..=255).filter(|byte| selected[*byte as usize]).collect()
            } else {
                first.bytes.clone()
            };
            for (position, byte) in bytes.iter().enumerate() {
                mapping[*byte as usize] = *second
                    .bytes
                    .get(position)
                    .unwrap_or(second.bytes.last().unwrap());
            }
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
            let byte = mapping[*byte as usize];
            if !squeeze || !squeeze_set[byte as usize] || previous != Some(byte) {
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
