//! Print arguments with GNU-style options and byte escapes.
use std::io::{self, Write};

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// Return true for \c, which suppresses all remaining arguments and the newline.
fn emit(output: &mut impl Write, text: &str, escapes: bool) -> io::Result<bool> {
    if !escapes {
        output.write_all(text.as_bytes())?;
        return Ok(false);
    }
    let input = text.as_bytes();
    let mut position = 0;
    while let Some(&byte) = input.get(position) {
        position += 1;
        let byte = if byte == b'\\' && position < input.len() {
            let escaped = input[position];
            position += 1;
            match escaped {
                b'a' => 7,
                b'b' => 8,
                b'c' => return Ok(true),
                b'e' => 27,
                b'f' => 12,
                b'n' => 10,
                b'r' => 13,
                b't' => 9,
                b'v' => 11,
                b'\\' => b'\\',
                b'0'..=b'7' => {
                    let (mut value, count) = if escaped == b'0' {
                        (0u8, 3)
                    } else {
                        (escaped - b'0', 2)
                    };
                    for _ in 0..count {
                        let Some(digit @ b'0'..=b'7') = input.get(position) else {
                            break;
                        };
                        // GNU echo emits the low byte even for octal values >255.
                        value = value.wrapping_mul(8).wrapping_add(digit - b'0');
                        position += 1;
                    }
                    value
                }
                b'x' => {
                    let Some(mut value) = input.get(position).copied().and_then(hex) else {
                        output.write_all(b"\\x")?;
                        continue;
                    };
                    position += 1;
                    if let Some(digit) = input.get(position).copied().and_then(hex) {
                        value = value * 16 + digit;
                        position += 1;
                    }
                    value
                }
                other => {
                    output.write_all(&[b'\\', other])?;
                    continue;
                }
            }
        } else {
            byte
        };
        output.write_all(&[byte])?;
    }
    Ok(false)
}

fn print(mut arguments: &[String]) -> io::Result<()> {
    let posix = std::env::var_os("POSIXLY_CORRECT").is_some();
    let allow_options = !posix || arguments.first().is_some_and(|arg| arg == "-n");
    let (mut newline, mut escapes) = (true, false);
    let mut output = io::BufWriter::new(io::stdout().lock());
    if allow_options && arguments.len() == 1 {
        match arguments[0].as_str() {
            "--help" => {
                output.write_all(b"usage: echo [-neE] [ARG]...\nPrint arguments separated by spaces. -n omits the newline; -e enables byte escapes and -E disables them.\nPOSIXLY_CORRECT enables escapes and restricts option parsing.\n")?;
                return output.flush();
            }
            "--version" => {
                writeln!(output, "sysbox echo {}", env!("CARGO_PKG_VERSION"))?;
                return output.flush();
            }
            _ => {}
        }
    }
    if allow_options {
        while let Some(argument) = arguments.first() {
            let bytes = argument.as_bytes();
            if bytes.len() < 2
                || bytes[0] != b'-'
                || !bytes[1..]
                    .iter()
                    .all(|byte| matches!(byte, b'n' | b'e' | b'E'))
            {
                break;
            }
            for flag in &bytes[1..] {
                match flag {
                    b'n' => newline = false,
                    b'e' => escapes = true,
                    b'E' => escapes = false,
                    _ => unreachable!(),
                }
            }
            arguments = &arguments[1..];
        }
    }
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            output.write_all(b" ")?;
        }
        if emit(&mut output, argument, escapes || posix)? {
            newline = false;
            break;
        }
    }
    if newline {
        output.write_all(b"\n")?;
    }
    output.flush()
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "echo");
    if let Err(error) = print(&args[1..]) {
        eprintln!("echo: write error: {}", super::wc::strerror(&error));
        std::process::exit(1);
    }
}
