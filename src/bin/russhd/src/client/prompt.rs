#[cfg(any(test, target_os = "motor"))]
use std::io::Read;
use std::io::{self, IsTerminal, Write};

pub fn line(message: &str) -> io::Result<String> {
    prompt(message, true)
}

pub fn secret(message: &str) -> io::Result<String> {
    prompt(message, false)
}

fn prompt(message: &str, echo: bool) -> io::Result<String> {
    let stdin_terminal = io::stdin().is_terminal();
    #[cfg(target_os = "motor")]
    let fallback_terminal = moto_rt::fs::is_terminal(moto_rt::FD_TERMINAL);
    #[cfg(not(target_os = "motor"))]
    let fallback_terminal = false;
    if !stdin_terminal && !fallback_terminal {
        return Err(io::Error::other("a terminal is required for prompting"));
    }
    let mut output: Box<dyn Write> = if io::stderr().is_terminal() {
        Box::new(io::stderr().lock())
    } else if io::stdout().is_terminal() {
        Box::new(io::stdout().lock())
    } else {
        return Err(io::Error::other(
            "a writable terminal is required for prompting",
        ));
    };
    output.write_all(message.as_bytes())?;
    output.flush()?;

    #[cfg(unix)]
    let _echo = (!echo).then(EchoGuard::disable).transpose()?;
    #[cfg(target_os = "motor")]
    let value = if stdin_terminal {
        read_edited_line(io::stdin().lock(), &mut output, echo)?
    } else {
        read_edited_line_motor(&mut output, echo)?
    };
    #[cfg(not(target_os = "motor"))]
    let value = {
        let mut value = String::new();
        io::stdin().read_line(&mut value)?;
        trim_line_end(&mut value);
        value
    };
    if !echo {
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(value)
}

#[cfg(target_os = "motor")]
fn read_edited_line_motor(output: &mut impl Write, echo: bool) -> io::Result<String> {
    read_edited_line_with(
        || {
            let mut byte = [0_u8; 1];
            moto_rt::fs::read(moto_rt::FD_TERMINAL, &mut byte)
                .map(|read| (read != 0).then_some(byte[0]))
                .map_err(|error| io::Error::other(error.to_string()))
        },
        output,
        echo,
    )
}

#[cfg(not(target_os = "motor"))]
fn trim_line_end(value: &mut String) {
    while value.ends_with(['\r', '\n']) {
        value.pop();
    }
}

#[cfg(any(test, target_os = "motor"))]
fn read_edited_line(
    mut input: impl Read,
    output: &mut impl Write,
    echo: bool,
) -> io::Result<String> {
    read_edited_line_with(
        || {
            let mut next = [0_u8; 1];
            input
                .read(&mut next)
                .map(|read| (read != 0).then_some(next[0]))
        },
        output,
        echo,
    )
}

#[cfg(any(test, target_os = "motor"))]
fn read_edited_line_with(
    mut read_byte: impl FnMut() -> io::Result<Option<u8>>,
    output: &mut impl Write,
    echo: bool,
) -> io::Result<String> {
    let mut value = Vec::new();
    while let Some(byte) = read_byte()? {
        match byte {
            b'\r' | b'\n' => {
                if echo {
                    output.write_all(b"\n")?;
                }
                break;
            }
            8 | 127 if !value.is_empty() => {
                value.pop();
                if echo {
                    output.write_all(b"\x08 \x08")?;
                }
            }
            21 => {
                if echo {
                    for _ in value.drain(..) {
                        output.write_all(b"\x08 \x08")?;
                    }
                } else {
                    value.clear();
                }
            }
            byte if !byte.is_ascii_control() => {
                value.push(byte);
                if echo {
                    output.write_all(&[byte])?;
                }
            }
            _ => {}
        }
    }
    String::from_utf8(value).map_err(|_| io::Error::other("terminal input is not UTF-8"))
}

#[cfg(unix)]
struct EchoGuard(libc::termios);

#[cfg(unix)]
impl EchoGuard {
    fn disable() -> io::Result<Self> {
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(original))
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_line_edits_and_echoes() {
        let mut output = Vec::new();
        let value = read_edited_line(&b"ab\x7fc\r"[..], &mut output, true).unwrap();
        assert_eq!(value, "ac");
        assert_eq!(output, b"ab\x08 \x08c\n");
    }

    #[test]
    fn raw_secret_does_not_echo() {
        let mut output = Vec::new();
        let value = read_edited_line(&b"bad\x15good\n"[..], &mut output, false).unwrap();
        assert_eq!(value, "good");
        assert!(output.is_empty());
    }
}
