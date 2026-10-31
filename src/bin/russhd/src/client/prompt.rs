#[cfg(any(test, target_os = "motor"))]
use std::io::Read;
use std::io::{self, IsTerminal, Write};

#[cfg(any(test, target_os = "motor"))]
#[derive(Default)]
struct TerminalInput {
    after_cr: bool,
}

#[cfg(any(test, target_os = "motor"))]
impl TerminalInput {
    fn accept(&mut self, byte: u8) -> bool {
        let after_cr = std::mem::replace(&mut self.after_cr, byte == b'\r');
        !(after_cr && byte == b'\n')
    }

    fn read(&mut self, input: &mut impl Read, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let read = input.read(bytes)?;
            let mut written = 0;
            for index in 0..read {
                let byte = bytes[index];
                if self.accept(byte) {
                    bytes[written] = byte;
                    written += 1;
                }
            }
            if written != 0 || read == 0 {
                return Ok(written);
            }
        }
    }
}

// Host-key prompts run on a worker thread; authentication and forwarding must
// retain their CRLF state even when the LF arrives in a later read.
#[cfg(target_os = "motor")]
static TERMINAL_INPUT: std::sync::Mutex<TerminalInput> =
    std::sync::Mutex::new(TerminalInput { after_cr: false });

#[cfg(target_os = "motor")]
pub(crate) fn read_terminal(input: &mut impl Read, bytes: &mut [u8]) -> io::Result<usize> {
    TERMINAL_INPUT.lock().unwrap().read(input, bytes)
}

pub fn line(message: &str) -> io::Result<String> {
    prompt(message, true)
}

pub fn secret(message: &str) -> io::Result<String> {
    prompt(message, false)
}

pub(crate) fn clear_secret(value: &mut String) {
    // Zero bytes remain valid UTF-8 while the String still owns them.
    clear_bytes(unsafe { value.as_bytes_mut() });
    value.clear();
}

fn clear_bytes(value: &mut [u8]) {
    // Ordinary dead stores may be optimized away before the allocation is freed.
    for byte in value {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn prompt(message: &str, echo: bool) -> io::Result<String> {
    let stdin_terminal = io::stdin().is_terminal();
    #[cfg(target_os = "motor")]
    let fallback_terminal = moto_sdk::rt::fs::is_terminal(moto_sdk::rt::FD_TERMINAL);
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
    let value = {
        let mut input = TERMINAL_INPUT.lock().unwrap();
        if stdin_terminal {
            read_edited_line(io::stdin().lock(), &mut output, echo, &mut input)?
        } else {
            read_edited_line_motor(&mut output, echo, &mut input)?
        }
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
fn read_edited_line_motor(
    output: &mut impl Write,
    echo: bool,
    input: &mut TerminalInput,
) -> io::Result<String> {
    read_edited_line_with(
        || {
            let mut byte = [0_u8; 1];
            moto_sdk::rt::fs::read(moto_sdk::rt::FD_TERMINAL, &mut byte)
                .map(|read| (read != 0).then_some(byte[0]))
                .map_err(|error| io::Error::other(error.to_string()))
        },
        output,
        echo,
        input,
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
    state: &mut TerminalInput,
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
        state,
    )
}

#[cfg(any(test, target_os = "motor"))]
fn read_edited_line_with(
    mut read_byte: impl FnMut() -> io::Result<Option<u8>>,
    output: &mut impl Write,
    echo: bool,
    input: &mut TerminalInput,
) -> io::Result<String> {
    let mut value = Vec::new();
    while let Some(byte) = read_byte()? {
        if !input.accept(byte) {
            continue;
        }
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
        let value = read_edited_line(
            &b"ab\x7fc\r"[..],
            &mut output,
            true,
            &mut TerminalInput::default(),
        )
        .unwrap();
        assert_eq!(value, "ac");
        assert_eq!(output, b"ab\x08 \x08c\n");
    }

    #[test]
    fn raw_secret_does_not_echo() {
        let mut output = Vec::new();
        let value = read_edited_line(
            &b"bad\x15good\n"[..],
            &mut output,
            false,
            &mut TerminalInput::default(),
        )
        .unwrap();
        assert_eq!(value, "good");
        assert!(output.is_empty());
    }

    #[test]
    fn enter_does_not_submit_the_next_prompt() {
        for ending in ["\r\n", "\r", "\n"] {
            let bytes = format!("yes{ending}password{ending}{ending}next{ending}");
            let mut input = bytes.as_bytes();
            let mut state = TerminalInput::default();
            let mut output = Vec::new();
            assert_eq!(
                read_edited_line(&mut input, &mut output, true, &mut state).unwrap(),
                "yes"
            );
            for expected in ["password", "", "next"] {
                assert_eq!(
                    read_edited_line(&mut input, &mut output, false, &mut state).unwrap(),
                    expected,
                    "ending {ending:?}"
                );
            }
            assert_eq!(output, b"yes\n");
        }
    }

    #[test]
    fn carriage_return_completes_prompt_without_lookahead() {
        let mut state = TerminalInput::default();
        let mut bytes = b"yes\r".iter().copied();
        let value = read_edited_line_with(
            || Ok(Some(bytes.next().expect("read past Enter"))),
            &mut Vec::new(),
            true,
            &mut state,
        )
        .unwrap();
        assert_eq!(value, "yes");
        assert!(state.after_cr);
    }

    #[test]
    fn terminal_forwarding_retains_prompt_state_and_empty_lines() {
        let mut input = &b"password\r\nfirst\r\n\r\nlast\n"[..];
        let mut state = TerminalInput::default();
        assert_eq!(
            read_edited_line(&mut input, &mut Vec::new(), false, &mut state).unwrap(),
            "password"
        );
        let mut output = Vec::new();
        let mut byte = [0];
        loop {
            let read = state.read(&mut input, &mut byte).unwrap();
            if read == 0 {
                break;
            }
            output.extend_from_slice(&byte[..read]);
        }
        assert_eq!(output, b"first\r\rlast\n");
    }

    #[test]
    fn terminal_crlf_is_coalesced_at_every_read_boundary() {
        let bytes = b"one\r\ntwo\r\n\r\nthree\nfour\rfive";
        for split in 0..=bytes.len() {
            let mut input = bytes[..split].chain(&bytes[split..]);
            let mut state = TerminalInput::default();
            let mut output = Vec::new();
            let mut buffer = [0; 64];
            loop {
                let read = state.read(&mut input, &mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                output.extend_from_slice(&buffer[..read]);
            }
            assert_eq!(output, b"one\rtwo\r\rthree\nfour\rfive", "split {split}");
        }
    }

    #[test]
    fn secret_bytes_are_zeroed() {
        let mut value = *b"secret";
        clear_bytes(&mut value);
        assert_eq!(value, [0; 6]);
    }
}
