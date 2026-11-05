//! Asks the user for HTTPS credentials on the terminal. Nothing is stored:
//! every command that needs credentials asks again.

use std::{
    io::{self, Write},
    time::Duration,
};

use base64::Engine;

use crate::cancellation::Cancellation;

#[cfg(any(target_os = "motor", test))]
mod input;

const MAX_USER_BYTES: usize = 256;
const MAX_PASSWORD_BYTES: usize = 4096;
/// How long one wait for a keystroke lasts before cancellation is checked again.
const KEY_WAIT: Duration = Duration::from_millis(100);

/// A user name and password or token, held in memory for one command only.
pub struct Credential {
    authorization: String,
}

impl Credential {
    pub(crate) fn new(user: &str, password: &str) -> io::Result<Credential> {
        if user.is_empty() || password.is_empty() {
            return Err(invalid(
                "the user name and the password or token must not be empty",
            ));
        }
        if user.contains(':') {
            return Err(invalid("the user name must not contain ':'"));
        }
        if user.chars().chain(password.chars()).any(char::is_control) {
            return Err(invalid("credentials must not contain control characters"));
        }
        let pair = format!("{user}:{password}");
        Ok(Credential {
            authorization: format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(pair)
            ),
        })
    }

    /// The `Authorization` header value. It is the secret itself.
    pub(crate) fn authorization(&self) -> &str {
        &self.authorization
    }
}

/// Raw keystrokes from a terminal that echoes nothing by itself.
trait Keys {
    /// Waiting input no further than the end of a line, `Some(0)` once the
    /// terminal is gone, or `None` if nothing arrived within `wait`.
    fn read(&mut self, buf: &mut [u8], wait: Duration) -> io::Result<Option<usize>>;
}

/// Ask for the credentials of `origin` (`https://host[:port]`) on the terminal.
pub fn ask(origin: &str, cancellation: &Cancellation) -> crate::Result<Credential> {
    #[cfg(target_os = "motor")]
    let keys = motor::Terminal::open()?;
    // A Linux terminal echoes what is typed, so Linux builds never ask.
    #[cfg(not(target_os = "motor"))]
    let keys = None::<NoTerminal>;
    let Some(mut keys) = keys else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{origin} wants a user name and password, and gix asks for them only on a Motor OS terminal"),
        )
        .into());
    };
    ask_with(&mut keys, &mut io::stderr().lock(), origin, cancellation)
}

fn ask_with(
    keys: &mut impl Keys,
    out: &mut impl Write,
    origin: &str,
    cancellation: &Cancellation,
) -> crate::Result<Credential> {
    let question = format!("Username for '{origin}': ");
    let user = answer(keys, out, &question, MAX_USER_BYTES, true, cancellation)?;
    let host = origin.strip_prefix("https://").unwrap_or(origin);
    let question = format!("Password or token for 'https://{user}@{host}': ");
    let password = answer(
        keys,
        out,
        &question,
        MAX_PASSWORD_BYTES,
        false,
        cancellation,
    )?;
    Ok(Credential::new(&user, &password)?)
}

fn answer(
    keys: &mut impl Keys,
    out: &mut impl Write,
    question: &str,
    limit: usize,
    echo: bool,
    cancellation: &Cancellation,
) -> crate::Result<String> {
    out.write_all(question.as_bytes())?;
    out.flush()?;
    let mut editor = Editor::new(limit, echo);
    let mut buf = [0; 256];
    loop {
        if let Err(error) = cancellation.check() {
            // Finish the question's line before the error is printed.
            _ = out.write_all(b"\n").and_then(|()| out.flush());
            return Err(error);
        }
        let Some(count) = keys.read(&mut buf, KEY_WAIT)? else {
            continue;
        };
        if count == 0 {
            out.write_all(b"\n")?;
            return Err(invalid("the terminal closed before the answer was complete").into());
        }
        for &byte in &buf[..count] {
            if editor.accept(byte, out)? {
                out.flush()?;
                return Ok(editor.finish()?);
            }
        }
        out.flush()?;
    }
}

/// One answer as typed so far, with the terminal's editing keys applied.
struct Editor {
    answer: Vec<u8>,
    limit: usize,
    echo: bool,
    overflow: bool,
    escape: Escape,
}

/// Arrow and function keys arrive as ESC, then `[` or `O`, then parameter
/// bytes up to a final byte in `@`..=`~`. They are dropped.
enum Escape {
    None,
    Opened,
    Control,
}

impl Editor {
    fn new(limit: usize, echo: bool) -> Editor {
        Editor {
            answer: Vec::new(),
            limit,
            echo,
            overflow: false,
            escape: Escape::None,
        }
    }

    /// Apply one byte, echoing what it changes, and report whether it was Enter.
    fn accept(&mut self, byte: u8, out: &mut impl Write) -> io::Result<bool> {
        match self.escape {
            Escape::Opened => {
                self.escape = Escape::None;
                if matches!(byte, b'[' | b'O') {
                    self.escape = Escape::Control;
                    return Ok(false);
                }
            }
            Escape::Control => {
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::None;
                }
                return Ok(false);
            }
            Escape::None => {}
        }
        match byte {
            b'\r' | b'\n' => {
                out.write_all(b"\n")?;
                return Ok(true);
            }
            0x1b => self.escape = Escape::Opened,
            0x08 | 0x7f => self.erase(out)?,
            0x15 => {
                while !self.answer.is_empty() {
                    self.erase(out)?;
                }
            }
            byte if byte.is_ascii_control() => {}
            _ if self.answer.len() == self.limit => self.overflow = true,
            _ => {
                self.answer.push(byte);
                if self.echo {
                    out.write_all(&[byte])?;
                }
            }
        }
        Ok(false)
    }

    /// Remove the last character and wipe it from the screen if it was shown.
    fn erase(&mut self, out: &mut impl Write) -> io::Result<()> {
        if self.answer.is_empty() {
            return Ok(());
        }
        while self.answer.pop().is_some_and(|byte| byte & 0xc0 == 0x80) {}
        if self.echo {
            out.write_all(b"\x08 \x08")?;
        }
        Ok(())
    }

    fn finish(self) -> io::Result<String> {
        if self.overflow {
            return Err(invalid(format!(
                "the answer exceeds its {}-byte limit",
                self.limit
            )));
        }
        String::from_utf8(self.answer).map_err(|_| invalid("the answer is not valid UTF-8"))
    }
}

#[cfg(not(target_os = "motor"))]
enum NoTerminal {}

#[cfg(not(target_os = "motor"))]
impl Keys for NoTerminal {
    fn read(&mut self, _: &mut [u8], _: Duration) -> io::Result<Option<usize>> {
        match *self {}
    }
}

#[cfg(target_os = "motor")]
mod motor {
    use std::{io, time::Duration};

    use moto_rt::{RtFd, poll};

    use super::input::{Input, LineReader};

    /// The terminal: stdin, or else the session's terminal stream on fd 3.
    pub struct Terminal {
        fd: RtFd,
        registry: RtFd,
        reader: LineReader,
    }

    impl Terminal {
        pub fn open() -> io::Result<Option<Terminal>> {
            let Some(fd) = [moto_rt::FD_STDIN, moto_rt::FD_TERMINAL]
                .into_iter()
                .find(|fd| moto_rt::fs::is_terminal(*fd))
            else {
                return Ok(None);
            };
            let registry = poll::new().map_err(error)?;
            if let Err(err) = poll::add(registry, fd, 0, poll::POLL_READABLE) {
                _ = moto_rt::fs::close(registry);
                return Err(error(err));
            }
            Ok(Some(Terminal {
                fd,
                registry,
                reader: LineReader::default(),
            }))
        }
    }

    impl super::Keys for Terminal {
        fn read(&mut self, buf: &mut [u8], wait: Duration) -> io::Result<Option<usize>> {
            let deadline = moto_rt::time::Instant::now() + wait;
            let mut event = poll::Event::default();
            if poll::wait(self.registry, &mut event, 1, Some(deadline)).map_err(error)? == 0 {
                return Ok(None);
            }
            self.reader.read(&mut TerminalInput(self.fd), buf)
        }
    }

    struct TerminalInput(RtFd);

    impl io::Read for TerminalInput {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            moto_rt::fs::read(self.0, buf).map_err(error)
        }
    }

    impl Input for TerminalInput {
        fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            moto_rt::net::peek(self.0, buf).map_err(|err| match err {
                moto_rt::Error::NotReady => io::ErrorKind::WouldBlock.into(),
                moto_rt::Error::BadHandle => io::ErrorKind::Unsupported.into(),
                err => error(err),
            })
        }
    }

    impl Drop for Terminal {
        fn drop(&mut self) {
            _ = moto_rt::fs::close(self.registry);
        }
    }

    fn error(error: moto_rt::Error) -> io::Error {
        io::Error::other(format!("terminal input failed: {error}"))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// Keystrokes in bursts; `None` is a wait that times out.
    struct Script(VecDeque<Option<&'static [u8]>>, Option<Cancellation>);

    impl Keys for Script {
        fn read(&mut self, buf: &mut [u8], _: Duration) -> io::Result<Option<usize>> {
            match self.0.pop_front() {
                Some(Some(bytes)) => {
                    buf[..bytes.len()].copy_from_slice(bytes);
                    Ok(Some(bytes.len()))
                }
                Some(None) => {
                    if let Some(cancellation) = &self.1 {
                        cancellation.cancel();
                    }
                    Ok(None)
                }
                None => Ok(Some(0)),
            }
        }
    }

    fn typed(input: &[u8], limit: usize, echo: bool) -> (io::Result<String>, Vec<u8>) {
        let mut out = Vec::new();
        let mut editor = Editor::new(limit, echo);
        for &byte in input {
            match editor.accept(byte, &mut out) {
                Ok(true) => return (editor.finish(), out),
                Ok(false) => {}
                Err(error) => return (Err(error), out),
            }
        }
        panic!("no Enter in {input:?}");
    }

    #[test]
    fn editing_keys_escapes_and_limits() {
        for (input, expected) in [
            (&b"user\r"[..], "user"),
            (b"user\n", "user"),
            (b"ab\x7fc\r", "ac"),
            (b"ab\x08c\r", "ac"),
            (b"old\x15new\r", "new"),
            (b"a\x1b[Ab\x1b[1;5Cc\x1bOPd\r", "abcd"),
            ("caf\u{e9}\x7fe\r".as_bytes(), "cafe"),
            (b"\x7f\x15tab\tbed\r", "tabbed"),
        ] {
            assert_eq!(typed(input, 16, true).0.unwrap(), expected, "{input:?}");
        }
        let (answer, out) = typed(b"ab\x7fc\r", 16, true);
        assert_eq!(answer.unwrap(), "ac");
        assert_eq!(out, b"ab\x08 \x08c\n");
        let (answer, out) = typed(b"s3cr3t\x7fT\r", 16, false);
        assert_eq!(answer.unwrap(), "s3cr3T");
        assert_eq!(out, b"\n");
        assert!(typed(b"12345\r", 5, true).0.is_ok());
        assert!(typed(b"123456\r", 5, true).0.is_err());
        assert!(typed(b"\xff\r", 5, true).0.is_err());
    }

    #[test]
    fn asks_twice_hides_the_secret_and_encodes_basic_credentials() -> crate::Result {
        let mut keys = Script(
            VecDeque::from([Some(&b"us"[..]), None, Some(b"er\r"), Some(b"tok\x7fken\r")]),
            None,
        );
        let mut out = Vec::new();
        let origin = "https://example.test:8443";
        let credential = ask_with(&mut keys, &mut out, origin, &Cancellation::new())?;
        // base64("user:token")
        assert_eq!(credential.authorization(), "Basic dXNlcjp0b2tlbg==");
        assert_eq!(
            String::from_utf8(out)?,
            "Username for 'https://example.test:8443': user\n\
             Password or token for 'https://user@example.test:8443': \n"
        );
        Ok(())
    }

    #[test]
    fn refusals_end_of_input_and_cancellation() {
        let origin = "https://example.test";
        for script in [
            &[&b"\r"[..], b"token\r"][..],
            &[b"us:er\r", b"token\r"],
            &[b"user\r", b"\r"],
            &[b"user\r", "to\u{85}ken\r".as_bytes()],
            &[b"user\r", b"tok"],
            &[b"us"],
        ] {
            let mut keys = Script(script.iter().map(|&bytes| Some(bytes)).collect(), None);
            let result = ask_with(&mut keys, &mut Vec::new(), origin, &Cancellation::new());
            assert!(result.is_err(), "{script:?}");
        }
        let cancellation = Cancellation::new();
        let mut keys = Script(VecDeque::from([Some(&b"user\r"[..]), None]), None);
        keys.1 = Some(cancellation.clone());
        let mut out = Vec::new();
        let error = ask_with(&mut keys, &mut out, origin, &cancellation)
            .err()
            .expect("cancelled");
        assert!(crate::cancellation::was_cancelled(error.as_ref()));
        assert!(out.ends_with(b"\n"));
    }

    #[test]
    fn linux_builds_never_ask() {
        let error = ask("https://example.test", &Cancellation::new())
            .err()
            .expect("no terminal");
        assert!(error.to_string().contains("only on a Motor OS terminal"));
    }
}
