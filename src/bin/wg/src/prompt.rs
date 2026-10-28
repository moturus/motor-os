//! Bounded line input for Motor terminals and newline-delimited scripts.
use std::io::{Read, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Cancelled,
    Invalid(&'static str),
    Io,
}

pub struct Prompt<R, W> {
    input: R,
    output: W,
    terminal: bool,
    skip_lf: bool,
}

impl<R: Read, W: Write> Prompt<R, W> {
    pub fn new(input: R, output: W, terminal: bool) -> Self {
        Self {
            input,
            output,
            terminal,
            skip_lf: false,
        }
    }

    pub fn say(&mut self, text: &str) -> Result<(), Error> {
        writeln!(self.output, "{text}").map_err(|_| Error::Io)
    }

    pub fn ask<T>(
        &mut self,
        label: &str,
        default: &str,
        limit: usize,
        secret: bool,
        validate: impl Fn(&str) -> crate::config::Result<T>,
    ) -> Result<T, Error> {
        loop {
            if default.is_empty() {
                write!(self.output, "{label}: ")
            } else {
                write!(self.output, "{label} [{default}]: ")
            }
            .map_err(|_| Error::Io)?;
            self.output.flush().map_err(|_| Error::Io)?;
            let value = match self.line(limit, secret) {
                Ok(value) => value,
                Err(Error::Invalid(error)) => {
                    self.say(error)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let value = value.trim();
            match validate(if value.is_empty() { default } else { value }) {
                Ok(value) => return Ok(value),
                Err(error) => self.say(error)?,
            }
        }
    }

    pub fn confirm(&mut self, label: &str) -> Result<(), Error> {
        if self.ask(label, "no", 16, false, |value| {
            match value.to_ascii_lowercase().as_str() {
                "y" | "yes" => Ok(true),
                "n" | "no" => Ok(false),
                _ => Err("enter yes or no"),
            }
        })? {
            Ok(())
        } else {
            Err(Error::Cancelled)
        }
    }

    fn line(&mut self, limit: usize, secret: bool) -> Result<String, Error> {
        let mut bytes = Vec::new();
        let mut overflow = false;
        let echo = self.terminal && !secret;
        loop {
            let mut byte = [0];
            match self.input.read(&mut byte) {
                Ok(0) => return Err(Error::Cancelled),
                Ok(_) => (),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Error::Io),
            }
            let byte = byte[0];
            if std::mem::take(&mut self.skip_lf) && byte == b'\n' {
                continue;
            }
            match byte {
                3 => return Err(Error::Cancelled),
                b'\r' | b'\n' => {
                    self.skip_lf = byte == b'\r';
                    if self.terminal {
                        writeln!(self.output).map_err(|_| Error::Io)?;
                    }
                    if overflow {
                        return Err(Error::Invalid("input exceeds this field's length limit"));
                    }
                    return String::from_utf8(bytes)
                        .map_err(|_| Error::Invalid("input must be UTF-8"));
                }
                8 | 127 | 21 if !overflow => {
                    let all = byte == 21;
                    while !bytes.is_empty() {
                        while bytes.pop().is_some_and(|byte| byte & 0xc0 == 0x80) {}
                        if echo {
                            self.output.write_all(b"\x08 \x08").map_err(|_| Error::Io)?;
                        }
                        if !all {
                            break;
                        }
                    }
                }
                _ if bytes.len() < limit && !overflow => {
                    bytes.push(byte);
                    if echo {
                        self.output.write_all(&[byte]).map_err(|_| Error::Io)?;
                    }
                }
                _ => overflow = true,
            }
            if echo {
                self.output.flush().map_err(|_| Error::Io)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_edits_crlf_and_secrets() {
        let mut output = Vec::new();
        let input = b"\r\nwg8\x7f1\r\nold\x15fresh\nsecret-value\nyes\n";
        let mut prompt = Prompt::new(&input[..], &mut output, true);
        let string = |value: &str| Ok(value.to_owned());
        assert_eq!(prompt.ask("name", "wg0", 20, false, string).unwrap(), "wg0");
        assert_eq!(prompt.ask("name", "wg0", 20, false, string).unwrap(), "wg1");
        assert_eq!(prompt.ask("name", "", 20, false, string).unwrap(), "fresh");
        assert_eq!(
            prompt.ask("PSK", "", 128, true, string).unwrap(),
            "secret-value"
        );
        prompt.confirm("Save?").unwrap();
        assert!(!String::from_utf8(output).unwrap().contains("secret-value"));
    }
    #[test]
    fn cancellation_and_bounded_invalid_input() {
        for input in [&b""[..], &b"partial"[..], &b"\x03"[..], &b"no\n"[..]] {
            assert_eq!(
                Prompt::new(input, Vec::new(), false).confirm("Save?"),
                Err(Error::Cancelled)
            );
        }
        let mut prompt = Prompt::new(&b"too-long\ninvalid\nok\n"[..], Vec::new(), false);
        assert_eq!(
            prompt.ask("value", "", 7, false, |value| if value == "ok" {
                Ok(7)
            } else {
                Err("invalid field")
            }),
            Ok(7)
        );
    }
}
