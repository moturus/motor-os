use std::io;

pub(super) trait Input: io::Read {
    /// Inspect waiting bytes without consuming them or waiting for more input.
    fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

#[derive(Default)]
pub(super) struct LineReader {
    after_cr: bool,
}

impl LineReader {
    /// Take at most one line, leaving later answers or commands in the terminal.
    pub(super) fn read(
        &mut self,
        input: &mut impl Input,
        buf: &mut [u8],
    ) -> io::Result<Option<usize>> {
        let take = match input.peek(buf) {
            Ok(0) => return Ok(Some(0)),
            Ok(peeked) => buf[..peeked]
                .iter()
                .position(|&byte| byte == b'\r' || byte == b'\n')
                .map_or(peeked, |end| end + 1),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            // Without peek, only a one-byte read can avoid taking the next line.
            Err(error) if error.kind() == io::ErrorKind::Unsupported => buf.len().min(1),
            Err(error) => return Err(error),
        };
        let count = input.read(&mut buf[..take])?;
        if count == 0 {
            return Ok(Some(0));
        }
        let kept = self.retain(&mut buf[..count]);
        if self.after_cr {
            // Consume a waiting LF now, including on the last answer, but never
            // wait for it or consume a byte belonging to the next program.
            let mut lf = [0];
            if matches!(input.peek(&mut lf), Ok(1)) && lf[0] == b'\n' {
                let count = input.read(&mut lf)?;
                self.retain(&mut lf[..count]);
            }
        }
        Ok((kept != 0).then_some(kept))
    }

    /// Every consumed byte updates the same CR/LF state, including lookahead.
    fn retain(&mut self, buf: &mut [u8]) -> usize {
        let mut kept = 0;
        for index in 0..buf.len() {
            let byte = buf[index];
            let after_cr = std::mem::replace(&mut self.after_cr, byte == b'\r');
            if after_cr && byte == b'\n' {
                continue;
            }
            buf[kept] = byte;
            kept += 1;
        }
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cancellation::Cancellation, prompt};

    struct Script {
        remaining: &'static [u8],
        can_peek: bool,
    }

    impl io::Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.remaining.read(buf)
        }
    }

    impl Input for Script {
        fn peek(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.can_peek {
                return Err(io::ErrorKind::Unsupported.into());
            }
            if self.remaining.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = buf.len().min(self.remaining.len());
            buf[..count].copy_from_slice(&self.remaining[..count]);
            Ok(count)
        }
    }

    struct Keys {
        input: Script,
        reader: LineReader,
    }

    impl prompt::Keys for Keys {
        fn read(&mut self, buf: &mut [u8], _: std::time::Duration) -> io::Result<Option<usize>> {
            self.reader.read(&mut self.input, buf)
        }
    }

    #[test]
    fn crlf_consumes_only_its_own_lf() -> io::Result<()> {
        for split in [false, true] {
            let mut input = Script {
                remaining: if split { b"user\r" } else { b"user\r\n\nnext" },
                can_peek: true,
            };
            let mut reader = LineReader::default();
            let mut buf = [0; 256];
            assert_eq!(reader.read(&mut input, &mut buf)?, Some(5));
            assert_eq!(&buf[..5], b"user\r");
            if split {
                assert_eq!(reader.read(&mut input, &mut buf)?, None);
                input.remaining = b"\n\nnext";
                assert_eq!(reader.read(&mut input, &mut buf)?, None);
            }
            assert_eq!(reader.read(&mut input, &mut buf)?, Some(1));
            assert_eq!(buf[0], b'\n');
            assert_eq!(input.remaining, b"next");
        }
        Ok(())
    }

    #[test]
    fn empty_password_after_crlf_leaves_the_next_command_unread() {
        let mut keys = Keys {
            input: Script {
                remaining: b"user\r\n\nnext-command\r",
                can_peek: true,
            },
            reader: LineReader::default(),
        };
        let error = prompt::ask_with(
            &mut keys,
            &mut Vec::new(),
            "https://example.test",
            &Cancellation::new(),
        )
        .err()
        .expect("empty password");
        assert!(error.to_string().contains("must not be empty"));
        assert_eq!(keys.input.remaining, b"next-command\r");
    }

    #[test]
    fn unsupported_peek_preserves_pasted_answers_and_the_next_command() -> crate::Result {
        let mut keys = Keys {
            input: Script {
                remaining: b"user\rtoken\rnext-command\r",
                can_peek: false,
            },
            reader: LineReader::default(),
        };
        let credential = prompt::ask_with(
            &mut keys,
            &mut Vec::new(),
            "https://example.test",
            &Cancellation::new(),
        )?;
        assert_eq!(credential.authorization(), "Basic dXNlcjp0b2tlbg==");
        assert_eq!(keys.input.remaining, b"next-command\r");
        Ok(())
    }
}
