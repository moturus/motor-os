//! Interactive replies.
//!
//! Motor OS has no line discipline (`docs/tui.md`): a terminal delivers typed
//! bytes raw and shows nothing until the program writes them back, and Enter
//! arrives as CR LF from the serial console and rmux but as a bare CR over
//! SSH. Every Lorry prompt therefore reads its reply through [`read_answer`],
//! which echoes and line-edits the reply itself wherever [`echo_required`]
//! says the console will not.

use std::io::{self, BufRead, Write};

/// The most input bytes one reply consumes, so an unattended stream cannot
/// be read without bound.
const REPLY_LIMIT: usize = 65;

/// Whether a prompt reading `terminal` input has to echo what is typed: a
/// Motor OS console never does, and a Linux terminal does in cooked mode.
pub fn echo_required(terminal: bool) -> bool {
    terminal && cfg!(target_os = "motor")
}

/// Reads one reply, without its line ending.
///
/// With `echo`, each arriving byte is written back to `output` and flushed at
/// once, Backspace and `^U` edit the reply, escape sequences such as arrow
/// keys are dropped, and CR or LF ends the reply, where an LF that directly
/// follows a CR is the same Enter. Without `echo`, the reply is the delivered
/// line up to LF, as a cooked terminal or a pipe hands it over.
pub fn read_answer(
    input: &mut impl BufRead,
    output: &mut impl Write,
    echo: bool,
) -> io::Result<String> {
    if echo {
        read_echoed(input, output)
    } else {
        read_delivered(input)
    }
}

fn read_delivered(input: &mut impl BufRead) -> io::Result<String> {
    let mut reply = String::new();
    io::Read::take(&mut *input, REPLY_LIMIT as u64).read_line(&mut reply)?;
    while reply.ends_with(['\r', '\n']) {
        reply.pop();
    }
    Ok(reply)
}

fn read_echoed(input: &mut impl BufRead, output: &mut impl Write) -> io::Result<String> {
    let mut editor = Editor::default();
    let mut consumed = 0;
    let mut ended = false;
    while !ended && consumed < REPLY_LIMIT {
        let available = input.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let mut used = 0;
        for &byte in &available[..available.len().min(REPLY_LIMIT - consumed)] {
            used += 1;
            if editor.accept(byte, output)? {
                // The serial console and rmux send Enter as CR LF: that LF
                // is the same key, not an empty next reply.
                if byte == b'\r' && available.get(used) == Some(&b'\n') {
                    used += 1;
                }
                ended = true;
                break;
            }
        }
        input.consume(used);
        consumed += used;
        output.flush()?;
    }
    if !ended {
        // End of input or the limit ended the reply instead of Enter: finish
        // the line so the next output does not continue the prompt's.
        output.write_all(b"\n")?;
        output.flush()?;
    }
    editor.finish()
}

/// The reply as typed so far, with the raw console's editing keys applied.
#[derive(Default)]
struct Editor {
    reply: Vec<u8>,
    escape: Escape,
}

/// Where an escape sequence stands: arrow and function keys arrive as ESC,
/// then `[` or `O`, then parameter bytes up to a final byte in `@`..=`~`.
#[derive(Default)]
enum Escape {
    #[default]
    None,
    Opened,
    Control,
}

impl Editor {
    /// Applies one typed byte, echoing what it changes, and reports whether
    /// it was the Enter that ends the reply.
    fn accept(&mut self, byte: u8, output: &mut impl Write) -> io::Result<bool> {
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
                output.write_all(b"\n")?;
                return Ok(true);
            }
            0x1b => self.escape = Escape::Opened,
            0x08 | 0x7f => {
                self.erase(output)?;
            }
            0x15 => while self.erase(output)? {},
            byte if byte.is_ascii_control() => {}
            byte => {
                self.reply.push(byte);
                output.write_all(&[byte])?;
            }
        }
        Ok(false)
    }

    /// Removes the last character, if there is one, and wipes it from the
    /// screen.
    fn erase(&mut self, output: &mut impl Write) -> io::Result<bool> {
        if self.reply.is_empty() {
            return Ok(false);
        }
        // Continuation bytes, then the byte that starts the character.
        while let Some(byte) = self.reply.pop() {
            if byte & 0xc0 != 0x80 {
                break;
            }
        }
        output.write_all(b"\x08 \x08")?;
        Ok(true)
    }

    fn finish(self) -> io::Result<String> {
        String::from_utf8(self.reply)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the reply is not valid UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Hands the input over one chunk per `fill_buf`, as a raw console
    /// delivers keystrokes.
    struct Keystrokes {
        chunks: Vec<Vec<u8>>,
        next: usize,
        offset: usize,
    }

    impl Keystrokes {
        fn new(chunks: &[&[u8]]) -> Self {
            Self {
                chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
                next: 0,
                offset: 0,
            }
        }
    }

    impl io::Read for Keystrokes {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let available = self.fill_buf()?;
            let count = available.len().min(buf.len());
            buf[..count].copy_from_slice(&available[..count]);
            self.consume(count);
            Ok(count)
        }
    }

    impl BufRead for Keystrokes {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            while self
                .chunks
                .get(self.next)
                .is_some_and(|chunk| self.offset >= chunk.len())
            {
                self.next += 1;
                self.offset = 0;
            }
            Ok(self
                .chunks
                .get(self.next)
                .map_or(&[][..], |chunk| &chunk[self.offset..]))
        }

        fn consume(&mut self, amount: usize) {
            self.offset += amount;
        }
    }

    /// Records what reaches the screen, split at each flush.
    #[derive(Default)]
    struct Screen {
        pending: Vec<u8>,
        flushed: Vec<Vec<u8>>,
    }

    impl Write for Screen {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.pending.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if !self.pending.is_empty() {
                self.flushed.push(std::mem::take(&mut self.pending));
            }
            Ok(())
        }
    }

    fn echoed(input: &[u8]) -> (String, Vec<u8>, u64) {
        let mut input = Cursor::new(input);
        let mut output = Vec::new();
        let reply = read_answer(&mut input, &mut output, true).unwrap();
        (reply, output, input.position())
    }

    #[test]
    fn echo_is_the_prompts_job_only_on_motor() {
        assert_eq!(echo_required(true), cfg!(target_os = "motor"));
        assert!(!echo_required(false));
    }

    #[test]
    fn a_delivered_reply_stops_at_the_line_feed() {
        let mut input = Cursor::new(b"yes\r\nno\n");
        let mut output = Vec::new();
        assert_eq!(read_answer(&mut input, &mut output, false).unwrap(), "yes");
        assert_eq!(input.position(), 5);
        assert!(output.is_empty());
    }

    #[test]
    fn a_delivered_reply_is_bounded() {
        let mut input = Cursor::new(vec![b'a'; 70]);
        let mut output = Vec::new();
        let reply = read_answer(&mut input, &mut output, false).unwrap();
        assert_eq!(reply, "a".repeat(REPLY_LIMIT));
        assert_eq!(input.position(), REPLY_LIMIT as u64);
    }

    #[test]
    fn an_echoed_reply_appears_as_it_is_typed() {
        let mut input = Keystrokes::new(&[b"y", b"\r\n"]);
        let mut screen = Screen::default();
        assert_eq!(read_answer(&mut input, &mut screen, true).unwrap(), "y");
        assert_eq!(screen.flushed, [b"y".to_vec(), b"\n".to_vec()]);
        assert!(input.fill_buf().unwrap().is_empty());
    }

    #[test]
    fn an_echoed_reply_takes_a_bare_return_as_enter() {
        assert_eq!(echoed(b"y\rn\n"), ("y".to_owned(), b"y\n".to_vec(), 2));
        assert_eq!(echoed(b"\r\n\n"), (String::new(), b"\n".to_vec(), 2));
    }

    #[test]
    fn an_echoed_reply_is_edited_in_place() {
        assert_eq!(
            echoed(b"ab\x7fc\n"),
            ("ac".to_owned(), b"ab\x08 \x08c\n".to_vec(), 5)
        );
        assert_eq!(
            echoed(b"no\x15\x08y\n"),
            ("y".to_owned(), b"no\x08 \x08\x08 \x08y\n".to_vec(), 6)
        );
    }

    #[test]
    fn an_echoed_reply_erases_whole_characters() {
        assert_eq!(
            echoed("é\x7fy\n".as_bytes()),
            ("y".to_owned(), "é\x08 \x08y\n".as_bytes().to_vec(), 5)
        );
    }

    #[test]
    fn an_echoed_reply_drops_escape_sequences_and_control_bytes() {
        assert_eq!(
            echoed(b"\x1b[A\x1bOP\x04y\x1b[3~\n"),
            ("y".to_owned(), b"y\n".to_vec(), 13)
        );
        assert_eq!(echoed(b"\x1b\r"), (String::new(), b"\n".to_vec(), 2));
    }

    #[test]
    fn an_echoed_reply_without_enter_still_ends_its_line() {
        assert_eq!(echoed(b"y"), ("y".to_owned(), b"y\n".to_vec(), 1));
        let (reply, output, position) = echoed(&[b'a'; 70]);
        assert_eq!(reply, "a".repeat(REPLY_LIMIT));
        assert_eq!(
            output,
            format!("{}\n", "a".repeat(REPLY_LIMIT)).into_bytes()
        );
        assert_eq!(position, REPLY_LIMIT as u64);
    }

    #[test]
    fn an_echoed_reply_must_be_utf8() {
        let mut output = Vec::new();
        let error = read_answer(&mut Cursor::new(b"\xff\n"), &mut output, true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
