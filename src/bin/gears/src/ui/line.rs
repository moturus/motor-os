//! A line editor for a console that is always raw.
//!
//! Motor OS has no termios: no cooked mode, no `ICANON`, no `ECHO` (the rush
//! contract, `rush/src/sys/mod.rs`). A program that reads a line there is
//! handed the keystrokes themselves, and nothing shows the user what they
//! typed unless the program writes it back. On the host the terminal driver
//! does all of this, which is why `BufRead::read_line` is enough there and
//! why this editor is only switched on where `platform::raw_console()` says
//! nobody else is doing the job.
//!
//! It is the smallest editor that is honest: echo, Backspace, ^U, Enter, and
//! the control bytes that mean something to the REPL — ^C (the interrupt,
//! which on Motor OS *only* exists as this in-band 0x03), ^P (pause), and ^D
//! on an empty line (end of input). CSI and SS3 escape sequences are swallowed whole rather
//! than smeared across the line as garbage; an incomplete sequence never owns a
//! later control key. History and cursor movement are rush's department, not
//! v1's here (plan decision 4 keeps the UI to plain lines).
//!
//! The state machine is fed bytes and answers with echoes, so all of it runs
//! and is tested on the host; nothing in this file is platform-specific.

use std::io::{BufRead, Write};

use crate::ui::repl::Renderer;

/// What reading one line came to.
#[derive(Debug, PartialEq)]
pub enum Read {
    Line(String),
    /// The input is over: it closed, or an empty line got ^D.
    End,
    /// A ^C. The line it interrupted is gone.
    Interrupted,
    Pause,
}

/// Where the editor is in an escape sequence.
enum Escape {
    No,
    /// An ESC byte arrived; the next byte says what kind.
    Esc,
    /// Inside `ESC [` / `ESC O`, until the final byte (`0x40..=0x7e`).
    Csi,
}

impl Default for Editor {
    fn default() -> Editor {
        Editor::new()
    }
}

pub struct Editor {
    /// The line so far, as the UTF-8 bytes that arrived.
    line: Vec<u8>,
    /// Enter came as CR, so the LF the console sends on its heels is the same
    /// keypress, not an empty second line. Kept across reads because the pair
    /// can split between them — and a swallowed "empty line" is not harmless
    /// here: at a permission question it would answer "no".
    swallow_lf: bool,
    escape: Escape,
}

impl Editor {
    pub fn new() -> Editor {
        Editor {
            line: Vec::new(),
            swallow_lf: false,
            escape: Escape::No,
        }
    }

    /// Read one line, echoing as it is typed. The echo goes through the
    /// renderer's own output so it lands on the same terminal as the prompt,
    /// and failing to echo is not failing to read.
    pub fn read<R: BufRead, W: Write>(
        &mut self,
        input: &mut R,
        renderer: &mut Renderer<W>,
    ) -> Read {
        loop {
            let mut echo = Vec::new();
            let mut outcome = None;
            let mut used = 0;
            match input.fill_buf() {
                Ok([]) | Err(_) => return Read::End,
                Ok(buffered) => {
                    for &byte in buffered {
                        used += 1;
                        if let Some(read) = self.feed(byte, &mut echo) {
                            outcome = Some(read);
                            break;
                        }
                    }
                }
            }
            input.consume(used);
            let _ = renderer.echo(&echo);
            if let Some(read) = outcome {
                return read;
            }
        }
    }

    /// One byte in; what to echo out, and the line when this byte ended it.
    pub(crate) fn feed(&mut self, byte: u8, echo: &mut Vec<u8>) -> Option<Read> {
        match self.escape {
            Escape::Esc => {
                if matches!(byte, b'[' | b'O') {
                    self.escape = Escape::Csi;
                    return None;
                }
                // A standalone Escape is ignored, but it must not steal the
                // ordinary key which followed it. Process that key below.
                self.escape = Escape::No;
            }
            Escape::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::No;
                    return None;
                }
                if (0x20..=0x3f).contains(&byte) {
                    return None;
                }
                // A control key or invalid sequence byte cancels an incomplete
                // sequence and keeps its normal meaning below.
                self.escape = Escape::No;
            }
            Escape::No => {}
        }
        if std::mem::take(&mut self.swallow_lf) && byte == b'\n' {
            return None;
        }
        match byte {
            b'\r' | b'\n' => {
                self.swallow_lf = byte == b'\r';
                echo.push(b'\n');
                let text = String::from_utf8_lossy(&self.line).into_owned();
                self.line.clear();
                Some(Read::Line(text))
            }
            // ^C, said the way the terminal driver would have said it.
            0x03 => {
                self.line.clear();
                echo.extend_from_slice(b"^C\n");
                Some(Read::Interrupted)
            }
            // ^P toggles the scheduling pause without discarding a partially
            // typed future prompt.
            0x10 => {
                echo.extend_from_slice(b"^P\n");
                Some(Read::Pause)
            }
            // ^D ends an empty line and does nothing to one with text on it.
            0x04 if self.line.is_empty() => {
                echo.push(b'\n');
                Some(Read::End)
            }
            0x1b => {
                self.escape = Escape::Esc;
                None
            }
            // Backspace, whichever byte the terminal calls it.
            0x7f | 0x08 => {
                self.erase_one(echo);
                None
            }
            // ^U: the whole line.
            0x15 => {
                while self.erase_one(echo) {}
                None
            }
            // Echo one display cell so erase arithmetic stays exact, but keep
            // the byte itself: tabs in pasted code may be significant.
            b'\t' => {
                self.line.push(b'\t');
                echo.push(b' ');
                None
            }
            // Every other control byte is a key this editor does not have
            // (a ^D with text on the line lands here too, and does nothing).
            0x00..=0x1f => None,
            _ => {
                self.line.push(byte);
                echo.push(byte);
                None
            }
        }
    }

    /// Erase the last character: from the line, and from the screen. One
    /// backspace-space-backspace per character, which puts the cursor right
    /// for everything single-width; a double-width glyph leaves its second
    /// column standing, the price of not owning a width table.
    fn erase_one(&mut self, echo: &mut Vec<u8>) -> bool {
        if self.line.is_empty() {
            return false;
        }
        while let Some(byte) = self.line.pop() {
            // Continuation bytes go with their lead byte: one char, not one byte.
            if byte & 0xc0 != 0x80 {
                break;
            }
        }
        echo.extend_from_slice(b"\x08 \x08");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run one read over `input`, returning the outcome and what was echoed.
    fn typed(editor: &mut Editor, input: &[u8]) -> (Read, String) {
        let mut renderer = Renderer::new(Vec::new(), true);
        let read = editor.read(&mut &input[..], &mut renderer);
        (
            read,
            String::from_utf8_lossy(renderer.get_ref()).into_owned(),
        )
    }

    #[test]
    fn typing_is_echoed_and_enter_ends_the_line() {
        let mut editor = Editor::new();
        let (read, echoed) = typed(&mut editor, b"hi there\r\n");
        assert_eq!(read, Read::Line("hi there".to_string()));
        assert_eq!(echoed, "hi there\n");
    }

    #[test]
    fn a_bare_lf_is_enter_too() {
        let mut editor = Editor::new();
        assert_eq!(typed(&mut editor, b"ok\n").0, Read::Line("ok".to_string()));
    }

    /// The CR and its LF can arrive in different reads; the LF must not come
    /// back as an empty line — at a permission question that would be a "no"
    /// the user never gave.
    #[test]
    fn the_lf_after_a_cr_is_the_same_enter_even_across_reads() {
        let mut editor = Editor::new();
        assert_eq!(
            typed(&mut editor, b"yes\r").0,
            Read::Line("yes".to_string())
        );
        assert_eq!(
            typed(&mut editor, b"\nno\r").0,
            Read::Line("no".to_string())
        );
    }

    #[test]
    fn backspace_erases_from_line_and_screen() {
        let mut editor = Editor::new();
        let (read, echoed) = typed(&mut editor, b"ab\x7fc\r");
        assert_eq!(read, Read::Line("ac".to_string()));
        assert_eq!(echoed, "ab\x08 \x08c\n");

        // And has nothing to say on an empty line.
        let (read, echoed) = typed(&mut editor, b"\x08\x7fx\r");
        assert_eq!(read, Read::Line("x".to_string()));
        assert_eq!(echoed, "x\n");
    }

    #[test]
    fn backspace_takes_a_whole_character_not_a_byte() {
        let mut editor = Editor::new();
        let (read, echoed) = typed(&mut editor, "é\u{7f}ok\r".as_bytes());
        assert_eq!(read, Read::Line("ok".to_string()));
        assert_eq!(echoed, "é\x08 \x08ok\n");
    }

    #[test]
    fn ctrl_u_erases_the_whole_line() {
        let mut editor = Editor::new();
        let (read, echoed) = typed(&mut editor, b"abc\x15d\r");
        assert_eq!(read, Read::Line("d".to_string()));
        assert_eq!(echoed, "abc\x08 \x08\x08 \x08\x08 \x08d\n");
    }

    #[test]
    fn ctrl_c_interrupts_and_drops_the_line() {
        let mut editor = Editor::new();
        let (read, echoed) = typed(&mut editor, b"half a promp\x03");
        assert_eq!(read, Read::Interrupted);
        assert!(echoed.ends_with("^C\n"), "{echoed}");
        // The dropped text is not waiting inside the next line.
        assert_eq!(typed(&mut editor, b"y\r").0, Read::Line("y".to_string()));
    }

    #[test]
    fn ctrl_p_pauses_without_dropping_the_line() {
        let mut editor = Editor::new();
        let (read, echoed) = typed(&mut editor, b"half");
        assert_eq!(read, Read::Pause);
        assert!(echoed.ends_with("^P\n"), "{echoed}");
        assert_eq!(
            typed(&mut editor, b" prompt\r").0,
            Read::Line("half prompt".to_string())
        );
    }

    #[test]
    fn ctrl_d_ends_an_empty_line_and_spares_a_full_one() {
        let mut editor = Editor::new();
        assert_eq!(typed(&mut editor, b"\x04").0, Read::End);
        let (read, _) = typed(&mut editor, b"keep\x04\r");
        assert_eq!(read, Read::Line("keep".to_string()));
    }

    #[test]
    fn input_closing_is_the_end() {
        let mut editor = Editor::new();
        assert_eq!(typed(&mut editor, b"").0, Read::End);
        // A line the close cut off is lost, as it is under cooked mode too.
        assert_eq!(typed(&mut editor, b"half").0, Read::End);
    }

    #[test]
    fn escape_sequences_are_swallowed_whole() {
        let mut editor = Editor::new();
        // Up arrow (CSI and SS3 forms), then a Home with a parameter.
        let (read, echoed) = typed(&mut editor, b"\x1b[Aa\x1bOBb\x1b[1;5Hc\r");
        assert_eq!(read, Read::Line("abc".to_string()));
        assert_eq!(echoed, "abc\n");
        // A standalone Escape must not steal the ordinary key after it.
        assert_eq!(
            typed(&mut editor, b"\x1bxd\r").0,
            Read::Line("xd".to_string())
        );
    }

    #[test]
    fn an_incomplete_escape_sequence_does_not_own_control_keys() {
        let mut editor = Editor::new();
        assert_eq!(
            typed(&mut editor, b"one\x1b\r").0,
            Read::Line("one".to_string())
        );
        assert_eq!(
            typed(&mut editor, b"ok\x1b[\r").0,
            Read::Line("ok".to_string())
        );
        assert_eq!(typed(&mut editor, b"no\x1b[\x03").0, Read::Interrupted);
    }

    #[test]
    fn a_tab_is_preserved_while_echoing_as_one_space() {
        let mut editor = Editor::new();
        let (read, echoed) = typed(&mut editor, b"a\tb\r");
        assert_eq!(read, Read::Line("a\tb".to_string()));
        assert_eq!(echoed, "a b\n");
    }
}
