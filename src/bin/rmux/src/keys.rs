//! Keys: what rmux calls them, how they arrive, and how they are passed on.
//!
//! The bytes are crossterm's now. Its Motor OS backend reads the console
//! through `moto_rt::poll`, holds a half-arrived escape sequence for as long as
//! a serial line that delivers one byte at a time needs to finish it, coalesces
//! the CR LF that one Enter arrives as, and asks the console how big it is with
//! `ESC[6n` — the three things §8.3 and §3.2 are about, in one place that every
//! program on the platform now shares rather than in rmux's own scanner.
//!
//! What is left here is rmux's own vocabulary and the two translations around
//! it: [`Key::from_event`] for what the user pressed, and [`Key::encode`] for
//! the bytes a pane's child is given for it.
//!
//! # The round trip §8.1 used to avoid
//!
//! rmux forwarded console bytes to panes verbatim, precisely so that nothing it
//! does not model could be mangled on the way. Decoding and re-encoding is a
//! deliberate change of that rule: a key rmux has no name for is now dropped
//! rather than passed through. What that costs is bounded by what can reach a
//! console rmux owns — it enables neither mouse reporting nor bracketed paste on
//! its own terminal, and a pane's program asking for either is talking to rmux's
//! emulator rather than to the terminal, so those bytes never arrive. What is
//! left is function keys and the like, which [`Code`] names, and the kitty
//! keyboard protocol, which nothing on Motor OS speaks.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::sys;

// ---- keys ------------------------------------------------------------------

/// A key, named the way tmux names one: `C-a`, `S-Left`, `M-Up`, `|`.
///
/// This is what a binding table is keyed by (§8.2), so it has to be comparable
/// and it has to parse from the strings a config file uses (§2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub code: Code,
    pub mods: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    Char(char),
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    Enter,
    Tab,
    Backspace,
    Escape,
    /// `F1`…`F12`. Named so that they can be *passed on*: rmux binds none of
    /// them, and a key with no name here is a key a pane's program never sees.
    F(u8),
}

impl Key {
    pub const CTRL: u8 = 1 << 0;
    pub const ALT: u8 = 1 << 1;
    pub const SHIFT: u8 = 1 << 2;

    pub fn plain(code: Code) -> Key {
        Key { code, mods: 0 }
    }

    pub fn with(code: Code, mods: u8) -> Key {
        Key { code, mods }
    }

    pub fn ctrl(c: char) -> Key {
        Key::with(Code::Char(c), Key::CTRL)
    }

    /// Parse a name as a config file writes it: `C-a`, `S-Left`, `M-Up`, `|`.
    ///
    /// Case matters for the *modifier* prefixes and not for the key, which is
    /// tmux's convention: `C-a` and `C-A` are the same key, `S-Left` and
    /// `s-Left` are not the same thing.
    pub fn parse(name: &str) -> Option<Key> {
        let mut mods = 0;
        let mut rest = name;
        loop {
            let (prefix, bit) = match rest.get(..2) {
                Some("C-") => ("C-", Key::CTRL),
                Some("M-") => ("M-", Key::ALT),
                Some("S-") => ("S-", Key::SHIFT),
                // A bare `-` is a key in its own right (the config binds it to
                // a vertical split), so a two-character name is never a prefix.
                _ => break,
            };
            if rest.len() == prefix.len() {
                break;
            }
            mods |= bit;
            rest = &rest[prefix.len()..];
        }

        let code = match rest {
            "Up" => Code::Up,
            "Down" => Code::Down,
            "Left" => Code::Left,
            "Right" => Code::Right,
            "Home" => Code::Home,
            "End" => Code::End,
            "PageUp" | "PPage" => Code::PageUp,
            "PageDown" | "NPage" => Code::PageDown,
            "Insert" | "IC" => Code::Insert,
            "Delete" | "DC" => Code::Delete,
            "Enter" => Code::Enter,
            "Tab" => Code::Tab,
            "BSpace" | "Backspace" => Code::Backspace,
            "Escape" | "Esc" => Code::Escape,
            "Space" => Code::Char(' '),
            _ if rest.starts_with('F') && rest.len() > 1 => {
                Code::F(rest[1..].parse().ok().filter(|n| (1..=12).contains(n))?)
            }
            _ => {
                let mut chars = rest.chars();
                let only = chars.next()?;
                if chars.next().is_some() {
                    return None;
                }
                // `C-A` is `C-a`: a control byte carries no case.
                Code::Char(if mods & Key::CTRL != 0 {
                    only.to_ascii_lowercase()
                } else {
                    only
                })
            }
        };
        Some(Key { code, mods })
    }

    /// What the user pressed, as crossterm read it — or `None` for a key rmux
    /// has no name for, which is dropped rather than guessed at.
    ///
    /// The shift of a capital letter is *the letter*: crossterm reports `G` with
    /// `SHIFT` held, and copy mode binds `G` (`bindings::vi_copy_keys`), so a
    /// key that kept the bit would match no binding at all. For the named keys
    /// shift is a modifier like any other — `S-Left` is a binding of its own.
    pub fn from_event(event: KeyEvent) -> Option<Key> {
        let mut mods = 0;
        for (held, bit) in [
            (KeyModifiers::CONTROL, Key::CTRL),
            (KeyModifiers::ALT, Key::ALT),
            (KeyModifiers::SHIFT, Key::SHIFT),
        ] {
            if event.modifiers.contains(held) {
                mods |= bit;
            }
        }

        let code = match event.code {
            // `^J` is Enter and `^H` is Backspace: a console that sends a bare
            // LF for Enter reaches raw mode as `^J`, and terminals disagree
            // about which byte Backspace sends. Both were true of the byte
            // decoder this replaces, so neither key is losing a binding.
            KeyCode::Char('j') if mods == Key::CTRL => return Some(Key::plain(Code::Enter)),
            KeyCode::Char('h') if mods == Key::CTRL => return Some(Key::plain(Code::Backspace)),
            KeyCode::Char(c) => {
                mods &= !Key::SHIFT;
                Code::Char(c)
            }
            KeyCode::Enter => Code::Enter,
            KeyCode::Tab => Code::Tab,
            KeyCode::BackTab => {
                mods |= Key::SHIFT;
                Code::Tab
            }
            KeyCode::Backspace => Code::Backspace,
            KeyCode::Esc => Code::Escape,
            KeyCode::Up => Code::Up,
            KeyCode::Down => Code::Down,
            KeyCode::Left => Code::Left,
            KeyCode::Right => Code::Right,
            KeyCode::Home => Code::Home,
            KeyCode::End => Code::End,
            KeyCode::PageUp => Code::PageUp,
            KeyCode::PageDown => Code::PageDown,
            KeyCode::Insert => Code::Insert,
            KeyCode::Delete => Code::Delete,
            KeyCode::F(n) if (1..=12).contains(&n) => Code::F(n),
            _ => return None,
        };
        Some(Key { code, mods })
    }

    /// The bytes a terminal sends for this key — what a pane's child is given
    /// for it (§8.1).
    ///
    /// xterm's encodings, which is what the decoder on the other side of every
    /// pane expects and what rmux's own tables were written against (§8.3).
    pub fn encode(&self) -> Vec<u8> {
        let alt = self.mods & Key::ALT != 0;
        let ctrl = self.mods & Key::CTRL != 0;
        let mut out = Vec::new();
        // `M-x` is `ESC x`, for every key that is not already an escape
        // sequence of its own; the parameterized forms below carry the alt in
        // their modifier instead.
        if alt && matches!(self.code, Code::Char(_) | Code::Enter | Code::Tab) {
            out.push(0x1b);
        }

        match self.code {
            Code::Char(c) if ctrl => out.push(control_byte(c)),
            Code::Char(c) => {
                let mut buf = [0_u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            // What the platform's own console sends for the key (§3.4): a
            // carriage return on the host, CR LF on Motor OS, where sys-tty
            // synthesizes both and a program must behave the same in a pane as
            // outside one.
            Code::Enter => out.extend_from_slice(sys::ENTER),
            Code::Tab if self.mods & Key::SHIFT != 0 => out.extend_from_slice(b"\x1b[Z"),
            Code::Tab => out.push(b'\t'),
            Code::Backspace => out.push(0x7f),
            Code::Escape => out.push(0x1b),
            Code::Up => self.csi(b'A', &mut out),
            Code::Down => self.csi(b'B', &mut out),
            Code::Right => self.csi(b'C', &mut out),
            Code::Left => self.csi(b'D', &mut out),
            Code::Home => self.csi(b'H', &mut out),
            Code::End => self.csi(b'F', &mut out),
            Code::Insert => self.tilde(2, &mut out),
            Code::Delete => self.tilde(3, &mut out),
            Code::PageUp => self.tilde(5, &mut out),
            Code::PageDown => self.tilde(6, &mut out),
            // F1-F4 are `SS3`-style and the rest are numbered, as they are on
            // every terminal since the VT220.
            Code::F(n @ 1..=4) if self.modifier() == 1 => {
                out.extend_from_slice(&[0x1b, b'O', b'P' + n - 1]);
            }
            Code::F(n @ 1..=4) => self.csi(b'P' + n - 1, &mut out),
            Code::F(n) => {
                if let Some(number) = FUNCTION_KEY_NUMBERS.get(usize::from(n).wrapping_sub(5)) {
                    self.tilde(*number, &mut out);
                }
            }
        }
        out
    }

    /// `ESC[{final}` — or `ESC[1;{mods}{final}` when anything is held, which is
    /// how a terminal says `S-Left` and how [`Key::from_event`] reads it back.
    fn csi(&self, final_byte: u8, out: &mut Vec<u8>) {
        match self.modifier() {
            1 => out.extend_from_slice(&[0x1b, b'[', final_byte]),
            m => out.extend_from_slice(format!("\x1b[1;{m}{}", final_byte as char).as_bytes()),
        }
    }

    /// `ESC[{n}~`, the numbered form: Insert, Delete, the page keys and F5 up.
    fn tilde(&self, n: u8, out: &mut Vec<u8>) {
        match self.modifier() {
            1 => out.extend_from_slice(format!("\x1b[{n}~").as_bytes()),
            m => out.extend_from_slice(format!("\x1b[{n};{m}~").as_bytes()),
        }
    }

    /// xterm's modifier parameter: 1 plus a bitmask of shift, alt, control.
    fn modifier(&self) -> u8 {
        let mut bits = 0;
        for (bit, held) in [(1, Key::SHIFT), (2, Key::ALT), (4, Key::CTRL)] {
            if self.mods & held != 0 {
                bits |= bit;
            }
        }
        1 + bits
    }
}

/// The numbers `ESC[{n}~` gives F5 to F12. Not a run: the gaps are where the
/// VT220's own keys were.
const FUNCTION_KEY_NUMBERS: [u8; 8] = [15, 17, 18, 19, 20, 21, 23, 24];

/// The byte a terminal sends for a character with control held.
///
/// `C-a` is 1 and `C-Space` is 0, which is the ASCII rule: the control byte is
/// the character with its top three bits cleared. A character that rule does
/// not reach stands for itself.
fn control_byte(c: char) -> u8 {
    match c {
        ' ' => 0,
        'a'..='z' => c as u8 - b'a' + 1,
        'A'..='Z' => c as u8 - b'A' + 1,
        '@'..='_' => c as u8 & 0x1f,
        _ => c as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key a terminal event decodes to.
    fn key(code: KeyCode, mods: KeyModifiers) -> Option<Key> {
        Key::from_event(KeyEvent::new(code, mods))
    }

    /// The key `bytes` stand for, as read back off the wire into a pane.
    fn encoded(key: Key) -> Vec<u8> {
        key.encode()
    }

    // ---- what the user pressed ----

    #[test]
    fn a_control_key_is_the_key_a_config_calls_it() {
        // `C-a` is the prefix this whole project is built around (§2.1).
        assert_eq!(
            key(KeyCode::Char('a'), KeyModifiers::CONTROL),
            Some(Key::ctrl('a'))
        );
        assert_eq!(
            key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Key::plain(Code::Enter))
        );
        assert_eq!(
            key(KeyCode::Tab, KeyModifiers::NONE),
            Some(Key::plain(Code::Tab))
        );
        assert_eq!(
            key(KeyCode::Backspace, KeyModifiers::NONE),
            Some(Key::plain(Code::Backspace))
        );
        // NUL is `C-Space`, the name `Key::parse` gives it and the key emacs
        // copy mode selects with.
        assert_eq!(
            key(KeyCode::Char(' '), KeyModifiers::CONTROL),
            Some(Key::ctrl(' '))
        );
        assert_eq!(Key::parse("C-Space"), Some(Key::ctrl(' ')));
    }

    #[test]
    fn the_shift_of_a_capital_letter_is_the_letter() {
        // Copy mode binds `G` (`bindings::vi_copy_keys`), and a terminal reports
        // it with shift held. A key that kept the bit would match no binding.
        assert_eq!(
            key(KeyCode::Char('G'), KeyModifiers::SHIFT),
            Some(Key::plain(Code::Char('G')))
        );
        // For a named key shift is a modifier like any other: `S-Left` is a
        // binding of its own (§2.1).
        assert_eq!(
            key(KeyCode::Left, KeyModifiers::SHIFT),
            Some(Key::with(Code::Left, Key::SHIFT))
        );
    }

    #[test]
    fn the_two_keys_terminals_disagree_about_have_both_spellings() {
        // Both were true of the byte decoder this replaces: `\n` and `\r` were
        // Enter, `0x08` and `0x7f` were Backspace.
        assert_eq!(
            key(KeyCode::Char('j'), KeyModifiers::CONTROL),
            Some(Key::plain(Code::Enter))
        );
        assert_eq!(
            key(KeyCode::Char('h'), KeyModifiers::CONTROL),
            Some(Key::plain(Code::Backspace))
        );
    }

    #[test]
    fn a_key_rmux_has_no_name_for_is_dropped_rather_than_guessed_at() {
        assert_eq!(key(KeyCode::CapsLock, KeyModifiers::NONE), None);
        assert_eq!(key(KeyCode::F(13), KeyModifiers::NONE), None);
    }

    // ---- what the pane is given ----

    #[test]
    fn the_measured_encodings_are_the_ones_a_pane_is_handed() {
        // Straight off §8.3's table, which was measured on both of Motor's
        // terminals rather than assumed -- read the other way now, since rmux
        // writes these bytes instead of forwarding them. If this is wrong,
        // S-Left silently types garbage into a pane.
        let cases: &[(Key, &[u8])] = &[
            (Key::plain(Code::Left), b"\x1b[D"),
            (Key::with(Code::Left, Key::SHIFT), b"\x1b[1;2D"),
            (Key::with(Code::Right, Key::SHIFT), b"\x1b[1;2C"),
            (Key::with(Code::Left, Key::ALT), b"\x1b[1;3D"),
            (Key::with(Code::Right, Key::ALT), b"\x1b[1;3C"),
            (Key::with(Code::Up, Key::ALT), b"\x1b[1;3A"),
            (Key::with(Code::Down, Key::ALT), b"\x1b[1;3B"),
            (Key::with(Code::Left, Key::CTRL), b"\x1b[1;5D"),
            (Key::plain(Code::Home), b"\x1b[H"),
            (Key::plain(Code::End), b"\x1b[F"),
            (Key::plain(Code::Delete), b"\x1b[3~"),
            (Key::plain(Code::PageUp), b"\x1b[5~"),
            (Key::with(Code::PageDown, Key::CTRL), b"\x1b[6;5~"),
            (Key::plain(Code::Escape), b"\x1b"),
            (Key::plain(Code::Tab), b"\t"),
            (Key::with(Code::Tab, Key::SHIFT), b"\x1b[Z"),
            (Key::plain(Code::Backspace), b"\x7f"),
            (Key::plain(Code::F(1)), b"\x1bOP"),
            (Key::plain(Code::F(5)), b"\x1b[15~"),
            (Key::plain(Code::F(12)), b"\x1b[24~"),
        ];
        for (key, bytes) in cases {
            assert_eq!(encoded(*key), *bytes, "{key:?}");
        }
    }

    #[test]
    fn a_control_key_is_the_byte_it_has_always_been() {
        assert_eq!(encoded(Key::ctrl('a')), b"\x01");
        assert_eq!(encoded(Key::ctrl('c')), b"\x03");
        // The one the arithmetic gets wrong: `C-Space` is NUL.
        assert_eq!(encoded(Key::ctrl(' ')), b"\x00");
        // `M-x` is `ESC x`, which is how a terminal has always sent it.
        assert_eq!(encoded(Key::with(Code::Char('x'), Key::ALT)), b"\x1bx");
    }

    #[test]
    fn a_character_is_a_character_whatever_its_width() {
        assert_eq!(encoded(Key::plain(Code::Char('|'))), b"|");
        assert_eq!(encoded(Key::plain(Code::Char('é'))), "é".as_bytes());
        assert_eq!(encoded(Key::plain(Code::Char('日'))), "日".as_bytes());
    }

    #[test]
    fn enter_is_what_this_platform_sends_for_it() {
        // §3.4: a carriage return on the host, CR LF on Motor OS, where sys-tty
        // synthesizes both and a program must behave the same inside a pane as
        // outside one.
        assert_eq!(encoded(Key::plain(Code::Enter)), sys::ENTER);
    }

    #[test]
    fn every_key_a_terminal_can_send_survives_the_round_trip() {
        // What §8.1 used to guarantee by not decoding at all: a key rmux does
        // not act on reaches the pane as the bytes it was. It cannot be checked
        // by re-reading the bytes here -- that is crossterm's parser, which this
        // crate does not own -- so the claim is the narrower one that every key
        // encodes to something, and to the sequence §8.3 measured above.
        let codes = [
            Code::Char('a'),
            Code::Up,
            Code::Down,
            Code::Left,
            Code::Right,
            Code::Home,
            Code::End,
            Code::PageUp,
            Code::PageDown,
            Code::Insert,
            Code::Delete,
            Code::Enter,
            Code::Tab,
            Code::Backspace,
            Code::Escape,
            Code::F(3),
        ];
        for code in codes {
            for mods in [0, Key::CTRL, Key::ALT, Key::SHIFT, Key::CTRL | Key::ALT] {
                let bytes = Key::with(code, mods).encode();
                assert!(!bytes.is_empty(), "{code:?} with {mods} encodes to nothing");
            }
        }
    }

    #[test]
    fn key_names_parse_as_a_config_file_writes_them() {
        // Every name §2.1's table uses, and the ones §2.2's example does.
        assert_eq!(Key::parse("C-a"), Some(Key::ctrl('a')));
        assert_eq!(Key::parse("C-A"), Some(Key::ctrl('a')));
        assert_eq!(
            Key::parse("S-Left"),
            Some(Key::with(Code::Left, Key::SHIFT))
        );
        assert_eq!(Key::parse("M-Up"), Some(Key::with(Code::Up, Key::ALT)));
        assert_eq!(Key::parse("|"), Some(Key::plain(Code::Char('|'))));
        assert_eq!(Key::parse("\""), Some(Key::plain(Code::Char('"'))));
        assert_eq!(Key::parse("%"), Some(Key::plain(Code::Char('%'))));
        assert_eq!(Key::parse("0"), Some(Key::plain(Code::Char('0'))));
        assert_eq!(Key::parse("Space"), Some(Key::plain(Code::Char(' '))));
        assert_eq!(Key::parse("Escape"), Some(Key::plain(Code::Escape)));
    }

    #[test]
    fn a_bare_dash_is_a_key_rather_than_half_a_modifier() {
        // The config binds `-` to a vertical split (§2.1), which is why the
        // parser stops treating `X-` as a prefix when nothing follows it.
        assert_eq!(Key::parse("-"), Some(Key::plain(Code::Char('-'))));
        assert_eq!(
            Key::parse("C--"),
            Some(Key::with(Code::Char('-'), Key::CTRL))
        );
        // A modifier with nothing to modify is not a key.
        assert_eq!(Key::parse("C-"), None);
    }

    #[test]
    fn a_name_that_is_not_a_key_is_refused_rather_than_guessed_at() {
        assert_eq!(Key::parse("Nonsense"), None);
        assert_eq!(Key::parse(""), None);
        assert_eq!(Key::parse("C-Nonsense"), None);
    }
}
