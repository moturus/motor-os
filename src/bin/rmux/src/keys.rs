//! Console bytes: what rmux keeps, and what it passes on.
//!
//! The rule is §8.1's, and it is the opposite of the obvious one: rmux does
//! **not** decode a keystroke into a `Key` and re-encode it for the pane. That
//! round trip is lossy for everything rmux does not model, which is most of
//! what a terminal can send. It recognizes only what it is waiting for, and
//! forwards the rest byte for byte.
//!
//! Two things are recognized here. The answer to rmux's own size probe (§3.2),
//! which the client keeps to itself; and a [`Key`], which the *server* looks up
//! in its tables (§8.2). Everything else is forwarded byte for byte, and a key
//! that turns out not to be bound is forwarded as the bytes it was made of —
//! which is why [`Keys::feed`] hands back the raw bytes alongside each key
//! rather than expecting anyone to re-encode one.
//!
//! # Why the probe needs a scanner at all
//!
//! Motor has no terminal-size call (§3.2), so rmux asks the terminal the way
//! red does — `ESC[9999;9999H ESC[6n` — and takes the answer the way rush does,
//! which is to say without waiting for it (`rush/src/term.rs:663-672`). A
//! console with nothing on the other end that answers `CPR` would otherwise
//! hang rmux at startup, before the user can type.
//!
//! So the answer turns up later, mixed into ordinary input, possibly **split
//! across reads** (§8.3), and it must not reach the pane — a shell handed a
//! stray `ESC[30;90R` prints it. Hence a small buffer, and hence the care
//! below about giving it back: `ESC[1;2D` is `S-Left` and looks exactly like a
//! report until its final byte.

/// What rmux writes to ask the console how big it is.
///
/// red's sequence (`red/src/terminal.rs:74`), because rmux needs rows as well
/// as columns; rush's discipline, because rmux must never block on the answer.
pub const SIZE_PROBE: &[u8] = b"\x1b[9999;9999H\x1b[6n";

/// The same question, asked while a session is on the screen.
///
/// Startup fires [`SIZE_PROBE`] at a console with nothing on it yet, so where
/// the cursor lands does not matter. A re-probe (§3.2) has no such luxury: the
/// frame diff leaves the cursor where the last paint put it and moves it again
/// only when something changes, so a probe that does not put it back leaves it
/// in the bottom-right corner until it does. `ESC 7`/`ESC 8` are DECSC/DECRC —
/// save and restore, in the same write, which is how a terminal is asked
/// without disturbing what is on it.
pub const SIZE_REPROBE: &[u8] = b"\x1b7\x1b[9999;9999H\x1b[6n\x1b8";

/// Watches console input for the answer to [`SIZE_PROBE`].
///
/// Bytes are held back *only* while an answer could still be arriving, and only
/// for as long as what has been held could still become one. Once the report
/// turns up — or the first byte that cannot be part of one does — this stops
/// buffering, so a lone `Esc` on its way to `red` in a pane is delayed by at
/// most the window the client keeps an answer open for.
pub struct SizeProbe {
    awaiting: bool,
    pending: Vec<u8>,
}

impl SizeProbe {
    /// A probe whose answer is expected.
    pub fn awaiting() -> SizeProbe {
        SizeProbe {
            awaiting: true,
            pending: Vec::new(),
        }
    }

    /// A probe that was never fired, because the platform could say (§3.2).
    pub fn none() -> SizeProbe {
        SizeProbe {
            awaiting: false,
            pending: Vec::new(),
        }
    }

    /// Expect an answer again, for a probe just fired.
    ///
    /// The console changes shape without telling anyone (§3.2), so the question
    /// is asked more than once, and every asking needs a scanner.
    pub fn rearm(&mut self) {
        self.awaiting = true;
    }

    /// Whether a keystroke is being held back for an answer right now.
    pub fn holding(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Hand back what was held, without giving up on the answer.
    ///
    /// Two clocks, deliberately: **holding costs a keystroke**, since a lone
    /// `Esc` on its way to `red` looks exactly like the start of a report, so it
    /// is let go after a window. **Waiting costs nothing**, and an answer slower
    /// than that window is still an answer rather than an `ESC[30;90R` printed
    /// in a pane (§3.2).
    pub fn release(&mut self, forward: &mut Vec<u8>) {
        forward.append(&mut self.pending);
    }

    /// Split `bytes` into what the pane should be sent and the size, if this is
    /// where the answer arrived.
    pub fn filter(&mut self, bytes: &[u8], forward: &mut Vec<u8>) -> Option<(u16, u16)> {
        if !self.awaiting {
            forward.extend_from_slice(bytes);
            return None;
        }

        let mut reported = None;
        for byte in bytes {
            if completes_report(&self.pending, *byte) {
                reported = parse_report(&self.pending);
                self.pending.clear();
                // One probe, one answer. Anything after this is the user's.
                self.awaiting = false;
                continue;
            }
            if extends_report(&self.pending, *byte) {
                self.pending.push(*byte);
                continue;
            }
            // Not a report after all: hand back every byte that was held for
            // it, in order, before the one that settled the question.
            forward.append(&mut self.pending);
            if *byte == 0x1b {
                self.pending.push(*byte);
            } else {
                forward.push(*byte);
            }
        }

        if !self.awaiting {
            forward.append(&mut self.pending);
        }
        reported
    }
}

/// Whether `byte` keeps `pending` on course to be `ESC[{row};{col}R`.
fn extends_report(pending: &[u8], byte: u8) -> bool {
    match pending {
        [] => byte == 0x1b,
        [0x1b] => byte == b'[',
        [0x1b, b'['] => byte.is_ascii_digit(),
        _ => match pending.iter().filter(|byte| **byte == b';').count() {
            0 => byte.is_ascii_digit() || byte == b';',
            1 => byte.is_ascii_digit(),
            _ => false,
        },
    }
}

fn completes_report(pending: &[u8], byte: u8) -> bool {
    byte == b'R'
        && pending.iter().filter(|byte| **byte == b';').count() == 1
        && pending.last().is_some_and(u8::is_ascii_digit)
}

fn parse_report(pending: &[u8]) -> Option<(u16, u16)> {
    let body = std::str::from_utf8(pending.get(2..)?).ok()?;
    let (rows, cols) = body.split_once(';')?;
    match (rows.parse().ok()?, cols.parse().ok()?) {
        (0, _) | (_, 0) => None,
        size => Some(size),
    }
}

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
}

/// Console bytes to keys, incrementally.
///
/// Incremental because it must be: on the serial console sys-tty forwards one
/// byte at a time, so a sequence arrives split at unpredictable points (§8.3).
/// Nothing here may assume a sequence lands in one read.
///
/// That leaves the question of a lone `Esc`, which is both a key and the start
/// of every other one. It is held only until [`Keys::flush`] is called, which
/// the caller does when input goes quiet — tmux spends its `escape-time` on the
/// same problem. Holding it forever would strand `red` in a pane; emitting it
/// at once would make every arrow key an `Esc` followed by junk.
#[derive(Default)]
pub struct Keys {
    pending: Vec<u8>,
}

impl Keys {
    pub fn new() -> Keys {
        Keys::default()
    }

    /// Decode what has arrived, reporting each key with the bytes it was made
    /// of, so an unbound one can be forwarded exactly as it came (§8.1).
    pub fn feed(&mut self, bytes: &[u8], each: &mut impl FnMut(Key, &[u8])) {
        self.pending.extend_from_slice(bytes);
        let mut at = 0;
        while at < self.pending.len() {
            match decode(&self.pending[at..]) {
                Decoded::Key(key, used) => {
                    each(key, &self.pending[at..at + used]);
                    at += used;
                }
                // The rest could still become a key; keep it for the next read.
                Decoded::More => break,
            }
        }
        self.pending.drain(..at);
    }

    /// Give up on what is held: input has gone quiet, so an `Esc` is an `Esc`.
    pub fn flush(&mut self, each: &mut impl FnMut(Key, &[u8])) {
        while !self.pending.is_empty() {
            let held = std::mem::take(&mut self.pending);
            let (key, used) = match decode(&held) {
                Decoded::Key(key, used) => (key, used),
                // Whatever it was, it is not going to finish. The first byte
                // stands for itself and the rest is decoded again behind it.
                Decoded::More => (byte_key(held[0]), 1),
            };
            each(key, &held[..used]);
            self.pending.extend_from_slice(&held[used..]);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

enum Decoded {
    Key(Key, usize),
    More,
}

fn decode(bytes: &[u8]) -> Decoded {
    match bytes[0] {
        0x1b => decode_escape(bytes),
        // A UTF-8 sequence may be split across reads like anything else.
        byte if byte >= 0x80 => match decode_utf8(bytes) {
            Some((c, used)) => Decoded::Key(Key::plain(Code::Char(c)), used),
            None => Decoded::More,
        },
        byte => Decoded::Key(byte_key(byte), 1),
    }
}

/// A single byte, as the key it stands for.
fn byte_key(byte: u8) -> Key {
    match byte {
        b'\r' | b'\n' => Key::plain(Code::Enter),
        b'\t' => Key::plain(Code::Tab),
        0x7f | 0x08 => Key::plain(Code::Backspace),
        0x1b => Key::plain(Code::Escape),
        // NUL is `C-Space`, which is what a terminal sends for it and what
        // tmux calls it -- and what [`Key::parse`] makes of that name. The
        // arithmetic below would call it `` C-` ``, a key nobody can type, so
        // the emacs copy table's `begin-selection` would never have fired.
        0x00 => Key::ctrl(' '),
        // A control byte *is* a modified letter: 0x01 is `C-a`, which is how
        // tmux names it and how a config file writes it.
        0x01..=0x1f => Key::ctrl((byte + 0x60) as char),
        byte => Key::plain(Code::Char(byte as char)),
    }
}

fn decode_escape(bytes: &[u8]) -> Decoded {
    match bytes.get(1) {
        None => Decoded::More,
        Some(b'[') => decode_csi(bytes),
        // `ESC O A` -- an arrow in application-keypad mode.
        Some(b'O') => match bytes.get(2) {
            None => Decoded::More,
            Some(byte) => match arrow(*byte) {
                Some(code) => Decoded::Key(Key::plain(code), 3),
                None => Decoded::Key(Key::plain(Code::Escape), 1),
            },
        },
        // `ESC ESC [ D` is the other spelling of `M-Left`, and it really does
        // arrive on both of Motor's terminals (§8.3, measured).
        Some(0x1b) => match decode(&bytes[1..]) {
            Decoded::Key(key, used) => {
                Decoded::Key(Key::with(key.code, key.mods | Key::ALT), used + 1)
            }
            Decoded::More => Decoded::More,
        },
        // `ESC x` is `M-x`.
        Some(byte) => Decoded::Key(
            Key::with(byte_key(*byte).code, byte_key(*byte).mods | Key::ALT),
            2,
        ),
    }
}

fn decode_csi(bytes: &[u8]) -> Decoded {
    // `ESC [ <params> <final>`, where the params carry the modifiers:
    // `ESC[1;2D` is `S-Left` and `ESC[1;3D` is `M-Left`.
    let mut at = 2;
    while at < bytes.len() && !(0x40..=0x7e).contains(&bytes[at]) {
        at += 1;
    }
    if at >= bytes.len() {
        return Decoded::More;
    }

    let final_byte = bytes[at];
    let params = std::str::from_utf8(&bytes[2..at]).unwrap_or("");
    let mods = params
        .split(';')
        .nth(1)
        .and_then(|m| m.parse::<u8>().ok())
        .map_or(0, modifiers);
    let used = at + 1;

    let code = match final_byte {
        b'A' | b'B' | b'C' | b'D' => arrow(final_byte),
        b'H' => Some(Code::Home),
        b'F' => Some(Code::End),
        b'~' => match params.split(';').next().unwrap_or("") {
            "1" | "7" => Some(Code::Home),
            "2" => Some(Code::Insert),
            "3" => Some(Code::Delete),
            "4" | "8" => Some(Code::End),
            "5" => Some(Code::PageUp),
            "6" => Some(Code::PageDown),
            _ => None,
        },
        _ => None,
    };

    match code {
        Some(code) => Decoded::Key(Key::with(code, mods), used),
        // A sequence rmux has no name for: report the `Esc` that began it and
        // let the rest decode behind it, so nothing is silently swallowed and
        // the bytes still reach the pane (§8.1).
        None => Decoded::Key(Key::plain(Code::Escape), 1),
    }
}

fn arrow(final_byte: u8) -> Option<Code> {
    Some(match final_byte {
        b'A' => Code::Up,
        b'B' => Code::Down,
        b'C' => Code::Right,
        b'D' => Code::Left,
        _ => return None,
    })
}

/// xterm's modifier parameter: 1 plus a bitmask of shift, alt, control.
fn modifiers(param: u8) -> u8 {
    let bits = param.saturating_sub(1);
    let mut mods = 0;
    if bits & 1 != 0 {
        mods |= Key::SHIFT;
    }
    if bits & 2 != 0 {
        mods |= Key::ALT;
    }
    if bits & 4 != 0 {
        mods |= Key::CTRL;
    }
    mods
}

/// One UTF-8 character, or `None` if it has not all arrived yet.
fn decode_utf8(bytes: &[u8]) -> Option<(char, usize)> {
    let len = match bytes[0] {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        // Not a lead byte at all; stand for itself rather than stall.
        _ => return Some((char::REPLACEMENT_CHARACTER, 1)),
    };
    if bytes.len() < len {
        return None;
    }
    match std::str::from_utf8(&bytes[..len]) {
        Ok(text) => text.chars().next().map(|c| (c, len)),
        Err(_) => Some((char::REPLACEMENT_CHARACTER, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `chunks` as successive reads, and return what was forwarded plus
    /// whatever size was reported.
    fn filter(chunks: &[&[u8]]) -> (Vec<u8>, Option<(u16, u16)>) {
        let mut probe = SizeProbe::awaiting();
        let mut forward = Vec::new();
        let mut reported = None;
        for chunk in chunks {
            reported = probe.filter(chunk, &mut forward).or(reported);
        }
        (forward, reported)
    }

    #[test]
    fn the_answer_is_taken_and_never_reaches_the_pane() {
        // A shell handed a stray `ESC[30;90R` prints it.
        let (forward, reported) = filter(&[b"\x1b[30;90R"]);
        assert_eq!(reported, Some((30, 90)));
        assert!(forward.is_empty(), "{forward:?}");
    }

    #[test]
    fn the_answer_is_recognized_however_it_is_split() {
        // The serial console hands sys-tty a byte at a time (§8.3).
        let split: Vec<&[u8]> = vec![b"\x1b", b"[", b"3", b"0", b";", b"9", b"0", b"R"];
        assert_eq!(filter(&split).1, Some((30, 90)));
        assert_eq!(filter(&[b"\x1b[30", b";90R"]).1, Some((30, 90)));
    }

    #[test]
    fn a_key_that_looks_like_the_answer_until_its_last_byte_is_forwarded_whole() {
        // `S-Left` is `ESC[1;2D` -- a report in every respect but the final
        // byte, and one of the six bindings the config depends on (§8.3).
        let (forward, reported) = filter(&[b"\x1b[1;2D"]);
        assert_eq!(reported, None);
        assert_eq!(forward, b"\x1b[1;2D");
    }

    #[test]
    fn ordinary_typing_is_forwarded_byte_for_byte() {
        let (forward, reported) = filter(&[b"ls -l\r"]);
        assert_eq!(reported, None);
        assert_eq!(forward, b"ls -l\r");
    }

    #[test]
    fn typing_around_the_answer_survives_it() {
        let (forward, reported) = filter(&[b"ab\x1b[24;80Rcd"]);
        assert_eq!(reported, Some((24, 80)));
        assert_eq!(forward, b"abcd");
    }

    #[test]
    fn nothing_is_held_back_once_the_answer_has_arrived() {
        // The buffering is a startup-window concession, not a permanent tax: a
        // lone `Esc` on its way to red in a pane must not be held.
        let mut probe = SizeProbe::awaiting();
        let mut forward = Vec::new();
        probe.filter(b"\x1b[30;90R", &mut forward);
        forward.clear();
        probe.filter(b"\x1b", &mut forward);
        assert_eq!(forward, b"\x1b");
    }

    #[test]
    fn releasing_hands_back_what_was_held_and_goes_on_listening() {
        // The console is asked on a clock (`client::SizeWatch`), so the two
        // halves come apart: the keystroke that might have been a report is let
        // go after a window, and the answer is still recognized whenever it
        // turns up -- which over a slow link is later than that window.
        let mut probe = SizeProbe::awaiting();
        let mut forward = Vec::new();
        probe.filter(b"\x1b[1", &mut forward);
        assert!(forward.is_empty(), "a possible report was not held");
        assert!(probe.holding());

        probe.release(&mut forward);
        assert_eq!(forward, b"\x1b[1");
        assert!(!probe.holding());

        forward.clear();
        assert_eq!(probe.filter(b"\x1b[30;90R", &mut forward), Some((30, 90)));
        assert!(forward.is_empty(), "a late report reached the pane");
    }

    #[test]
    fn a_probe_fired_again_expects_another_answer() {
        // One asking, one answer (`filter`) -- and the console is asked once a
        // second, because nothing says a window was dragged (§3.2).
        let mut probe = SizeProbe::awaiting();
        let mut forward = Vec::new();
        assert_eq!(probe.filter(b"\x1b[30;90R", &mut forward), Some((30, 90)));
        assert_eq!(probe.filter(b"\x1b[40;100R", &mut forward), None);
        forward.clear();

        probe.rearm();
        assert_eq!(probe.filter(b"\x1b[40;100R", &mut forward), Some((40, 100)));
        assert!(forward.is_empty());
    }

    #[test]
    fn a_probe_that_was_never_fired_holds_nothing_at_all() {
        let mut probe = SizeProbe::none();
        let mut forward = Vec::new();
        assert_eq!(probe.filter(b"\x1b[30;90R", &mut forward), None);
        assert_eq!(forward, b"\x1b[30;90R");
    }

    #[test]
    fn a_malformed_report_is_given_back_rather_than_swallowed() {
        let (forward, reported) = filter(&[b"\x1b[;R"]);
        assert_eq!(reported, None);
        assert_eq!(forward, b"\x1b[;R");
    }

    // ---- keys ----

    /// Decode `chunks` as successive reads, returning each key with the bytes
    /// it was made of.
    fn keys(chunks: &[&[u8]]) -> Vec<(Key, Vec<u8>)> {
        let mut decoder = Keys::new();
        let mut out = Vec::new();
        for chunk in chunks {
            decoder.feed(chunk, &mut |key, raw| out.push((key, raw.to_vec())));
        }
        decoder.flush(&mut |key, raw| out.push((key, raw.to_vec())));
        out
    }

    fn just_keys(chunks: &[&[u8]]) -> Vec<Key> {
        keys(chunks).into_iter().map(|(key, _)| key).collect()
    }

    #[test]
    fn a_control_byte_is_the_key_a_config_calls_it() {
        // `C-a` is the prefix this whole project is built around (§2.1), and
        // on the wire it is one byte.
        assert_eq!(just_keys(&[b"\x01"]), [Key::ctrl('a')]);
        assert_eq!(just_keys(&[b"\x03"]), [Key::ctrl('c')]);
        assert_eq!(just_keys(&[b"\r"]), [Key::plain(Code::Enter)]);
        assert_eq!(just_keys(&[b"\t"]), [Key::plain(Code::Tab)]);
        assert_eq!(just_keys(&[b"\x7f"]), [Key::plain(Code::Backspace)]);
        // And the one the arithmetic gets wrong: NUL is `C-Space`, the name
        // `Key::parse` gives it and the key emacs copy mode selects with.
        assert_eq!(just_keys(&[b"\x00"]), [Key::ctrl(' ')]);
        assert_eq!(Key::parse("C-Space"), Some(Key::ctrl(' ')));
    }

    #[test]
    fn the_measured_arrow_encodings_decode_to_the_keys_they_name() {
        // Straight off §8.3's table, which was measured on both of Motor's
        // terminals rather than assumed. These six are the bindings the config
        // depends on; if this test is wrong, S-Left silently types garbage.
        let cases: &[(&[u8], Key)] = &[
            (b"\x1b[D", Key::plain(Code::Left)),
            (b"\x1b[1;2D", Key::with(Code::Left, Key::SHIFT)),
            (b"\x1b[1;2C", Key::with(Code::Right, Key::SHIFT)),
            (b"\x1b[1;3D", Key::with(Code::Left, Key::ALT)),
            (b"\x1b[1;3C", Key::with(Code::Right, Key::ALT)),
            (b"\x1b[1;3A", Key::with(Code::Up, Key::ALT)),
            (b"\x1b[1;3B", Key::with(Code::Down, Key::ALT)),
            // The alternate spelling of `M-Left`, which arrives intact too.
            (b"\x1b\x1b[D", Key::with(Code::Left, Key::ALT)),
        ];
        for (bytes, key) in cases {
            assert_eq!(just_keys(&[bytes]), [*key], "{bytes:?}");
        }
    }

    #[test]
    fn a_key_split_across_reads_is_still_one_key() {
        // What the serial console actually does (§8.3).
        let whole = just_keys(&[b"\x1b[1;2D"]);
        assert_eq!(whole, [Key::with(Code::Left, Key::SHIFT)]);
        assert_eq!(just_keys(&[b"\x1b[", b"1;2D"]), whole);
        assert_eq!(just_keys(&[b"\x1b", b"[", b"1", b";", b"2", b"D"]), whole);
    }

    #[test]
    fn the_bytes_a_key_was_made_of_come_back_with_it() {
        // An unbound key is forwarded as it arrived (§8.1), so the decoder has
        // to hand back the bytes rather than expect anyone to re-encode one.
        let decoded = keys(&[b"\x1b[1;3A"]);
        assert_eq!(decoded[0].1, b"\x1b[1;3A");
        let decoded = keys(&[b"ab"]);
        assert_eq!(decoded[0].1, b"a");
        assert_eq!(decoded[1].1, b"b");
    }

    #[test]
    fn a_lone_escape_is_a_key_only_once_input_goes_quiet() {
        // Both halves matter: emitting it at once would turn every arrow key
        // into an Esc followed by junk, and holding it forever would strand
        // red in a pane.
        let mut decoder = Keys::new();
        let mut out = Vec::new();
        decoder.feed(b"\x1b", &mut |key, _| out.push(key));
        assert!(out.is_empty(), "{out:?}");
        decoder.flush(&mut |key, _| out.push(key));
        assert_eq!(out, [Key::plain(Code::Escape)]);
    }

    #[test]
    fn an_escape_that_turns_into_an_arrow_is_never_an_escape() {
        let mut decoder = Keys::new();
        let mut out = Vec::new();
        decoder.feed(b"\x1b", &mut |key, _| out.push(key));
        decoder.feed(b"[A", &mut |key, _| out.push(key));
        decoder.flush(&mut |key, _| out.push(key));
        assert_eq!(out, [Key::plain(Code::Up)]);
    }

    #[test]
    fn a_sequence_rmux_has_no_name_for_does_not_swallow_what_follows() {
        // The bytes still reach the pane (§8.1); what rmux cannot name simply
        // matches no binding.
        let decoded = just_keys(&[b"\x1b[?1;2c"]);
        assert_eq!(decoded[0], Key::plain(Code::Escape));
        assert!(decoded.len() > 1, "{decoded:?}");
    }

    #[test]
    fn a_character_is_a_character_whatever_its_width() {
        assert_eq!(just_keys(&[b"|"]), [Key::plain(Code::Char('|'))]);
        assert_eq!(just_keys(&["é".as_bytes()]), [Key::plain(Code::Char('é'))]);
        assert_eq!(
            just_keys(&[b"\xc3", b"\xa9"]),
            [Key::plain(Code::Char('é'))]
        );
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
