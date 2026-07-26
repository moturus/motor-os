//! The VT parser: bytes in, [`Action`]s out.
//!
//! There is no ANSI parser in this repo to reuse (details.md §5): rush's
//! `read_csi` recognizes *input* keys and knows nothing of SGR, and the closest
//! prior art is the CSI-subset emulator in rush's test file. So this is a
//! VTE-style state machine over the ECMA-48 byte ranges rush already gets right
//! (`rush/src/term.rs:186-207`): `0x30..=0x3f` parameters, `0x20..=0x2f`
//! intermediates, `0x40..=0x7e` final. `ESC[1;31m` is that grammar with a
//! different final byte from `ESC[1;5C`, which is why one machine covers both.
//!
//! **This module is pure**: no I/O, no grid, no allocation. That is the most
//! important structural decision in the emulator (§5.1) — it is what makes the
//! whole thing testable on Linux over byte slices, with no pty and no terminal,
//! the same trick that makes red's editor and rush's `read_key` testable.
//!
//! It is also **incremental**, because it has to be: on the serial console
//! sys-tty forwards one byte at a time, so a sequence arrives split at
//! unpredictable points (§8.3). No method here may assume a sequence lands in
//! one call.
//!
//! What the parser does *not* do is decide what a sequence means. An `Action`
//! is syntax — a final byte and its parameters — and `grid.rs` is where the
//! vocabulary of §5.2 is interpreted. Keeping the split there means an
//! unsupported sequence is a grid that ignores it, never a parser that
//! mis-frames the bytes after it.

/// Parameters past this are dropped; nothing rmux answers to has more.
const MAX_PARAMS: usize = 16;
/// ECMA-48 allows several intermediates; two is more than anything real uses.
const MAX_INTERMEDIATES: usize = 2;
/// An OSC string longer than this is truncated: a window title is short, and a
/// pane must not be able to grow rmux's memory by never sending a terminator.
const MAX_STRING: usize = 256;

/// One decoded step of the byte stream.
///
/// Borrowed from the parser rather than owned, so nothing here allocates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// A character to put in the grid.
    Print(char),
    /// A C0 control byte to act on: `\n`, `\r`, `\t`, `\x08`, `\x07`.
    C0(u8),
    /// `ESC [ ... final`.
    Csi(Csi<'a>),
    /// `ESC final`, with any intermediates: `ESC 7`, `ESC M`, `ESC ( B`.
    Esc {
        intermediates: &'a [u8],
        final_byte: u8,
    },
    /// An OSC string, terminated by BEL or ST and stripped of both.
    Osc(&'a [u8]),
}

/// A CSI sequence, split into the parts a consumer actually asks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Csi<'a> {
    /// Parameters as written, with an omitted one stored as 0 — which is what
    /// ECMA-48 means by it, and what `?25` in `ESC[?25h` is *not* (see
    /// [`Csi::private`]).
    pub params: &'a [u16],
    /// The private marker: `?` in `ESC[?25l`, `>` in `ESC[>c`.
    pub private: Option<u8>,
    pub intermediates: &'a [u8],
    pub final_byte: u8,
}

impl Csi<'_> {
    /// Parameter `i` as written, 0 when absent.
    ///
    /// For the parameters where 0 is a value of its own — SGR, where it means
    /// reset, and the erase and mode selectors, where it is one of the choices.
    pub fn raw(&self, i: usize) -> u16 {
        self.params.get(i).copied().unwrap_or(0)
    }

    /// Parameter `i` as a repeat count: absent or 0 both mean 1.
    ///
    /// ECMA-48's default for every "how many" parameter — `ESC[A`, `ESC[0A`
    /// and `ESC[1A` all move one row.
    pub fn count(&self, i: usize) -> u16 {
        match self.params.get(i) {
            Some(0) | None => 1,
            Some(n) => *n,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum State {
    #[default]
    Ground,
    Escape,
    EscapeIntermediate,
    CsiEntry,
    CsiParam,
    CsiIntermediate,
    /// A malformed CSI: consume to its final byte and dispatch nothing.
    CsiIgnore,
    Osc,
    /// A string rmux has no use for (DCS, APC, PM): swallowed whole.
    StringIgnore,
    /// An `ESC` inside a string, which is half of an ST terminator.
    StringEscape,
}

/// The parser. One per pane; feed it everything that pane writes.
pub struct Parser {
    state: State,
    params: [u16; MAX_PARAMS],
    num_params: usize,
    private: Option<u8>,
    intermediates: [u8; MAX_INTERMEDIATES],
    num_intermediates: usize,
    string: [u8; MAX_STRING],
    string_len: usize,
    /// Set when the string state should dispatch on its terminator.
    string_is_osc: bool,
    utf8: Utf8,
}

impl Default for Parser {
    fn default() -> Parser {
        Parser {
            state: State::Ground,
            params: [0; MAX_PARAMS],
            num_params: 0,
            private: None,
            intermediates: [0; MAX_INTERMEDIATES],
            num_intermediates: 0,
            string: [0; MAX_STRING],
            string_len: 0,
            string_is_osc: false,
            utf8: Utf8::default(),
        }
    }
}

impl Parser {
    pub fn new() -> Parser {
        Parser::default()
    }

    /// Feed `bytes`, calling `sink` once per decoded action.
    pub fn feed(&mut self, bytes: &[u8], sink: &mut impl FnMut(Action)) {
        for byte in bytes {
            self.byte(*byte, sink);
        }
    }

    fn byte(&mut self, byte: u8, sink: &mut impl FnMut(Action)) {
        match self.state {
            State::Ground => self.ground(byte, sink),
            State::Escape => self.escape(byte, sink),
            State::EscapeIntermediate => match byte {
                0x20..=0x2f => self.collect_intermediate(byte),
                0x30..=0x7e => {
                    sink(Action::Esc {
                        intermediates: &self.intermediates[..self.num_intermediates],
                        final_byte: byte,
                    });
                    self.state = State::Ground;
                }
                _ => self.control_or_restart(byte, sink),
            },
            State::CsiEntry | State::CsiParam => self.csi_param(byte, sink),
            State::CsiIntermediate => match byte {
                0x20..=0x2f => self.collect_intermediate(byte),
                0x30..=0x3f => self.state = State::CsiIgnore,
                0x40..=0x7e => self.dispatch_csi(byte, sink),
                _ => self.control_or_restart(byte, sink),
            },
            State::CsiIgnore => match byte {
                0x40..=0x7e => self.state = State::Ground,
                _ => self.control_or_restart(byte, sink),
            },
            State::Osc | State::StringIgnore => self.string(byte, sink),
            State::StringEscape => {
                // `ESC \` is ST and ends the string; anything else means the
                // string was never terminated and an escape sequence has begun.
                self.end_string(sink);
                if byte != b'\\' {
                    self.state = State::Escape;
                    self.escape(byte, sink);
                }
            }
        }
    }

    fn ground(&mut self, byte: u8, sink: &mut impl FnMut(Action)) {
        // A control byte cannot appear inside a character, so an unfinished one
        // is abandoned rather than left to absorb the next character's bytes.
        match byte {
            0x1b => {
                self.utf8.reset();
                self.begin_escape();
            }
            // DEL is not a control the grid acts on, and never a character.
            0x7f => self.utf8.reset(),
            0x00..=0x1f => {
                self.utf8.reset();
                sink(Action::C0(byte));
            }
            _ => self.utf8.feed(byte, &mut |c| sink(Action::Print(c))),
        }
    }

    fn escape(&mut self, byte: u8, sink: &mut impl FnMut(Action)) {
        match byte {
            b'[' => self.state = State::CsiEntry,
            b']' => self.begin_string(true),
            // DCS, SOS, PM, APC: strings with no meaning here (§5.2).
            b'P' | b'X' | b'^' | b'_' => self.begin_string(false),
            0x20..=0x2f => self.collect_intermediate(byte),
            0x30..=0x7e => {
                sink(Action::Esc {
                    intermediates: &[],
                    final_byte: byte,
                });
                self.state = State::Ground;
            }
            _ => self.control_or_restart(byte, sink),
        }
    }

    fn csi_param(&mut self, byte: u8, sink: &mut impl FnMut(Action)) {
        match byte {
            b'0'..=b'9' => {
                if self.num_params == 0 {
                    self.num_params = 1;
                }
                if let Some(slot) = self.params.get_mut(self.num_params - 1) {
                    *slot = slot.saturating_mul(10).saturating_add((byte - b'0') as u16);
                }
                self.state = State::CsiParam;
            }
            // `:` separates sub-parameters, which rmux's vocabulary has none
            // of; treating it as `;` keeps the sequence framed either way.
            //
            // A separator before any digit means the parameter it closes was
            // omitted, so `ESC[;5H` is two parameters, not one: the column must
            // not slide into the row's place.
            b';' | b':' => {
                self.num_params = if self.num_params == 0 {
                    2
                } else {
                    (self.num_params + 1).min(MAX_PARAMS)
                };
                self.state = State::CsiParam;
            }
            // A private marker is only a marker in the first position.
            0x3c..=0x3f if self.state == State::CsiEntry => {
                self.private = Some(byte);
                self.state = State::CsiParam;
            }
            0x3c..=0x3f => self.state = State::CsiIgnore,
            0x20..=0x2f => {
                self.collect_intermediate(byte);
                self.state = State::CsiIntermediate;
            }
            0x40..=0x7e => self.dispatch_csi(byte, sink),
            _ => self.control_or_restart(byte, sink),
        }
    }

    fn dispatch_csi(&mut self, final_byte: u8, sink: &mut impl FnMut(Action)) {
        sink(Action::Csi(Csi {
            params: &self.params[..self.num_params.min(MAX_PARAMS)],
            private: self.private,
            intermediates: &self.intermediates[..self.num_intermediates],
            final_byte,
        }));
        self.state = State::Ground;
    }

    /// A byte that is neither parameter, intermediate nor final.
    ///
    /// A control still acts — rush's instinct, that "a `^C` mid-escape is still
    /// a `^C`" (`term.rs:200-203`) — and an `ESC` starts over, because a
    /// half-arrived sequence must never eat the one that follows it.
    fn control_or_restart(&mut self, byte: u8, sink: &mut impl FnMut(Action)) {
        match byte {
            0x1b => self.begin_escape(),
            0x7f => {}
            0x00..=0x1f => sink(Action::C0(byte)),
            _ => self.state = State::Ground,
        }
    }

    fn begin_escape(&mut self) {
        self.state = State::Escape;
        self.params = [0; MAX_PARAMS];
        self.num_params = 0;
        self.private = None;
        self.num_intermediates = 0;
    }

    fn begin_string(&mut self, is_osc: bool) {
        self.state = if is_osc {
            State::Osc
        } else {
            State::StringIgnore
        };
        self.string_is_osc = is_osc;
        self.string_len = 0;
    }

    fn string(&mut self, byte: u8, sink: &mut impl FnMut(Action)) {
        match byte {
            0x07 => self.end_string(sink),
            0x1b => self.state = State::StringEscape,
            _ => {
                if let Some(slot) = self.string.get_mut(self.string_len) {
                    *slot = byte;
                    self.string_len += 1;
                }
            }
        }
    }

    fn end_string(&mut self, sink: &mut impl FnMut(Action)) {
        if self.string_is_osc {
            sink(Action::Osc(&self.string[..self.string_len]));
        }
        self.state = State::Ground;
    }

    fn collect_intermediate(&mut self, byte: u8) {
        if let Some(slot) = self.intermediates.get_mut(self.num_intermediates) {
            *slot = byte;
            self.num_intermediates += 1;
        }
        if self.state == State::Escape {
            self.state = State::EscapeIntermediate;
        }
    }
}

/// An incremental UTF-8 decoder.
///
/// Incremental for the same reason the parser is (§8.3): a multi-byte character
/// can arrive one byte per read. Malformed input yields U+FFFD and resynchronizes
/// on the offending byte rather than swallowing it, so a bad byte costs one
/// character rather than the rest of the line. rmux stores a `char` per cell and
/// treats every one as a single column (§1.2).
#[derive(Default)]
struct Utf8 {
    codepoint: u32,
    remaining: u8,
}

impl Utf8 {
    /// Feed one byte, emitting each character it completes.
    ///
    /// Emits twice when a truncated sequence is followed by a fresh
    /// single-byte one, which is why this takes a sink rather than returning.
    fn feed(&mut self, byte: u8, out: &mut impl FnMut(char)) {
        if self.remaining > 0 {
            if byte & 0xc0 == 0x80 {
                self.codepoint = (self.codepoint << 6) | (byte & 0x3f) as u32;
                self.remaining -= 1;
                if self.remaining == 0 {
                    out(char::from_u32(self.codepoint).unwrap_or(char::REPLACEMENT_CHARACTER));
                }
                return;
            }
            self.remaining = 0;
            out(char::REPLACEMENT_CHARACTER);
        }

        match byte {
            0x00..=0x7f => out(byte as char),
            0xc2..=0xdf => self.start(byte & 0x1f, 1),
            0xe0..=0xef => self.start(byte & 0x0f, 2),
            0xf0..=0xf4 => self.start(byte & 0x07, 3),
            _ => out(char::REPLACEMENT_CHARACTER),
        }
    }

    fn start(&mut self, bits: u8, remaining: u8) {
        self.codepoint = bits as u32;
        self.remaining = remaining;
    }

    fn reset(&mut self) {
        self.remaining = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An owned `Action`, so a test can compare against a literal.
    #[derive(Debug, PartialEq, Eq)]
    enum Owned {
        Print(char),
        C0(u8),
        Csi(Vec<u16>, Option<u8>, Vec<u8>, u8),
        Esc(Vec<u8>, u8),
        Osc(Vec<u8>),
    }

    /// Parse `chunks` as successive reads, which is how bytes really arrive.
    fn parse(chunks: &[&[u8]]) -> Vec<Owned> {
        let mut parser = Parser::new();
        let mut out = Vec::new();
        for chunk in chunks {
            parser.feed(chunk, &mut |action| {
                out.push(match action {
                    Action::Print(c) => Owned::Print(c),
                    Action::C0(b) => Owned::C0(b),
                    Action::Csi(csi) => Owned::Csi(
                        csi.params.to_vec(),
                        csi.private,
                        csi.intermediates.to_vec(),
                        csi.final_byte,
                    ),
                    Action::Esc {
                        intermediates,
                        final_byte,
                    } => Owned::Esc(intermediates.to_vec(), final_byte),
                    Action::Osc(s) => Owned::Osc(s.to_vec()),
                })
            });
        }
        out
    }

    fn csi(params: &[u16], final_byte: u8) -> Owned {
        Owned::Csi(params.to_vec(), None, Vec::new(), final_byte)
    }

    #[test]
    fn plain_text_is_printed_character_by_character() {
        assert_eq!(parse(&[b"hi"]), vec![Owned::Print('h'), Owned::Print('i')]);
    }

    #[test]
    fn a_control_byte_is_reported_rather_than_printed() {
        assert_eq!(
            parse(&[b"a\r\n\x07"]),
            vec![
                Owned::Print('a'),
                Owned::C0(b'\r'),
                Owned::C0(b'\n'),
                Owned::C0(0x07)
            ]
        );
    }

    #[test]
    fn a_csi_sequence_arrives_with_its_parameters() {
        assert_eq!(parse(&[b"\x1b[1;31m"]), vec![csi(&[1, 31], b'm')]);
    }

    #[test]
    fn an_omitted_parameter_is_the_ecma48_default() {
        // `ESC[A`, `ESC[0A` and `ESC[1A` all mean one row.
        let one_row = |bytes: &[u8]| match &parse(&[bytes])[..] {
            [Owned::Csi(params, _, _, b'A')] => {
                let csi = Csi {
                    params,
                    private: None,
                    intermediates: &[],
                    final_byte: b'A',
                };
                csi.count(0)
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(one_row(b"\x1b[A"), 1);
        assert_eq!(one_row(b"\x1b[0A"), 1);
        assert_eq!(one_row(b"\x1b[1A"), 1);
        assert_eq!(one_row(b"\x1b[9A"), 9);
    }

    #[test]
    fn an_omitted_parameter_in_the_middle_keeps_its_position() {
        // `ESC[;5H` is row default, column 5 -- not column 5 in position zero.
        assert_eq!(parse(&[b"\x1b[;5H"]), vec![csi(&[0, 5], b'H')]);
    }

    #[test]
    fn a_private_marker_is_kept_apart_from_the_parameters() {
        assert_eq!(
            parse(&[b"\x1b[?25l"]),
            vec![Owned::Csi(vec![25], Some(b'?'), Vec::new(), b'l')]
        );
    }

    #[test]
    fn a_sequence_split_across_reads_is_still_one_sequence() {
        // What the serial console actually does (§8.3): sys-tty forwards a byte
        // at a time, so the split point is unpredictable.
        let whole = parse(&[b"\x1b[1;2D"]);
        assert_eq!(whole, vec![csi(&[1, 2], b'D')]);
        assert_eq!(parse(&[b"\x1b[", b"1;2D"]), whole);
        assert_eq!(parse(&[b"\x1b", b"[1", b";", b"2", b"D"]), whole);
    }

    #[test]
    fn a_control_byte_inside_a_sequence_still_acts() {
        // rush's instinct, from the other side of the wire: a `^C` mid-escape
        // is still a `^C`, and the sequence around it still completes.
        assert_eq!(
            parse(&[b"\x1b[1\x03;2D"]),
            vec![Owned::C0(3), csi(&[1, 2], b'D')]
        );
    }

    #[test]
    fn an_escape_abandons_a_half_finished_sequence() {
        // A sequence that never arrives must not eat the one that follows.
        assert_eq!(parse(&[b"\x1b[12;\x1b[2J"]), vec![csi(&[2], b'J')]);
    }

    #[test]
    fn an_escape_sequence_carries_its_intermediates() {
        assert_eq!(parse(&[b"\x1b7"]), vec![Owned::Esc(Vec::new(), b'7')]);
        assert_eq!(parse(&[b"\x1b(B"]), vec![Owned::Esc(vec![b'('], b'B')]);
    }

    #[test]
    fn an_osc_string_ends_at_bel_or_at_st() {
        assert_eq!(
            parse(&[b"\x1b]0;title\x07"]),
            vec![Owned::Osc(b"0;title".to_vec())]
        );
        assert_eq!(
            parse(&[b"\x1b]2;title\x1b\\"]),
            vec![Owned::Osc(b"2;title".to_vec())]
        );
    }

    #[test]
    fn an_unterminated_osc_string_does_not_swallow_what_follows() {
        assert_eq!(
            parse(&[b"\x1b]0;title\x1b[2J"]),
            vec![Owned::Osc(b"0;title".to_vec()), csi(&[2], b'J')]
        );
    }

    #[test]
    fn a_string_rmux_has_no_use_for_is_swallowed_whole() {
        // DCS: the payload must not reach the grid as text.
        assert_eq!(
            parse(&[b"\x1bP1;2q#0\x1b\\ok"]),
            vec![Owned::Print('o'), Owned::Print('k')]
        );
    }

    #[test]
    fn utf8_is_decoded_however_it_is_split() {
        assert_eq!(parse(&[b"\xc3\xa9"]), vec![Owned::Print('é')]);
        assert_eq!(parse(&[b"\xc3", b"\xa9"]), vec![Owned::Print('é')]);
        assert_eq!(parse(&[b"\xe2", b"\x86", b"\x92"]), vec![Owned::Print('→')]);
    }

    #[test]
    fn a_malformed_utf8_byte_costs_one_character_not_the_rest() {
        assert_eq!(
            parse(&[b"\xc3ab"]),
            vec![
                Owned::Print(char::REPLACEMENT_CHARACTER),
                Owned::Print('a'),
                Owned::Print('b')
            ]
        );
    }

    #[test]
    fn a_control_byte_abandons_an_unfinished_character() {
        // `\xe2\x86` is two thirds of an arrow. The `\r` cannot belong to it,
        // and must not leave the decoder waiting to eat what follows.
        assert_eq!(
            parse(&[b"\xe2\x86\ra"]),
            vec![Owned::C0(b'\r'), Owned::Print('a')]
        );
    }

    #[test]
    fn more_parameters_than_rmux_keeps_do_not_run_off_the_end() {
        let many = b"\x1b[1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18;19;20m";
        match &parse(&[many])[..] {
            [Owned::Csi(params, _, _, b'm')] => assert_eq!(params.len(), MAX_PARAMS),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_oversized_string_is_truncated_rather_than_kept() {
        let mut bytes = b"\x1b]0;".to_vec();
        bytes.extend(std::iter::repeat_n(b'x', MAX_STRING * 2));
        bytes.push(0x07);
        match &parse(&[&bytes])[..] {
            [Owned::Osc(s)] => assert_eq!(s.len(), MAX_STRING),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_parameter_too_large_to_hold_saturates_rather_than_wraps() {
        // `ESC[9999999H` is red's own probe with a digit too many; it must not
        // come out as a small number (§3.2).
        match &parse(&[b"\x1b[99999999H"])[..] {
            [Owned::Csi(params, _, _, b'H')] => assert_eq!(params[0], u16::MAX),
            other => panic!("{other:?}"),
        }
    }
}
