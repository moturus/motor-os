//! The interactive line editor.
//!
//! Everything here is driven by **ANSI escape sequences over an always-raw
//! console**, per the contract in [`crate::sys`]: Motor OS has no termios, so
//! there is no cooked mode to fall back on and no terminal driver doing the
//! editing, the echo, or the `^C`. The editor owns all of it.
//!
//! # Rendering
//!
//! The screen is painted from a single model — prompt + line + cursor — by
//! [`Term::render`], which is the only function that moves the cursor. It
//! remembers the paint it last made ([`Painted`]) and writes only the difference
//! against it: a character typed at the end of a line costs the one byte that
//! character is, and an edit in the middle costs the tail after it. Nothing is
//! erased that is only going to be drawn again — which is what repainting a
//! whole line per keystroke does, and why it flickers on a console slow enough
//! to show you the blank before the text lands back on it.
//!
//! When the difference cannot be reasoned about — the first paint of a line, a
//! changed prompt or width, a screen someone else has written on — the fallback
//! is a full repaint, the way linenoise's multi-line refresh works: erase the
//! rows the last paint used, draw the text, step the cursor back to where it
//! belongs. Both paths place characters through [`layout`] and [`cell_at`], so
//! they agree on where the terminal puts things; that agreement is what lets a
//! partial paint land exactly where a full one would have.
//!
//! The one thing the model needs from outside is the terminal's width, and it is
//! obtained without ever *waiting* on the terminal (see [`Term::probe_width`]):
//! a blocking `ESC[6n` round-trip would hang the shell on any console that does
//! not answer, which is exactly what the boot console can be.
//!
//! # What the editor deliberately does not do
//!
//! No termios, no `SIGWINCH`, no terminfo: a resize is noticed at the next
//! prompt (the width probe rides along with it), and the escape sequences are
//! the plain ANSI ones every terminal understands.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::Mutex;

use crate::complete::{self, Quote};
use crate::history::History;
use crate::shell::Shell;
use crate::sys::{NoopTerm, TermImpl, TerminalBackend};

/// The width assumed when nothing can tell us better. The classic terminal.
const DEFAULT_COLS: usize = 80;

/// How many completions are listed without asking first, so that a stray Tab in
/// `/bin` does not dump hundreds of names down a slow console.
const MAX_UNASKED_CANDIDATES: usize = 100;

// ---- keys ------------------------------------------------------------------

/// A key press, decoded from the raw byte stream.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Key {
    Char(char),
    /// `^A`…`^Z`, as the lowercase letter.
    Ctrl(char),
    /// `ESC` followed by a character (`Alt`/`Meta`). `Alt('\x7f')` is
    /// Alt-Backspace.
    Alt(char),
    Enter,
    Tab,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    /// Ctrl/Alt + Left/Right: move by a word.
    WordLeft,
    WordRight,
    /// A cursor-position report, `ESC[<row>;<col>R` — the terminal answering
    /// [`Term::probe_width`].
    CursorReport(usize, usize),
    /// The input stream ended.
    Eof,
    /// Something unrecognized; the editor beeps rather than inserting garbage.
    Unknown,
}

/// A source of input bytes, with pushback. Decoding is written against this
/// rather than against stdin so it can be unit-tested over a byte slice.
trait Bytes {
    /// The next byte, or `None` at end of input.
    fn get(&mut self) -> Option<u8>;
    /// Return a byte to the front of the stream.
    fn unget(&mut self, b: u8);
}

/// Decode one key. Blocks until a key is complete; there are no timeouts, so a
/// bare `ESC` is only seen once the next byte arrives (as in every editor
/// without a timer, and unlike readline's 0.5 s escape delay).
///
/// `after_cr` carries one bit of state between calls: whether the last byte was
/// a CR, so that the LF of a CRLF can be recognised as the rest of that Enter
/// rather than another one. **Motor's console sends CRLF for one keypress**, so
/// taking both halves as Enter runs the typed line and then a blank line after
/// it — two prompts for one press of the key. The LF cannot be peeked for
/// instead: that would mean waiting on a terminal that may only ever send the
/// CR, and this editor never waits on the terminal. So the LF is dropped when
/// it turns up, however much later that is — and it can be much later, since the
/// CR's Enter runs a command first, and the LF is not read until the next prompt.
fn read_key<B: Bytes>(src: &mut B, after_cr: &mut bool) -> Key {
    let b = loop {
        let Some(b) = src.get() else {
            return Key::Eof;
        };
        let was_cr = std::mem::replace(after_cr, b == b'\r');
        if b == b'\n' && was_cr {
            continue; // the second half of a CRLF; the Enter is already reported
        }
        break b;
    };
    match b {
        0x1b => read_escape(src),
        b'\r' | b'\n' => Key::Enter,
        b'\t' => Key::Tab,
        // Both, because terminals disagree about which one Backspace sends and
        // there is no termios `erase` setting to consult.
        0x08 | 0x7f => Key::Backspace,
        0x01..=0x1a => Key::Ctrl((b + b'a' - 1) as char),
        0x20..=0x7e => Key::Char(b as char),
        0x80.. => read_utf8(src, b),
        _ => Key::Unknown,
    }
}

/// A byte ≥ 0x80 begins a UTF-8 sequence: assemble it into one `char`.
fn read_utf8<B: Bytes>(src: &mut B, first: u8) -> Key {
    let len = match first {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        // A continuation byte with no lead, or an overlong/invalid lead.
        _ => return Key::Unknown,
    };
    let mut buf = [first, 0, 0, 0];
    for slot in buf.iter_mut().take(len).skip(1) {
        match src.get() {
            Some(b) if (0x80..=0xbf).contains(&b) => *slot = b,
            // Not a continuation: this byte begins something else, so give it
            // back rather than eating the next key along with the bad one.
            Some(b) => {
                src.unget(b);
                return Key::Unknown;
            }
            None => return Key::Unknown,
        }
    }
    match std::str::from_utf8(&buf[..len]) {
        Ok(s) => Key::Char(s.chars().next().unwrap()),
        Err(_) => Key::Unknown,
    }
}

fn read_escape<B: Bytes>(src: &mut B) -> Key {
    let Some(b) = src.get() else {
        return Key::Unknown;
    };
    match b {
        b'[' => read_csi(src),
        // SS3: what a terminal in "application cursor keys" mode sends instead
        // of CSI — the arrows and Home/End of many terminals, including some
        // that only do it when full-screen programs have been running.
        b'O' => match src.get() {
            Some(b'A') => Key::Up,
            Some(b'B') => Key::Down,
            Some(b'C') => Key::Right,
            Some(b'D') => Key::Left,
            Some(b'H') => Key::Home,
            Some(b'F') => Key::End,
            _ => Key::Unknown,
        },
        0x08 | 0x7f => Key::Alt('\x7f'),
        0x20..=0x7e => Key::Alt(b as char),
        _ => Key::Unknown,
    }
}

/// Read the rest of a CSI (`ESC[…`) sequence: parameter bytes, optional
/// intermediates, then a final byte in `@`–`~` (ECMA-48 §5.4).
fn read_csi<B: Bytes>(src: &mut B) -> Key {
    let mut params = String::new();
    loop {
        let Some(b) = src.get() else {
            return Key::Unknown;
        };
        match b {
            0x30..=0x3f => params.push(b as char),
            // Intermediate bytes carry no meaning for the keys we know.
            0x20..=0x2f => {}
            0x40..=0x7e => return finish_csi(&params, b as char),
            // A control byte inside a sequence: the sequence is broken. Hand the
            // byte back so a `^C` mid-escape is still a `^C`.
            _ => {
                src.unget(b);
                return Key::Unknown;
            }
        }
    }
}

fn finish_csi(params: &str, final_byte: char) -> Key {
    let parts: Vec<&str> = params.split(';').collect();
    let num = |i: usize| -> usize { parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0) };
    // `ESC[1;5C` = Ctrl-Right, `ESC[1;3C` = Alt-Right: 5 is Ctrl, 3 is Alt.
    let by_word = matches!(parts.get(1).and_then(|s| s.parse::<u32>().ok()), Some(3 | 5));
    match final_byte {
        'A' => Key::Up,
        'B' => Key::Down,
        'C' => {
            if by_word {
                Key::WordRight
            } else {
                Key::Right
            }
        }
        'D' => {
            if by_word {
                Key::WordLeft
            } else {
                Key::Left
            }
        }
        'H' => Key::Home,
        'F' => Key::End,
        'R' => Key::CursorReport(num(0), num(1)),
        '~' => match num(0) {
            1 | 7 => Key::Home,
            4 | 8 => Key::End,
            3 => Key::Delete,
            _ => Key::Unknown,
        },
        _ => Key::Unknown,
    }
}

// ---- display width ---------------------------------------------------------

/// How many columns `c` occupies.
///
/// An approximation of Unicode's East Asian Width, hand-rolled because the
/// charter says no dependencies for what the shell can do itself: the wide
/// (W/F) blocks count 2, combining marks and other zero-width characters count
/// 0, everything else counts 1. It is not a full `wcwidth` — the tables are the
/// major blocks, not every last codepoint — and where it is wrong the cost is
/// cosmetic (the cursor lands a column off on a line mixing scripts), never
/// data loss.
fn char_width(c: char) -> usize {
    let cp = c as u32;
    if cp == 0 || c.is_control() {
        return 0;
    }
    if is_zero_width(cp) {
        return 0;
    }
    if is_wide(cp) { 2 } else { 1 }
}

/// Combining marks, joiners, and variation selectors: they render onto the
/// previous character and advance the cursor not at all.
fn is_zero_width(cp: u32) -> bool {
    matches!(cp,
        0x0300..=0x036f      // combining diacritical marks
        | 0x0483..=0x0489
        | 0x0591..=0x05bd | 0x05bf | 0x05c1..=0x05c2 | 0x05c4..=0x05c5 | 0x05c7
        | 0x0610..=0x061a | 0x064b..=0x065f | 0x0670
        | 0x06d6..=0x06dc | 0x06df..=0x06e4 | 0x06e7..=0x06e8 | 0x06ea..=0x06ed
        | 0x0711 | 0x0730..=0x074a | 0x07a6..=0x07b0 | 0x07eb..=0x07f3
        | 0x0816..=0x0819 | 0x081b..=0x0823 | 0x0825..=0x0827 | 0x0829..=0x082d
        | 0x0900..=0x0902 | 0x093a | 0x093c | 0x0941..=0x0948 | 0x094d
        | 0x0951..=0x0957 | 0x0962..=0x0963
        | 0x0e31 | 0x0e34..=0x0e3a | 0x0e47..=0x0e4e
        | 0x1ab0..=0x1aff    // combining diacritical marks extended
        | 0x1dc0..=0x1dff    // combining diacritical marks supplement
        | 0x200b..=0x200f    // zero-width space/joiners, directional marks
        | 0x20d0..=0x20f0    // combining marks for symbols
        | 0xfe00..=0xfe0f    // variation selectors
        | 0xfe20..=0xfe2f    // combining half marks
        | 0xfeff             // BOM / zero-width no-break space
        | 0xe0100..=0xe01ef  // variation selectors supplement
    )
}

/// The East Asian Wide and Fullwidth blocks, plus emoji: two columns each.
fn is_wide(cp: u32) -> bool {
    matches!(cp,
        0x1100..=0x115f      // Hangul Jamo initial consonants
        | 0x2e80..=0x303e    // CJK radicals … CJK symbols (not 0x303f)
        | 0x3041..=0x33ff    // kana, Bopomofo, Hangul compat, CJK compat
        | 0x3400..=0x4dbf    // CJK extension A
        | 0x4e00..=0x9fff    // CJK unified ideographs
        | 0xa000..=0xa4cf    // Yi
        | 0xa960..=0xa97f    // Hangul Jamo extended-A
        | 0xac00..=0xd7a3    // Hangul syllables
        | 0xf900..=0xfaff    // CJK compatibility ideographs
        | 0xfe10..=0xfe19    // vertical forms
        | 0xfe30..=0xfe6f    // CJK compatibility forms
        | 0xff00..=0xff60    // fullwidth forms
        | 0xffe0..=0xffe6    // fullwidth signs
        | 0x1f300..=0x1f64f  // emoji: symbols/pictographs, emoticons
        | 0x1f900..=0x1f9ff  // supplemental symbols and pictographs
        | 0x20000..=0x2fffd  // CJK extension B…
        | 0x30000..=0x3fffd
    )
}

/// The printable width of an already-drawn prompt: escape sequences move no
/// cursor, so they must not count toward the column the input starts at.
/// Handles the CSI (`ESC[` … final byte) and OSC (`ESC]` … BEL/ST) forms a
/// prompt can plausibly carry — including rush's own colored default `PS1`.
fn display_width(s: &str) -> usize {
    let mut width = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            width += char_width(c);
            continue;
        }
        match chars.next() {
            // CSI: parameter/intermediate bytes, then a final byte in @-~.
            Some('[') => {
                for f in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&f) {
                        break;
                    }
                }
            }
            // OSC: a string terminated by BEL or ESC \.
            Some(']') => {
                while let Some(f) = chars.next() {
                    if f == '\x07' {
                        break;
                    }
                    if f == '\x1b' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            // A two-character escape (or a stray ESC at the end): consumed.
            _ => {}
        }
    }
    width
}

/// A prompt as drawn, with the display width the cursor math needs.
struct Prompt {
    text: String,
    width: usize,
}

impl Prompt {
    fn new(text: &str) -> Self {
        Self {
            width: display_width(text),
            text: text.to_string(),
        }
    }
}

// ---- layout ----------------------------------------------------------------

/// Where prompt + line put things on a terminal `cols` wide.
#[derive(Debug, PartialEq, Eq)]
struct Layout {
    /// Rows the whole rendering occupies.
    rows: usize,
    /// Row and column of the cursor, 0-based, within the rendering.
    crow: usize,
    ccol: usize,
    /// Whether the text ends exactly at the right edge. Such a line leaves the
    /// terminal's cursor in an ambiguous place (autowrap is *pending*: the
    /// cursor is still on the last column until one more character arrives), so
    /// the renderer writes a newline to force the issue.
    wrapped_end: bool,
}

/// Walk prompt + line and place every character, wrapping when the next one
/// does not fit.
///
/// This models what the terminal does rather than dividing by `cols`, because a
/// double-width character that does not fit is pushed whole onto the next row —
/// terminals do not split one down the middle.
fn layout(plen: usize, line: &[char], pos: usize, cols: usize) -> Layout {
    let cols = cols.max(1);
    // A prompt wider than the terminal wraps like anything else.
    let mut row = plen / cols;
    let mut col = plen % cols;

    for c in line {
        let w = char_width(*c);
        if col + w > cols {
            row += 1;
            col = 0;
        }
        col += w;
    }
    let wrapped_end = col >= cols;
    // The cursor goes in the cell the character at `pos` occupies — the same
    // question [`cell_at`] answers for a repaint, and the same answer, so that
    // the two never place one character in two different cells.
    let (crow, ccol) = cell_at(plen, line, pos, cols);
    Layout {
        rows: row + 1 + usize::from(wrapped_end),
        crow,
        ccol,
        wrapped_end,
    }
}

/// The cell the character at `i` is drawn in — or, for `i == line.len()`, the
/// one the next character would land in.
///
/// This is the question a partial repaint asks and [`layout`] does not answer:
/// *where do I start writing*. It walks the same terminal [`layout`] models,
/// including the rule that a character which does not fit is pushed whole onto
/// the next row, so a repaint that starts here lands in the cell a full one
/// would have put that character in.
fn cell_at(plen: usize, line: &[char], i: usize, cols: usize) -> (usize, usize) {
    let cols = cols.max(1);
    let mut row = plen / cols;
    let mut col = plen % cols;
    for c in &line[..i.min(line.len())] {
        let w = char_width(*c);
        if col + w > cols {
            row += 1;
            col = 0;
        }
        col += w;
    }
    // Take a pending wrap now instead of leaving it to the terminal: the caller
    // wants the cell the character really occupies. Past the end of the line,
    // ask where a one-column character would go — that is where the cursor sits.
    let w = line.get(i).map_or(1, |c| char_width(*c).max(1));
    if col + w > cols {
        row += 1;
        col = 0;
    }
    (row, col)
}

/// Move the cursor between two cells of the paint, and say whether that took any
/// bytes at all.
///
/// The motion is relative, because the editor knows exactly where it left the
/// cursor. Absolute motion would need the row on the *screen*, which it can only
/// learn by asking the terminal — the one thing it must never wait to do (see
/// [`Term::probe_width`]).
fn move_cursor(buf: &mut String, from: (usize, usize), to: (usize, usize)) -> bool {
    if to.0 < from.0 {
        buf.push_str(&format!("\x1b[{}A", from.0 - to.0));
    } else if to.0 > from.0 {
        buf.push_str(&format!("\x1b[{}B", to.0 - from.0));
    }
    // A vertical move keeps the column, so the column is settled on its own.
    if to.1 != from.1 {
        if to.1 == 0 {
            buf.push('\r'); // one byte, where the escape sequence is four
        } else if to.1 > from.1 {
            buf.push_str(&format!("\x1b[{}C", to.1 - from.1));
        } else {
            buf.push_str(&format!("\x1b[{}D", from.1 - to.1));
        }
    }
    from != to
}

// ---- word motion -----------------------------------------------------------

/// The start of the word before `pos`, by readline's `M-b` rule: skip
/// non-alphanumerics, then the alphanumeric run.
fn word_start(line: &[char], pos: usize) -> usize {
    let mut i = pos;
    while i > 0 && !line[i - 1].is_alphanumeric() {
        i -= 1;
    }
    while i > 0 && line[i - 1].is_alphanumeric() {
        i -= 1;
    }
    i
}

/// The end of the word after `pos`, by readline's `M-f` rule.
fn word_end(line: &[char], pos: usize) -> usize {
    let mut i = pos;
    while i < line.len() && !line[i].is_alphanumeric() {
        i += 1;
    }
    while i < line.len() && line[i].is_alphanumeric() {
        i += 1;
    }
    i
}

/// The start of the whitespace-delimited word before `pos` — what `^W` kills.
/// (readline's `unix-word-rubout`: shell words, so `/usr/bin/ls` goes whole.)
fn ws_word_start(line: &[char], pos: usize) -> usize {
    let mut i = pos;
    while i > 0 && line[i - 1].is_whitespace() {
        i -= 1;
    }
    while i > 0 && !line[i - 1].is_whitespace() {
        i -= 1;
    }
    i
}

// ---- the editor ------------------------------------------------------------

/// What one pass of the line editor produced.
enum ReadOutcome {
    Line(String),
    /// `^C`: the line (and any command it was continuing) is abandoned.
    Interrupted,
    /// End of input: `^D` on an empty line, or the input stream closing.
    Eof,
    /// Nothing to hand back yet — an empty line, or one the editor handled
    /// itself — so read another.
    Again,
}

/// Input bytes from stdin, buffered so a partially-read escape sequence can be
/// put back.
struct Stdin {
    pending: VecDeque<u8>,
    eof: bool,
}

impl Stdin {
    fn new() -> Self {
        Self {
            pending: VecDeque::new(),
            eof: false,
        }
    }
}

impl Bytes for Stdin {
    fn get(&mut self) -> Option<u8> {
        if let Some(b) = self.pending.pop_front() {
            return Some(b);
        }
        if self.eof {
            return None;
        }
        let mut buf = [0_u8; 64];
        match std::io::stdin().read(&mut buf) {
            Ok(0) => {
                // A closed stdin stays closed: remember it, so that a shell
                // whose input went away exits instead of spinning on EOF.
                self.eof = true;
                None
            }
            Ok(n) => {
                self.pending.extend(&buf[1..n]);
                Some(buf[0])
            }
            // A read error is as final as EOF, and the shell is about to be told
            // so by the same `None`.
            Err(_) => {
                self.eof = true;
                None
            }
        }
    }

    fn unget(&mut self, b: u8) {
        self.pending.push_front(b);
    }
}

/// What the last [`Term::render`] left on the screen.
///
/// This is the editor's memory of the terminal: it is what lets the next paint
/// write only the cells that change, and erase exactly the ones the last paint
/// drew. `None` means the screen is not ours to reason about (see
/// [`Term::reset_screen`]) and the next paint must be a full one.
struct Painted {
    prompt: String,
    line: Vec<char>,
    /// The width it was laid out for. A different one moves every cell.
    cols: usize,
    /// Rows it occupies, and where among them the cursor was left.
    rows: usize,
    crow: usize,
    ccol: usize,
}

struct Term {
    input: Stdin,
    term_impl: Box<dyn TermImpl>,
    history: History,

    /// The screen, as this editor last painted it.
    painted: Option<Painted>,

    /// Whether the last byte read was a CR — see [`read_key`]. It outlives a
    /// single `readline`, because the two halves of the CRLF that one Enter
    /// sends are read either side of the command it ran.
    after_cr: bool,

    /// A width learned from the terminal's answer to [`Term::probe_width`].
    probed_cols: Option<usize>,
    /// `$COLUMNS`, sampled at the start of each line.
    shell_cols: Option<usize>,
    /// Whether there is no terminal at all (`--piped`).
    piped: bool,

    /// The text `^K`/`^U`/`^W` cut and `^Y` pastes back.
    kill_ring: Vec<char>,
}

impl Term {
    fn new(piped: bool) -> Self {
        Self {
            input: Stdin::new(),
            term_impl: if piped {
                Box::new(NoopTerm::new())
            } else {
                Box::new(TerminalBackend::new())
            },
            history: History::new(),
            painted: None,
            after_cr: false,
            probed_cols: None,
            shell_cols: None,
            piped,
            kill_ring: Vec::new(),
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut stdout = std::io::stdout().lock();
        // Nowhere to report a failed write to but the very stream that failed;
        // the next read will end the session anyway.
        let _ = stdout.write_all(bytes);
        let _ = stdout.flush();
    }

    fn beep(&mut self) {
        self.write(&[7]);
    }

    /// The terminal's width, from the best source that has one.
    fn cols(&mut self) -> usize {
        if let Some(w) = self.term_impl.width().filter(|w| *w > 0) {
            return w;
        }
        if let Some(w) = self.shell_cols {
            return w;
        }
        self.probed_cols.unwrap_or(DEFAULT_COLS)
    }

    /// Ask the terminal how wide it is — **without waiting for the answer**.
    ///
    /// `ESC[999C` walks the cursor as far right as it goes (terminals clamp at
    /// the last column) and `ESC[6n` asks where that was; the reply arrives on
    /// stdin as an ordinary [`Key::CursorReport`] whenever it turns up, and the
    /// editor simply repaints if it changed the width. Nothing ever blocks on
    /// it, which is the whole point: a console that never answers — a serial log
    /// with no terminal on the other end, say — costs 12 invisible bytes and
    /// keeps the default width, where a blocking round-trip would hang the shell
    /// at its first prompt.
    ///
    /// Skipped entirely when the platform can just say (the Unix host's ioctl)
    /// or when there is no terminal to ask (`--piped`).
    fn probe_width(&mut self) {
        if self.piped || self.term_impl.width().is_some() {
            return;
        }
        // Hidden: `ESC[999C` throws the cursor at the right-hand edge of the
        // screen and `\r` drags it back, once per prompt. Nobody needs to watch
        // that happen.
        self.write(b"\x1b[?25l\r\x1b[999C\x1b[6n\r\x1b[?25h");
    }

    /// Paint prompt + line and leave the cursor at `pos`.
    fn render(&mut self, prompt: &Prompt, line: &[char], pos: usize) {
        let cols = self.cols();
        let lay = layout(prompt.width, line, pos, cols);
        let prev = self.painted.take();

        match &prev {
            // The screen is still the one we painted, laid out the same way, so
            // most of what is wanted is already on it.
            Some(p) if p.cols == cols && p.prompt == prompt.text => {
                self.render_diff(p, prompt, line, &lay)
            }
            // A changed prompt or width moves every cell after it, and a screen
            // we did not paint tells us nothing: draw the whole line.
            _ => self.render_full(prev.as_ref(), prompt, line, &lay, cols),
        }

        self.painted = Some(Painted {
            prompt: prompt.text.clone(),
            line: line.to_vec(),
            cols,
            rows: lay.rows,
            crow: lay.crow,
            ccol: lay.ccol,
        });
    }

    /// Draw only what the last paint got wrong: the tail from the first
    /// character that changed, and whatever the old line left on the screen past
    /// the end of the new one.
    fn render_diff(&mut self, prev: &Painted, prompt: &Prompt, line: &[char], lay: &Layout) {
        let (plen, cols) = (prompt.width, prev.cols);
        // Everything before the first character that differs is already on the
        // screen, in the cells it belongs in — the prompt and the width have not
        // moved, so nothing before the change can have moved either.
        let k = prev.line.iter().zip(line).take_while(|(a, b)| a == b).count();

        let mut buf = String::new();
        let mut at = (prev.crow, prev.ccol);
        // Whether the cursor is going to visit cells it does not stay in — the
        // only thing hiding it is for.
        let mut travels = false;

        let redrawn = k < line.len() || k < prev.line.len();
        if redrawn {
            travels |= move_cursor(&mut buf, at, cell_at(plen, line, k, cols));
            buf.extend(line[k..].iter());
            at = cell_at(plen, line, line.len(), cols);
            if k < line.len() && lay.wrapped_end {
                // As a full paint does: take the pending wrap now, while we
                // still know where the cursor is. (Nothing was written when
                // `k == line.len()`, so there is no wrap pending to take: the
                // cursor was *moved* to `at`, which is already past it.)
                buf.push_str("\n\r");
            }
            // The old line reached further than the new one — erase the rest of
            // it, or it stays on the screen as a ghost.
            let was = cell_at(plen, &prev.line, prev.line.len(), cols);
            if was > at {
                buf.push_str("\x1b[0K");
                for _ in at.0..was.0 {
                    buf.push_str("\x1b[1B\r\x1b[0K");
                }
                if was.0 > at.0 {
                    at = (was.0, 0);
                }
                travels = true;
            }
        }
        let back = move_cursor(&mut buf, at, (lay.crow, lay.ccol));

        // Hiding the cursor is worth its twelve bytes only when the cursor is
        // going somewhere it will not stay. A paint that *only* moves the cursor
        // has nothing to hide — moving is the whole of what the user asked for —
        // and one echoed character leaves it exactly where it belongs.
        if travels || (redrawn && back) {
            self.write(format!("\x1b[?25l{buf}\x1b[?25h").as_bytes());
        } else {
            self.write(buf.as_bytes());
        }
    }

    /// Erase the rows the last paint used and draw prompt + line from scratch.
    fn render_full(
        &mut self,
        prev: Option<&Painted>,
        prompt: &Prompt,
        line: &[char],
        lay: &Layout,
        cols: usize,
    ) {
        // With no memory of the screen, the cursor is at column 0 of a row that
        // is ours to take: erase that row and nothing else. That is the contract
        // every `reset_screen` caller leaves behind.
        let (rows, crow) = prev.map_or((1, 0), |p| (p.rows, p.crow));
        let mut buf = String::new();

        buf.push_str("\x1b[?25l"); // hide the cursor: one flicker-free paint
        // Down to the last row of the *previous* paint, then erase upward.
        if rows > crow + 1 {
            buf.push_str(&format!("\x1b[{}B", rows - crow - 1));
        }
        for _ in 1..rows {
            buf.push_str("\r\x1b[0K\x1b[1A");
        }
        buf.push_str("\r\x1b[0K");

        buf.push_str(&prompt.text);
        buf.extend(line.iter());
        if lay.wrapped_end {
            // Force the pending wrap, so the cursor's row is unambiguous (and
            // the terminal scrolls now, while we still know where we are).
            buf.push_str("\n\r");
        }
        // The cursor is at the end of the text; walk it back to `pos`.
        let end = cell_at(prompt.width, line, line.len(), cols);
        move_cursor(&mut buf, end, (lay.crow, lay.ccol));
        buf.push_str("\x1b[?25h");

        self.write(buf.as_bytes());
    }

    /// Start painting afresh at the cursor's current row, forgetting the screen
    /// the last paint left. Used before the first paint of a line, and after
    /// anything that scrolled or cleared the terminal behind the editor's back
    /// (a completion listing, `^L`).
    ///
    /// Callers must leave the cursor at column 0 of a row the next paint may
    /// have: it takes that row over and erases it.
    fn reset_screen(&mut self) {
        self.painted = None;
    }

    /// Get to column 0 without destroying a last line of output that had no
    /// trailing newline (`printf hi`, or a file that does not end in one).
    ///
    /// The editor paints from column 0 and erases as it goes, so a prompt drawn
    /// where such output left the cursor would wipe it off the screen. It cannot
    /// simply ask where the cursor is — that is a round-trip the console may
    /// never answer (see [`Term::probe_width`]) — so it uses the trick zsh calls
    /// `PROMPT_SP`: write a marker and then a whole row of spaces, and let the
    /// terminal's own wrapping decide.
    ///
    /// - Cursor mid-row: the spaces run off the end and wrap to a fresh row,
    ///   leaving the marker behind to show the output was cut short.
    /// - Cursor already at column 0: marker + spaces fill the row *exactly*
    ///   without wrapping, `\r` returns to it, and the prompt paints over the
    ///   marker. Nothing shows.
    ///
    /// The cursor stays hidden throughout. Those spaces walk it the full width
    /// of the screen and back, once for every prompt, and on a slow console you
    /// can watch it go: hiding it costs twelve bytes a prompt, and is the
    /// difference between a marker nobody ever sees and a cursor that sweeps the
    /// row before every prompt.
    fn mark_partial_line(&mut self) {
        let cols = self.cols();
        let mut buf = String::from("\x1b[?25l\x1b[7m%\x1b[0m"); // reverse video, as zsh's
        buf.push_str(&" ".repeat(cols.saturating_sub(1)));
        buf.push_str("\r\x1b[?25h");
        self.write(buf.as_bytes());
    }

    fn read_key(&mut self) -> Key {
        read_key(&mut self.input, &mut self.after_cr)
    }

    fn readline(&mut self, prompt: &str, continuation: bool, sh: &Shell) -> ReadOutcome {
        let prompt = Prompt::new(prompt);
        if self.piped {
            return self.readline_piped(&prompt, continuation);
        }
        self.term_impl.make_raw();
        self.shell_cols = sh.get("COLUMNS").and_then(|c| c.trim().parse().ok());
        self.probe_width();

        let mut line: Vec<char> = Vec::new();
        let mut pos = 0_usize;
        // Where history browsing stands: `history.len()` means "the line being
        // typed", which `saved` holds while the browse is elsewhere.
        let mut hist = self.history.len();
        let mut saved: Vec<char> = Vec::new();

        self.reset_screen();
        self.mark_partial_line();
        self.render(&prompt, &line, pos);

        loop {
            let mut key = self.read_key();

            // `^R` runs its own read loop and hands back the key that ended it,
            // which is then handled here as if it had just been typed — so
            // Enter runs the found line and Left starts editing it.
            if key == Key::Ctrl('r') {
                match self.reverse_search(&prompt, &mut line, &mut pos) {
                    Some(k) => key = k,
                    None => continue,
                }
            }

            match key {
                Key::Char(c) => {
                    line.insert(pos, c);
                    pos += 1;
                    self.render(&prompt, &line, pos);
                }
                Key::Enter => {
                    pos = line.len();
                    self.render(&prompt, &line, pos);
                    self.write(b"\n");
                    self.term_impl.make_cooked();
                    let cmd: String = line.iter().collect();
                    // A blank line is nothing to run — but only when it is not
                    // continuing something. Inside a here-doc or a quoted
                    // string an empty line is *content*, and swallowing it (as
                    // rush did before Phase 8) silently corrupted the command.
                    if cmd.trim().is_empty() && !continuation {
                        return ReadOutcome::Again;
                    }
                    return ReadOutcome::Line(cmd);
                }
                Key::Ctrl('c') => {
                    pos = line.len();
                    self.render(&prompt, &line, pos);
                    // No terminal driver turns this byte into a signal — not on
                    // Motor OS, which has none, and not on the Linux host
                    // either, where the raw mode rush installs clears ISIG (see
                    // `sys`). So the shell raises SIGINT itself, and any
                    // `trap … INT` fires from the interactive loop's safe point
                    // exactly as it would on a signalling platform.
                    crate::sys::note_signal(crate::signal::SIGINT);
                    self.write(b"^C\n");
                    self.term_impl.make_cooked();
                    // Hand control back rather than just redrawing: the trap has
                    // to run now, and an abandoned *continuation* line must drop
                    // the rest of the half-typed command with it.
                    return ReadOutcome::Interrupted;
                }
                Key::Ctrl('d') => {
                    if line.is_empty() {
                        // A newline, so whatever comes next — a diagnostic, the
                        // exiting shell's caller — does not start on the prompt.
                        // dash prints one here too.
                        self.write(b"\n");
                        self.term_impl.make_cooked();
                        return ReadOutcome::Eof;
                    }
                    // Non-empty: `^D` is delete-forward, as in readline.
                    if pos < line.len() {
                        line.remove(pos);
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::Eof => {
                    self.term_impl.make_cooked();
                    return ReadOutcome::Eof;
                }
                Key::Tab => self.complete_at(&prompt, &mut line, &mut pos, sh),
                Key::Backspace => {
                    if pos > 0 {
                        pos -= 1;
                        line.remove(pos);
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::Delete => {
                    if pos < line.len() {
                        line.remove(pos);
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::Left | Key::Ctrl('b') => {
                    if pos > 0 {
                        pos -= 1;
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::Right | Key::Ctrl('f') => {
                    if pos < line.len() {
                        pos += 1;
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::Home | Key::Ctrl('a') => {
                    pos = 0;
                    self.render(&prompt, &line, pos);
                }
                Key::End | Key::Ctrl('e') => {
                    pos = line.len();
                    self.render(&prompt, &line, pos);
                }
                Key::WordLeft | Key::Alt('b') => {
                    pos = word_start(&line, pos);
                    self.render(&prompt, &line, pos);
                }
                Key::WordRight | Key::Alt('f') => {
                    pos = word_end(&line, pos);
                    self.render(&prompt, &line, pos);
                }
                Key::Ctrl('k') => {
                    self.kill_ring = line.split_off(pos);
                    self.render(&prompt, &line, pos);
                }
                Key::Ctrl('u') => {
                    // readline's `unix-line-discard`: kill *back* to the start.
                    self.kill_ring = line.drain(..pos).collect();
                    pos = 0;
                    self.render(&prompt, &line, pos);
                }
                Key::Ctrl('w') => {
                    let start = ws_word_start(&line, pos);
                    self.kill_ring = line.drain(start..pos).collect();
                    pos = start;
                    self.render(&prompt, &line, pos);
                }
                Key::Alt('\x7f') => {
                    let start = word_start(&line, pos);
                    self.kill_ring = line.drain(start..pos).collect();
                    pos = start;
                    self.render(&prompt, &line, pos);
                }
                Key::Alt('d') => {
                    let end = word_end(&line, pos);
                    self.kill_ring = line.drain(pos..end).collect();
                    self.render(&prompt, &line, pos);
                }
                Key::Ctrl('y') => {
                    let yank = self.kill_ring.clone();
                    for c in yank {
                        line.insert(pos, c);
                        pos += 1;
                    }
                    self.render(&prompt, &line, pos);
                }
                Key::Ctrl('t') => {
                    // Transpose the two characters around the cursor, and step
                    // over them — readline's `transpose-chars`.
                    if line.len() >= 2 && pos > 0 {
                        let at = if pos == line.len() { pos - 1 } else { pos };
                        line.swap(at - 1, at);
                        pos = (at + 1).min(line.len());
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::Ctrl('l') => {
                    self.write(b"\x1b[H\x1b[2J");
                    self.reset_screen();
                    self.render(&prompt, &line, pos);
                }
                Key::Up | Key::Ctrl('p') => {
                    if hist > 0 {
                        if hist == self.history.len() {
                            saved = line.clone();
                        }
                        hist -= 1;
                        line = self.history.get(hist).unwrap_or_default().chars().collect();
                        pos = line.len();
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::Down | Key::Ctrl('n') => {
                    if hist < self.history.len() {
                        hist += 1;
                        line = if hist == self.history.len() {
                            saved.clone()
                        } else {
                            self.history.get(hist).unwrap_or_default().chars().collect()
                        };
                        pos = line.len();
                        self.render(&prompt, &line, pos);
                    } else {
                        self.beep();
                    }
                }
                Key::CursorReport(_, col) => {
                    // The width probe came back. Repaint only if it told us
                    // something new: the layout was computed against the old
                    // width.
                    if col > 0 && self.probed_cols != Some(col) {
                        self.probed_cols = Some(col);
                        self.render(&prompt, &line, pos);
                    }
                }
                Key::Ctrl(_) | Key::Alt(_) | Key::Unknown => self.beep(),
            }
        }
    }

    /// Read a line with no terminal on the other end (`--piped`, or `-i` with a
    /// redirected stdin).
    ///
    /// There is nothing to edit *on*: no cursor to move, no echo to own, and —
    /// the part that matters for correctness — the bytes arriving are a script,
    /// not keystrokes. An `ESC` in a here-doc is data; running it through the key
    /// decoder would turn the text into cursor motion. So this reads plain lines
    /// and prints the prompt, which is exactly what `dash -i < file` does.
    fn readline_piped(&mut self, prompt: &Prompt, continuation: bool) -> ReadOutcome {
        self.write(prompt.text.as_bytes());
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            match self.input.get() {
                Some(b'\n') => break,
                Some(b) => bytes.push(b),
                None => {
                    if bytes.is_empty() {
                        return ReadOutcome::Eof;
                    }
                    break; // a last line with no newline of its own
                }
            }
        }
        // Lossy: a shell script is text, and a stray non-UTF-8 byte in one is
        // better replaced than fatal.
        let line = String::from_utf8_lossy(&bytes).into_owned();
        if line.trim().is_empty() && !continuation {
            return ReadOutcome::Again;
        }
        ReadOutcome::Line(line)
    }

    /// The newest history entry containing `needle`.
    fn search_newest(&self, needle: &str) -> Option<usize> {
        let newest = self.history.len().checked_sub(1)?;
        self.history.search_back(needle, newest)
    }

    /// `^R`: search the history backwards as the needle grows.
    ///
    /// Returns the key that ended the search for the caller to handle — `None`
    /// if the search was cancelled and the line restored.
    fn reverse_search(
        &mut self,
        prompt: &Prompt,
        line: &mut Vec<char>,
        pos: &mut usize,
    ) -> Option<Key> {
        let original: Vec<char> = line.clone();
        let original_pos = *pos;
        let mut needle = String::new();
        // The entry being shown, if the needle matched one.
        let mut found: Option<usize> = None;

        loop {
            // readline's prompt, including its `failed` marker.
            let sp = Prompt::new(&format!(
                "({}reverse-i-search)`{needle}': ",
                if found.is_none() && !needle.is_empty() {
                    "failed "
                } else {
                    ""
                }
            ));
            // Show the match with the cursor on the needle, as readline does.
            let shown: Vec<char> = match found {
                Some(i) => self.history.get(i).unwrap_or_default().chars().collect(),
                None => original.clone(),
            };
            let at = match found {
                Some(i) => {
                    let hay = self.history.get(i).unwrap_or_default();
                    hay.find(&needle)
                        .map(|b| hay[..b].chars().count())
                        .unwrap_or(0)
                }
                None => original_pos.min(shown.len()),
            };
            self.render(&sp, &shown, at);

            match self.read_key() {
                // Growing or shrinking the needle re-searches from the newest
                // entry, as readline does: it is `^R` alone that walks back.
                Key::Char(c) => {
                    needle.push(c);
                    found = self.search_newest(&needle);
                    if found.is_none() {
                        self.beep();
                    }
                }
                Key::Backspace => {
                    needle.pop();
                    found = if needle.is_empty() {
                        None
                    } else {
                        self.search_newest(&needle)
                    };
                }
                Key::Ctrl('r') => {
                    // Again: the next match strictly older than this one.
                    match found
                        .and_then(|i| i.checked_sub(1))
                        .and_then(|next| self.history.search_back(&needle, next))
                    {
                        Some(i) => found = Some(i),
                        None => self.beep(),
                    }
                }
                // Cancel: put back the line the search started from.
                Key::Ctrl('c') | Key::Ctrl('g') => {
                    *line = original;
                    *pos = original_pos;
                    self.render(prompt, line, *pos);
                    return None;
                }
                Key::Eof => {
                    *line = original;
                    *pos = original_pos;
                    return Some(Key::Eof);
                }
                // Anything else ends the search, keeping what it found, and is
                // then handled as an ordinary key.
                key => {
                    if let Some(i) = found {
                        *line = self.history.get(i).unwrap_or_default().chars().collect();
                        *pos = line.len();
                    } else {
                        *line = original;
                        *pos = original_pos;
                    }
                    // `ESC` only leaves the search; it is not a key of its own.
                    if key == Key::Unknown {
                        self.render(prompt, line, *pos);
                        return None;
                    }
                    return Some(key);
                }
            }
        }
    }

    /// Tab: complete the word under the cursor.
    fn complete_at(&mut self, prompt: &Prompt, line: &mut Vec<char>, pos: &mut usize, sh: &Shell) {
        let c = complete::complete(line, *pos, sh);
        if c.candidates.is_empty() {
            self.beep();
            return;
        }
        let lcp = complete::common_prefix(&c.candidates);
        let single = c.candidates.len() == 1;
        let mut text = complete::quote_for_insert(&lcp, c.quote);
        if single {
            // A finished word gets its quote closed and a space; a directory
            // gets neither, because the next component follows the slash.
            if !lcp.ends_with('/') {
                match c.quote {
                    Quote::Single => text.push('\''),
                    Quote::Double => text.push('"'),
                    Quote::None => {}
                }
                text.push(' ');
            }
        }

        let current: String = line[c.start..*pos].iter().collect();
        if text != current {
            let tail: Vec<char> = line[*pos..].to_vec();
            line.truncate(c.start);
            line.extend(text.chars());
            *pos = line.len();
            line.extend(tail);
            self.render(prompt, line, *pos);
        } else if single {
            // Already exactly the one completion there is.
            self.beep();
        } else {
            // Ambiguous and no progress to make: show what the choices are.
            // (bash waits for a second Tab; there is nothing to gain by making
            // the user ask twice when the first Tab could not insert anything.)
            self.list_candidates(&c.candidates);
            self.reset_screen();
            self.render(prompt, line, *pos);
        }
    }

    /// Print the candidates in `ls`-style columns, below the line.
    fn list_candidates(&mut self, candidates: &[String]) {
        self.write(b"\n");
        if candidates.len() > MAX_UNASKED_CANDIDATES && !self.confirm_listing(candidates.len()) {
            return;
        }
        let names: Vec<&str> = candidates.iter().map(|c| display_name(c)).collect();
        let cols = self.cols();
        let widest = names.iter().map(|n| display_width(n)).max().unwrap_or(1);
        let cell = widest + 2;
        let ncols = (cols / cell).max(1);
        let nrows = names.len().div_ceil(ncols);

        let mut out = String::new();
        for r in 0..nrows {
            // Column-major, like `ls`: names read down, then across.
            for c in 0..ncols {
                let Some(name) = names.get(c * nrows + r) else {
                    continue;
                };
                out.push_str(name);
                if c * nrows + r + nrows < names.len() {
                    for _ in 0..cell - display_width(name) {
                        out.push(' ');
                    }
                }
            }
            out.push_str("\r\n");
        }
        self.write(out.as_bytes());
    }

    /// bash's "Display all 400 possibilities?" — a Tab in `/bin` should not
    /// bury the prompt under hundreds of names, least of all down a serial line.
    fn confirm_listing(&mut self, n: usize) -> bool {
        self.write(format!("Display all {n} possibilities? (y or n) ").as_bytes());
        loop {
            match self.read_key() {
                Key::Char('y') | Key::Char('Y') => {
                    self.write(b"\n");
                    return true;
                }
                Key::Char('n') | Key::Char('N') | Key::Ctrl('c') | Key::Eof => {
                    self.write(b"\n");
                    return false;
                }
                _ => self.beep(),
            }
        }
    }
}

/// What a candidate is called, for a listing: its last path component (bash
/// lists `ls`, not `/usr/bin/ls`), keeping a directory's trailing slash.
fn display_name(candidate: &str) -> &str {
    let trimmed = candidate.strip_suffix('/').unwrap_or(candidate);
    match trimmed.rfind('/') {
        Some(i) => &candidate[i + 1..],
        None => candidate,
    }
}

static TERM: Mutex<Option<Term>> = Mutex::new(None);

/// Start the line editor, loading `$HISTFILE`.
///
/// The startup files have already been sourced by now, so a `$HISTFILE` set in
/// `$ENV` or a profile is in effect. It is sampled once: rush persists to the
/// file the session started with, whatever the variable is later set to.
pub fn init(piped: bool, sh: &Shell) {
    debug_assert!(TERM.lock().unwrap().is_none());
    let mut term = Term::new(piped);
    term.history
        .open(sh.get("HISTFILE").as_deref(), sh.get("HISTSIZE").as_deref());
    *TERM.lock().unwrap() = Some(term);
}

/// One line of input, or why there is none.
pub enum Input {
    Line(String),
    /// `^C` abandoned the line.
    Interrupted,
    /// End of input: `^D` at an empty prompt, or a closed stdin.
    Eof,
}

/// Read one line.
pub fn readline(prompt: &str, sh: &Shell) -> Input {
    readline_inner(prompt, false, sh)
}

/// Read a `PS2` continuation line.
pub fn readline_continuation(prompt: &str, sh: &Shell) -> Input {
    readline_inner(prompt, true, sh)
}

fn readline_inner(prompt: &str, continuation: bool, sh: &Shell) -> Input {
    // Held for the whole line. Nothing the editor calls may re-enter this
    // module — completion reads the `Shell` but never runs shell code — and the
    // `history` builtin only runs once the line is back in the executor's hands.
    let term = &mut *TERM.lock().unwrap();
    loop {
        match term.as_mut().unwrap().readline(prompt, continuation, sh) {
            ReadOutcome::Line(line) => return Input::Line(line),
            ReadOutcome::Interrupted => return Input::Interrupted,
            ReadOutcome::Eof => return Input::Eof,
            // An empty line, or one the editor handled itself: read again.
            ReadOutcome::Again => {}
        }
    }
}

/// Record a command that [`readline`] did not (a multi-line command, which the
/// caller had to merge before it made sense as one entry).
pub fn add_to_history(cmd: &str) {
    if let Some(term) = &mut *TERM.lock().unwrap() {
        term.history.add(cmd);
    }
}

/// The history list, for the `history` builtin. Empty in a non-interactive
/// shell, which never starts an editor.
pub fn history_entries() -> Vec<String> {
    match &*TERM.lock().unwrap() {
        Some(term) => term.history.entries().to_vec(),
        None => Vec::new(),
    }
}

/// `history -c`.
pub fn clear_history() {
    if let Some(term) = &mut *TERM.lock().unwrap() {
        term.history.clear();
    }
}

pub fn on_exit() {
    if let Some(term) = &mut *TERM.lock().unwrap() {
        term.history.save();
        term.term_impl.on_exit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte source over a fixed slice, for decoding tests.
    struct Fake(VecDeque<u8>);

    impl Fake {
        fn new(bytes: &[u8]) -> Self {
            Self(bytes.iter().copied().collect())
        }
    }

    impl Bytes for Fake {
        fn get(&mut self) -> Option<u8> {
            self.0.pop_front()
        }
        fn unget(&mut self, b: u8) {
            self.0.push_front(b);
        }
    }

    fn key(bytes: &[u8]) -> Key {
        read_key(&mut Fake::new(bytes), &mut false)
    }

    fn keys(bytes: &[u8]) -> Vec<Key> {
        let mut src = Fake::new(bytes);
        let mut after_cr = false;
        let mut out = Vec::new();
        loop {
            match read_key(&mut src, &mut after_cr) {
                Key::Eof => return out,
                k => out.push(k),
            }
        }
    }

    #[test]
    fn plain_bytes_decode_to_keys() {
        assert_eq!(key(b"a"), Key::Char('a'));
        assert_eq!(key(b" "), Key::Char(' '));
        assert_eq!(key(b"\r"), Key::Enter);
        assert_eq!(key(b"\n"), Key::Enter);
        assert_eq!(key(b"\t"), Key::Tab);
        assert_eq!(key(&[0x7f]), Key::Backspace);
        assert_eq!(key(&[0x08]), Key::Backspace);
        assert_eq!(key(&[]), Key::Eof);
    }

    #[test]
    fn control_bytes_decode_to_their_letters() {
        assert_eq!(key(&[0x01]), Key::Ctrl('a'));
        assert_eq!(key(&[0x03]), Key::Ctrl('c'));
        assert_eq!(key(&[0x04]), Key::Ctrl('d'));
        assert_eq!(key(&[0x12]), Key::Ctrl('r'));
        assert_eq!(key(&[0x1a]), Key::Ctrl('z'));
    }

    #[test]
    fn escape_sequences_decode_to_named_keys() {
        assert_eq!(key(b"\x1b[A"), Key::Up);
        assert_eq!(key(b"\x1b[B"), Key::Down);
        assert_eq!(key(b"\x1b[C"), Key::Right);
        assert_eq!(key(b"\x1b[D"), Key::Left);
        assert_eq!(key(b"\x1b[H"), Key::Home);
        assert_eq!(key(b"\x1b[F"), Key::End);
        assert_eq!(key(b"\x1b[1~"), Key::Home);
        assert_eq!(key(b"\x1b[7~"), Key::Home);
        assert_eq!(key(b"\x1b[4~"), Key::End);
        assert_eq!(key(b"\x1b[8~"), Key::End);
        assert_eq!(key(b"\x1b[3~"), Key::Delete);
        // Application-cursor-key mode.
        assert_eq!(key(b"\x1bOA"), Key::Up);
        assert_eq!(key(b"\x1bOH"), Key::Home);
        // Alt/meta.
        assert_eq!(key(b"\x1bb"), Key::Alt('b'));
        assert_eq!(key(b"\x1bf"), Key::Alt('f'));
        assert_eq!(key(&[0x1b, 0x7f]), Key::Alt('\x7f'));
        // Ctrl/Alt + arrows.
        assert_eq!(key(b"\x1b[1;5C"), Key::WordRight);
        assert_eq!(key(b"\x1b[1;5D"), Key::WordLeft);
        assert_eq!(key(b"\x1b[1;3C"), Key::WordRight);
        // Modifier-less arrows are not word motion.
        assert_eq!(key(b"\x1b[1;2C"), Key::Right);
    }

    #[test]
    fn a_cursor_report_is_a_key_of_its_own() {
        assert_eq!(key(b"\x1b[24;80R"), Key::CursorReport(24, 80));
        assert_eq!(key(b"\x1b[1;213R"), Key::CursorReport(1, 213));
    }

    #[test]
    fn an_unknown_sequence_does_not_swallow_the_next_key() {
        // A `^C` arriving inside a half-finished escape must survive: the
        // sequence is abandoned and the byte handed back.
        assert_eq!(keys(&[0x1b, b'[', 0x03, b'a']), [
            Key::Unknown,
            Key::Ctrl('c'),
            Key::Char('a')
        ]);
    }

    #[test]
    fn utf8_input_decodes_by_codepoint() {
        assert_eq!(key("é".as_bytes()), Key::Char('é'));
        assert_eq!(key("→".as_bytes()), Key::Char('→'));
        assert_eq!(key("日".as_bytes()), Key::Char('日'));
        assert_eq!(key("🦀".as_bytes()), Key::Char('🦀'));
        // A whole typed word, one key at a time.
        assert_eq!(keys("héllo".as_bytes()), [
            Key::Char('h'),
            Key::Char('é'),
            Key::Char('l'),
            Key::Char('l'),
            Key::Char('o')
        ]);
    }

    #[test]
    fn invalid_utf8_is_dropped_without_eating_the_next_key() {
        // A lead byte whose continuation never came: the `a` is still a key.
        assert_eq!(keys(&[0xc3, b'a']), [Key::Unknown, Key::Char('a')]);
        // A stray continuation byte.
        assert_eq!(keys(&[0x80, b'a']), [Key::Unknown, Key::Char('a')]);
    }

    #[test]
    fn widths_follow_east_asian_width() {
        assert_eq!(char_width('a'), 1);
        assert_eq!(char_width('é'), 1);
        assert_eq!(char_width('日'), 2);
        assert_eq!(char_width('🦀'), 2);
        assert_eq!(char_width('\u{0301}'), 0, "combining acute");
        assert_eq!(char_width('\u{200b}'), 0, "zero-width space");
        assert_eq!(char_width('\x07'), 0, "control");
    }

    #[test]
    fn prompt_width_ignores_escape_sequences() {
        assert_eq!(display_width("$ "), 2);
        assert_eq!(display_width("\x1b[32mrush\x1b[0m$ "), 6);
        assert_eq!(display_width("\x1b]0;title\x07$ "), 2);
        assert_eq!(display_width("日本$ "), 6);
    }

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn layout_of_a_line_that_fits_is_one_row() {
        let l = layout(2, &chars("echo hi"), 7, 80);
        assert_eq!(l, Layout {
            rows: 1,
            crow: 0,
            ccol: 9,
            wrapped_end: false
        });
    }

    #[test]
    fn layout_wraps_a_long_line_and_places_the_cursor() {
        // Prompt 2 + 10 chars on a 6-column terminal: "$ abcd", "efghij".
        let line = chars("abcdefghij");
        let l = layout(2, &line, 10, 6);
        // "$ abcd" and "efghij" both fill their row exactly, so the cursor sits
        // at the start of a third — which the terminal is really on, once the
        // renderer forces the pending wrap.
        assert_eq!(l.rows, 3);
        assert_eq!((l.crow, l.ccol), (2, 0), "cursor is past the last char");
        // The cursor at the start of the second row.
        let l = layout(2, &line, 4, 6);
        assert_eq!((l.crow, l.ccol), (1, 0));
        // …and one before it, at the end of the first.
        let l = layout(2, &line, 3, 6);
        assert_eq!((l.crow, l.ccol), (0, 5));
    }

    #[test]
    fn a_line_ending_exactly_at_the_edge_forces_a_wrap() {
        // Prompt 2 + 4 chars fills a 6-column row exactly.
        let l = layout(2, &chars("abcd"), 4, 6);
        assert!(l.wrapped_end);
        assert_eq!(l.rows, 2, "the empty next row is real: the terminal is on it");
        assert_eq!((l.crow, l.ccol), (1, 0), "the cursor moved to it");
    }

    #[test]
    fn layout_never_splits_a_wide_character() {
        // 5 columns: "$ " + '日' (2) leaves 1 column, so the second '日' wraps
        // rather than being cut in half.
        let l = layout(2, &chars("日日"), 2, 5);
        assert_eq!(l.rows, 2);
        assert_eq!((l.crow, l.ccol), (1, 2));
    }

    #[test]
    fn layout_wraps_a_prompt_wider_than_the_terminal() {
        let l = layout(10, &chars("ab"), 2, 4);
        // The prompt alone is 2 full rows and 2 columns into the third; "ab"
        // then fills that row exactly, putting the cursor on a fourth.
        assert_eq!(l.rows, 4);
        assert_eq!((l.crow, l.ccol), (3, 0));
        assert!(l.wrapped_end);
    }

    #[test]
    fn a_crlf_is_one_enter() {
        // What a terminal sends for Enter is a CR. Motor's console sends CRLF,
        // and counting that as two runs the typed line and then a blank one —
        // two prompts for one keypress, which is what this is here to stop.
        assert_eq!(keys(b"\r\n"), [Key::Enter]);
        assert_eq!(keys(b"ab\r\ncd\r\n"), [
            Key::Char('a'),
            Key::Char('b'),
            Key::Enter,
            Key::Char('c'),
            Key::Char('d'),
            Key::Enter
        ]);
    }

    #[test]
    fn a_lone_lf_is_still_an_enter() {
        // Only the LF *of a CRLF* is the other half of something. On its own it
        // is a terminal saying Enter the other way, and dropping it would leave
        // such a console with no way to run anything.
        assert_eq!(keys(b"\n"), [Key::Enter]);
        assert_eq!(keys(b"\n\n"), [Key::Enter, Key::Enter]);
        // ...and a CR that ends up next to an LF it did not come with keeps it:
        // only the LF *immediately* after a CR is swallowed.
        assert_eq!(keys(b"\r\na\n"), [Key::Enter, Key::Char('a'), Key::Enter]);
        assert_eq!(keys(b"\r\r"), [Key::Enter, Key::Enter]);
    }

    #[test]
    fn the_lf_of_a_crlf_is_dropped_however_late_it_arrives() {
        // The halves are read either side of the command the CR ran, so the bit
        // of state has to survive between calls — which is why it is the
        // caller's and not a local.
        let mut after_cr = false;
        assert_eq!(read_key(&mut Fake::new(b"\r"), &mut after_cr), Key::Enter);
        assert!(after_cr);
        // A whole command later, from a source that knows nothing of the CR:
        assert_eq!(read_key(&mut Fake::new(b"\nx"), &mut after_cr), Key::Char('x'));
    }

    #[test]
    fn cell_at_places_a_character_where_layout_would_put_the_cursor() {
        // The two walk the same terminal, and a partial paint is only safe if
        // they agree: `cell_at` decides where to start writing, `layout` decides
        // where the cursor ends up, and a disagreement is a character drawn in
        // the wrong place.
        let line = chars("echo 日本 hello world");
        for cols in [4, 7, 10, 20, 80] {
            for i in 0..=line.len() {
                let lay = layout(2, &line, i, cols);
                assert_eq!(
                    cell_at(2, &line, i, cols),
                    (lay.crow, lay.ccol),
                    "index {i} at {cols} columns"
                );
            }
        }
    }

    #[test]
    fn cell_at_pushes_a_character_that_does_not_fit_onto_the_next_row() {
        // 10 columns, prompt 2: "abcdefgh" fills the row, and the 9th character
        // starts the next one — that is where a repaint must start writing it.
        let line = chars("abcdefghi");
        assert_eq!(cell_at(2, &line, 8, 10), (1, 0));
        assert_eq!(cell_at(2, &line, 7, 10), (0, 9));
        // The end of a line that stops exactly at the edge is the next row too:
        // the cursor belongs where the next character typed will appear.
        assert_eq!(cell_at(2, &chars("abcdefgh"), 8, 10), (1, 0));
        // A wide character that cannot be split goes over whole, so the cell
        // before it stays empty and the cell it lands in is the next row's.
        assert_eq!(cell_at(2, &chars("abcdefg日"), 7, 10), (1, 0));
    }

    /// The bytes `move_cursor` emits to get from one cell to another.
    fn moves(from: (usize, usize), to: (usize, usize)) -> String {
        let mut buf = String::new();
        let any = move_cursor(&mut buf, from, to);
        assert_eq!(any, from != to, "{from:?} -> {to:?}: {buf:?}");
        buf
    }

    #[test]
    fn move_cursor_says_nothing_when_there_is_nowhere_to_go() {
        assert_eq!(moves((2, 5), (2, 5)), "");
    }

    #[test]
    fn move_cursor_moves_relatively_and_by_the_shortest_route() {
        assert_eq!(moves((2, 5), (0, 5)), "\x1b[2A");
        assert_eq!(moves((0, 5), (2, 5)), "\x1b[2B");
        assert_eq!(moves((1, 5), (1, 9)), "\x1b[4C");
        assert_eq!(moves((1, 9), (1, 5)), "\x1b[4D");
        // Column 0 is a carriage return, not a four-byte escape.
        assert_eq!(moves((1, 9), (1, 0)), "\r");
        // A vertical move keeps the column, so only the difference is paid for.
        assert_eq!(moves((3, 9), (1, 0)), "\x1b[2A\r");
        assert_eq!(moves((3, 9), (1, 9)), "\x1b[2A");
    }

    #[test]
    fn word_motion_follows_readline() {
        let l = chars("echo foo bar");
        assert_eq!(word_start(&l, 12), 9, "back over `bar`");
        assert_eq!(word_start(&l, 9), 5, "back over the space and `foo`");
        assert_eq!(word_start(&l, 0), 0);
        assert_eq!(word_end(&l, 0), 4, "forward over `echo`");
        assert_eq!(word_end(&l, 4), 8, "over the space and `foo`");
        assert_eq!(word_end(&l, 12), 12);
    }

    #[test]
    fn ctrl_w_kills_a_whole_shell_word() {
        // Unlike M-DEL, `^W` is whitespace-delimited: a path goes at once.
        let l = chars("cat /usr/bin/ls");
        assert_eq!(ws_word_start(&l, 15), 4);
        // Trailing whitespace is skipped first.
        let l = chars("cat foo   ");
        assert_eq!(ws_word_start(&l, 10), 4);
        // …where M-DEL stops at the punctuation.
        let l = chars("cat /usr/bin/ls");
        assert_eq!(word_start(&l, 15), 13);
    }

    #[test]
    fn candidate_display_names_are_the_last_component() {
        assert_eq!(display_name("/usr/bin/ls"), "ls");
        assert_eq!(display_name("src/main.rs"), "main.rs");
        assert_eq!(display_name("src/"), "src/");
        assert_eq!(display_name("a/b/"), "b/");
        assert_eq!(display_name("echo"), "echo");
    }
}
