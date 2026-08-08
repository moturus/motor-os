//! The interactive line editor.
//!
//! Keys, the terminal's size and raw mode come from `crossterm`, which is where
//! the platform's terminal layer lives now: on Motor OS its backend reads stdin
//! through `moto_rt::poll`, coalesces the CR LF that one Enter arrives as, holds
//! a half-arrived escape sequence for as long as the serial console needs to
//! finish it, and subscribes to the terminal's size in band (DEC private mode
//! 2048) because there is no `TIOCGWINSZ` and no `SIGWINCH` to be told with. On
//! the Unix host the same API is termios and ioctls. What the editor keeps is
//! everything above that seam: the model, the painting, and what each key
//! means.
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
//! The one thing the model needs from outside is the terminal's width, which is
//! [`crossterm::terminal::size`]: on the host an ioctl, and on Motor OS the last
//! size the terminal reported while the editor was waiting for a key. Nothing is
//! ever staked on an answer — the call cannot block — so a console with nothing
//! on the other end keeps the default width instead of hanging the shell at its
//! first prompt.
//!
//! # What the editor deliberately does not do
//!
//! No terminfo: the escape sequences are the plain ANSI ones crossterm emits,
//! which every terminal understands.

use std::collections::VecDeque;
use std::io::{IsTerminal, Read, Write};
use std::sync::Mutex;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::{Attribute, SetAttribute};
use crossterm::terminal::{Clear, ClearType, disable_raw_mode, enable_raw_mode};
use crossterm::{Command, cursor};

use crate::complete::{self, Quote};
use crate::history::History;
use crate::shell::Shell;

/// The width assumed when nothing can tell us better. The classic terminal.
const DEFAULT_COLS: usize = 80;

/// How many completions are listed without asking first, so that a stray Tab in
/// `/bin` does not dump hundreds of names down a slow console.
const MAX_UNASKED_CANDIDATES: usize = 100;

// ---- keys ------------------------------------------------------------------

/// A key press, as the editor names one.
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
    /// The terminal is a different shape now, and this is its width.
    ///
    /// Not a key, but it arrives among them: with no signal to carry it, a
    /// resize reaches a program on Motor OS as bytes in its own stdin, so the
    /// event source that reads the keys is what finds it — and only while the
    /// editor is waiting for one.
    Resize(usize),
    /// The input stream ended.
    Eof,
    /// Something unrecognized; the editor beeps rather than inserting garbage.
    Unknown,
}

/// What the editor makes of one key event.
///
/// Everything below `KeyCode` is crossterm's — a byte, an escape sequence or a
/// UTF-8 character, however split across reads it arrived. What is left here is
/// which of those the editor has a use for, and the two spellings a terminal is
/// allowed to disagree about: `^J` for Enter (a console that sends a bare LF for
/// the key reaches raw mode as Ctrl-J, and readline runs the line for both) and
/// `^H` for Backspace (there is no termios `erase` setting to consult).
fn key_of(event: KeyEvent) -> Key {
    let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
    let alt = event.modifiers.contains(KeyModifiers::ALT);
    match event.code {
        KeyCode::Char('j') if ctrl && !alt => Key::Enter,
        KeyCode::Char('h') if ctrl && !alt => Key::Backspace,
        KeyCode::Char(c) if ctrl => Key::Ctrl(c.to_ascii_lowercase()),
        KeyCode::Char(c) if alt => Key::Alt(c),
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Enter => Key::Enter,
        KeyCode::Tab => Key::Tab,
        // Alt-Backspace, which readline binds to "kill the word behind".
        KeyCode::Backspace if alt => Key::Alt('\x7f'),
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Delete => Key::Delete,
        // `ESC[1;5C` is Ctrl-Right and `ESC[1;3C` is Alt-Right; both move by a
        // word, as they do in readline.
        KeyCode::Left if ctrl || alt => Key::WordLeft,
        KeyCode::Right if ctrl || alt => Key::WordRight,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        // Esc, the function keys, and anything else the editor has no use for.
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

/// Add what `command` does to a paint being built.
///
/// A paint is assembled whole and written in one go, so the commands are
/// rendered into a buffer rather than executed one at a time: a cursor that
/// moves in three writes is a cursor the user watches move.
fn paint(buf: &mut String, command: impl Command) {
    // The only way this fails is a `fmt::Write` that errors, and a `String`
    // cannot.
    let _ = command.write_ansi(buf);
}

/// A distance in cells, as a terminal counts one.
fn steps(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

/// Take a pending wrap now, so the cursor's row is unambiguous.
///
/// A line that ends exactly at the right-hand edge leaves the terminal's cursor
/// in a place that is not a cell: still on the last column, wrapping only when
/// one more character arrives. There is no command for resolving that, because
/// it is not a cursor movement — it is the newline itself, which is also what
/// makes the terminal scroll now, while the editor still knows where it is.
fn wrap_now(buf: &mut String) {
    buf.push('\n');
    paint(buf, cursor::MoveToColumn(0));
}

/// Move the cursor between two cells of the paint, and say whether that took any
/// bytes at all.
///
/// The motion is relative, because the editor knows exactly where it left the
/// cursor. Absolute motion would need the row on the *screen*, which it can only
/// learn by asking the terminal — and no paint may be staked on an answer that
/// may never come.
fn move_cursor(buf: &mut String, from: (usize, usize), to: (usize, usize)) -> bool {
    if to.0 < from.0 {
        paint(buf, cursor::MoveUp(steps(from.0 - to.0)));
    } else if to.0 > from.0 {
        paint(buf, cursor::MoveDown(steps(to.0 - from.0)));
    }
    // A vertical move keeps the column, so the column is settled on its own.
    if to.1 != from.1 {
        if to.1 == 0 {
            paint(buf, cursor::MoveToColumn(0));
        } else if to.1 > from.1 {
            paint(buf, cursor::MoveRight(steps(to.1 - from.1)));
        } else {
            paint(buf, cursor::MoveLeft(steps(from.1 - to.1)));
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

/// Input bytes from stdin, for the one mode that has no terminal to read from.
///
/// A script is not keystrokes ([`Term::readline_piped`]), so it does not go
/// through crossterm at all: these bytes are read and handed on as they came.
/// Deliberately a small read: what is buffered here is out of reach of a child
/// that inherits this stdin.
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

    /// Take whatever stdin has to give into `pending`, and report whether the
    /// stream is still open. Blocks until there is something to take.
    fn absorb(&mut self) -> bool {
        if self.eof {
            return false;
        }
        let mut buf = [0_u8; 64];
        match std::io::stdin().read(&mut buf) {
            Ok(n) if n > 0 => {
                self.pending.extend(&buf[..n]);
                true
            }
            // A closed stdin stays closed, and a read error is as final as EOF:
            // remember it, so that a shell whose input went away exits instead
            // of spinning on it.
            _ => {
                self.eof = true;
                false
            }
        }
    }

    /// The next byte, or `None` at end of input.
    fn get(&mut self) -> Option<u8> {
        if self.pending.is_empty() {
            self.absorb();
        }
        self.pending.pop_front()
    }
}

/// The terminal's size, or `None` where there is no terminal to ask.
///
/// On the Unix host this is `TIOCGWINSZ`; on Motor OS it is the last size the
/// terminal reported to crossterm's event source, falling back to `$COLUMNS` —
/// which the terminal's owner sets at spawn — and then to 80. Cheap, and it
/// cannot block — but it is asked only where there is a terminal, because
/// crossterm's host path falls back to *spawning* `tput` when the ioctl has
/// nothing to say, and a prompt is not the place to spawn a process.
fn terminal_size() -> Option<(usize, usize)> {
    if !std::io::stdout().is_terminal() {
        return None;
    }
    match crossterm::terminal::size() {
        Ok((cols, rows)) if cols > 0 && rows > 0 => Some((usize::from(cols), usize::from(rows))),
        _ => None,
    }
}

/// The terminal's width, or [`DEFAULT_COLS`] where there is no terminal to ask.
fn terminal_cols() -> usize {
    terminal_size().map_or(DEFAULT_COLS, |(cols, _)| cols)
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
    history: History,

    /// The screen, as this editor last painted it.
    painted: Option<Painted>,

    /// The width every layout on screen was computed with.
    ///
    /// Sampled at the start of each line and updated whenever the terminal says
    /// it changed shape, so that one line is never painted at two widths.
    cols: usize,
    /// Whether there is no terminal at all (`--piped`).
    piped: bool,

    /// The text `^K`/`^U`/`^W` cut and `^Y` pastes back.
    kill_ring: Vec<char>,
}

impl Term {
    fn new(piped: bool) -> Self {
        Self {
            input: Stdin::new(),
            history: History::new(),
            painted: None,
            cols: DEFAULT_COLS,
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

    /// Paint prompt + line and leave the cursor at `pos`.
    fn render(&mut self, prompt: &Prompt, line: &[char], pos: usize) {
        let cols = self.cols;
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
        let k = prev
            .line
            .iter()
            .zip(line)
            .take_while(|(a, b)| a == b)
            .count();

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
                wrap_now(&mut buf);
            }
            // The old line reached further than the new one — erase the rest of
            // it, or it stays on the screen as a ghost.
            let was = cell_at(plen, &prev.line, prev.line.len(), cols);
            if was > at {
                paint(&mut buf, Clear(ClearType::UntilNewLine));
                for _ in at.0..was.0 {
                    paint(&mut buf, cursor::MoveDown(1));
                    paint(&mut buf, cursor::MoveToColumn(0));
                    paint(&mut buf, Clear(ClearType::UntilNewLine));
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
            let mut hidden = String::new();
            paint(&mut hidden, cursor::Hide);
            hidden.push_str(&buf);
            paint(&mut hidden, cursor::Show);
            self.write(hidden.as_bytes());
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

        paint(&mut buf, cursor::Hide); // one flicker-free paint
        // Down to the last row of the *previous* paint, then erase upward.
        if rows > crow + 1 {
            paint(&mut buf, cursor::MoveDown(steps(rows - crow - 1)));
        }
        for _ in 1..rows {
            paint(&mut buf, cursor::MoveToColumn(0));
            paint(&mut buf, Clear(ClearType::UntilNewLine));
            paint(&mut buf, cursor::MoveUp(1));
        }
        paint(&mut buf, cursor::MoveToColumn(0));
        paint(&mut buf, Clear(ClearType::UntilNewLine));

        buf.push_str(&prompt.text);
        buf.extend(line.iter());
        if lay.wrapped_end {
            wrap_now(&mut buf);
        }
        // The cursor is at the end of the text; walk it back to `pos`.
        let end = cell_at(prompt.width, line, line.len(), cols);
        move_cursor(&mut buf, end, (lay.crow, lay.ccol));
        paint(&mut buf, cursor::Show);

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
    /// never answer — so it uses the trick zsh calls
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
        let mut buf = String::new();
        paint(&mut buf, cursor::Hide);
        paint(&mut buf, SetAttribute(Attribute::Reverse)); // as zsh's marker is
        buf.push('%');
        paint(&mut buf, SetAttribute(Attribute::Reset));
        buf.push_str(&" ".repeat(self.cols.saturating_sub(1)));
        paint(&mut buf, cursor::MoveToColumn(0));
        paint(&mut buf, cursor::Show);
        self.write(buf.as_bytes());
    }

    /// Wait for the next key.
    ///
    /// Everything that is not a key is handled here rather than by the editor:
    /// a resize is the terminal's own news and the width it carries is what the
    /// next paint has to be laid out for, so it is taken before the caller sees
    /// it. A read error is as final as EOF — a shell whose terminal went away
    /// exits rather than spinning on it.
    fn read_key(&mut self) -> Key {
        loop {
            match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => return key_of(key),
                Ok(Event::Resize(cols, _)) if cols > 0 => {
                    self.cols = usize::from(cols);
                    return Key::Resize(self.cols);
                }
                // A key release, a resize to nothing, a paste: not this editor's.
                Ok(_) => {}
                Err(_) => return Key::Eof,
            }
        }
    }

    fn readline(&mut self, prompt: &str, continuation: bool, sh: &Shell) -> ReadOutcome {
        let prompt = Prompt::new(prompt);
        if self.piped {
            return self.readline_piped(&prompt, continuation);
        }
        // Raw mode is the editor's for as long as it is editing: it owns the
        // echo, the line editing and the `^C`. On Motor OS the console is always
        // raw and this only records the fact, which is what makes a bare LF a
        // `^J` there rather than a second Enter.
        let _ = enable_raw_mode();
        self.cols = terminal_cols();

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
                    self.write(b"\r\n");
                    let _ = disable_raw_mode();
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
                    // either, where raw mode clears ISIG. So the shell raises
                    // SIGINT itself, and any
                    // `trap … INT` fires from the interactive loop's safe point
                    // exactly as it would on a signalling platform.
                    crate::sys::note_signal(crate::signal::SIGINT);
                    self.write(b"^C\r\n");
                    let _ = disable_raw_mode();
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
                        self.write(b"\r\n");
                        let _ = disable_raw_mode();
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
                    let _ = disable_raw_mode();
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
                    let mut buf = String::new();
                    paint(&mut buf, cursor::MoveTo(0, 0));
                    paint(&mut buf, Clear(ClearType::All));
                    self.write(buf.as_bytes());
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
                // The terminal changed shape under the line being typed. The
                // width is already taken (`read_key`); what is left is to lay
                // the line out again, because the paint on screen was computed
                // against a screen that no longer exists.
                Key::Resize(_) => self.render(&prompt, &line, pos),
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
                // A resize is not the user leaving the search: the loop paints
                // the search prompt again at the width `read_key` just took.
                Key::Resize(_) => {}
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
        self.write(b"\r\n");
        if candidates.len() > MAX_UNASKED_CANDIDATES && !self.confirm_listing(candidates.len()) {
            return;
        }
        let names: Vec<&str> = candidates.iter().map(|c| display_name(c)).collect();
        let cols = self.cols;
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
                    self.write(b"\r\n");
                    return true;
                }
                Key::Char('n') | Key::Char('N') | Key::Ctrl('c') | Key::Eof => {
                    self.write(b"\r\n");
                    return false;
                }
                // The question is still the question at a different width.
                Key::Resize(_) => {}
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

/// Put `$COLUMNS` and `$LINES` back in step with the terminal.
///
/// A resize is news the shell has and a command it launches does not: the size
/// a program is given at spawn is the environment it inherits, and on Motor OS
/// that environment is how the terminal's owner — rmux for a pane, russhd for a
/// session — tells a child how big its terminal is before the child has said
/// anything at all (`docs/plans/terminal-size-events.md` §5). A shell that let
/// those variables go stale would hand every program it started the size the
/// terminal used to be, and the design's promise that owner-known geometry is
/// right at *first* paint would hold for the shell and for nobody it ran.
///
/// bash does the same under `checkwinsize`, on by default since 5.0, and so is
/// the export rule this borrows from [`Shell::set`]: the value follows the
/// variable it is assigned to. Under rmux and over ssh the owner put `$COLUMNS`
/// in the environment, so the update stays in the environment and reaches
/// children; on the serial console, where nobody set it, it stays a shell
/// variable — the console's children ask the terminal themselves, over the very
/// same wire their parent did.
pub fn sync_size(sh: &mut Shell) {
    let Some((cols, rows)) = terminal_size() else {
        return;
    };
    // `readonly COLUMNS` is the user's decision and is not worth a complaint at
    // every prompt; the assignment is simply not made.
    let _ = sh.set("COLUMNS", cols.to_string());
    let _ = sh.set("LINES", rows.to_string());
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
        if !term.piped {
            // The terminal is the user's again — on the host that is termios
            // being put back, and on Motor OS it is nothing at all.
            let _ = disable_raw_mode();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key event a terminal sends for `code` with `mods`.
    fn event(code: KeyCode, mods: KeyModifiers) -> Key {
        key_of(KeyEvent::new(code, mods))
    }

    /// A plain, unmodified key.
    fn plain(code: KeyCode) -> Key {
        event(code, KeyModifiers::NONE)
    }

    /// A key with control held: what a control byte parses as.
    fn ctrl(c: char) -> Key {
        event(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn characters_and_the_named_keys_are_themselves() {
        assert_eq!(plain(KeyCode::Char('a')), Key::Char('a'));
        assert_eq!(plain(KeyCode::Char(' ')), Key::Char(' '));
        // Uppercase arrives with shift held, and is still the character typed.
        assert_eq!(
            event(KeyCode::Char('A'), KeyModifiers::SHIFT),
            Key::Char('A')
        );
        assert_eq!(plain(KeyCode::Char('日')), Key::Char('日'));
        assert_eq!(plain(KeyCode::Enter), Key::Enter);
        assert_eq!(plain(KeyCode::Tab), Key::Tab);
        assert_eq!(plain(KeyCode::Backspace), Key::Backspace);
        assert_eq!(plain(KeyCode::Delete), Key::Delete);
        assert_eq!(plain(KeyCode::Up), Key::Up);
        assert_eq!(plain(KeyCode::Down), Key::Down);
        assert_eq!(plain(KeyCode::Left), Key::Left);
        assert_eq!(plain(KeyCode::Right), Key::Right);
        assert_eq!(plain(KeyCode::Home), Key::Home);
        assert_eq!(plain(KeyCode::End), Key::End);
    }

    #[test]
    fn control_keys_are_the_letters_the_bindings_name() {
        assert_eq!(ctrl('a'), Key::Ctrl('a'));
        assert_eq!(ctrl('c'), Key::Ctrl('c'));
        assert_eq!(ctrl('d'), Key::Ctrl('d'));
        assert_eq!(ctrl('r'), Key::Ctrl('r'));
        assert_eq!(ctrl('z'), Key::Ctrl('z'));
        // Ctrl-Shift-C is `^C`: a control byte carries no case.
        assert_eq!(
            event(
                KeyCode::Char('C'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT
            ),
            Key::Ctrl('c')
        );
    }

    #[test]
    fn the_two_keys_terminals_disagree_about_have_both_spellings() {
        // A console that sends a bare LF for Enter reaches raw mode as `^J`
        // (crossterm's issue #371), and dropping it would leave such a terminal
        // with no way to run anything. `^H` is the other Backspace: terminals
        // disagree about which one the key sends and Motor OS has no termios
        // `erase` setting to consult.
        assert_eq!(ctrl('j'), Key::Enter);
        assert_eq!(ctrl('h'), Key::Backspace);
    }

    #[test]
    fn word_motion_is_reached_with_either_modifier() {
        // `ESC[1;5C` is Ctrl-Right and `ESC[1;3C` is Alt-Right; readline moves
        // by a word for both.
        assert_eq!(event(KeyCode::Right, KeyModifiers::CONTROL), Key::WordRight);
        assert_eq!(event(KeyCode::Right, KeyModifiers::ALT), Key::WordRight);
        assert_eq!(event(KeyCode::Left, KeyModifiers::CONTROL), Key::WordLeft);
        assert_eq!(event(KeyCode::Left, KeyModifiers::ALT), Key::WordLeft);
    }

    #[test]
    fn meta_keys_are_the_alt_bindings() {
        assert_eq!(event(KeyCode::Char('b'), KeyModifiers::ALT), Key::Alt('b'));
        assert_eq!(event(KeyCode::Char('f'), KeyModifiers::ALT), Key::Alt('f'));
        assert_eq!(event(KeyCode::Char('d'), KeyModifiers::ALT), Key::Alt('d'));
        // Alt-Backspace kills the word behind the cursor.
        assert_eq!(
            event(KeyCode::Backspace, KeyModifiers::ALT),
            Key::Alt('\x7f')
        );
    }

    #[test]
    fn a_key_the_editor_has_no_use_for_is_not_guessed_at() {
        // The editor beeps for these rather than inserting garbage -- and in
        // `^R` an `Esc` leaves the search, which is what `Unknown` means there.
        assert_eq!(plain(KeyCode::Esc), Key::Unknown);
        assert_eq!(plain(KeyCode::F(5)), Key::Unknown);
        assert_eq!(plain(KeyCode::BackTab), Key::Unknown);
        assert_eq!(plain(KeyCode::Insert), Key::Unknown);
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
        // The default `PS1` itself: its amber is a multi-parameter `38;5;n`,
        // which a stripper that stopped at the first `m` would measure wrong,
        // and a prompt measured wrong is a line edited in the wrong column.
        let ps1 = crate::shell::default_prompt("PS1").replace("$PWD", "/tmp");
        assert_eq!(display_width(&ps1), 11, "{ps1:?}");
    }

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn layout_of_a_line_that_fits_is_one_row() {
        let l = layout(2, &chars("echo hi"), 7, 80);
        assert_eq!(
            l,
            Layout {
                rows: 1,
                crow: 0,
                ccol: 9,
                wrapped_end: false
            }
        );
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
        assert_eq!(
            l.rows, 2,
            "the empty next row is real: the terminal is on it"
        );
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
        // Column 0 is named rather than returned to. Three bytes more than the
        // `\r` this used to be, and worth them: a movement the editor makes on
        // purpose says so, where a carriage return is also the thing terminals
        // rewrite (sys-tty puts a `\r` after every `\n` it sends).
        assert_eq!(moves((1, 9), (1, 0)), "\x1b[1G");
        // A vertical move keeps the column, so only the difference is paid for.
        assert_eq!(moves((3, 9), (1, 0)), "\x1b[2A\x1b[1G");
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
