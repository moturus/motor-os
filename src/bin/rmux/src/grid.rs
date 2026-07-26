//! The screen a pane's program thinks it is writing on.
//!
//! [`Grid`] consumes the [`Action`]s `ansi.rs` decodes and is the other pure
//! half of the emulator (details.md §5.1): no I/O, no pane, no console. Give it
//! bytes' worth of actions and ask it what the screen says — which is what
//! makes every rule below testable on Linux in milliseconds, and what the tmux
//! oracle will later compare against (§9.1).
//!
//! Two rules here are load-bearing far outside this module:
//!
//! - **The cursor is clamped to the grid, and clamping is what reports the
//!   size.** `ESC[999C` and `ESC[9999;9999H` are how rush and red ask how wide
//!   their terminal is (§3.2); both stop at the last column, and the DSR that
//!   follows reports where they landed. Clamp to the *pane*, and red sizes
//!   itself to its pane; clamp to anything else and it draws outside it.
//! - **Wrapping is deferred.** A character written to the last column does not
//!   move the cursor; it arms a pending wrap that the *next* character spends
//!   (§5.3). Getting this wrong is invisible until something draws a box.
//!
//! Every character is one column wide, including the wide ones — the project's
//! pure-ASCII treatment, and a documented divergence (§1.2).
//!
//! What the grid does *not* do is talk to anything. A `ESC[6n` comes back out
//! as a [`Reply`] for the pane to write into its child's stdin (§5.3); the grid
//! never learns there is a pipe.
//!
//! # History is not made of grids
//!
//! `history-limit 9999999` (§2.1) is ten million lines *per pane*, and a
//! `Vec<Cell>` apiece would be gigabytes on an OS that does not have them
//! (§7.5). So a line that scrolls off the top stops being cells and becomes a
//! [`Line`]: its text as a `String`, its styling as a run-length list, and its
//! trailing blanks not stored at all. The live screen stays `Cell`-based;
//! only history is compacted, and [`Grid::row_cells`] renders either kind, so
//! copy mode never learns which side of the boundary a row is on.

use std::collections::VecDeque;

use crate::ansi::Action;
use crate::ansi::Csi;

/// A colour as a program may name one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Color {
    #[default]
    Default,
    /// A palette entry: SGR 30-37, 90-97 and `38;5;n` all land here.
    Indexed(u8),
    Rgb(u8, u8, u8),
}

/// How a cell looks.
///
/// red's cell holds `style: &'static str`, a reset-prefixed SGR literal, and
/// that is exactly what rmux cannot do — a pane composites arbitrary SGR from a
/// child (§6.1). What is kept is the *invariant*: this is `Copy` and `Eq`, so
/// the frame diff compares cells directly, and it renders to a self-contained,
/// reset-prefixed SGR at diff time. There is no `String` in a cell.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub fg: Color,
    pub bg: Color,
    /// Bold, underline, reverse and friends, one bit each.
    pub flags: u8,
}

impl Attrs {
    pub const BOLD: u8 = 1 << 0;
    pub const DIM: u8 = 1 << 1;
    pub const ITALIC: u8 = 1 << 2;
    pub const UNDERLINE: u8 = 1 << 3;
    pub const BLINK: u8 = 1 << 4;
    pub const REVERSE: u8 = 1 << 5;
    pub const HIDDEN: u8 = 1 << 6;
    pub const STRIKE: u8 = 1 << 7;

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub attrs: Attrs,
}

impl Default for Cell {
    fn default() -> Cell {
        Cell {
            ch: ' ',
            attrs: Attrs::default(),
        }
    }
}

/// A line that has scrolled off the top, stored the way ten million of them
/// have to be (§7.5).
///
/// Typical shell output is unstyled ASCII, which this keeps at about a byte per
/// character: the text is a `String`, `spans` is empty unless something is
/// styled, and trailing blanks are dropped on the way in — a blank line costs
/// an empty `String` rather than 80 cells.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    text: String,
    /// How many characters look alike, in order, covering `text`. Empty means
    /// the whole line is in the default style, which is the common case.
    spans: Vec<(u32, Attrs)>,
}

impl Line {
    fn from_cells(cells: &[Cell]) -> Line {
        let end = cells
            .iter()
            .rposition(|cell| *cell != Cell::default())
            .map_or(0, |at| at + 1);
        let kept = &cells[..end];

        let mut spans: Vec<(u32, Attrs)> = Vec::new();
        for cell in kept {
            match spans.last_mut() {
                Some((run, attrs)) if *attrs == cell.attrs => *run += 1,
                _ => spans.push((1, cell.attrs)),
            }
        }
        if spans.iter().all(|(_, attrs)| *attrs == Attrs::default()) {
            spans.clear();
        }
        Line {
            text: kept.iter().map(|cell| cell.ch).collect(),
            spans,
        }
    }

    /// The line as cells again, `cols` of them: what a compositor needs.
    pub fn cells(&self, cols: usize) -> Vec<Cell> {
        let mut cells: Vec<Cell> = self
            .text
            .chars()
            .map(|ch| Cell {
                ch,
                attrs: Attrs::default(),
            })
            .collect();
        let mut at = 0;
        for (run, attrs) in &self.spans {
            for cell in cells.iter_mut().skip(at).take(*run as usize) {
                cell.attrs = *attrs;
            }
            at += *run as usize;
        }
        cells.resize(cols, Cell::default());
        cells.truncate(cols);
        cells
    }

    /// The line's text, which is what a search reads.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// How much scrollback a pane keeps unless a config says otherwise.
///
/// §2.1's `set -g history-limit 9999999`, and a *cap* rather than a
/// preallocation: memory tracks what a pane has actually printed (§7.5).
pub const DEFAULT_HISTORY_LIMIT: usize = 9_999_999;

/// One pane's screen.
pub struct Grid {
    rows: usize,
    cols: usize,
    cells: Vec<Cell>,
    row: usize,
    col: usize,
    attrs: Attrs,
    /// The last column has been written and the next character wraps (§5.3).
    pending_wrap: bool,
    /// DECAWM. On by default, as every terminal has it.
    autowrap: bool,
    /// Whether `\n` is a *new line* — a carriage return as well as an index.
    ///
    /// DEC calls this LNM, and a real terminal leaves it off because the tty's
    /// line discipline adds the carriage return on the way out (`ONLCR`). Motor
    /// OS has no line discipline (details.md §3.1) and a pane there is a pipe, so
    /// there is nothing between a program's `\n` and this grid — which is why
    /// `sys-tty` rewrites `\n` as `\n\r` for the real console (§3.3), and why a
    /// pane must do the same or every second line of output starts where the
    /// last one ended. Set by [`crate::pane::Pane`] from the platform, not by a
    /// program: `ESC[20h` is not parsed, because a program that turned it *off*
    /// on Motor would be turning off what the platform's own terminal does
    /// unconditionally.
    newline_mode: bool,
    /// The scroll region (DECSTBM), inclusive. Scrolling happens *here*, and
    /// only here: it is what a full-screen program uses to keep a status line
    /// still while the text above it moves.
    top: usize,
    bottom: usize,
    /// DECTCEM. Per *pane*: only the active pane's cursor is composited, so an
    /// inactive pane hiding its own must not hide the user's (§3.2).
    cursor_visible: bool,
    /// Bracketed paste, as this pane asked for it. rmux turns it off on its own
    /// console but wraps a paste in whatever the pane wants (§7.6).
    bracketed_paste: bool,
    saved: Saved,
    /// The primary screen, parked while the alt screen is in front of it.
    primary: Option<Primary>,
    /// OSC 0/2, which is what the status line shows.
    title: String,
    /// The lines that have scrolled off the top, oldest first (§7.5).
    history: VecDeque<Line>,
    /// How many of them are kept. `history-limit` (§2.2), a cap and no more.
    history_limit: usize,
    /// Whether the program has ever asked where the cursor is (DSR 6).
    ///
    /// It is how a program asks how big its terminal is (§3.2), and a program
    /// that has asked once has a parser for the answer by construction — which
    /// is what makes it safe to answer *again*, unasked, when the size changes.
    /// [`crate::pane::Pane::resize`] is what does that; nothing here does.
    asked_where_it_is: bool,
}

/// A cursor put away by `ESC 7`, and brought back by `ESC 8`.
#[derive(Clone, Copy, Default)]
struct Saved {
    row: usize,
    col: usize,
    attrs: Attrs,
}

/// The primary screen while `?1049` has the alt screen in front of it.
///
/// The alt screen is a *fresh* grid and its scrolled-off lines are discarded
/// (§5.3) -- red lives there (`red/src/terminal.rs:14`), so this is exercised
/// the moment red runs in a pane.
struct Primary {
    cells: Vec<Cell>,
    row: usize,
    col: usize,
    attrs: Attrs,
    top: usize,
    bottom: usize,
}

/// Something a pane owes its child, written to that child's *stdin*.
///
/// The one round trip a terminal makes on a program's behalf, and the reason
/// rush reports its pane's width and red its pane's geometry (§3.2). Getting
/// the direction backwards -- answering on stdout -- is the easy mistake
/// (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// `ESC[{row};{col}R`, one-based, as DSR 6 asks for.
    CursorPosition { row: usize, col: usize },
}

impl Reply {
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Reply::CursorPosition { row, col } => format!("\x1b[{row};{col}R").into_bytes(),
        }
    }
}

impl Grid {
    pub fn new(rows: usize, cols: usize) -> Grid {
        let (rows, cols) = (rows.max(1), cols.max(1));
        Grid {
            rows,
            cols,
            cells: vec![Cell::default(); rows * cols],
            row: 0,
            col: 0,
            attrs: Attrs::default(),
            pending_wrap: false,
            autowrap: true,
            newline_mode: false,
            top: 0,
            bottom: rows - 1,
            cursor_visible: true,
            bracketed_paste: false,
            saved: Saved::default(),
            primary: None,
            title: String::new(),
            history: VecDeque::new(),
            history_limit: DEFAULT_HISTORY_LIMIT,
            asked_where_it_is: false,
        }
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// How many lines a pane keeps once they have scrolled off (§2.2).
    pub fn set_history_limit(&mut self, limit: usize) {
        self.history_limit = limit;
        self.trim_history();
    }

    /// How many lines are in the scrollback right now.
    ///
    /// **None at all while the alt screen is up** (§5.3). The lines above a
    /// full-screen program's screen belong to the screen *underneath* it, and
    /// showing them in copy mode would put a shell's old output above red's
    /// window; they are still there when the program gives the screen back.
    pub fn history(&self) -> usize {
        if self.primary.is_some() {
            0
        } else {
            self.history.len()
        }
    }

    /// Every row this pane has, history included: what copy mode walks (§7.6).
    pub fn total_rows(&self) -> usize {
        self.history() + self.rows
    }

    /// One row of that, wherever it lives.
    ///
    /// The accessor §7.5 asks for: below [`Grid::history`] it renders a
    /// compacted [`Line`], above it copies cells, and a caller cannot tell
    /// which without asking.
    pub fn row_cells(&self, at: usize) -> Vec<Cell> {
        if at < self.history() {
            return self.history[at].cells(self.cols);
        }
        match at - self.history() {
            row if row < self.rows => self.cells[row * self.cols..(row + 1) * self.cols].to_vec(),
            _ => vec![Cell::default(); self.cols],
        }
    }

    /// The same row's text, trailing blanks trimmed — what a search reads.
    pub fn row_text(&self, at: usize) -> String {
        if at < self.history() {
            return self.history[at].text().trim_end().to_owned();
        }
        match at - self.history() {
            row if row < self.rows => self.line(row),
            _ => String::new(),
        }
    }

    /// Whether this pane's program has ever asked where the cursor is (DSR 6).
    pub fn asked_where_it_is(&self) -> bool {
        self.asked_where_it_is
    }

    /// Make `\n` a new line rather than a bare index (see `newline_mode`).
    pub fn set_newline_mode(&mut self, on: bool) {
        self.newline_mode = on;
    }

    /// Change the size of the screen this pane's program is writing on.
    ///
    /// Content is **clipped and padded**, never reflowed: a line that no longer
    /// fits loses its tail rather than wrapping onto the next row. That is what
    /// tmux does, and it is what keeps a resize from rewriting history that a
    /// program still believes it has addressed. The scroll region goes back to
    /// the whole screen, as it must -- a region can outlive the rows it named.
    pub fn resize(&mut self, rows: usize, cols: usize) {
        let (rows, cols) = (rows.max(1), cols.max(1));
        if (rows, cols) == (self.rows, self.cols) {
            return;
        }

        self.cells = reshape(&self.cells, self.rows, self.cols, rows, cols);
        if let Some(primary) = &mut self.primary {
            primary.cells = reshape(&primary.cells, self.rows, self.cols, rows, cols);
            primary.row = primary.row.min(rows - 1);
            primary.col = primary.col.min(cols - 1);
            primary.top = 0;
            primary.bottom = rows - 1;
        }

        self.rows = rows;
        self.cols = cols;
        self.top = 0;
        self.bottom = rows - 1;
        self.row = self.row.min(rows - 1);
        self.col = self.col.min(cols - 1);
        self.saved.row = self.saved.row.min(rows - 1);
        self.saved.col = self.saved.col.min(cols - 1);
        self.pending_wrap = false;
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    /// The cursor, as a zero-based (row, column).
    ///
    /// A pending wrap is *not* reflected here: the cursor is still on the last
    /// column it wrote, which is what a DSR must report.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// Whether this pane wants its cursor drawn (§3.2).
    pub fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    /// Whether this pane asked for bracketed paste (§7.6).
    pub fn bracketed_paste(&self) -> bool {
        self.bracketed_paste
    }

    pub fn on_alt_screen(&self) -> bool {
        self.primary.is_some()
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn cell(&self, row: usize, col: usize) -> Cell {
        self.cells[row * self.cols + col]
    }

    /// A row's text, with trailing blanks trimmed.
    pub fn line(&self, row: usize) -> String {
        let start = row * self.cols;
        let text: String = self.cells[start..start + self.cols]
            .iter()
            .map(|cell| cell.ch)
            .collect();
        text.trim_end().to_owned()
    }

    /// Apply one action, and hand back anything the child is owed in return.
    pub fn apply(&mut self, action: Action<'_>) -> Option<Reply> {
        match action {
            Action::Print(c) => self.print(c),
            Action::C0(byte) => self.control(byte),
            Action::Csi(csi) => return self.csi(csi),
            Action::Esc {
                intermediates: [],
                final_byte,
            } => self.esc(final_byte),
            // A charset designation (`ESC ( B`) and every other intermediate
            // form: parsed so it cannot be printed, and otherwise ignored.
            Action::Esc { .. } => {}
            Action::Osc(string) => self.osc(string),
        }
        None
    }

    fn print(&mut self, c: char) {
        if self.pending_wrap {
            self.col = 0;
            self.index();
            self.pending_wrap = false;
        }
        let (row, col) = (self.row, self.col);
        self.cells[row * self.cols + col] = Cell {
            ch: c,
            attrs: self.attrs,
        };
        if self.col + 1 < self.cols {
            self.col += 1;
        } else if self.autowrap {
            self.pending_wrap = true;
        }
    }

    fn control(&mut self, byte: u8) {
        match byte {
            0x08 => {
                self.col = self.col.saturating_sub(1);
                self.pending_wrap = false;
            }
            b'\t' => self.move_to(self.row, ((self.col / 8) + 1) * 8),
            b'\n' | 0x0b | 0x0c => {
                self.index();
                if self.newline_mode {
                    self.col = 0;
                }
            }
            b'\r' => {
                self.col = 0;
                self.pending_wrap = false;
            }
            _ => {}
        }
    }

    fn csi(&mut self, csi: Csi<'_>) -> Option<Reply> {
        let count = |i| csi.count(i) as usize;
        match csi.final_byte {
            b'A' => self.move_to(self.row.saturating_sub(count(0)), self.col),
            b'B' => self.move_to(self.row + count(0), self.col),
            b'C' => self.move_to(self.row, self.col + count(0)),
            b'D' => self.move_to(self.row, self.col.saturating_sub(count(0))),
            b'G' => self.move_to(self.row, count(0) - 1),
            b'd' => self.move_to(count(0) - 1, self.col),
            b'H' | b'f' => self.move_to(count(0) - 1, count(1) - 1),
            b'J' => self.erase_in_display(csi.raw(0)),
            b'K' => self.erase_in_line(csi.raw(0)),
            b'm' => self.sgr(csi.params),
            b'L' => self.insert_lines(count(0)),
            b'M' => self.delete_lines(count(0)),
            b'@' => self.insert_chars(count(0)),
            b'P' => self.delete_chars(count(0)),
            b'X' => self.erase_chars(count(0)),
            b'S' => self.scroll_region_up(count(0)),
            b'T' => self.scroll_region_down(count(0)),
            b'r' if csi.private.is_none() => self.set_scroll_region(&csi),
            b'h' => self.set_mode(&csi, true),
            b'l' => self.set_mode(&csi, false),
            // DSR 6, and only 6: nothing rmux hosts asks anything else, and a
            // terminal is entitled to leave a question unanswered (§3.2).
            b'n' if csi.raw(0) == 6 => {
                self.asked_where_it_is = true;
                return Some(Reply::CursorPosition {
                    row: self.row + 1,
                    col: self.col + 1,
                });
            }
            _ => {}
        }
        None
    }

    /// The private modes rmux implements (§5.2). An ANSI mode -- `ESC[4h` and
    /// the rest -- reaches nothing here; none of them are wanted.
    fn set_mode(&mut self, csi: &Csi<'_>, on: bool) {
        if csi.private != Some(b'?') {
            return;
        }
        for param in csi.params {
            match param {
                7 => self.autowrap = on,
                25 => self.cursor_visible = on,
                // 47 and 1047 are the older spellings, without the implicit
                // cursor save that 1049 makes explicit; rmux saves either way.
                47 | 1047 | 1049 => {
                    if on {
                        self.enter_alt_screen();
                    } else {
                        self.leave_alt_screen();
                    }
                }
                1048 => {
                    if on {
                        self.save_cursor();
                    } else {
                        self.restore_cursor();
                    }
                }
                2004 => self.bracketed_paste = on,
                _ => {}
            }
        }
    }

    fn enter_alt_screen(&mut self) {
        if self.primary.is_some() {
            return;
        }
        let fresh = vec![Cell::default(); self.rows * self.cols];
        self.primary = Some(Primary {
            cells: std::mem::replace(&mut self.cells, fresh),
            row: self.row,
            col: self.col,
            attrs: self.attrs,
            top: self.top,
            bottom: self.bottom,
        });
        self.attrs = Attrs::default();
        self.top = 0;
        self.bottom = self.rows - 1;
        self.move_to(0, 0);
    }

    fn leave_alt_screen(&mut self) {
        let Some(primary) = self.primary.take() else {
            return;
        };
        self.cells = primary.cells;
        self.attrs = primary.attrs;
        self.top = primary.top;
        self.bottom = primary.bottom;
        self.move_to(primary.row, primary.col);
    }

    fn save_cursor(&mut self) {
        self.saved = Saved {
            row: self.row,
            col: self.col,
            attrs: self.attrs,
        };
    }

    fn restore_cursor(&mut self) {
        let saved = self.saved;
        self.attrs = saved.attrs;
        self.move_to(saved.row, saved.col);
    }

    /// OSC 0 and 2 name the window. Everything else -- including 52, the
    /// clipboard rmux deliberately does not have (§7.6) -- is dropped.
    fn osc(&mut self, string: &[u8]) {
        let mut parts = string.splitn(2, |byte| *byte == b';');
        if let (Some(b"0" | b"2"), Some(title)) = (parts.next(), parts.next()) {
            self.title = String::from_utf8_lossy(title).into_owned();
        }
    }

    fn esc(&mut self, final_byte: u8) {
        match final_byte {
            b'7' => self.save_cursor(),
            b'8' => self.restore_cursor(),
            b'D' => self.index(),
            b'M' => self.reverse_index(),
            // NEL is a carriage return and an index, in that order.
            b'E' => {
                self.move_to(self.row, 0);
                self.index();
            }
            _ => {}
        }
    }

    /// Select graphic rendition: what cells written from now on look like.
    ///
    /// `ESC[m` with no parameters is `ESC[0m`, a full reset — which is what
    /// makes red's reset-prefixed style literals work at all (§6.1), and what
    /// every partial repaint depends on.
    fn sgr(&mut self, params: &[u16]) {
        if params.is_empty() {
            self.attrs = Attrs::default();
            return;
        }
        let mut i = 0;
        while i < params.len() {
            match params[i] {
                0 => self.attrs = Attrs::default(),
                1 => self.attrs.flags |= Attrs::BOLD,
                2 => self.attrs.flags |= Attrs::DIM,
                3 => self.attrs.flags |= Attrs::ITALIC,
                4 => self.attrs.flags |= Attrs::UNDERLINE,
                5 | 6 => self.attrs.flags |= Attrs::BLINK,
                7 => self.attrs.flags |= Attrs::REVERSE,
                8 => self.attrs.flags |= Attrs::HIDDEN,
                9 => self.attrs.flags |= Attrs::STRIKE,
                // 21 is "doubly underlined" in ECMA-48 and "bold off" in much
                // of the world; both readings clear the bold rmux can show.
                21 | 22 => self.attrs.flags &= !(Attrs::BOLD | Attrs::DIM),
                23 => self.attrs.flags &= !Attrs::ITALIC,
                24 => self.attrs.flags &= !Attrs::UNDERLINE,
                25 => self.attrs.flags &= !Attrs::BLINK,
                27 => self.attrs.flags &= !Attrs::REVERSE,
                28 => self.attrs.flags &= !Attrs::HIDDEN,
                29 => self.attrs.flags &= !Attrs::STRIKE,
                30..=37 => self.attrs.fg = Color::Indexed((params[i] - 30) as u8),
                38 => i += self.extended_color(&params[i..], true),
                39 => self.attrs.fg = Color::Default,
                40..=47 => self.attrs.bg = Color::Indexed((params[i] - 40) as u8),
                48 => i += self.extended_color(&params[i..], false),
                49 => self.attrs.bg = Color::Default,
                90..=97 => self.attrs.fg = Color::Indexed((params[i] - 90 + 8) as u8),
                100..=107 => self.attrs.bg = Color::Indexed((params[i] - 100 + 8) as u8),
                _ => {}
            }
            i += 1;
        }
    }

    /// `38;5;n` and `38;2;r;g;b`, and their `48` counterparts for the
    /// background. Returns how many *extra* parameters were swallowed, so an
    /// SGR that continues after a colour is not misread as more colours.
    fn extended_color(&mut self, params: &[u16], foreground: bool) -> usize {
        let byte = |i: usize| params.get(i).copied().unwrap_or(0).min(255) as u8;
        let (color, used) = match params.get(1) {
            Some(5) => (Color::Indexed(byte(2)), 2),
            Some(2) => (Color::Rgb(byte(2), byte(3), byte(4)), 4),
            _ => return 0,
        };
        if foreground {
            self.attrs.fg = color;
        } else {
            self.attrs.bg = color;
        }
        used
    }

    /// Move down one row, scrolling when the row below is outside the region.
    fn index(&mut self) {
        if self.row == self.bottom {
            self.scroll_region_up(1);
        } else if self.row + 1 < self.rows {
            self.row += 1;
        }
        self.pending_wrap = false;
    }

    /// Move up one row, scrolling when the row above is outside the region.
    fn reverse_index(&mut self) {
        if self.row == self.top {
            self.scroll_region_down(1);
        } else {
            self.row = self.row.saturating_sub(1);
        }
        self.pending_wrap = false;
    }

    fn set_scroll_region(&mut self, csi: &Csi<'_>) {
        let top = csi.count(0) as usize - 1;
        // An absent second parameter means the last row -- `ESC[r` is how a
        // program puts the region back to the whole screen.
        let bottom = match csi.params.get(1) {
            Some(0) | None => self.rows,
            Some(bottom) => (*bottom as usize).min(self.rows),
        };
        let bottom = bottom.saturating_sub(1);
        if top < bottom && bottom < self.rows {
            self.top = top;
            self.bottom = bottom;
            self.move_to(0, 0);
        }
    }

    /// Move the region's lines up, keeping what leaves the top (§7.5).
    fn scroll_region_up(&mut self, lines: usize) {
        let height = self.bottom - self.top + 1;
        let lines = lines.min(height);
        self.remember(lines);
        let (blank, cols) = (self.blank(), self.cols);
        let (first, last) = (self.top * cols, (self.bottom + 1) * cols);
        self.cells[first..last].rotate_left(lines * cols);
        self.cells[last - lines * cols..last].fill(blank);
    }

    /// Put the lines about to leave the top of the screen into history.
    ///
    /// **Only the whole screen scrolling into history**, which is what tmux
    /// does (`grid_view_scroll_region_up`: the lines are kept when the region
    /// is every row and moved without them otherwise). A program with a scroll
    /// region is holding a header or a status line still and moving text
    /// *between* them; those lines never left its screen, and putting them in
    /// the scrollback would interleave a redrawn pager with itself.
    ///
    /// The alt screen has no scrollback at all (§5.3) — red lives there, and
    /// its every repaint would otherwise become history.
    fn remember(&mut self, lines: usize) {
        if self.primary.is_some() || self.top != 0 || self.bottom + 1 != self.rows {
            return;
        }
        for row in 0..lines.min(self.rows) {
            let start = row * self.cols;
            self.history
                .push_back(Line::from_cells(&self.cells[start..start + self.cols]));
        }
        self.trim_history();
    }

    fn trim_history(&mut self) {
        while self.history.len() > self.history_limit {
            self.history.pop_front();
        }
    }

    fn scroll_region_down(&mut self, lines: usize) {
        let height = self.bottom - self.top + 1;
        let lines = lines.min(height);
        let (blank, cols) = (self.blank(), self.cols);
        let (first, last) = (self.top * cols, (self.bottom + 1) * cols);
        self.cells[first..last].rotate_right(lines * cols);
        self.cells[first..first + lines * cols].fill(blank);
    }

    /// IL and DL, which scroll a *smaller* region: the one starting at the
    /// cursor. Outside the scroll region they do nothing at all.
    fn insert_lines(&mut self, lines: usize) {
        self.scroll_from_cursor(lines, true);
    }

    fn delete_lines(&mut self, lines: usize) {
        self.scroll_from_cursor(lines, false);
    }

    fn scroll_from_cursor(&mut self, lines: usize, down: bool) {
        if self.row < self.top || self.row > self.bottom {
            return;
        }
        let top = std::mem::replace(&mut self.top, self.row);
        if down {
            self.scroll_region_down(lines);
        } else {
            self.scroll_region_up(lines);
        }
        self.top = top;
        self.move_to(self.row, 0);
    }

    fn insert_chars(&mut self, count: usize) {
        let count = count.min(self.cols - self.col);
        let (blank, start) = (self.blank(), self.row * self.cols + self.col);
        let end = self.row * self.cols + self.cols;
        self.cells[start..end].rotate_right(count);
        self.cells[start..start + count].fill(blank);
    }

    fn delete_chars(&mut self, count: usize) {
        let count = count.min(self.cols - self.col);
        let (blank, start) = (self.blank(), self.row * self.cols + self.col);
        let end = self.row * self.cols + self.cols;
        self.cells[start..end].rotate_left(count);
        self.cells[end - count..end].fill(blank);
    }

    /// ECH: blank cells in place, without moving what is to their right.
    fn erase_chars(&mut self, count: usize) {
        let start = self.row * self.cols + self.col;
        let end = start + count.min(self.cols - self.col);
        self.fill(start, end);
    }

    fn erase_in_display(&mut self, mode: u16) {
        let (first, last) = match mode {
            0 => (self.row * self.cols + self.col, self.cells.len()),
            1 => (0, self.row * self.cols + self.col + 1),
            2 => (0, self.cells.len()),
            // Mode 3 is the scrollback and nothing on screen -- `clear` sends
            // it, and a pane whose history is gone has to say so.
            3 => {
                self.history.clear();
                return;
            }
            _ => return,
        };
        self.fill(first, last);
    }

    fn erase_in_line(&mut self, mode: u16) {
        let start = self.row * self.cols;
        let (first, last) = match mode {
            0 => (start + self.col, start + self.cols),
            1 => (start, start + self.col + 1),
            2 => (start, start + self.cols),
            _ => return,
        };
        self.fill(first, last);
    }

    fn fill(&mut self, first: usize, last: usize) {
        let blank = self.blank();
        for cell in &mut self.cells[first..last] {
            *cell = blank;
        }
    }

    /// What an erased cell holds: the current *background* and nothing else.
    ///
    /// Erasing keeps the background a program has selected, as xterm does, but
    /// not its bold or reverse — a blank painted in reverse video is a visible
    /// block, and no program asking to erase means to draw one.
    fn blank(&self) -> Cell {
        Cell {
            ch: ' ',
            attrs: Attrs {
                bg: self.attrs.bg,
                ..Attrs::default()
            },
        }
    }

    /// Move the cursor, clamped to the grid.
    ///
    /// This is §3.2's whole mechanism: `ESC[999C` and `ESC[9999;9999H` are size
    /// probes, and the answer is wherever this leaves the cursor. Only real
    /// motion comes through here -- erasing and SGR must not spend a pending
    /// wrap, which is cursor state rather than screen state.
    fn move_to(&mut self, row: usize, col: usize) {
        self.row = row.min(self.rows - 1);
        self.col = col.min(self.cols - 1);
        self.pending_wrap = false;
    }
}

/// Move `cells` into a grid of a different shape, clipping and padding.
fn reshape(
    cells: &[Cell],
    old_rows: usize,
    old_cols: usize,
    rows: usize,
    cols: usize,
) -> Vec<Cell> {
    let mut out = vec![Cell::default(); rows * cols];
    for row in 0..rows.min(old_rows) {
        for col in 0..cols.min(old_cols) {
            out[row * cols + col] = cells[row * old_cols + col];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ansi::Parser;

    /// Feed `bytes` to a fresh grid, as a pane's program would write them.
    fn paint(rows: usize, cols: usize, bytes: &[u8]) -> Grid {
        painted(rows, cols, bytes).0
    }

    /// The same, keeping whatever the grid owes the child in return.
    fn painted(rows: usize, cols: usize, bytes: &[u8]) -> (Grid, Vec<Reply>) {
        let mut grid = Grid::new(rows, cols);
        let mut replies = Vec::new();
        let mut parser = Parser::new();
        parser.feed(bytes, &mut |action| {
            if let Some(reply) = grid.apply(action) {
                replies.push(reply);
            }
        });
        (grid, replies)
    }

    #[test]
    fn text_lands_on_the_first_line() {
        let grid = paint(4, 10, b"hello");
        assert_eq!(grid.line(0), "hello");
        assert_eq!(grid.cursor(), (0, 5));
    }

    #[test]
    fn a_carriage_return_and_newline_start_the_next_line() {
        let grid = paint(4, 10, b"one\r\ntwo");
        assert_eq!(grid.line(0), "one");
        assert_eq!(grid.line(1), "two");
    }

    #[test]
    fn a_character_in_the_last_column_does_not_move_the_cursor() {
        // Deferred wrap (§5.3): the cursor stays where it wrote, so a DSR here
        // reports the last column, not the first column of the next row.
        let grid = paint(4, 5, b"abcde");
        assert_eq!(grid.cursor(), (0, 4));
        assert_eq!(grid.line(0), "abcde");
    }

    #[test]
    fn the_character_after_the_last_column_is_what_wraps() {
        let grid = paint(4, 5, b"abcdef");
        assert_eq!(grid.line(0), "abcde");
        assert_eq!(grid.line(1), "f");
        assert_eq!(grid.cursor(), (1, 1));
    }

    #[test]
    fn a_cursor_move_spends_a_pending_wrap_without_wrapping() {
        // The classic bug: `abcde` then a CR must return to column 0 of the
        // same row, not of the row below.
        let grid = paint(4, 5, b"abcde\rX");
        assert_eq!(grid.line(0), "Xbcde");
        assert_eq!(grid.line(1), "");
    }

    #[test]
    fn the_cursor_is_clamped_to_the_grid_not_to_what_was_asked_for() {
        // rush's width probe and red's geometry probe, verbatim (§3.2). What
        // the cursor reports after these *is* the pane's size.
        let grid = paint(24, 80, b"\x1b[999C");
        assert_eq!(grid.cursor(), (0, 79));
        let grid = paint(24, 80, b"\x1b[9999;9999H");
        assert_eq!(grid.cursor(), (23, 79));
    }

    #[test]
    fn cursor_motion_stops_at_the_edges() {
        let grid = paint(10, 10, b"\x1b[5;5H\x1b[99A\x1b[99D");
        assert_eq!(grid.cursor(), (0, 0));
        let grid = paint(10, 10, b"\x1b[99B\x1b[99C");
        assert_eq!(grid.cursor(), (9, 9));
    }

    #[test]
    fn a_position_is_one_based_on_the_wire_and_zero_based_here() {
        let grid = paint(10, 10, b"\x1b[1;1H");
        assert_eq!(grid.cursor(), (0, 0));
        let grid = paint(10, 10, b"\x1b[3;7H");
        assert_eq!(grid.cursor(), (2, 6));
        // An omitted parameter is 1, so `ESC[H` is home.
        let grid = paint(10, 10, b"\x1b[5;5H\x1b[H");
        assert_eq!(grid.cursor(), (0, 0));
    }

    #[test]
    fn a_row_and_a_column_can_be_set_on_their_own() {
        let grid = paint(10, 10, b"\x1b[4d\x1b[8G");
        assert_eq!(grid.cursor(), (3, 7));
    }

    #[test]
    fn a_newline_on_the_last_row_scrolls_the_screen_up() {
        let grid = paint(3, 10, b"one\r\ntwo\r\nthree\r\nfour");
        assert_eq!(grid.line(0), "two");
        assert_eq!(grid.line(1), "three");
        assert_eq!(grid.line(2), "four");
        assert_eq!(grid.cursor(), (2, 4));
    }

    #[test]
    fn wrapping_off_the_last_row_scrolls_too() {
        let grid = paint(2, 3, b"abc\r\ndefg");
        assert_eq!(grid.line(0), "def");
        assert_eq!(grid.line(1), "g");
    }

    #[test]
    fn erase_in_line_takes_all_three_modes() {
        let grid = paint(2, 8, b"abcdefgh\r\x1b[4C\x1b[0K");
        assert_eq!(grid.line(0), "abcd");
        let grid = paint(2, 8, b"abcdefgh\r\x1b[4C\x1b[1K");
        assert_eq!(grid.line(0), "     fgh");
        let grid = paint(2, 8, b"abcdefgh\r\x1b[4C\x1b[2K");
        assert_eq!(grid.line(0), "");
    }

    #[test]
    fn erase_in_display_takes_all_three_modes() {
        let painted = b"one\r\ntwo\r\nthree";
        let mut bytes = painted.to_vec();
        bytes.extend_from_slice(b"\x1b[2;2H\x1b[0J");
        let grid = paint(3, 8, &bytes);
        assert_eq!(
            (grid.line(0), grid.line(1), grid.line(2)),
            ("one".into(), "t".into(), "".into())
        );

        let mut bytes = painted.to_vec();
        bytes.extend_from_slice(b"\x1b[2;2H\x1b[1J");
        let grid = paint(3, 8, &bytes);
        assert_eq!(
            (grid.line(0), grid.line(1), grid.line(2)),
            ("".into(), "  o".into(), "three".into())
        );

        let mut bytes = painted.to_vec();
        bytes.extend_from_slice(b"\x1b[2J");
        let grid = paint(3, 8, &bytes);
        assert_eq!(
            (grid.line(0), grid.line(1), grid.line(2)),
            (String::new(), String::new(), String::new())
        );
    }

    #[test]
    fn erasing_does_not_spend_a_pending_wrap() {
        // `ESC[K` at the last column erases the cell under the cursor and no
        // more; the armed wrap is cursor state and survives it, so the next
        // character still belongs on the row below.
        let grid = paint(3, 5, b"abcde\x1b[0Kf");
        assert_eq!(grid.line(0), "abcd");
        assert_eq!(grid.line(1), "f");
    }

    #[test]
    fn erasing_does_not_move_the_cursor() {
        let grid = paint(3, 8, b"abcdef\x1b[2K");
        assert_eq!(grid.cursor(), (0, 6));
    }

    #[test]
    fn a_backspace_moves_left_and_stops_at_the_margin() {
        let grid = paint(2, 8, b"ab\x08\x08\x08X");
        assert_eq!(grid.line(0), "Xb");
    }

    #[test]
    fn a_tab_advances_to_the_next_eight_column_stop() {
        let grid = paint(2, 20, b"a\tb\tc");
        assert_eq!(grid.line(0), "a       b       c");
    }

    #[test]
    fn a_tab_past_the_last_column_stops_there() {
        let grid = paint(2, 10, b"\t\t\t\tx");
        assert_eq!(grid.cursor(), (0, 9));
    }

    #[test]
    fn a_sequence_rmux_does_not_implement_leaves_the_screen_alone() {
        // An unknown final byte must not print as text -- the parser framed it,
        // and the grid's job is to ignore it.
        let grid = paint(2, 8, b"ab\x1b[5Wcd");
        assert_eq!(grid.line(0), "abcd");
    }

    #[test]
    fn a_scroll_region_confines_scrolling_to_itself() {
        // Rows 1 and 4 are the header and status line a full-screen program
        // wants to hold still; only the region between them moves.
        let grid = paint(4, 8, b"A\r\nB\r\nC\r\nD\x1b[2;3r\x1b[3;1H\n");
        assert_eq!(grid.line(0), "A");
        assert_eq!(grid.line(1), "C");
        assert_eq!(grid.line(2), "");
        assert_eq!(grid.line(3), "D");
    }

    #[test]
    fn a_reverse_index_at_the_top_of_a_region_scrolls_it_down() {
        let grid = paint(4, 8, b"A\r\nB\r\nC\r\nD\x1b[2;3r\x1b[2;1H\x1bM");
        assert_eq!(grid.line(0), "A");
        assert_eq!(grid.line(1), "");
        assert_eq!(grid.line(2), "B");
        assert_eq!(grid.line(3), "D");
    }

    #[test]
    fn an_empty_scroll_region_is_the_whole_screen_again() {
        let grid = paint(3, 8, b"\x1b[2;3r\x1b[rA\r\nB\r\nC\r\nD");
        assert_eq!(grid.line(0), "B");
        assert_eq!(grid.line(1), "C");
        assert_eq!(grid.line(2), "D");
    }

    #[test]
    fn setting_a_scroll_region_homes_the_cursor() {
        let grid = paint(6, 8, b"\x1b[4;5H\x1b[2;5r");
        assert_eq!(grid.cursor(), (0, 0));
    }

    #[test]
    fn inserting_a_line_pushes_the_ones_below_it_down() {
        let grid = paint(4, 8, b"A\r\nB\r\nC\r\nD\x1b[2;1H\x1b[L");
        assert_eq!(grid.line(0), "A");
        assert_eq!(grid.line(1), "");
        assert_eq!(grid.line(2), "B");
        assert_eq!(grid.line(3), "C");
    }

    #[test]
    fn deleting_a_line_pulls_the_ones_below_it_up() {
        let grid = paint(4, 8, b"A\r\nB\r\nC\r\nD\x1b[2;1H\x1b[M");
        assert_eq!(grid.line(1), "C");
        assert_eq!(grid.line(2), "D");
        assert_eq!(grid.line(3), "");
    }

    #[test]
    fn inserting_a_line_outside_the_scroll_region_does_nothing() {
        let grid = paint(4, 8, b"A\r\nB\r\nC\r\nD\x1b[2;3r\x1b[4;1H\x1b[L");
        assert_eq!(grid.line(3), "D");
    }

    #[test]
    fn inserting_characters_pushes_the_rest_of_the_line_right() {
        let grid = paint(2, 8, b"abcdef\r\x1b[2C\x1b[2@");
        assert_eq!(grid.line(0), "ab  cdef");
    }

    #[test]
    fn deleting_characters_pulls_the_rest_of_the_line_left() {
        let grid = paint(2, 8, b"abcdef\r\x1b[2C\x1b[2P");
        assert_eq!(grid.line(0), "abef");
    }

    #[test]
    fn erasing_characters_leaves_the_rest_of_the_line_where_it_is() {
        let grid = paint(2, 8, b"abcdef\r\x1b[2C\x1b[2X");
        assert_eq!(grid.line(0), "ab  ef");
    }

    #[test]
    fn scrolling_the_region_does_not_move_the_cursor() {
        let grid = paint(3, 8, b"A\r\nB\r\nC\x1b[2;2H\x1b[S");
        assert_eq!(grid.line(0), "B");
        assert_eq!(grid.line(1), "C");
        assert_eq!(grid.line(2), "");
        assert_eq!(grid.cursor(), (1, 1));
    }

    #[test]
    fn an_index_moves_down_without_returning_to_column_zero() {
        let grid = paint(3, 8, b"abc\x1bDd");
        assert_eq!(grid.line(0), "abc");
        assert_eq!(grid.line(1), "   d");
    }

    #[test]
    fn a_next_line_is_a_carriage_return_and_an_index() {
        let grid = paint(3, 8, b"abc\x1bEd");
        assert_eq!(grid.line(0), "abc");
        assert_eq!(grid.line(1), "d");
    }

    #[test]
    fn a_charset_designation_is_ignored_rather_than_printed() {
        let grid = paint(2, 8, b"\x1b(Bok");
        assert_eq!(grid.line(0), "ok");
    }

    #[test]
    fn the_size_probes_report_the_pane_and_nothing_larger() {
        // rush asks for the width (`term.rs:676`), red for the whole geometry
        // (`terminal.rs:74`). Both must come back with the *pane's* size, which
        // is what sizes them correctly with no cooperation from either (§3.2).
        let (_, replies) = painted(24, 80, b"\x1b[?25l\r\x1b[999C\x1b[6n");
        assert_eq!(replies, vec![Reply::CursorPosition { row: 1, col: 80 }]);
        assert_eq!(replies[0].bytes(), b"\x1b[1;80R");

        let (_, replies) = painted(24, 80, b"\x1b[?25l\x1b[9999;9999H\x1b[6n");
        assert_eq!(replies, vec![Reply::CursorPosition { row: 24, col: 80 }]);
        assert_eq!(replies[0].bytes(), b"\x1b[24;80R");
    }

    #[test]
    fn answering_a_status_report_does_not_touch_the_screen() {
        let (grid, replies) = painted(3, 8, b"ab\x1b[6ncd");
        assert_eq!(grid.line(0), "abcd");
        assert_eq!(replies.len(), 1);
    }

    #[test]
    fn a_status_report_rmux_does_not_answer_gets_no_reply() {
        let (_, replies) = painted(3, 8, b"\x1b[5n");
        assert!(replies.is_empty());
    }

    #[test]
    fn the_alt_screen_is_fresh_and_hands_the_primary_one_back() {
        let grid = paint(3, 8, b"primary\x1b[?1049h");
        assert_eq!(grid.line(0), "");
        assert!(grid.on_alt_screen());

        let grid = paint(3, 8, b"primary\x1b[?1049hscratch\x1b[?1049l");
        assert_eq!(grid.line(0), "primary");
        assert!(!grid.on_alt_screen());
        assert_eq!(grid.cursor(), (0, 7));
    }

    #[test]
    fn a_pane_can_hide_its_own_cursor() {
        assert!(paint(2, 8, b"").cursor_visible());
        assert!(!paint(2, 8, b"\x1b[?25l").cursor_visible());
        assert!(paint(2, 8, b"\x1b[?25l\x1b[?25h").cursor_visible());
    }

    #[test]
    fn a_bare_newline_indexes_without_returning_the_carriage() {
        // What a real terminal does, and what the tty's `ONLCR` normally hides:
        // the second line starts where the first one ended. Measured on Motor,
        // where nothing hides it -- `printf 'aa\nbb\ncc\n'` in a pane came out
        // as a staircase two columns further right on every line.
        let grid = paint(4, 10, b"aa\nbb\ncc");
        assert_eq!(grid.line(1), "  bb");
        assert_eq!(grid.line(2), "    cc");
    }

    #[test]
    fn a_pane_with_no_line_discipline_makes_a_newline_a_new_line() {
        // Motor OS has no line discipline (§3.1), so the pane is it: `sys-tty`
        // rewrites `\n` as `\n\r` for the real console (§3.3) and a pane must do
        // the same. `Pane` sets this from the platform.
        let mut grid = Grid::new(4, 10);
        grid.set_newline_mode(true);
        let mut parser = Parser::new();
        parser.feed(b"aa\nbb\ncc", &mut |action| {
            let _ = grid.apply(action);
        });
        assert_eq!(grid.line(0), "aa");
        assert_eq!(grid.line(1), "bb");
        assert_eq!(grid.line(2), "cc");
        assert_eq!(grid.cursor(), (2, 2));
    }

    #[test]
    fn autowrap_can_be_turned_off() {
        let grid = paint(2, 4, b"\x1b[?7labcdefg");
        assert_eq!(grid.line(0), "abcg");
        assert_eq!(grid.line(1), "");
    }

    #[test]
    fn a_saved_cursor_comes_back_where_it_was() {
        let grid = paint(4, 8, b"\x1b[2;3H\x1b7\x1b[4;8H\x1b8x");
        assert_eq!(grid.cursor(), (1, 3));
        assert_eq!(grid.line(1), "  x");
    }

    #[test]
    fn a_pane_can_ask_for_bracketed_paste() {
        assert!(!paint(2, 8, b"").bracketed_paste());
        assert!(paint(2, 8, b"\x1b[?2004h").bracketed_paste());
        assert!(!paint(2, 8, b"\x1b[?2004h\x1b[?2004l").bracketed_paste());
    }

    #[test]
    fn an_osc_names_the_window_and_nothing_else_does() {
        assert_eq!(paint(2, 8, b"\x1b]0;build\x07").title(), "build");
        assert_eq!(paint(2, 8, b"\x1b]2;notes\x1b\\").title(), "notes");
        // 52 is the clipboard rmux deliberately does not have (§7.6).
        assert_eq!(paint(2, 8, b"\x1b]52;c;aGk=\x07").title(), "");
    }

    #[test]
    fn sgr_styles_the_cells_written_after_it_and_no_others() {
        let grid = paint(2, 8, b"a\x1b[1;31mb\x1b[mc");
        assert_eq!(grid.cell(0, 0).attrs, Attrs::default());
        assert!(grid.cell(0, 1).attrs.has(Attrs::BOLD));
        assert_eq!(grid.cell(0, 1).attrs.fg, Color::Indexed(1));
        assert_eq!(grid.cell(0, 2).attrs, Attrs::default());
    }

    #[test]
    fn an_attribute_can_be_turned_off_without_disturbing_the_rest() {
        let grid = paint(2, 8, b"\x1b[1;4;31m\x1b[24mx");
        let attrs = grid.cell(0, 0).attrs;
        assert!(attrs.has(Attrs::BOLD));
        assert!(!attrs.has(Attrs::UNDERLINE));
        assert_eq!(attrs.fg, Color::Indexed(1));
    }

    #[test]
    fn a_bright_colour_is_the_upper_half_of_the_palette() {
        let grid = paint(2, 8, b"\x1b[90;101mx");
        assert_eq!(grid.cell(0, 0).attrs.fg, Color::Indexed(8));
        assert_eq!(grid.cell(0, 0).attrs.bg, Color::Indexed(9));
    }

    #[test]
    fn an_extended_colour_swallows_its_own_parameters_and_no_more() {
        // The trap: `38;5;196` is one colour, and the `1` after it is bold --
        // not another colour.
        let grid = paint(2, 8, b"\x1b[38;5;196;1mx");
        assert_eq!(grid.cell(0, 0).attrs.fg, Color::Indexed(196));
        assert!(grid.cell(0, 0).attrs.has(Attrs::BOLD));

        let grid = paint(2, 8, b"\x1b[48;2;10;20;30;7mx");
        assert_eq!(grid.cell(0, 0).attrs.bg, Color::Rgb(10, 20, 30));
        assert!(grid.cell(0, 0).attrs.has(Attrs::REVERSE));
    }

    #[test]
    fn erasing_keeps_the_background_and_drops_everything_else() {
        // A blank painted in reverse video is a visible block, and no program
        // asking to erase means to draw one.
        let grid = paint(2, 8, b"\x1b[7;44mabc\x1b[2K");
        let blank = grid.cell(0, 0).attrs;
        assert_eq!(blank.bg, Color::Indexed(4));
        assert!(!blank.has(Attrs::REVERSE));
    }

    #[test]
    fn a_resize_clips_and_pads_rather_than_reflowing() {
        let mut grid = paint(3, 10, b"abcdefgh\r\nsecond");
        grid.resize(2, 4);
        assert_eq!(grid.rows(), 2);
        assert_eq!(grid.cols(), 4);
        assert_eq!(grid.line(0), "abcd");
        assert_eq!(grid.line(1), "seco");
    }

    #[test]
    fn a_resize_puts_the_cursor_and_the_scroll_region_back_inside() {
        let mut grid = paint(10, 10, b"\x1b[3;8r\x1b[9;9H");
        grid.resize(4, 4);
        assert_eq!(grid.cursor(), (3, 3));
        // The region is the whole screen again, so a newline at the bottom
        // scrolls rather than falling into rows that no longer exist.
        let mut parser = Parser::new();
        parser.feed(b"x\n", &mut |action| {
            let _ = grid.apply(action);
        });
        assert_eq!(grid.line(2), "   x");
    }

    // ---- scrollback (§7.5) ----

    /// What history holds, as text, oldest first.
    fn remembered(grid: &Grid) -> Vec<String> {
        (0..grid.history()).map(|at| grid.row_text(at)).collect()
    }

    #[test]
    fn a_line_that_scrolls_off_the_top_is_kept() {
        let grid = paint(3, 10, b"one\r\ntwo\r\nthree\r\nfour\r\nfive");
        assert_eq!(remembered(&grid), ["one", "two"]);
        assert_eq!(grid.line(0), "three");
    }

    #[test]
    fn history_and_the_screen_read_the_same_way() {
        // §7.5's accessor: copy mode walks `total_rows` and cannot tell which
        // side of the boundary a row is on.
        let grid = paint(2, 10, b"one\r\ntwo\r\nthree");
        assert_eq!(grid.total_rows(), grid.history() + grid.rows());
        let all: Vec<String> = (0..grid.total_rows()).map(|at| grid.row_text(at)).collect();
        assert_eq!(all, ["one", "two", "three"]);
        assert_eq!(grid.row_cells(0)[0].ch, 'o');
        assert_eq!(grid.row_cells(0).len(), grid.cols());
    }

    #[test]
    fn the_limit_is_a_cap_and_the_oldest_lines_are_what_go() {
        let mut grid = Grid::new(2, 10);
        grid.set_history_limit(2);
        let mut parser = Parser::new();
        parser.feed(b"a\r\nb\r\nc\r\nd\r\ne", &mut |action| {
            let _ = grid.apply(action);
        });
        assert_eq!(remembered(&grid), ["b", "c"]);

        // Lowering the limit takes effect at once rather than at the next
        // scroll, which is what makes it a memory bound.
        grid.set_history_limit(1);
        assert_eq!(remembered(&grid), ["c"]);
        grid.set_history_limit(0);
        assert_eq!(grid.history(), 0);
    }

    #[test]
    fn the_alt_screen_has_nothing_above_it_to_read() {
        // The same rule from copy mode's side (§5.3): the lines above a
        // full-screen program's screen are the screen underneath it, and tmux
        // does not show them either. They are still kept, and come back when
        // the program gives the screen back.
        let grid = paint(2, 10, b"one\r\ntwo\r\nthree\x1b[?1049h");
        assert_eq!(grid.history(), 0);
        assert_eq!(grid.total_rows(), grid.rows());
        assert_eq!(grid.row_text(0), "");

        let grid = paint(2, 10, b"one\r\ntwo\r\nthree\x1b[?1049h\x1b[?1049l");
        assert_eq!(grid.history(), 1);
        assert_eq!(grid.row_text(0), "one");
    }

    #[test]
    fn the_alt_screen_has_no_scrollback() {
        // §5.3, and red lives there (`red/src/terminal.rs:14`): every repaint
        // would otherwise become history.
        let grid = paint(2, 10, b"\x1b[?1049hone\r\ntwo\r\nthree");
        assert_eq!(grid.history(), 0);
        assert_eq!(grid.line(1), "three");
    }

    #[test]
    fn a_scroll_region_keeps_its_lines_to_itself() {
        // tmux's rule (`grid_view_scroll_region_up`): only the whole screen
        // scrolling makes history. A program with a region is holding a header
        // still and moving text between it and a status line.
        let grid = paint(4, 10, b"A\r\nB\r\nC\r\nD\x1b[2;3r\x1b[3;1H\n\n");
        assert_eq!(grid.history(), 0);
    }

    #[test]
    fn styling_survives_the_trip_into_history() {
        let grid = paint(2, 10, b"\x1b[1;31mred\x1b[m\r\nplain\r\nlast");
        let kept = grid.row_cells(0);
        assert_eq!(kept[0].ch, 'r');
        assert!(kept[0].attrs.has(Attrs::BOLD));
        assert_eq!(kept[0].attrs.fg, Color::Indexed(1));
        // And what was never styled comes back unstyled, at the width asked for.
        assert_eq!(kept[5].attrs, Attrs::default());
        assert_eq!(kept.len(), 10);
    }

    #[test]
    fn a_line_is_stored_without_its_trailing_blanks() {
        // The difference between a byte a character and 80 cells a line, which
        // is what makes ten million of them survivable (§7.5).
        let cells = [
            Cell {
                ch: 'h',
                attrs: Attrs::default(),
            },
            Cell::default(),
            Cell::default(),
        ];
        let line = Line::from_cells(&cells);
        assert_eq!(line.text(), "h");
        assert_eq!(line.cells(3), cells);
        assert_eq!(Line::from_cells(&[Cell::default(); 80]).text(), "");
    }

    #[test]
    fn erase_in_display_3_is_what_clears_the_scrollback() {
        let mut grid = paint(2, 10, b"one\r\ntwo\r\nthree");
        assert_eq!(grid.history(), 1);
        let mut parser = Parser::new();
        parser.feed(b"\x1b[3J", &mut |action| {
            let _ = grid.apply(action);
        });
        assert_eq!(grid.history(), 0);
        // And only the scrollback: what is on screen stays where it was.
        assert_eq!(grid.line(1), "three");
    }

    #[test]
    fn every_character_is_one_column_wide_including_the_wide_ones() {
        // The documented divergence (§1.2): rmux stores a char per cell and
        // spends one column on it, whatever the character is.
        let grid = paint(2, 4, "aあb".as_bytes());
        assert_eq!(grid.cursor(), (0, 3));
        assert_eq!(grid.line(0), "aあb");
    }
}
