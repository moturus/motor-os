//! The compositor and the frame diff.
//!
//! Straight from red (`editor.rs:44-53`, `477`, `494`, `524`): build a whole
//! frame of cells, diff it against the last one, repaint only what changed,
//! flush once. Pure — bytes out, no I/O — so what a paint *costs* is something
//! a test can hold (details.md §9.2).
//!
//! The diff is not an optimization here, it is the feature (§6.3). rmux's
//! output reaches the user through `sys-tty`, which reads it in 80-byte chunks
//! and writes it to a polled UART one byte at a time. A full 80x24 repaint with
//! styling is several kilobytes; on a real 115200-baud line that is about a
//! second, for one keystroke.
//!
//! Two rules the console imposes, both from §3.3:
//!
//! - **Never emit `\n`, `\r` or backspace for layout.** `sys-tty`'s `send()`
//!   rewrites all three — `\n` becomes `\n\r`, and `0x08`/`0x7f` become a
//!   *destructive* `BS SP BS`. Every cell is placed with an absolute
//!   `ESC[{row};{col}H`. rush uses relative motion and documents why
//!   (`term.rs:450-457`): it cannot know its row on the screen without asking.
//!   rmux is a full-screen alt-screen application and owns every row by
//!   construction, so absolute is correct here.
//! - **Anything that writes to the console behind the compositor's back
//!   invalidates it.** [`Screen::invalidate`] is how that is said, and `None`
//!   rather than a length check is how it is stored (§6.2) — rush's
//!   formulation, which reads as "the screen is not ours to reason about".

use std::io::Write;

use crate::grid::Attrs;
use crate::grid::Cell;
use crate::grid::Color;
use crate::grid::Grid;

/// A whole screen's worth of cells: what the user should be looking at.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    rows: usize,
    cols: usize,
    cells: Vec<Cell>,
    /// Where the cursor goes, or `None` when it should not be shown.
    ///
    /// Only the active pane's cursor reaches a frame, and only if that pane
    /// wants it: `ESC[?25l` is per-pane state, and an inactive pane hiding its
    /// cursor must not hide the user's (§3.2).
    cursor: Option<(usize, usize)>,
}

impl Frame {
    pub fn new(rows: usize, cols: usize) -> Frame {
        let (rows, cols) = (rows.max(1), cols.max(1));
        Frame {
            rows,
            cols,
            cells: vec![Cell::default(); rows * cols],
            cursor: None,
        }
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn cursor(&self) -> Option<(usize, usize)> {
        self.cursor
    }

    pub fn set_cursor(&mut self, cursor: Option<(usize, usize)>) {
        self.cursor = cursor.filter(|(row, col)| *row < self.rows && *col < self.cols);
    }

    /// Copy `grid` into this frame with its top-left corner at `(top, left)`.
    ///
    /// The compositor's one primitive: M3 calls it once for a full-screen pane,
    /// and the split tree (§7.1) will call it once per pane with the offsets
    /// the layout gives it. Anything that does not fit is clipped rather than
    /// wrapped — a pane that overflows its box is a layout bug, and wrapping it
    /// would hide that.
    pub fn blit(&mut self, top: usize, left: usize, grid: &Grid) {
        for row in 0..grid.rows().min(self.rows.saturating_sub(top)) {
            for col in 0..grid.cols().min(self.cols.saturating_sub(left)) {
                let at = (top + row) * self.cols + left + col;
                self.cells[at] = grid.cell(row, col);
            }
        }
    }

    /// Put one cell on the frame — a border between panes (§7.1).
    ///
    /// Borders are painted after the panes, so a pane starved of space by a
    /// window too small for its layout loses its cell rather than the picture
    /// losing the line that says where the panes are.
    pub fn set_cell(&mut self, row: usize, col: usize, cell: Cell) {
        if row < self.rows && col < self.cols {
            self.cells[row * self.cols + col] = cell;
        }
    }

    /// Put `cells` on row `row` — the status line's one row (§7.3).
    pub fn set_row(&mut self, row: usize, cells: &[Cell]) {
        self.set_row_at(row, 0, cells);
    }

    /// The same, starting at a column: one row of one pane's box, which is what
    /// copy mode paints (§7.6) since its rows come from history rather than
    /// from the pane's grid.
    pub fn set_row_at(&mut self, row: usize, left: usize, cells: &[Cell]) {
        if row >= self.rows || left >= self.cols {
            return;
        }
        let start = row * self.cols + left;
        for (at, cell) in cells.iter().take(self.cols - left).enumerate() {
            self.cells[start + at] = *cell;
        }
    }

    fn row(&self, row: usize) -> &[Cell] {
        &self.cells[row * self.cols..(row + 1) * self.cols]
    }
}

/// What is on the console, and how to get from there to the next frame.
///
/// Every byte the console receives passes through here, so what it is *in* --
/// where its cursor sits and which SGR is in force -- is known rather than
/// guessed. That is what lets a repaint skip the position and the style it
/// would otherwise have to restate, and it is the difference between a
/// keystroke costing seven bytes and seventeen. `None` in any of these means
/// "not ours to reason about": the next paint says it out loud.
#[derive(Default)]
pub struct Screen {
    last: Option<Frame>,
    cursor_at: Option<(usize, usize)>,
    cursor_shown: Option<bool>,
    style: Option<Attrs>,
}

impl Screen {
    pub fn new() -> Screen {
        Screen::default()
    }

    /// Forget what is on the console; the next paint is a full one.
    ///
    /// For `refresh-client`, for a resize, and for anything that writes to the console
    /// without going through here (§6.2).
    pub fn invalidate(&mut self) {
        self.last = None;
        self.cursor_at = None;
        self.cursor_shown = None;
        self.style = None;
    }

    /// The bytes that turn the console into `frame`.
    pub fn draw(&mut self, frame: Frame) -> Vec<u8> {
        let mut out = Vec::new();

        // A size change is a full repaint, and both axes count: red triggers
        // one only on a row-count change (`editor.rs:535`) and gets away with
        // it because its rows are ragged and `ESC[K` cleans up. rmux's panes
        // are not ragged (§6.2).
        let previous = match self.last.take() {
            Some(last) if last.rows == frame.rows && last.cols == frame.cols => last,
            _ => {
                out.extend_from_slice(b"\x1b[0m\x1b[2J");
                self.cursor_at = None;
                self.cursor_shown = None;
                self.style = Some(Attrs::default());
                Frame::new(frame.rows, frame.cols)
            }
        };

        for row in 0..frame.rows {
            self.diff_row(row, previous.row(row), frame.row(row), &mut out);
        }
        self.place_cursor(&frame, &mut out);

        self.last = Some(frame);
        out
    }

    /// Repaint one row, from the first cell that differs to the last.
    fn diff_row(&mut self, row: usize, previous: &[Cell], next: &[Cell], out: &mut Vec<u8>) {
        let Some(first) = (0..next.len()).find(|at| previous[*at] != next[*at]) else {
            return;
        };
        let last = (0..next.len())
            .rev()
            .find(|at| previous[*at] != next[*at])
            .unwrap_or(first);

        self.move_to(row, first, out);

        // A tail that has gone blank is one `ESC[K`, not a run of spaces --
        // the difference between eight bytes and eighty on a line a program
        // just cleared. `ESC[K` erases in the *current* background, so the
        // reset in front of it is what makes it erase to blank.
        if next[first..].iter().all(is_blank) {
            self.set_style(Attrs::default(), out);
            out.extend_from_slice(b"\x1b[K");
            return;
        }

        for cell in &next[first..=last] {
            self.set_style(cell.attrs, out);
            let mut buf = [0_u8; 4];
            out.extend_from_slice(cell.ch.encode_utf8(&mut buf).as_bytes());
        }

        // Painting moved the console's cursor. At the right edge it lands in a
        // deferred-wrap state (§5.3) that is not a position, so say nothing.
        self.cursor_at = (last + 1 < next.len()).then_some((row, last + 1));
    }

    fn move_to(&mut self, row: usize, col: usize, out: &mut Vec<u8>) {
        if self.cursor_at != Some((row, col)) {
            let _ = write!(out, "\x1b[{};{}H", row + 1, col + 1);
            self.cursor_at = Some((row, col));
        }
    }

    /// Put the console into `attrs`, if it is not already.
    ///
    /// The SGR is reset-prefixed, which is what makes a partial repaint legal
    /// at all: a cell can be repainted in isolation without depending on
    /// whatever style preceded it *on screen* (red's `editor.rs:59-62`). What
    /// it may depend on is what rmux itself last sent, which is not a guess.
    fn set_style(&mut self, attrs: Attrs, out: &mut Vec<u8>) {
        if self.style != Some(attrs) {
            sgr(attrs, out);
            self.style = Some(attrs);
        }
    }

    fn place_cursor(&mut self, frame: &Frame, out: &mut Vec<u8>) {
        match frame.cursor {
            Some((row, col)) => {
                self.move_to(row, col, out);
                if self.cursor_shown != Some(true) {
                    out.extend_from_slice(b"\x1b[?25h");
                    self.cursor_shown = Some(true);
                }
            }
            None => {
                if self.cursor_shown != Some(false) {
                    out.extend_from_slice(b"\x1b[?25l");
                    self.cursor_shown = Some(false);
                }
            }
        }
    }
}

fn is_blank(cell: &Cell) -> bool {
    cell.ch == ' ' && cell.attrs == Attrs::default()
}

/// The SGR that puts a terminal into `attrs` from *any* prior state.
///
/// red affords a `&'static str` of SGR per cell because its palette is fixed;
/// a pane composites arbitrary SGR from a child, so rmux keeps the invariant
/// and renders it here from a packed `Attrs` (§6.1).
fn sgr(attrs: Attrs, out: &mut Vec<u8>) {
    out.extend_from_slice(b"\x1b[0");
    for (flag, code) in [
        (Attrs::BOLD, 1),
        (Attrs::DIM, 2),
        (Attrs::ITALIC, 3),
        (Attrs::UNDERLINE, 4),
        (Attrs::BLINK, 5),
        (Attrs::REVERSE, 7),
        (Attrs::HIDDEN, 8),
        (Attrs::STRIKE, 9),
    ] {
        if attrs.has(flag) {
            let _ = write!(out, ";{code}");
        }
    }
    color(attrs.fg, 30, out);
    color(attrs.bg, 40, out);
    out.push(b'm');
}

fn color(color: Color, base: u16, out: &mut Vec<u8>) {
    let _ = match color {
        Color::Default => Ok(()),
        // The eight bright entries have their own codes; the rest of the
        // palette needs the `5;n` form, and no terminal is assumed to know
        // more than that without being told.
        Color::Indexed(n) if n < 8 => write!(out, ";{}", base + n as u16),
        Color::Indexed(n) if n < 16 => write!(out, ";{}", base + 60 + (n - 8) as u16),
        Color::Indexed(n) => write!(out, ";{};5;{}", base + 8, n),
        Color::Rgb(r, g, b) => write!(out, ";{};2;{};{};{}", base + 8, r, g, b),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ansi::Parser;

    /// A frame showing what `bytes` paint on a `rows` x `cols` pane.
    fn frame(rows: usize, cols: usize, bytes: &[u8]) -> Frame {
        let mut grid = Grid::new(rows, cols);
        let mut parser = Parser::new();
        parser.feed(bytes, &mut |action| {
            let _ = grid.apply(action);
        });
        let mut frame = Frame::new(rows, cols);
        frame.blit(0, 0, &grid);
        frame.set_cursor(Some(grid.cursor()));
        frame
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn the_first_paint_clears_the_screen_and_writes_what_is_on_it() {
        let mut screen = Screen::new();
        let out = text(&screen.draw(frame(3, 10, b"hi")));
        assert!(out.starts_with("\x1b[0m\x1b[2J"), "{out:?}");
        assert!(out.contains("hi"), "{out:?}");
    }

    #[test]
    fn an_unchanged_frame_costs_nothing_at_all() {
        let mut screen = Screen::new();
        screen.draw(frame(3, 10, b"hi"));
        assert_eq!(screen.draw(frame(3, 10, b"hi")), Vec::<u8>::new());
    }

    #[test]
    fn a_keystroke_echoed_in_a_pane_costs_the_bytes_of_that_keystroke() {
        // §9.2's central claim, and the reason the diff exists (§6.3): one more
        // character on screen is one position and one character, not a row.
        let mut screen = Screen::new();
        screen.draw(frame(24, 80, b"hello"));
        let out = screen.draw(frame(24, 80, b"hellox"));
        assert!(text(&out).contains('x'), "{:?}", text(&out));
        assert!(
            out.len() <= 16,
            "a keystroke cost {} bytes: {:?}",
            out.len(),
            text(&out)
        );
    }

    #[test]
    fn only_the_cells_that_changed_are_repainted() {
        let mut screen = Screen::new();
        screen.draw(frame(3, 20, b"unchanged left\rX"));
        let out = text(&screen.draw(frame(3, 20, b"unchanged left\rY")));
        assert!(out.contains('Y'), "{out:?}");
        assert!(!out.contains("nchanged"), "{out:?}");
    }

    #[test]
    fn a_tail_that_went_blank_is_erased_rather_than_overwritten() {
        // Eight bytes rather than eighty, on a line a program just cleared.
        let mut screen = Screen::new();
        screen.draw(frame(3, 40, b"a line with a good deal of text on it"));
        let out = screen.draw(frame(3, 40, b"a line\x1b[0K"));
        assert!(text(&out).contains("\x1b[K"), "{:?}", text(&out));
        assert!(out.len() < 30, "{:?}", text(&out));
    }

    #[test]
    fn a_resize_is_a_full_repaint_on_either_axis() {
        // red repaints only on a row-count change and gets away with it
        // because its rows are ragged; rmux's panes are not (§6.2).
        let mut screen = Screen::new();
        screen.draw(frame(24, 80, b"hi"));
        assert!(text(&screen.draw(frame(24, 40, b"hi"))).contains("\x1b[2J"));

        let mut screen = Screen::new();
        screen.draw(frame(24, 80, b"hi"));
        assert!(text(&screen.draw(frame(12, 80, b"hi"))).contains("\x1b[2J"));
    }

    #[test]
    fn invalidating_the_screen_forces_a_full_repaint() {
        let mut screen = Screen::new();
        screen.draw(frame(3, 10, b"hi"));
        screen.invalidate();
        assert!(text(&screen.draw(frame(3, 10, b"hi"))).contains("\x1b[2J"));
    }

    #[test]
    fn every_cell_is_placed_absolutely_and_never_with_a_newline() {
        // sys-tty rewrites `\n`, `\r` and backspace on their way to the wire
        // (§3.3), so a compositor that used them would paint something else.
        let mut screen = Screen::new();
        let out = screen.draw(frame(4, 10, b"one\r\ntwo\r\nthree"));
        assert!(!out.contains(&b'\n'), "{:?}", text(&out));
        assert!(!out.contains(&b'\r'), "{:?}", text(&out));
        assert!(!out.contains(&0x08), "{:?}", text(&out));
    }

    #[test]
    fn a_repainted_cell_states_the_style_the_console_is_not_already_in() {
        let mut screen = Screen::new();
        screen.draw(frame(3, 20, b"plain"));

        // The console is in the default style, so a red cell has to say so --
        // reset-prefixed, since it must not inherit what preceded it on screen.
        let out = text(&screen.draw(frame(3, 20, b"plain\x1b[31mX")));
        assert!(out.contains("\x1b[0;31m"), "{out:?}");

        // Now the console *is* red. Another red cell restates nothing and
        // costs one byte: the cursor is already where it goes, and the style
        // is already what it should be. Sound only because every byte the
        // console has received came from here.
        let out = text(&screen.draw(frame(3, 20, b"plain\x1b[31mXY")));
        assert_eq!(out, "Y");
    }

    #[test]
    fn a_style_run_is_written_once_rather_than_per_cell() {
        let mut screen = Screen::new();
        let out = text(&screen.draw(frame(3, 20, b"\x1b[1;32mgreen")));
        assert_eq!(out.matches("\x1b[0;1;32m").count(), 1, "{out:?}");
    }

    #[test]
    fn the_palette_and_true_colour_have_their_own_spellings() {
        let mut sgr_bytes = Vec::new();
        sgr(
            Attrs {
                fg: Color::Indexed(9),
                bg: Color::Indexed(200),
                flags: 0,
            },
            &mut sgr_bytes,
        );
        assert_eq!(text(&sgr_bytes), "\x1b[0;91;48;5;200m");

        let mut sgr_bytes = Vec::new();
        sgr(
            Attrs {
                fg: Color::Rgb(1, 2, 3),
                bg: Color::Default,
                flags: Attrs::BOLD,
            },
            &mut sgr_bytes,
        );
        assert_eq!(text(&sgr_bytes), "\x1b[0;1;38;2;1;2;3m");
    }

    #[test]
    fn the_cursor_is_placed_last_and_only_told_to_show_once() {
        let mut screen = Screen::new();
        // Painting `hi` leaves the console's cursor exactly where the cursor
        // goes, so there is nothing to move and only the showing to say.
        let out = text(&screen.draw(frame(3, 10, b"hi")));
        assert!(out.ends_with("hi\x1b[?25h"), "{out:?}");

        // Already shown, so the second paint spends nothing on saying so.
        let out = text(&screen.draw(frame(3, 10, b"hip")));
        assert!(!out.contains("?25h"), "{out:?}");
    }

    #[test]
    fn the_cursor_is_moved_when_painting_did_not_leave_it_there() {
        let mut screen = Screen::new();
        screen.draw(frame(4, 20, b"one\r\ntwo"));
        // Repaint the first row while the cursor belongs on the second: the
        // paint leaves the console's cursor on row one, so it has to move.
        let out = text(&screen.draw(frame(4, 20, b"oneX\r\ntwo")));
        assert!(out.ends_with("\x1b[2;4H"), "{out:?}");
    }

    #[test]
    fn a_hidden_cursor_is_hidden_and_not_placed() {
        let mut screen = Screen::new();
        screen.draw(frame(3, 10, b"hi"));
        let mut hidden = frame(3, 10, b"hi");
        hidden.set_cursor(None);
        let out = text(&screen.draw(hidden));
        assert_eq!(out, "\x1b[?25l");
    }

    #[test]
    fn a_pane_is_composited_at_the_offset_it_is_given() {
        // What the split tree will use (§7.1); M3 only ever passes (0, 0).
        let mut grid = Grid::new(1, 3);
        let mut parser = Parser::new();
        parser.feed(b"abc", &mut |action| {
            let _ = grid.apply(action);
        });

        let mut frame = Frame::new(4, 10);
        frame.blit(2, 5, &grid);
        assert_eq!(frame.row(2)[5].ch, 'a');
        assert_eq!(frame.row(2)[7].ch, 'c');
        assert_eq!(frame.row(0)[0].ch, ' ');
    }

    #[test]
    fn a_border_goes_on_top_of_the_panes_it_divides() {
        // What the server paints for a split window (§7.1): the panes at the
        // boxes the layout gave them, then the border cells over them. Borders
        // last, so a window too small for its layout loses a pane's cell rather
        // than the line that says where the panes are.
        let pane = |text: &[u8]| {
            let mut grid = Grid::new(1, 2);
            let mut parser = Parser::new();
            parser.feed(text, &mut |action| {
                let _ = grid.apply(action);
            });
            grid
        };

        let mut frame = Frame::new(1, 5);
        frame.blit(0, 0, &pane(b"ab"));
        frame.blit(0, 3, &pane(b"cd"));
        frame.set_cell(
            0,
            2,
            Cell {
                ch: '|',
                attrs: Attrs::default(),
            },
        );
        let painted: String = frame.row(0).iter().map(|cell| cell.ch).collect();
        assert_eq!(painted, "ab|cd");
    }

    #[test]
    fn a_pane_that_does_not_fit_is_clipped_rather_than_wrapped() {
        let mut grid = Grid::new(2, 8);
        let mut parser = Parser::new();
        parser.feed(b"abcdefgh", &mut |action| {
            let _ = grid.apply(action);
        });

        let mut frame = Frame::new(2, 4);
        frame.blit(0, 2, &grid);
        assert_eq!(frame.row(0)[2].ch, 'a');
        assert_eq!(frame.row(0)[3].ch, 'b');
        assert_eq!(frame.row(1)[2].ch, ' ');
    }
}
