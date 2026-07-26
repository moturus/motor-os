//! Copy mode: reading a pane's scrollback, and taking text out of it.
//!
//! `prefix [` enters, `q` or `Esc` leaves, and in between the keys are vi's
//! because the config says `mode-keys vi` (details.md §2.1, §7.6). What copy mode
//! walks is the pane's whole buffer — history first, then the live screen —
//! through [`Grid::row_cells`] and [`Grid::row_text`], which render either
//! representation (§7.5). Nothing here knows that a line below the fold is a
//! compacted [`crate::grid::Line`] and a line above it is cells.
//!
//! This module is **pure**: a grid in, a viewport and a string out. No pane, no
//! client, no I/O — so every motion below is a unit test measured in
//! microseconds (§9.3), and the server's job is reduced to holding one of these
//! per client and painting what it says.
//!
//! # What copy mode copies is what is *on the screen*
//!
//! Not what the program thinks it has (§7.6). Copying out of `red` means
//! selecting the text as red *painted* it; rmux cannot see red's yank register,
//! only the cells. That is exactly tmux's behaviour and the reason this reads
//! the grid rather than talking to the pane.
//!
//! # Coordinates
//!
//! One system throughout: a row is an index into the pane's whole buffer, where
//! `0` is the oldest line in history and `total_rows() - 1` is the bottom of the
//! screen. [`CopyMode::top`] is which of those rows is drawn at the top of the
//! pane's box, and it is the only place the two coordinate systems meet.

use crate::grid::Attrs;
use crate::grid::Cell;
use crate::grid::Grid;
use crate::pane::PaneId;

/// Where a key takes the cursor, in tmux's `-X` vocabulary (`bindings`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motion {
    Left,
    Down,
    Up,
    Right,
    NextWord,
    PreviousWord,
    LineStart,
    LineEnd,
    /// `g` and `G`: the oldest line kept, and the bottom of the screen.
    Top,
    Bottom,
    HalfPageUp,
    HalfPageDown,
    PageUp,
    PageDown,
}

/// One client's place in one pane's scrollback.
pub struct CopyMode {
    /// The pane this was entered on. Copy mode belongs to a pane's buffer, so
    /// a pane that goes takes it with it (`CopyMode::pane`).
    pane: PaneId,
    /// The buffer row drawn at the top of the pane's box.
    top: usize,
    row: usize,
    col: usize,
    /// Where `Space` started a selection, if it has.
    anchor: Option<(usize, usize)>,
}

impl CopyMode {
    /// Enter copy mode where the pane's cursor is, showing the live screen.
    pub fn enter(pane: PaneId, grid: &Grid) -> CopyMode {
        let (row, col) = grid.cursor();
        CopyMode {
            pane,
            top: grid.history(),
            row: grid.history() + row,
            col,
            anchor: None,
        }
    }

    pub fn pane(&self) -> PaneId {
        self.pane
    }

    /// Where the console's cursor goes, in the pane's own coordinates.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row.saturating_sub(self.top), self.col)
    }

    /// Start selecting at the cursor (`Space`), or drop what was selected.
    pub fn begin_selection(&mut self) {
        self.anchor = Some((self.row, self.col));
    }

    pub fn clear_selection(&mut self) {
        self.anchor = None;
    }

    /// The selected text, as `Enter` copies it into a paste buffer (§7.6).
    ///
    /// Line by line, each with its trailing blanks trimmed, joined by
    /// newlines — a screen is padded to its width and pasting that padding back
    /// into a shell would be typing spaces nobody selected.
    pub fn text(&self, grid: &Grid) -> Option<String> {
        let (from, to) = self.span()?;
        let mut out = String::new();
        for row in from.0..=to.0 {
            let line: Vec<char> = grid.row_text(row).chars().collect();
            let start = if row == from.0 { from.1 } else { 0 };
            let end = if row == to.0 {
                (to.1 + 1).min(line.len())
            } else {
                line.len()
            };
            let piece: String = line
                .get(start..end.max(start))
                .unwrap_or(&[])
                .iter()
                .collect();
            out.push_str(piece.trim_end());
            if row < to.0 {
                out.push('\n');
            }
        }
        Some(out)
    }

    /// What the pane's box shows: the viewport, selection in reverse video.
    ///
    /// The selection is *toggled* rather than set, so text a program had
    /// already painted in reverse still reads as selected.
    pub fn view(&self, grid: &Grid) -> Vec<Vec<Cell>> {
        (0..grid.rows())
            .map(|screen_row| {
                let at = self.top + screen_row;
                let mut cells = grid.row_cells(at);
                for (col, cell) in cells.iter_mut().enumerate() {
                    if self.selected(at, col) {
                        cell.attrs.flags ^= Attrs::REVERSE;
                    }
                }
                cells
            })
            .collect()
    }

    /// tmux's copy-mode indicator: how far up the history the viewport is.
    pub fn indicator(&self, grid: &Grid) -> String {
        format!(
            "[{}/{}]",
            grid.history().saturating_sub(self.top),
            grid.history()
        )
    }

    /// Move, then make sure the cursor is still on a row the box shows.
    pub fn apply(&mut self, motion: Motion, grid: &Grid) {
        let rows = grid.rows();
        match motion {
            Motion::Left => self.col = self.col.saturating_sub(1),
            Motion::Right => self.col += 1,
            Motion::Up => self.row = self.row.saturating_sub(1),
            Motion::Down => self.row += 1,
            Motion::NextWord => self.next_word(grid),
            Motion::PreviousWord => self.previous_word(grid),
            Motion::LineStart => self.col = 0,
            // The last character the line has, not the last column it could:
            // `$` on a short line must not land in the padding.
            Motion::LineEnd => self.col = last_column(grid, self.row),
            Motion::Top => {
                self.row = 0;
                self.col = 0;
            }
            Motion::Bottom => self.row = grid.total_rows().saturating_sub(1),
            Motion::HalfPageUp => self.scroll(true, rows / 2),
            Motion::HalfPageDown => self.scroll(false, rows / 2),
            Motion::PageUp => self.scroll(true, rows),
            Motion::PageDown => self.scroll(false, rows),
        }
        self.clamp(grid);
    }

    /// Put the cursor at `(row, col)`, which is what a search match is.
    pub fn go_to(&mut self, at: (usize, usize), grid: &Grid) {
        (self.row, self.col) = at;
        self.clamp(grid);
    }

    /// Where the cursor is, in the buffer's coordinates.
    pub fn at(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    /// The viewport and the cursor both move; `C-u` and friends scroll the
    /// text rather than only walking the cursor over it.
    fn scroll(&mut self, up: bool, lines: usize) {
        let lines = lines.max(1);
        if up {
            self.row = self.row.saturating_sub(lines);
            self.top = self.top.saturating_sub(lines);
        } else {
            self.row += lines;
            self.top += lines;
        }
    }

    /// Keep the cursor inside the buffer and the viewport around the cursor.
    ///
    /// Called after every motion, and after anything that could have changed
    /// the pane underneath — a pane whose program is still printing grows its
    /// history while copy mode is up, and a resize changes the box.
    pub fn clamp(&mut self, grid: &Grid) {
        let rows = grid.rows();
        self.row = self.row.min(grid.total_rows().saturating_sub(1));
        self.col = self.col.min(grid.cols().saturating_sub(1));
        self.top = self.top.min(grid.total_rows().saturating_sub(rows));
        self.top = self.top.min(self.row);
        if self.row >= self.top + rows {
            self.top = self.row + 1 - rows;
        }
    }

    /// The selection's two ends, in reading order.
    fn span(&self) -> Option<((usize, usize), (usize, usize))> {
        let anchor = self.anchor?;
        let cursor = (self.row, self.col);
        Some(if anchor <= cursor {
            (anchor, cursor)
        } else {
            (cursor, anchor)
        })
    }

    fn selected(&self, row: usize, col: usize) -> bool {
        match self.span() {
            Some((from, to)) => from <= (row, col) && (row, col) <= to,
            None => false,
        }
    }

    /// `w`: the first character of the next word, wherever it is.
    ///
    /// A word is a run of anything that is not a blank, and the padding past
    /// the end of a line is blank — so a word motion crosses lines, as vi's
    /// does, without the grid having to say where a line ends.
    fn next_word(&mut self, grid: &Grid) {
        let mut at = (self.row, self.col);
        let mut crossed_a_blank = false;
        while let Some(next) = step(grid, at, true) {
            crossed_a_blank |= is_blank(grid, at);
            at = next;
            if crossed_a_blank && !is_blank(grid, at) {
                break;
            }
        }
        (self.row, self.col) = at;
    }

    /// `b`: the first character of this word, or of the one before it.
    fn previous_word(&mut self, grid: &Grid) {
        let mut at = (self.row, self.col);
        while let Some(previous) = step(grid, at, false) {
            at = previous;
            if !is_blank(grid, at) {
                break;
            }
        }
        while let Some(previous) = step(grid, at, false) {
            if is_blank(grid, previous) {
                break;
            }
            at = previous;
        }
        (self.row, self.col) = at;
    }
}

/// Find `needle` in the pane's text, starting one position past `from`.
///
/// **It wraps**, as vi's `n` and tmux's search both do: a search that runs off
/// the end carries on from the other, so the last match leads back to the first
/// rather than to nothing. Case-sensitive, which is vi's default and the only
/// one §7.6 asks for.
///
/// What it searches is the *text* of each row — the same accessor copy mode
/// walks (§7.5) — so a match in history reads exactly like a match on screen.
pub fn find(
    grid: &Grid,
    needle: &str,
    from: (usize, usize),
    forward: bool,
) -> Option<(usize, usize)> {
    if needle.is_empty() {
        return None;
    }
    let total = grid.total_rows();
    // `0..=total` visits the row the cursor is on twice: once for the matches
    // past the cursor, and once at the end of the wrap for the ones before it.
    for offset in 0..=total {
        let row = if forward {
            (from.0 + offset) % total
        } else {
            (from.0 + total - offset % total) % total
        };
        let line = grid.row_text(row);
        let mut hits = columns_of(&line, needle).into_iter();
        let hit = if forward {
            hits.find(|col| offset > 0 || *col > from.1)
        } else {
            hits.rev().find(|col| offset > 0 || *col < from.1)
        };
        if hit.is_some() {
            return hit.map(|col| (row, col));
        }
    }
    None
}

/// Every column `needle` starts at in `line`, counting characters rather than
/// bytes: a column is a character here, whatever its width (§1.2).
fn columns_of(line: &str, needle: &str) -> Vec<usize> {
    let hay: Vec<char> = line.chars().collect();
    let pin: Vec<char> = needle.chars().collect();
    if pin.is_empty() || pin.len() > hay.len() {
        return Vec::new();
    }
    (0..=hay.len() - pin.len())
        .filter(|at| hay[*at..*at + pin.len()] == pin[..])
        .collect()
}

/// One position forward or back, wrapping between lines.
fn step(grid: &Grid, (row, col): (usize, usize), forward: bool) -> Option<(usize, usize)> {
    if forward {
        if col + 1 < grid.cols() {
            Some((row, col + 1))
        } else if row + 1 < grid.total_rows() {
            Some((row + 1, 0))
        } else {
            None
        }
    } else if col > 0 {
        Some((row, col - 1))
    } else if row > 0 {
        Some((row - 1, grid.cols() - 1))
    } else {
        None
    }
}

fn is_blank(grid: &Grid, (row, col): (usize, usize)) -> bool {
    grid.row_text(row)
        .chars()
        .nth(col)
        .is_none_or(|c| c.is_whitespace())
}

/// The column of a line's last character, or 0 for an empty one.
fn last_column(grid: &Grid, row: usize) -> usize {
    grid.row_text(row).chars().count().saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ansi::Parser;

    /// A pane `rows` x `cols` that has printed `bytes`, plus copy mode on it.
    fn copying(rows: usize, cols: usize, bytes: &[u8]) -> (Grid, CopyMode) {
        let mut grid = Grid::new(rows, cols);
        let mut parser = Parser::new();
        parser.feed(bytes, &mut |action| {
            let _ = grid.apply(action);
        });
        let copy = CopyMode::enter(PaneId::next(), &grid);
        (grid, copy)
    }

    /// The viewport as text, which is what the user is looking at.
    fn shown(copy: &CopyMode, grid: &Grid) -> Vec<String> {
        copy.view(grid)
            .iter()
            .map(|row| {
                let text: String = row.iter().map(|cell| cell.ch).collect();
                text.trim_end().to_owned()
            })
            .collect()
    }

    fn walk(copy: &mut CopyMode, grid: &Grid, motions: &[Motion]) {
        for motion in motions {
            copy.apply(*motion, grid);
        }
    }

    #[test]
    fn copy_mode_opens_on_the_live_screen_at_the_cursor() {
        // What the user was looking at does not move under them when they press
        // `prefix [`; only the keys change meaning.
        let (grid, copy) = copying(3, 10, b"one\r\ntwo\r\nthree\r\nfour");
        assert_eq!(shown(&copy, &grid), ["two", "three", "four"]);
        assert_eq!(copy.cursor(), grid.cursor());
    }

    #[test]
    fn scrolling_up_reaches_the_lines_that_left_the_screen() {
        // The whole point of scrollback: `one` is off the screen and in history
        // (§7.5), and copy mode is how it is read.
        let (grid, mut copy) = copying(2, 10, b"one\r\ntwo\r\nthree");
        assert_eq!(shown(&copy, &grid), ["two", "three"]);
        walk(&mut copy, &grid, &[Motion::Up, Motion::Up]);
        assert_eq!(shown(&copy, &grid), ["one", "two"]);
        assert_eq!(copy.cursor().0, 0);
    }

    #[test]
    fn the_top_and_the_bottom_are_the_ends_of_the_history_not_of_the_screen() {
        let (grid, mut copy) = copying(2, 10, b"one\r\ntwo\r\nthree\r\nfour");
        walk(&mut copy, &grid, &[Motion::Top]);
        assert_eq!(shown(&copy, &grid), ["one", "two"]);
        walk(&mut copy, &grid, &[Motion::Bottom]);
        assert_eq!(shown(&copy, &grid), ["three", "four"]);
    }

    #[test]
    fn a_motion_cannot_walk_off_either_end() {
        let (grid, mut copy) = copying(2, 10, b"one\r\ntwo\r\nthree");
        // Up and down keep the column, as vi's `j` and `k` do.
        walk(&mut copy, &grid, &[Motion::Up; 20]);
        assert_eq!(copy.at().0, 0);
        walk(&mut copy, &grid, &[Motion::Down; 20]);
        assert_eq!(copy.at().0, grid.total_rows() - 1);
        walk(&mut copy, &grid, &[Motion::Right; 40]);
        assert_eq!(copy.at().1, grid.cols() - 1);
        walk(&mut copy, &grid, &[Motion::Left; 40]);
        assert_eq!(copy.at().1, 0);
    }

    #[test]
    fn a_page_moves_the_viewport_and_a_half_page_moves_half_of_one() {
        let lines: Vec<String> = (0..20).map(|n| format!("line{n}\r\n")).collect();
        let (grid, mut copy) = copying(4, 10, lines.concat().as_bytes());
        // The screen is the last four lines; the rest is history.
        assert_eq!(shown(&copy, &grid)[0], "line17");
        walk(&mut copy, &grid, &[Motion::PageUp]);
        assert_eq!(shown(&copy, &grid)[0], "line13");
        walk(&mut copy, &grid, &[Motion::HalfPageUp]);
        assert_eq!(shown(&copy, &grid)[0], "line11");
        walk(&mut copy, &grid, &[Motion::HalfPageDown, Motion::PageDown]);
        assert_eq!(shown(&copy, &grid)[0], "line17");
    }

    #[test]
    fn the_line_ends_are_where_the_text_ends_not_where_the_padding_does() {
        // `$` in the padding would select blanks nobody can see.
        let (grid, mut copy) = copying(2, 20, b"a short line\r\n");
        walk(&mut copy, &grid, &[Motion::Up, Motion::LineEnd]);
        assert_eq!(copy.at(), (0, 11));
        walk(&mut copy, &grid, &[Motion::LineStart]);
        assert_eq!(copy.at(), (0, 0));
    }

    #[test]
    fn word_motions_cross_the_end_of_a_line_as_vi_does() {
        let (grid, mut copy) = copying(3, 20, b"alpha bravo\r\ncharlie\r\n");
        walk(&mut copy, &grid, &[Motion::Top]);
        walk(&mut copy, &grid, &[Motion::NextWord]);
        assert_eq!(copy.at(), (0, 6));
        walk(&mut copy, &grid, &[Motion::NextWord]);
        assert_eq!(copy.at(), (1, 0));
        walk(&mut copy, &grid, &[Motion::PreviousWord]);
        assert_eq!(copy.at(), (0, 6));
        walk(&mut copy, &grid, &[Motion::PreviousWord]);
        assert_eq!(copy.at(), (0, 0));
    }

    #[test]
    fn a_word_motion_in_the_middle_of_a_word_goes_to_its_start() {
        let (grid, mut copy) = copying(2, 20, b"alpha bravo\r\n");
        copy.go_to((0, 8), &grid);
        walk(&mut copy, &grid, &[Motion::PreviousWord]);
        assert_eq!(copy.at(), (0, 6));
    }

    #[test]
    fn a_selection_is_what_was_between_the_two_ends() {
        let (grid, mut copy) = copying(3, 20, b"alpha bravo\r\ncharlie\r\n");
        copy.go_to((0, 6), &grid);
        copy.begin_selection();
        copy.go_to((1, 3), &grid);
        assert_eq!(copy.text(&grid).unwrap(), "bravo\nchar");
    }

    #[test]
    fn a_selection_made_backwards_reads_the_same_way_round() {
        let (grid, mut copy) = copying(3, 20, b"alpha bravo\r\ncharlie\r\n");
        copy.go_to((1, 3), &grid);
        copy.begin_selection();
        copy.go_to((0, 6), &grid);
        assert_eq!(copy.text(&grid).unwrap(), "bravo\nchar");
    }

    #[test]
    fn a_selected_line_is_copied_without_the_padding_after_it() {
        // A screen is padded to its width; pasting that back into a shell would
        // be typing spaces nobody selected.
        let (grid, mut copy) = copying(3, 20, b"ab\r\ncd\r\n");
        copy.go_to((0, 0), &grid);
        copy.begin_selection();
        copy.go_to((1, 1), &grid);
        assert_eq!(copy.text(&grid).unwrap(), "ab\ncd");
    }

    #[test]
    fn nothing_is_selected_until_something_is() {
        let (grid, mut copy) = copying(2, 10, b"text\r\n");
        assert!(copy.text(&grid).is_none());
        copy.begin_selection();
        assert_eq!(copy.text(&grid).unwrap(), "");
        copy.clear_selection();
        assert!(copy.text(&grid).is_none());
    }

    #[test]
    fn the_selection_is_marked_on_the_screen_and_nothing_else_is() {
        let (grid, mut copy) = copying(2, 10, b"abcd\r\n");
        copy.go_to((0, 1), &grid);
        copy.begin_selection();
        copy.go_to((0, 2), &grid);
        let painted = &copy.view(&grid)[0];
        let marked: Vec<bool> = painted
            .iter()
            .take(4)
            .map(|cell| cell.attrs.has(Attrs::REVERSE))
            .collect();
        assert_eq!(marked, [false, true, true, false]);
    }

    #[test]
    fn a_search_finds_the_next_match_and_then_the_one_after_it() {
        let (grid, _) = copying(2, 20, b"alpha\r\nbravo\r\nalpha again\r\n");
        assert_eq!(find(&grid, "alpha", (0, 0), true), Some((2, 0)));
        assert_eq!(find(&grid, "again", (0, 0), true), Some((2, 6)));
        assert_eq!(find(&grid, "nothing", (0, 0), true), None);
    }

    #[test]
    fn a_search_wraps_rather_than_stopping_at_the_end() {
        // vi's `n` at the last match goes back to the first, and so does this.
        let (grid, _) = copying(2, 20, b"alpha\r\nbravo\r\nalpha again\r\n");
        assert_eq!(find(&grid, "alpha", (2, 0), true), Some((0, 0)));
        assert_eq!(find(&grid, "alpha", (0, 0), false), Some((2, 0)));
    }

    #[test]
    fn a_backward_search_finds_the_match_before_the_cursor() {
        let (grid, _) = copying(2, 20, b"alpha\r\nbravo\r\nalpha again\r\n");
        assert_eq!(find(&grid, "alpha", (2, 6), false), Some((2, 0)));
        assert_eq!(find(&grid, "bravo", (2, 0), false), Some((1, 0)));
    }

    #[test]
    fn a_search_reads_history_and_the_screen_the_same_way() {
        // The needle is on a line that has scrolled off (§7.5), which is the
        // whole reason to have a search in copy mode at all.
        let (grid, mut copy) = copying(2, 20, b"needle here\r\ntwo\r\nthree\r\n");
        assert!(grid.history() > 0);
        let at = find(&grid, "needle", copy.at(), false).unwrap();
        assert_eq!(at, (0, 0));
        copy.go_to(at, &grid);
        assert_eq!(shown(&copy, &grid)[0], "needle here");
    }

    #[test]
    fn the_indicator_says_how_far_up_the_history_the_view_is() {
        // tmux's `[0/N]`, which is the only thing on screen that says copy mode
        // is up at all.
        let (grid, mut copy) = copying(2, 10, b"one\r\ntwo\r\nthree\r\nfour");
        assert_eq!(copy.indicator(&grid), "[0/2]");
        walk(&mut copy, &grid, &[Motion::Top]);
        assert_eq!(copy.indicator(&grid), "[2/2]");
    }
}
