//! The status line: one row that says where you are.
//!
//! tmux's default `status-left` is `[#S]`, so the session's name is the first
//! thing on it — which is the point, because with real sessions (details.md §7.3)
//! "which one am I in" is a question a user can actually have. After it comes
//! the window list, with the current window marked, since `prefix 0`-`9`
//! selects by the numbers shown here (§2.1).
//!
//! # What is deliberately not here
//!
//! **The `#{...}` format language** (§1.2). The layout below is fixed, and
//! `status-left`/`status-right` are not settable — `rmux.toml` has one `status`
//! key, on or off (§2.2).
//!
//! **A clock.** §9.2 names "a status-line clock tick rewrites only the digits
//! that changed" as a byte-cost claim worth pinning, and it would be a good
//! one, but a clock means waking the server every second where it now blocks
//! until something happens (§4.5) — and an idle multiplexer that costs nothing
//! is worth more than a clock. The frame diff is already held to the byte by
//! the keystroke tests, which make the same claim without the timer.
//!
//! This module is **pure**: a session in, a row of cells out. It never asks
//! what time it is or how wide the terminal was last time.

use crate::grid::Attrs;
use crate::grid::Cell;
use crate::grid::Color;
use crate::session::Session;

/// How many rows the status line takes when it is shown.
pub const HEIGHT: usize = 1;

/// The chrome's two colours: the bar's, and the deeper one the current window
/// is picked out in. Both carry the same near-black ink, so the bar reads the
/// same on a dark terminal and on a light one -- which it has to, because
/// nothing in rmux ever learns which one it is on. 256-colour, as the rest of
/// the tree emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    bar: Color,
    current: Color,
}

impl Palette {
    /// Amber, where tmux's default status line is green.
    pub const AMBER: Palette = Palette {
        bar: Color::Indexed(222),
        current: Color::Indexed(214),
    };
    /// Light green, for a server whose panes have the None role: the bar is
    /// the colour of a None rush's prompt, and the current window is one step
    /// darker in every channel.
    pub const GREEN: Palette = Palette {
        bar: Color::Indexed(120),
        current: Color::Indexed(77),
    };

    /// The palette for a server whose panes do, or do not, have the None role.
    pub fn for_panes(none_role: bool) -> Palette {
        if none_role { Self::GREEN } else { Self::AMBER }
    }
}

const INK: Color = Color::Indexed(233);

/// Draw the status line for `session`, `cols` wide.
///
/// The bar's colour under near-black ink for the whole row, which is the
/// cheapest way to make a row read as chrome rather than as content. The
/// current window takes the deeper colour -- the bar is the lighter of the
/// two, so what is picked out is the window and not the row -- and nothing
/// else: the text is the same whichever window is current, so a switch moves
/// the highlight and not a single character. The price is that a terminal with
/// no colour cannot tell.
pub fn row(session: &Session, cols: usize, palette: Palette) -> Vec<Cell> {
    let bar = bar(palette);
    let current = Attrs {
        bg: palette.current,
        ..bar
    };

    let mut cells = Vec::with_capacity(cols);
    let mut put = |text: &str, attrs: Attrs| {
        for c in text.chars() {
            cells.push(Cell { ch: c, attrs });
        }
    };

    // Every title brings a space either side, so the highlight has a margin
    // inside it and whatever is next to it keeps its own -- which is why the
    // session name has one of its own too.
    put(&format!("[{}] ", session.name()), bar);
    let front = session.windows().current().map(|window| window.number());
    for window in session.windows().iter() {
        let is_current = front == Some(window.number());
        // `Z` is tmux's flag for a zoomed window (§7.1), and it is the only
        // thing on screen that says why the other panes are not.
        let zoom = if window.is_zoomed() { "Z" } else { "" };
        put(
            &format!(" {}:{}{zoom} ", window.number(), window.name()),
            if is_current { current } else { bar },
        );
    }

    // The bar reaches the right edge whatever is on it: a status line that
    // stopped short of the last column would read as content, not chrome.
    cells.resize(
        cols,
        Cell {
            ch: ' ',
            attrs: bar,
        },
    );
    cells.truncate(cols);
    cells
}

/// The status line, replaced by a prompt the user is typing into.
///
/// tmux puts `prefix ,` and `prefix $` here rather than in a window of their
/// own, and so does rmux: the row is already chrome, and a rename is one line
/// of text. `command-prompt` (`prefix :`) landed in the same place.
pub fn prompt_row(label: &str, typed: &str, cols: usize, palette: Palette) -> Vec<Cell> {
    render(&format!("{label} {typed}"), bar(palette), cols)
}

/// The message line of §2.2: one thing rmux has to say, on the status row.
///
/// Not a row of its own. tmux's message takes the status line over and a key
/// takes it back, and so does this -- a permanent extra row would cost a row of
/// pane for something that is empty almost always. It is drawn as chrome
/// because that is what it is; tmux gives it a colour of its own, where rmux
/// has the one palette and no option to change it (§2.2).
pub fn message_row(text: &str, cols: usize, palette: Palette) -> Vec<Cell> {
    render(text, bar(palette), cols)
}

fn bar(palette: Palette) -> Attrs {
    Attrs {
        fg: INK,
        bg: palette.bar,
        flags: 0,
    }
}

/// How the cells dividing panes are drawn (§7.1) -- chrome, like the bar, and
/// in the bar's colour so that all of it reads as one thing.
///
/// The glyph is what is coloured, not a filled column: `Window::borders` hands
/// out junction glyphs as well as `│` and `─`, and a junction only reads as one
/// if the line is the coloured part.
pub fn border(palette: Palette) -> Attrs {
    Attrs {
        fg: palette.bar,
        ..Attrs::default()
    }
}

/// The session list of §7.3: a plain numbered menu, not `choose-tree` (§1.2).
///
/// One row per session, the current choice marked. With sessions being real,
/// *some* way to see and switch them is a basic, and this is the smallest thing
/// that is one.
pub fn session_overlay(
    lines: &[String],
    at: usize,
    cols: usize,
    palette: Palette,
) -> Vec<Vec<Cell>> {
    let plain = Attrs::default();
    let chosen = bar(palette);

    let mut rows = vec![render(
        "-- sessions: digit or arrows, Esc cancels --",
        plain,
        cols,
    )];
    for (number, line) in lines.iter().enumerate() {
        let attrs = if number == at { chosen } else { plain };
        rows.push(render(&format!("{number}: {line}"), attrs, cols));
    }
    rows
}

fn render(text: &str, attrs: Attrs, cols: usize) -> Vec<Cell> {
    let mut cells: Vec<Cell> = text.chars().map(|ch| Cell { ch, attrs }).collect();
    cells.resize(cols, Cell { ch: ' ', attrs });
    cells.truncate(cols);
    cells
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PaneOpts;
    use crate::server::Event;
    use crate::session::Sessions;
    use std::sync::mpsc;

    /// A pane running `true`, which exits at once and exists long enough to be
    /// counted and named.
    fn opts() -> PaneOpts {
        PaneOpts::new("true")
    }

    fn session_with(name: &str, windows: usize) -> (Sessions, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel();
        let mut sessions = Sessions::new();
        let id = sessions
            .create(Some(name.to_owned()), &opts(), (24, 80), true, tx.clone())
            .unwrap();
        for _ in 1..windows {
            sessions
                .get_mut(id)
                .unwrap()
                .windows_mut()
                .open(&opts(), (24, 80), tx.clone())
                .unwrap();
        }
        (sessions, rx)
    }

    fn text(cells: &[Cell]) -> String {
        cells.iter().map(|cell| cell.ch).collect()
    }

    const AMBER: Palette = Palette::AMBER;

    /// The status line as an Interactive server draws it.
    fn row(session: &Session, cols: usize) -> Vec<Cell> {
        super::row(session, cols, AMBER)
    }

    /// The cells in `palette`'s current-window colour.
    fn lit_in(cells: &[Cell], palette: Palette) -> String {
        cells
            .iter()
            .filter(|cell| cell.attrs.bg == palette.current)
            .map(|cell| cell.ch)
            .collect()
    }

    fn lit(cells: &[Cell]) -> String {
        lit_in(cells, AMBER)
    }

    /// A 256-colour cube entry's red, green, and blue levels, each 0 to 5.
    fn cube(color: Color) -> [u8; 3] {
        let Color::Indexed(n @ 16..=231) = color else {
            panic!("{color:?} is not in the 256-colour cube");
        };
        let n = n - 16;
        [n / 36, n / 6 % 6, n % 6]
    }

    #[test]
    fn the_session_name_comes_first_because_that_is_the_question() {
        let (sessions, _rx) = session_with("build", 1);
        let session = sessions.iter().next().unwrap();
        assert!(text(&row(session, 40)).starts_with("[build] "));
    }

    #[test]
    fn every_window_is_listed_by_the_number_that_selects_it() {
        let (sessions, _rx) = session_with("build", 3);
        let session = sessions.iter().next().unwrap();
        let line = text(&row(session, 60));
        assert!(line.contains("0:true"), "{line:?}");
        assert!(line.contains("1:true"), "{line:?}");
        assert!(line.contains("2:true"), "{line:?}");
    }

    #[test]
    fn every_title_has_a_space_either_side() {
        // Two between titles, so a highlighted title has a margin inside the
        // highlight and the titles next to it keep theirs outside it.
        let (sessions, _rx) = session_with("build", 3);
        let session = sessions.iter().next().unwrap();
        assert_eq!(text(&row(session, 32)), "[build]  0:true  1:true  2:true ");
    }

    #[test]
    fn a_switch_moves_the_highlight_and_not_a_character() {
        // A mark on the current title alone would push every title after it
        // along by its width whenever the current window changed.
        let (mut sessions, _rx) = session_with("build", 3);
        let id = sessions.iter().next().unwrap().id();
        let before = row(sessions.get(id).unwrap(), 60);
        assert!(sessions.get_mut(id).unwrap().windows_mut().select(0));
        let after = row(sessions.get(id).unwrap(), 60);

        assert_eq!(text(&before), text(&after));
        // The third window is the one just opened, so it was in front.
        assert_eq!(lit(&before), " 2:true ");
        assert_eq!(lit(&after), " 0:true ");
    }

    #[test]
    fn a_zoomed_window_is_flagged_because_nothing_else_would_say_so() {
        // tmux's `Z`. A zoomed window looks exactly like a window with one pane
        // (§7.1), so without this the user has no way to tell why the rest of
        // their panes are gone.
        let (mut sessions, _rx) = session_with("build", 1);
        let id = sessions.iter().next().unwrap().id();
        let (tx, _rx2) = mpsc::channel();
        let window = sessions
            .get_mut(id)
            .unwrap()
            .windows_mut()
            .current_mut()
            .unwrap();
        assert!(
            window
                .split(crate::bindings::Split::Vertical, &opts(), tx)
                .unwrap()
        );
        window.zoom();

        let session = sessions.iter().next().unwrap();
        assert!(
            text(&row(session, 60)).contains(" 0:trueZ "),
            "{:?}",
            text(&row(session, 60))
        );
    }

    #[test]
    fn the_bar_is_exactly_as_wide_as_the_console() {
        let (sessions, _rx) = session_with("build", 2);
        let session = sessions.iter().next().unwrap();
        for cols in [1, 8, 20, 80, 200] {
            assert_eq!(row(session, cols).len(), cols, "{cols}");
        }
    }

    #[test]
    fn a_line_too_long_for_the_console_is_cut_rather_than_wrapped() {
        // A status line that wrapped would eat a row of the pane above it.
        let (sessions, _rx) = session_with("a-rather-long-session-name", 4);
        let session = sessions.iter().next().unwrap();
        assert_eq!(row(session, 12).len(), 12);
    }

    #[test]
    fn a_prompt_takes_the_status_row_and_shows_what_is_typed() {
        let cells = prompt_row("(rename-window)", "buil", 40, AMBER);
        assert!(text(&cells).starts_with("(rename-window) buil"));
        assert_eq!(cells.len(), 40);
        assert!(cells.iter().all(|cell| cell.attrs.bg == AMBER.bar));
    }

    #[test]
    fn the_session_list_numbers_every_session_and_marks_the_choice() {
        let lines = ["build: 1 window".to_owned(), "notes: 2 windows".to_owned()];
        let rows = session_overlay(&lines, 1, 40, AMBER);
        assert_eq!(rows.len(), 3);
        assert!(text(&rows[1]).starts_with("0: build"));
        assert!(text(&rows[2]).starts_with("1: notes"));
        // Only the chosen line is highlighted; the rest sit over a pane and are
        // drawn in the pane's own colours.
        assert!(rows[1].iter().all(|cell| cell.attrs == Attrs::default()));
        assert!(rows[2].iter().all(|cell| cell.attrs.bg == AMBER.bar));
    }

    #[test]
    fn the_whole_bar_is_chrome_and_says_so() {
        // Amber to the last column, including the padding: a bar that stopped
        // short would read as content.
        let (sessions, _rx) = session_with("build", 1);
        let session = sessions.iter().next().unwrap();
        let cells = row(session, 40);
        assert!(cells.iter().all(|cell| cell.attrs.fg == INK));
        assert!(
            cells
                .iter()
                .all(|cell| cell.attrs.bg == AMBER.bar || cell.attrs.bg == AMBER.current)
        );
    }

    #[test]
    fn the_split_lines_are_the_bar_colour() {
        // Chrome is chrome: a white divider under an amber bar reads as two
        // different things drawn by two different programs.
        for palette in [Palette::AMBER, Palette::GREEN] {
            assert_eq!(border(palette).fg, palette.bar);
            assert_eq!(border(palette).fg, bar(palette).bg);
            // No background of its own, so a border costs one glyph rather than
            // a column of fill over whatever pane it divides.
            assert_eq!(border(palette).bg, Color::Default);
        }
    }

    #[test]
    fn a_server_with_none_role_panes_draws_all_of_its_chrome_green() {
        assert_eq!(Palette::for_panes(false), Palette::AMBER);
        assert_eq!(Palette::for_panes(true), Palette::GREEN);
        // The colour of a None rush's prompt (rush's `default_prompt`), so a
        // None shell in a None rmux reads as one thing.
        assert_eq!(Palette::GREEN.bar, Color::Indexed(120));

        let (sessions, _rx) = session_with("build", 3);
        let session = sessions.iter().next().unwrap();
        let cells = super::row(session, 60, Palette::GREEN);
        assert_eq!(lit_in(&cells, Palette::GREEN), " 2:true ");
        assert!(cells.iter().all(|cell| cell.attrs.fg == INK));
        assert!(cells.iter().all(|cell| {
            cell.attrs.bg == Palette::GREEN.bar || cell.attrs.bg == Palette::GREEN.current
        }));
        let prompt = prompt_row("(rename-window)", "", 40, Palette::GREEN);
        assert!(
            prompt
                .iter()
                .all(|cell| cell.attrs.bg == Palette::GREEN.bar)
        );
        let message = message_row("no room", 40, Palette::GREEN);
        assert!(
            message
                .iter()
                .all(|cell| cell.attrs.bg == Palette::GREEN.bar)
        );
        let overlay = session_overlay(&["build: 3 windows".to_owned()], 0, 40, Palette::GREEN);
        assert!(
            overlay[1]
                .iter()
                .all(|cell| cell.attrs.bg == Palette::GREEN.bar)
        );
    }

    #[test]
    fn only_the_current_window_takes_the_deeper_amber() {
        // Margins and all, and in the bar's own weight: the colour is the one
        // thing that differs.
        let (sessions, _rx) = session_with("build", 3);
        let session = sessions.iter().next().unwrap();
        let cells = row(session, 60);
        assert_eq!(lit(&cells), " 2:true ");
        assert!(cells.iter().all(|cell| cell.attrs.flags == 0));
    }

    #[test]
    fn the_bar_is_lighter_than_the_window_it_picks_out() {
        // The point of the pair: the row recedes and the current window comes
        // forward, rather than the other way about. In the 256-colour cube,
        // lighter means no channel lower and at least one higher.
        for palette in [Palette::AMBER, Palette::GREEN] {
            let (bar, current) = (cube(palette.bar), cube(palette.current));
            assert!(
                bar != current && bar.iter().zip(current).all(|(b, c)| *b >= c),
                "{palette:?}: the bar is not lighter than the current window"
            );
        }
    }
}
