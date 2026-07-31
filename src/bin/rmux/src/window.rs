//! The windows in a session, and the numbers they answer to.
//!
//! A session has windows; a window has panes (details.md §7.1). The panes live
//! here and where they *go* lives in `layout` — the split tree, which holds
//! [`PaneId`]s and no panes, and is therefore the half of a window that can be
//! tested without spawning anything (§9.3). A window is the join between the
//! two: it owns the children, asks the tree for the boxes, and keeps every
//! pane's screen the size of the box it was given.
//!
//! # Numbers are a user-visible name, not an index
//!
//! `prefix 0`-`9` selects a window *by number* (§2.1), and the status line
//! shows those numbers, so they have to survive things a `Vec` index would not:
//! killing window 1 of `0 1 2` leaves `0 2` and window 2 is still called 2 —
//! unless `renumber-windows` is on, which the config sets (§2.1), and then the
//! list compacts to `0 1`. Both behaviours are one function apart, and mixing
//! them up means `prefix 2` silently selecting somebody else's shell.
//!
//! # A window's name follows its program until a user says otherwise
//!
//! tmux names a window after what is running in it and lets `prefix ,` override
//! that for good. rmux does the same with what §5.2 already collects: the
//! **active** pane's `OSC 0`/`2` title. Once renamed, a window keeps its name —
//! the flag that remembers this is the whole difference between a status line
//! that tracks reality and one that argues with the user.
//!
//! # A pane is removed when its child's output ends, and only then
//!
//! `prefix x` kills a child; it does not take the pane out. What does that is
//! the drain (§4.5), which arrives once everything the program printed is in the
//! grid — so the one path that removes a pane is the one that has all of its
//! output, whether the program exited or was killed.

use std::sync::mpsc::Sender;

use crate::bindings::Direction;
use crate::bindings::Split;
use crate::config::PaneOpts;
use crate::layout::Layout;
use crate::layout::Rect;
use crate::pane::Pane;
use crate::pane::PaneId;
use crate::server::Event;

/// One window: a number, a name, and the panes running in it.
pub struct Window {
    number: usize,
    name: String,
    /// Whether [`Window::name`] is still following the active pane's title.
    auto_name: bool,
    panes: Vec<Pane>,
    layout: Layout,
    /// The size the window has to live in, and what the layout divides.
    size: (u16, u16),
}

impl Window {
    pub fn number(&self) -> usize {
        self.number
    }

    /// What the status line calls this window.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Give the window a name of its own (`prefix ,`), for good.
    pub fn rename(&mut self, name: String) {
        self.name = name;
        self.auto_name = false;
    }

    /// The pane a client's keys go to.
    ///
    /// `None` never happens in practice — a window always has a pane, and one of
    /// them is always in front (`layout`) — but the tree and the panes are two
    /// collections and this is not the place to assert that they agree.
    pub fn pane(&self) -> Option<&Pane> {
        let active = self.layout.active();
        self.panes.iter().find(|pane| pane.id() == active)
    }

    pub fn pane_mut(&mut self) -> Option<&mut Pane> {
        let active = self.layout.active();
        self.panes.iter_mut().find(|pane| pane.id() == active)
    }

    /// One pane of this window by identity, wherever it is on screen.
    pub fn pane_by(&mut self, pane: PaneId) -> Option<&mut Pane> {
        self.panes.iter_mut().find(|held| held.id() == pane)
    }

    pub fn holds(&self, pane: PaneId) -> bool {
        self.panes.iter().any(|held| held.id() == pane)
    }

    pub fn panes(&self) -> usize {
        self.panes.len()
    }

    /// Whether one pane has the window to itself (`prefix z`).
    ///
    /// The status line says so, as tmux's does: a zoomed window otherwise looks
    /// exactly like a window with one pane, and the user is left wondering where
    /// the others went.
    pub fn is_zoomed(&self) -> bool {
        self.layout.is_zoomed()
    }

    /// Every pane that is on screen, and the box it goes in.
    ///
    /// A zoomed window shows one pane and no borders; the rest are still here
    /// and still running (`layout`).
    pub fn on_screen(&self) -> Vec<(&Pane, Rect)> {
        self.layout
            .geometry(self.area())
            .into_iter()
            .filter_map(|(id, at)| {
                self.panes
                    .iter()
                    .find(|pane| pane.id() == id)
                    .map(|pane| (pane, at))
            })
            .collect()
    }

    /// The border cells between the panes, and the glyph each one gets.
    pub fn borders(&self) -> Vec<(usize, usize, char)> {
        self.layout.borders(self.area())
    }

    /// Where the console's cursor goes, in the window's own coordinates.
    ///
    /// The active pane's, offset by that pane's box, and only when that pane
    /// wants it shown: `ESC[?25l` is per-pane state, and an inactive pane hiding
    /// its cursor must not hide the user's (§3.2).
    pub fn cursor(&self) -> Option<(usize, usize)> {
        let pane = self.pane()?;
        if !pane.grid().cursor_visible() {
            return None;
        }
        let at = self.layout.rect(pane.id(), self.area())?;
        let (row, col) = pane.grid().cursor();
        Some((at.top + row, at.left + col))
    }

    /// Divide the pane in front, and run `shell` in the half that opens up.
    ///
    /// `false` when there was no room for it, and then nothing was spawned:
    /// the tree is asked before a child is started rather than after, so a
    /// refused split does not leave a shell with nowhere to be (tmux's "no
    /// space for new pane").
    ///
    /// The child is spawned **at the size of the box it is about to get**, not
    /// at the window's. On the host either would do, since `fit` tells it again
    /// a moment later; on Motor a pane's `$COLUMNS`/`$LINES` are fixed when its
    /// child is spawned and nothing can change them (§3.2), so being born the
    /// wrong size is permanent -- and a shell that believes it is twice as wide
    /// as it is paints over its neighbour's rows.
    pub fn split(
        &mut self,
        how: Split,
        opts: &PaneOpts,
        events: Sender<Event>,
    ) -> std::io::Result<bool> {
        let Some(box_for_it) = self.layout.room_for(how, self.area()) else {
            return Ok(false);
        };
        let size = (box_for_it.rows as u16, box_for_it.cols as u16);
        let pane = spawn(opts, size, events)?;
        let id = pane.id();
        self.panes.push(pane);
        self.layout.split(how, id, self.area());
        // The pane that *was* there is smaller now, whatever the new one got.
        self.fit();
        Ok(true)
    }

    /// Move to the pane next door (§7.2) — `M-Left` and the prefix arrows.
    pub fn select(&mut self, direction: Direction) -> bool {
        self.layout.select(direction, self.area())
    }

    /// `prefix o`: the next pane in the tree, wrapping.
    pub fn next_pane(&mut self) -> bool {
        self.layout.next_pane()
    }

    /// `prefix z`: give the pane in front the whole window, or put it back.
    pub fn zoom(&mut self) {
        self.layout.zoom();
        self.fit();
    }

    /// End the pane in front (`prefix x`).
    ///
    /// It comes off the layout **at once**, so what the user types next goes to
    /// the pane that is left instead of into a dead pty — a pane that stayed in
    /// front until its output drained swallowed every keystroke in between. The
    /// pane itself is still held until then (see the module docs), which is what
    /// eventually drops the child; asking the layout to close a pane it no
    /// longer has is what makes that second step harmless.
    ///
    /// The *last* pane is not taken off, because there would be nothing to be in
    /// front. It goes when it drains, and the window with it.
    pub fn kill_pane(&mut self) {
        let doomed = self.layout.active();
        if let Some(pane) = self.pane_by(doomed) {
            pane.kill();
        }
        if self.layout.count() > 1 {
            self.layout.close(doomed);
            self.fit();
        }
    }

    /// End every pane, because the window or the session is going (§3.6).
    pub fn kill_panes(&mut self) {
        for pane in &mut self.panes {
            pane.kill();
        }
    }

    /// Take a pane out, its child having gone. Returns whether the window lives.
    ///
    /// The last pane is not removed: with it the window is over, and the caller
    /// takes the whole window away rather than leaving an empty one.
    pub fn close_pane(&mut self, pane: PaneId) -> bool {
        if !self.layout.close(pane) {
            return false;
        }
        self.panes.retain(|held| held.id() != pane);
        self.fit();
        true
    }

    /// Tell the window the size it has to live in.
    ///
    /// The layout is scaled to the new size before the panes are fitted to it,
    /// so a border a user has moved keeps its proportion (`layout::refit`).
    pub fn resize(&mut self, size: (u16, u16)) {
        let was = self.area();
        self.size = size;
        self.layout.refit(was, self.area());
        self.fit();
    }

    /// Move the border next to the active pane — `resize-pane` (§7.1).
    pub fn resize_pane(&mut self, direction: Direction, by: usize) -> bool {
        let moved = self.layout.resize(direction, by, self.area());
        if moved {
            self.fit();
        }
        moved
    }

    /// Give every pane on screen the size of its box.
    ///
    /// The one place a pane learns how big it is, so the tree and the grids
    /// cannot disagree: a split, a kill, a zoom and a resize all end here.
    fn fit(&mut self) {
        for (id, at) in self.layout.geometry(self.area()) {
            if let Some(pane) = self.panes.iter_mut().find(|pane| pane.id() == id) {
                pane.resize((at.rows as u16, at.cols as u16));
            }
        }
    }

    fn area(&self) -> (usize, usize) {
        (self.size.0 as usize, self.size.1 as usize)
    }

    /// Follow the active pane's title, unless the user has taken the name over.
    fn track_title(&mut self) {
        if !self.auto_name {
            return;
        }
        if let Some(title) = self.pane().map(|pane| pane.grid().title())
            && !title.is_empty()
        {
            self.name = title.to_owned();
        }
    }
}

/// Start a pane the way both a new window and a split want one: running the
/// configured shell, keeping the configured scrollback (§2.2).
fn spawn(opts: &PaneOpts, size: (u16, u16), events: Sender<Event>) -> std::io::Result<Pane> {
    let mut pane = Pane::spawn(std::process::Command::new(&opts.shell), size, events)?;
    pane.set_history_limit(opts.history_limit);
    Ok(pane)
}

/// A session's windows, and which one is in front.
pub struct Windows {
    windows: Vec<Window>,
    current: usize,
    /// `renumber-windows`: whether closing a window compacts the rest (§2.1).
    renumber: bool,
}

impl Windows {
    pub fn new(renumber: bool) -> Windows {
        Windows {
            windows: Vec::new(),
            current: 0,
            renumber,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.windows.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Window> {
        self.windows.iter()
    }

    pub fn current(&self) -> Option<&Window> {
        self.windows.get(self.current)
    }

    pub fn current_mut(&mut self) -> Option<&mut Window> {
        self.windows.get_mut(self.current)
    }

    /// Open a window running `shell`, and make it the current one.
    ///
    /// The number is the lowest one free, as tmux does — so filling a gap left
    /// by a killed window reuses its number rather than counting past it.
    pub fn open(
        &mut self,
        opts: &PaneOpts,
        size: (u16, u16),
        events: Sender<Event>,
    ) -> std::io::Result<usize> {
        let pane = spawn(opts, size, events)?;
        let number = self.lowest_free_number();
        let shell = opts.shell.as_str();
        let name = shell.rsplit('/').next().unwrap_or(shell).to_owned();
        let at = self
            .windows
            .iter()
            .position(|window| window.number > number)
            .unwrap_or(self.windows.len());
        self.windows.insert(
            at,
            Window {
                number,
                name,
                auto_name: true,
                layout: Layout::new(pane.id()),
                panes: vec![pane],
                size,
            },
        );
        self.current = at;
        Ok(number)
    }

    fn lowest_free_number(&self) -> usize {
        let mut number = 0;
        while self.windows.iter().any(|window| window.number == number) {
            number += 1;
        }
        number
    }

    /// Move to the next window, wrapping — `prefix n` and `S-Right`.
    pub fn next(&mut self) {
        if !self.windows.is_empty() {
            self.current = (self.current + 1) % self.windows.len();
        }
    }

    /// Move to the previous window, wrapping — `prefix p` and `S-Left`.
    pub fn previous(&mut self) {
        if !self.windows.is_empty() {
            self.current = (self.current + self.windows.len() - 1) % self.windows.len();
        }
    }

    /// Select by the number the user sees, not by position.
    pub fn select(&mut self, number: usize) -> bool {
        match self
            .windows
            .iter()
            .position(|window| window.number == number)
        {
            Some(at) => {
                self.current = at;
                true
            }
            None => false,
        }
    }

    /// Close the current window. Returns whether any are left.
    pub fn close_current(&mut self) -> bool {
        if self.windows.is_empty() {
            return false;
        }
        self.windows.remove(self.current);
        self.after_close();
        !self.windows.is_empty()
    }

    /// A pane's child has gone: take the pane out, and the window with it if it
    /// was the last one. Returns whether the session still has a window.
    pub fn close_holding(&mut self, pane: PaneId) -> bool {
        let Some(at) = self.windows.iter().position(|window| window.holds(pane)) else {
            return !self.windows.is_empty();
        };
        // The window lives on while it has another pane, which is the whole
        // difference a split makes to what a program exiting means.
        if self.windows[at].close_pane(pane) {
            return true;
        }
        self.windows.remove(at);
        if self.current > at {
            self.current -= 1;
        }
        self.after_close();
        !self.windows.is_empty()
    }

    fn after_close(&mut self) {
        if self.renumber {
            // `renumber-windows on`: close the gap, as the config asks (§2.1).
            for (at, window) in self.windows.iter_mut().enumerate() {
                window.number = at;
            }
        }
        self.current = self.current.min(self.windows.len().saturating_sub(1));
    }

    pub fn holding(&self, pane: PaneId) -> Option<usize> {
        self.windows
            .iter()
            .find(|window| window.holds(pane))
            .map(|window| window.number)
    }

    pub fn pane_mut(&mut self, pane: PaneId) -> Option<&mut Pane> {
        self.windows
            .iter_mut()
            .find_map(|window| window.pane_by(pane))
    }

    pub fn get_mut(&mut self, number: usize) -> Option<&mut Window> {
        self.windows
            .iter_mut()
            .find(|window| window.number == number)
    }

    /// End every pane in every window: the session is over (§3.6).
    pub fn kill_all(&mut self) {
        for window in &mut self.windows {
            window.kill_panes();
        }
    }

    /// Let every window's name catch up with what is running in it.
    pub fn track_titles(&mut self) {
        for window in &mut self.windows {
            window.track_title();
        }
    }

    /// Tell every window the size it has to live in.
    pub fn resize(&mut self, size: (u16, u16)) {
        for window in &mut self.windows {
            window.resize(size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// A window list running `true` in each window, which exits at once but
    /// exists long enough to be counted, numbered and named.
    fn opts() -> PaneOpts {
        PaneOpts::new("true")
    }

    fn windows(renumber: bool, count: usize) -> (Windows, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel();
        let mut windows = Windows::new(renumber);
        for _ in 0..count {
            windows.open(&opts(), (24, 80), tx.clone()).unwrap();
        }
        (windows, rx)
    }

    /// One window of `panes` panes, split side by side, `size` big.
    fn split_window(size: (u16, u16), panes: usize) -> (Windows, mpsc::Receiver<Event>) {
        let (tx, rx) = mpsc::channel();
        let mut windows = Windows::new(true);
        windows.open(&opts(), size, tx.clone()).unwrap();
        for _ in 1..panes {
            assert!(
                windows
                    .current_mut()
                    .unwrap()
                    .split(Split::Horizontal, &opts(), tx.clone())
                    .unwrap()
            );
        }
        (windows, rx)
    }

    fn numbers(windows: &Windows) -> Vec<usize> {
        windows.iter().map(|window| window.number()).collect()
    }

    /// Every pane's screen size, in the order the layout puts them on screen.
    fn grids(window: &Window) -> Vec<(usize, usize)> {
        window
            .on_screen()
            .iter()
            .map(|(pane, _)| (pane.grid().rows(), pane.grid().cols()))
            .collect()
    }

    #[test]
    fn windows_are_numbered_from_zero_as_tmux_numbers_them() {
        let (windows, _rx) = windows(true, 3);
        assert_eq!(numbers(&windows), [0, 1, 2]);
    }

    #[test]
    fn a_new_window_becomes_the_current_one() {
        let (windows, _rx) = windows(true, 3);
        assert_eq!(windows.current().unwrap().number(), 2);
    }

    #[test]
    fn next_and_previous_wrap_around() {
        let (mut windows, _rx) = windows(true, 3);
        windows.select(0);
        windows.previous();
        assert_eq!(windows.current().unwrap().number(), 2);
        windows.next();
        assert_eq!(windows.current().unwrap().number(), 0);
    }

    #[test]
    fn a_window_is_selected_by_the_number_the_user_sees() {
        // `prefix 2` must find the window *called* 2, which after a kill is not
        // the third one in the list unless renumbering says so.
        let (mut windows, _rx) = windows(false, 3);
        windows.select(1);
        assert!(windows.close_current());
        assert_eq!(numbers(&windows), [0, 2]);
        assert!(windows.select(2));
        assert_eq!(windows.current().unwrap().number(), 2);
        assert!(!windows.select(1));
    }

    #[test]
    fn renumbering_closes_the_gap_a_kill_leaves() {
        // `set -g renumber-windows on` (§2.1).
        let (mut windows, _rx) = windows(true, 3);
        windows.select(1);
        assert!(windows.close_current());
        assert_eq!(numbers(&windows), [0, 1]);
    }

    #[test]
    fn without_renumbering_the_numbers_stay_where_they_were() {
        let (mut windows, _rx) = windows(false, 3);
        windows.select(0);
        assert!(windows.close_current());
        assert_eq!(numbers(&windows), [1, 2]);
    }

    #[test]
    fn a_new_window_takes_the_lowest_free_number() {
        let (mut windows, _rx) = windows(false, 3);
        windows.select(1);
        windows.close_current();
        let (tx, _rx2) = mpsc::channel();
        assert_eq!(windows.open(&opts(), (24, 80), tx).unwrap(), 1);
        assert_eq!(numbers(&windows), [0, 1, 2]);
    }

    #[test]
    fn closing_the_last_window_says_the_session_is_over() {
        let (mut windows, _rx) = windows(true, 1);
        assert!(!windows.close_current());
        assert!(windows.is_empty());
    }

    #[test]
    fn the_current_window_stays_inside_the_list_after_a_kill() {
        let (mut windows, _rx) = windows(true, 3);
        // The last one is current; killing it must not leave `current` past the
        // end, which would make every later lookup return nothing.
        assert!(windows.close_current());
        assert!(windows.current().is_some());
        assert_eq!(windows.current().unwrap().number(), 1);
    }

    #[test]
    fn killing_a_window_before_the_current_one_keeps_the_same_one_in_front() {
        let (mut windows, _rx) = windows(false, 3);
        let held = windows.iter().next().unwrap().pane().unwrap().id();
        windows.select(2);
        assert!(windows.close_holding(held));
        assert_eq!(windows.current().unwrap().number(), 2);
    }

    #[test]
    fn a_window_is_named_after_what_runs_in_it() {
        let (windows, _rx) = windows(true, 1);
        assert_eq!(windows.current().unwrap().name(), "true");
    }

    #[test]
    fn a_renamed_window_keeps_its_name() {
        // `prefix ,` overrides the program's name for good, so a later title
        // from the pane must not argue with the user.
        let (mut windows, _rx) = windows(true, 1);
        windows.current_mut().unwrap().rename("build".into());
        windows.track_titles();
        assert_eq!(windows.current().unwrap().name(), "build");
    }

    #[test]
    fn a_split_puts_a_second_pane_in_the_same_window() {
        // `prefix |` makes a pane, not a window: the window list is unchanged
        // and `prefix 1` still means nothing.
        let (windows, _rx) = split_window((24, 80), 2);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows.current().unwrap().panes(), 2);
    }

    #[test]
    fn every_pane_is_given_the_size_of_its_box() {
        // The pane's screen *is* what its program is told the terminal is
        // (§3.2), so a pane whose grid is still the whole window answers
        // `ESC[6n` with a lie and draws outside its box.
        let (windows, _rx) = split_window((24, 80), 2);
        assert_eq!(grids(windows.current().unwrap()), [(24, 40), (24, 39)]);
    }

    #[test]
    fn a_pane_keeps_the_scrollback_the_config_asked_for() {
        // `history-limit` is a memory bound (§7.5), so it has to reach the grid
        // that does the remembering rather than stop at the config.
        let (tx, _rx) = mpsc::channel();
        let mut windows = Windows::new(true);
        let opts = PaneOpts {
            shell: "cat".to_owned(),
            history_limit: 2,
        };
        windows.open(&opts, (2, 10), tx).unwrap();
        let window = windows.current_mut().unwrap();
        window.pane_mut().unwrap().feed(b"a\r\nb\r\nc\r\nd\r\ne");
        assert_eq!(window.pane().unwrap().grid().history(), 2);
    }

    #[test]
    fn resizing_the_window_resizes_every_pane_in_it() {
        let (mut windows, _rx) = split_window((24, 80), 2);
        windows.resize((12, 40));
        assert_eq!(grids(windows.current().unwrap()), [(12, 20), (12, 19)]);
    }

    #[test]
    fn a_window_with_no_room_to_split_keeps_the_pane_it_has() {
        // Nothing is spawned, which is the point of asking first: a shell with
        // nowhere to be would sit there holding a pipe.
        let (windows, _rx) = split_window((24, 2), 1);
        let (tx, _rx2) = mpsc::channel();
        let mut windows = windows;
        let window = windows.current_mut().unwrap();
        assert!(!window.split(Split::Horizontal, &opts(), tx).unwrap());
        assert_eq!(window.panes(), 1);
    }

    #[test]
    fn a_pane_exiting_leaves_the_window_to_the_others() {
        // The difference a split makes to what a program exiting means: the
        // window survives it, and the space goes to the pane that is left.
        let (mut windows, _rx) = split_window((24, 80), 2);
        let gone = windows.current().unwrap().pane().unwrap().id();
        assert!(windows.close_holding(gone));
        assert_eq!(windows.len(), 1);
        let window = windows.current().unwrap();
        assert_eq!(window.panes(), 1);
        assert_eq!(grids(window), [(24, 80)]);
    }

    #[test]
    fn the_last_pane_exiting_closes_the_window() {
        let (mut windows, _rx) = split_window((24, 80), 2);
        let first = windows.current().unwrap().pane().unwrap().id();
        assert!(windows.close_holding(first));
        let second = windows.current().unwrap().pane().unwrap().id();
        assert!(!windows.close_holding(second));
        assert!(windows.is_empty());
    }

    #[test]
    fn a_killed_pane_stops_being_the_one_in_front_at_once() {
        // `prefix x` kills a child, and a pane is only removed once its output
        // has drained -- so between the two the keys have to go somewhere, and
        // it must not be the pane whose pty just died. Found by a host test that
        // typed straight after the kill and watched it vanish.
        let (mut windows, _rx) = split_window((24, 80), 2);
        let window = windows.current_mut().unwrap();
        let doomed = window.pane().unwrap().id();
        window.kill_pane();

        assert_ne!(window.pane().unwrap().id(), doomed);
        assert_eq!(window.on_screen().len(), 1);
        assert!(window.borders().is_empty());
        assert_eq!(grids(window), [(24, 80)]);
        // Still held, because its output has not drained yet.
        assert_eq!(window.panes(), 2);

        assert!(window.close_pane(doomed));
        assert_eq!(window.panes(), 1);
    }

    #[test]
    fn killing_the_only_pane_leaves_it_in_front_until_it_drains() {
        // There would be nothing else to be in front, and the window is what
        // goes -- when the pane drains, along with it.
        let (mut windows, _rx) = split_window((24, 80), 1);
        let window = windows.current_mut().unwrap();
        let doomed = window.pane().unwrap().id();
        window.kill_pane();
        assert_eq!(window.pane().unwrap().id(), doomed);
        assert!(!window.close_pane(doomed));
    }

    #[test]
    fn a_zoomed_pane_is_the_only_one_on_screen_and_gets_the_whole_window() {
        let (mut windows, _rx) = split_window((24, 80), 2);
        let window = windows.current_mut().unwrap();
        window.zoom();
        assert_eq!(grids(window), [(24, 80)]);
        assert!(window.borders().is_empty());
        // The other pane is still there, and comes back the size of its box.
        assert_eq!(window.panes(), 2);
        window.zoom();
        assert_eq!(grids(window), [(24, 40), (24, 39)]);
    }

    #[test]
    fn the_cursor_is_the_active_panes_own_moved_into_its_box() {
        // A pane draws in its own coordinates and knows nothing about the
        // window, so the offset is the window's job -- and getting it wrong puts
        // the console's cursor in the wrong pane entirely.
        let (mut windows, _rx) = split_window((24, 80), 2);
        let window = windows.current_mut().unwrap();
        // The second pane is in front, and its box starts at column 41.
        window.pane_mut().unwrap().feed(b"\x1b[3;5H");
        assert_eq!(window.cursor(), Some((2, 41 + 4)));

        // A pane that hides its cursor must not hide the user's when it is not
        // the one in front (§3.2).
        window.pane_mut().unwrap().feed(b"\x1b[?25l");
        assert_eq!(window.cursor(), None);
    }

    #[test]
    fn the_name_follows_the_pane_in_front_after_a_split() {
        let (mut windows, _rx) = split_window((24, 80), 2);
        let window = windows.current_mut().unwrap();
        window.pane_mut().unwrap().feed(b"\x1b]2;second\x07");
        windows.track_titles();
        assert_eq!(windows.current().unwrap().name(), "second");
    }
}
