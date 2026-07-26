//! The split tree: a window's panes, and the boxes they live in.
//!
//! tmux's model, and rmux's (details.md §7.1): a window is a binary tree of
//! splits with panes at the leaves. `split-window -h` divides a pane into two
//! side by side, `-v` stacks them, and each split spends one row or column on a
//! border.
//!
//! # A split remembers one number, and the geometry is the rest of it
//!
//! Every box falls out of the shape of the tree: ask for the geometry with the
//! window's size and it divides its way down. The single exception is where
//! each split puts its border, which a split has to remember because
//! `resize-pane` is a user moving one and a window resized afterwards must
//! keep the shape they chose. That is tmux's model (`layout_cell`), and it is
//! stored the way tmux stores it — in cells, not as a fraction.
//!
//! **What that costs is an invariant**: a stored size means the tree can
//! disagree with the window that owns it. [`Layout::refit`] is what keeps them
//! in step, and the rule is that **the area a layout is asked about only ever
//! changes through a `refit`** — `window.rs` has one place that changes a
//! window's size and it refits there. Anything else asking for geometry at a
//! new size gets borders that were placed for the old one, clamped to fit.
//! Untouched splits cost nothing to keep honest: an even split scaled is an
//! even split, so a layout nobody has resized behaves exactly as it did when
//! nothing was stored at all.
//!
//! # This module is pure
//!
//! Leaves are [`PaneId`]s rather than panes, which is what makes the tree the
//! half of a window that tests in microseconds without spawning anything
//! (§9.3). The geometry, the borders, the adjacency rules and zoom all live
//! here; `window.rs` owns the panes and asks here where to put them.

use std::collections::HashMap;

use crate::bindings::Direction;
use crate::bindings::Split;
use crate::pane::PaneId;

/// A pane's box inside its window, in cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub top: usize,
    pub left: usize,
    pub rows: usize,
    pub cols: usize,
}

impl Rect {
    /// How many cells this box has along the axis a split of `how` divides.
    fn span(self, how: Split) -> usize {
        match how {
            Split::Horizontal => self.cols,
            Split::Vertical => self.rows,
        }
    }

    /// The cells left to divide once the border has taken its own.
    fn room(self, how: Split) -> usize {
        self.span(how).saturating_sub(1)
    }

    /// The two boxes a split leaves, with `at` cells going to the first.
    ///
    /// `at` is clamped rather than trusted. A window can shrink under a layout
    /// without anyone being asked (§3.2), and a box with less room than it was
    /// told to divide gives what it has: the panes are clipped, which is what
    /// happens to everything here that no longer fits.
    fn split_at(self, how: Split, at: usize) -> (Rect, Rect) {
        let room = self.room(how);
        let first = at.max(1).min(room.saturating_sub(1));
        match how {
            Split::Horizontal => (
                Rect {
                    cols: first,
                    ..self
                },
                Rect {
                    left: self.left + first + 1,
                    cols: room - first,
                    ..self
                },
            ),
            Split::Vertical => (
                Rect {
                    rows: first,
                    ..self
                },
                Rect {
                    top: self.top + first + 1,
                    rows: room - first,
                    ..self
                },
            ),
        }
    }

    /// What a fresh split gives its first pane: half, with the odd cell, as
    /// tmux gives it — 80 columns split `-h` become 40, a border, and 39.
    fn even(self, how: Split) -> usize {
        let room = self.room(how);
        room - room / 2
    }

    /// Whether dividing this box leaves both halves something to be: one cell
    /// each, and one for the border.
    fn divisible(self, how: Split) -> bool {
        self.span(how) >= 3
    }
}

/// A split, or a pane at the end of one.
enum Node {
    Leaf(PaneId),
    Split {
        how: Split,
        /// Cells the first child gets, the border not counted.
        ///
        /// **The one thing this tree remembers.** Everything else about a box
        /// falls out of the shape of the tree; this does not, because
        /// `resize-pane` is a user moving a border and a window that changes
        /// size afterwards has to keep the proportion they chose rather than
        /// putting it back to even.
        at: usize,
        first: Box<Node>,
        second: Box<Node>,
    },
}

/// A window's panes, and which one is in front.
pub struct Layout {
    root: Node,
    /// Every pane, most recently used first — so the head is the active one.
    ///
    /// Kept as an order rather than as a single `active`, because two of §7.2's
    /// rules need the history: a tie between panes adjacent in the same
    /// direction goes to the most recent, and so does the pane that takes over
    /// when the active one is killed.
    mru: Vec<PaneId>,
    /// The pane filling the window on its own (`prefix z`), if any.
    zoomed: Option<PaneId>,
}

impl Layout {
    pub fn new(pane: PaneId) -> Layout {
        Layout {
            root: Node::Leaf(pane),
            mru: vec![pane],
            zoomed: None,
        }
    }

    /// The pane a client's keys go to, and the only one whose cursor is drawn.
    pub fn active(&self) -> PaneId {
        self.mru[0]
    }

    /// Every pane in tree order, which is the order `prefix o` walks.
    pub fn panes(&self) -> Vec<PaneId> {
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }

    /// How many panes the window has. Never zero: a layout is made from one.
    pub fn count(&self) -> usize {
        self.panes().len()
    }

    /// The box a split would give the new pane, or `None` if there is no room.
    ///
    /// Asked *before* a pane is spawned, and it answers both questions a caller
    /// has: whether to spawn at all — a window with no space must not start a
    /// shell it has nowhere to put, which is tmux's "no space for new pane" —
    /// and how big to make it. The size matters on Motor beyond the first paint,
    /// because a pane's `$COLUMNS`/`$LINES` are set when its child is spawned and
    /// nothing can change them afterwards (§3.2).
    pub fn room_for(&self, how: Split, area: (usize, usize)) -> Option<Rect> {
        let at = self.rect(self.active(), area)?;
        at.divisible(how).then(|| at.split_at(how, at.even(how)).1)
    }

    /// Divide the active pane, putting `new` in the half that opens up.
    ///
    /// The new pane becomes the active one, as it does in tmux. Refuses, and
    /// changes nothing, when there is no room for it.
    pub fn split(&mut self, how: Split, new: PaneId, area: (usize, usize)) -> bool {
        let Some(box_for_it) = self
            .rect(self.active(), area)
            .filter(|at| at.divisible(how))
        else {
            return false;
        };
        // A zoomed pane is the whole window, so what a split divides is not
        // what the user is looking at. tmux unzooms; so does this.
        self.zoomed = None;
        let active = self.active();
        divide(&mut self.root, active, how, new, box_for_it.even(how));
        self.mru.insert(0, new);
        true
    }

    /// Move a border, by `by` cells — `resize-pane -L`/`-R`/`-U`/`-D` (§7.1).
    ///
    /// **Which border is tmux's rule, and it is not the obvious one**
    /// (`layout_resize_pane`): the one moved is the border *after* the pane,
    /// and only when the pane has none — it is the last one along that axis —
    /// the border before it. In a binary tree "after the pane" is the nearest
    /// ancestor that holds the pane in its *first* child: everything below it
    /// on the way down was a second child, so the pane is the last leaf of that
    /// subtree and the ancestor's border is against the pane's own edge.
    ///
    /// The border then moves **the way the arrow points**, whichever side of
    /// it the pane is on: `-R` on a pane with a border after it widens the
    /// pane, and `-R` on the last pane along the axis narrows it, because the
    /// border it shares with its neighbour has moved into it. That reads
    /// backwards until you watch tmux do it, which is what the corpus case is
    /// for -- a version that always widened the active pane looked more
    /// helpful and put the border in the wrong column.
    ///
    /// Returns whether anything moved: a border already against the edge of
    /// what it divides stays there, and says so by returning `false`.
    pub fn resize(&mut self, direction: Direction, by: usize, area: (usize, usize)) -> bool {
        let how = match direction {
            Direction::Left | Direction::Right => Split::Horizontal,
            Direction::Up | Direction::Down => Split::Vertical,
        };
        let mut path = Vec::new();
        if !path_to(&self.root, self.active(), &mut path) {
            return false;
        }
        let matching = |after: bool| {
            (0..path.len())
                .rev()
                .find(|depth| path[*depth].0 == how && path[*depth].1 == after)
        };
        let Some(depth) = matching(true).or_else(|| matching(false)) else {
            return false;
        };

        let room = rect_of(&self.root, &path[..depth], whole(area)).room(how);
        let grow = matches!(direction, Direction::Right | Direction::Down);
        let Node::Split { at, .. } = node_at(&mut self.root, &path[..depth]) else {
            return false;
        };
        let was = *at;
        let moved = if grow {
            was.saturating_add(by)
        } else {
            was.saturating_sub(by)
        };
        *at = moved.max(1).min(room.saturating_sub(1).max(1));
        *at != was
    }

    /// Scale every border to a window that has changed size (§7.1).
    ///
    /// A split a user has moved keeps the proportion they gave it, which is the
    /// whole reason the tree remembers anything. A split nobody has touched is
    /// still even afterwards, because an even split scaled is an even split —
    /// so this costs the untouched case nothing.
    pub fn refit(&mut self, old: (usize, usize), new: (usize, usize)) {
        refit(&mut self.root, whole(old), whole(new));
    }

    /// Take `pane` out of the tree, and give its space to its sibling.
    ///
    /// Returns whether the window still has a pane in it. The last one is *not*
    /// removed: a window with no panes is over, and the caller closes it rather
    /// than being left holding a tree nobody can ask a question of.
    pub fn close(&mut self, pane: PaneId) -> bool {
        if !self.panes().contains(&pane) {
            return true;
        }
        if self.count() == 1 {
            return false;
        }
        prune(&mut self.root, pane);
        self.mru.retain(|held| *held != pane);
        if self.zoomed == Some(pane) {
            self.zoomed = None;
        }
        true
    }

    /// Put `pane` in front, if the window has it.
    ///
    /// **The pane in front is always on screen**, which is what lets a caller
    /// ask where its cursor goes and get an answer. A zoom hiding the pane being
    /// put in front is therefore over — the same thing tmux does when
    /// `select-pane` names a pane a zoom has covered.
    pub fn focus(&mut self, pane: PaneId) -> bool {
        if !self.panes().contains(&pane) {
            return false;
        }
        if self.zoomed.is_some_and(|zoomed| zoomed != pane) {
            self.zoomed = None;
        }
        self.mru.retain(|held| *held != pane);
        self.mru.insert(0, pane);
        true
    }

    /// Move to the pane next door in `direction` (§7.2).
    ///
    /// **Geometric, not tree order**: what is to the left of a pane is whatever
    /// pane its left edge is up against, however the tree happens to be shaped.
    /// Two panes can be up against the same edge, and the tie goes to the one
    /// used most recently, which is the rule §7.2 states and the reason the
    /// order is kept at all. Nothing there means nothing happens — an edge of
    /// the window does not wrap around to the other side.
    pub fn select(&mut self, direction: Direction, area: (usize, usize)) -> bool {
        let boxes = self.boxes(area);
        let active = self.active();
        let Some((_, from)) = boxes.iter().find(|(pane, _)| *pane == active) else {
            return false;
        };
        let next_door: Vec<PaneId> = boxes
            .iter()
            .filter(|(pane, at)| *pane != active && next_to(*from, *at, direction))
            .map(|(pane, _)| *pane)
            .collect();
        let Some(chosen) = self
            .mru
            .iter()
            .copied()
            .find(|pane| next_door.contains(pane))
        else {
            return false;
        };
        self.focus(chosen)
    }

    /// Move to the next pane in tree order, wrapping — `prefix o`.
    ///
    /// Tree order rather than adjacency, so that repeating it reaches every
    /// pane exactly once. That is what makes it the way round a window when
    /// the geometry is awkward.
    pub fn next_pane(&mut self) -> bool {
        let panes = self.panes();
        let at = panes
            .iter()
            .position(|pane| *pane == self.active())
            .unwrap_or(0);
        let next = panes[(at + 1) % panes.len()];
        self.focus(next)
    }

    /// `prefix z`: give the active pane the whole window, or put the layout
    /// back.
    ///
    /// The other panes are untouched — still running, still holding what they
    /// have printed, just not on screen. A window with one pane has nothing to
    /// zoom, and says so by staying unzoomed rather than by claiming a state
    /// the status line would then have to explain.
    pub fn zoom(&mut self) {
        self.zoomed = match self.zoomed {
            Some(_) => None,
            None if self.count() > 1 => Some(self.active()),
            None => None,
        };
    }

    pub fn is_zoomed(&self) -> bool {
        self.zoomed.is_some()
    }

    /// Where every pane goes in a window `area` big.
    ///
    /// A zoomed pane is the only one with a box. The rest are still there and
    /// still running — they are simply not on screen.
    pub fn geometry(&self, area: (usize, usize)) -> Vec<(PaneId, Rect)> {
        match self.zoomed {
            Some(zoomed) => vec![(zoomed, whole(area))],
            None => self.boxes(area),
        }
    }

    /// The boxes the tree gives, whether or not a zoom is hiding them.
    ///
    /// Adjacency is a question about the layout, not about what is on screen
    /// (§7.2), so `select` asks here and unzooms afterwards.
    fn boxes(&self, area: (usize, usize)) -> Vec<(PaneId, Rect)> {
        let mut out = Vec::new();
        boxes(&self.root, whole(area), &mut out);
        out
    }

    /// One pane's box, or `None` when it is off screen behind a zoom.
    pub fn rect(&self, pane: PaneId, area: (usize, usize)) -> Option<Rect> {
        self.geometry(area)
            .into_iter()
            .find(|(held, _)| *held == pane)
            .map(|(_, at)| at)
    }

    /// The border cells, and the glyph each one gets.
    ///
    /// ASCII `|`, `-` and `+`, not the box-drawing characters real tmux prefers:
    /// a visible, intended divergence (§7.1) that a conformance case will have
    /// to allow for (§9.1).
    ///
    /// Two borders never share a cell — a split's border spans only the pane it
    /// divides, and that pane never includes its parent's border. What they do
    /// is *meet*: a row border stops against a column border, and the cell it
    /// stopped against becomes the `+` that says so.
    pub fn borders(&self, area: (usize, usize)) -> Vec<(usize, usize, char)> {
        if self.zoomed.is_some() {
            return Vec::new();
        }
        let mut cells = HashMap::new();
        border_cells(&self.root, whole(area), &mut cells);

        // From a snapshot, so that a junction cannot make junctions of its own
        // neighbours: what promotes a cell is a border of the *other*
        // orientation running into it.
        let abutted: Vec<(usize, usize)> = cells
            .iter()
            .filter(|((row, col), glyph)| {
                let crossing = match glyph {
                    '|' => [(*row, col.wrapping_sub(1)), (*row, col + 1)],
                    _ => [(row.wrapping_sub(1), *col), (row + 1, *col)],
                };
                let wanted = if **glyph == '|' { '-' } else { '|' };
                crossing.iter().any(|at| cells.get(at) == Some(&wanted))
            })
            .map(|(at, _)| *at)
            .collect();
        for at in abutted {
            cells.insert(at, '+');
        }

        let mut cells: Vec<(usize, usize, char)> = cells
            .into_iter()
            .map(|((row, col), glyph)| (row, col, glyph))
            .collect();
        cells.sort_unstable_by_key(|(row, col, _)| (*row, *col));
        cells
    }
}

/// The whole window as a box, which is what the tree divides.
fn whole(area: (usize, usize)) -> Rect {
    Rect {
        top: 0,
        left: 0,
        rows: area.0,
        cols: area.1,
    }
}

/// Whether `to` is the box immediately `direction` of `from`.
///
/// Immediately: exactly one cell of border between the two edges, since that is
/// what a split leaves and there is nothing else a gap could be. The other axis
/// only has to overlap — two panes are side by side even when one is taller.
fn next_to(from: Rect, to: Rect, direction: Direction) -> bool {
    let rows_overlap = to.top < from.top + from.rows && from.top < to.top + to.rows;
    let cols_overlap = to.left < from.left + from.cols && from.left < to.left + to.cols;
    match direction {
        Direction::Left => to.left + to.cols + 1 == from.left && rows_overlap,
        Direction::Right => from.left + from.cols + 1 == to.left && rows_overlap,
        Direction::Up => to.top + to.rows + 1 == from.top && cols_overlap,
        Direction::Down => from.top + from.rows + 1 == to.top && cols_overlap,
    }
}

fn walk(node: &Node, out: &mut Vec<PaneId>) {
    match node {
        Node::Leaf(pane) => out.push(*pane),
        Node::Split { first, second, .. } => {
            walk(first, out);
            walk(second, out);
        }
    }
}

fn boxes(node: &Node, rect: Rect, out: &mut Vec<(PaneId, Rect)>) {
    match node {
        Node::Leaf(pane) => out.push((*pane, rect)),
        Node::Split {
            how,
            at,
            first,
            second,
        } => {
            let (a, b) = rect.split_at(*how, *at);
            boxes(first, a, out);
            boxes(second, b, out);
        }
    }
}

/// The one cell each split spends, for every split under `node`.
fn border_cells(node: &Node, rect: Rect, out: &mut HashMap<(usize, usize), char>) {
    let Node::Split {
        how,
        at,
        first,
        second,
    } = node
    else {
        return;
    };
    let (a, b) = rect.split_at(*how, *at);
    match how {
        Split::Horizontal => {
            let col = a.left + a.cols;
            out.extend((rect.top..rect.top + rect.rows).map(|row| ((row, col), '|')));
        }
        Split::Vertical => {
            let row = a.top + a.rows;
            out.extend((rect.left..rect.left + rect.cols).map(|col| ((row, col), '-')));
        }
    }
    border_cells(first, a, out);
    border_cells(second, b, out);
}

/// The way down to `target`: at each split, whether it is in the first child.
fn path_to(node: &Node, target: PaneId, path: &mut Vec<(Split, bool)>) -> bool {
    match node {
        Node::Leaf(pane) => *pane == target,
        Node::Split {
            how, first, second, ..
        } => {
            for (side, child) in [(true, first), (false, second)] {
                path.push((*how, side));
                if path_to(child, target, path) {
                    return true;
                }
                path.pop();
            }
            false
        }
    }
}

/// The node `path` leads to, to change it.
fn node_at<'a>(mut node: &'a mut Node, path: &[(Split, bool)]) -> &'a mut Node {
    for (_, side) in path {
        let Node::Split { first, second, .. } = node else {
            break;
        };
        node = if *side { first } else { second };
    }
    node
}

/// The box that node has, which is what its border has to stay inside.
fn rect_of(mut node: &Node, path: &[(Split, bool)], mut rect: Rect) -> Rect {
    for (_, side) in path {
        let Node::Split {
            how,
            at,
            first,
            second,
        } = node
        else {
            break;
        };
        let (a, b) = rect.split_at(*how, *at);
        (node, rect) = if *side { (&**first, a) } else { (&**second, b) };
    }
    rect
}

/// Scale one split's border, and everything under it, to a new box.
fn refit(node: &mut Node, old: Rect, new: Rect) {
    let Node::Split {
        how,
        at,
        first,
        second,
    } = node
    else {
        return;
    };
    let (old_a, old_b) = old.split_at(*how, *at);
    let (old_room, new_room) = (old.room(*how), new.room(*how));
    if let Some(old_room) = std::num::NonZeroUsize::new(old_room).map(|room| room.get()) {
        // To the nearest cell, which is not reversible: a window that shrinks
        // and grows back can leave a border a cell from where it started,
        // because the proportion was rounded on the way down. Never below one,
        // though -- a border scaled to nothing could never be scaled back out
        // at all.
        *at = ((*at * new_room + old_room / 2) / old_room).max(1);
    }
    let (new_a, new_b) = new.split_at(*how, *at);
    refit(first, old_a, new_a);
    refit(second, old_b, new_b);
}

/// Turn the leaf holding `target` into a split of `target` and `new`.
fn divide(node: &mut Node, target: PaneId, how: Split, new: PaneId, at: usize) -> bool {
    match node {
        Node::Leaf(pane) if *pane == target => {
            *node = Node::Split {
                how,
                at,
                first: Box::new(Node::Leaf(target)),
                second: Box::new(Node::Leaf(new)),
            };
            true
        }
        Node::Leaf(_) => false,
        Node::Split { first, second, .. } => {
            divide(first, target, how, new, at) || divide(second, target, how, new, at)
        }
    }
}

/// Take the leaf holding `target` out, and put its sibling in their parent's
/// place — which is what gives the space back without leaving a hole.
fn prune(node: &mut Node, target: PaneId) -> bool {
    let Node::Split { first, second, .. } = node else {
        return false;
    };
    let survivor = match (&**first, &**second) {
        (Node::Leaf(pane), _) if *pane == target => Some(false),
        (_, Node::Leaf(pane)) if *pane == target => Some(true),
        _ => None,
    };
    match survivor {
        Some(keep_first) => {
            let Node::Split { first, second, .. } = std::mem::replace(node, Node::Leaf(target))
            else {
                unreachable!("just matched a split")
            };
            *node = if keep_first { *first } else { *second };
            true
        }
        None => prune(first, target) || prune(second, target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout of `count` panes, split whichever way, each split dividing the
    /// pane the previous one made — which is what typing `prefix |` twice does.
    fn layout(how: Split, count: usize, area: (usize, usize)) -> Layout {
        let mut layout = Layout::new(PaneId::next());
        for _ in 1..count {
            assert!(layout.split(how, PaneId::next(), area));
        }
        layout
    }

    fn rects(layout: &Layout, area: (usize, usize)) -> Vec<Rect> {
        layout
            .geometry(area)
            .into_iter()
            .map(|(_, at)| at)
            .collect()
    }

    #[test]
    fn one_pane_has_the_whole_window() {
        let pane = PaneId::next();
        let layout = Layout::new(pane);
        assert_eq!(
            layout.geometry((24, 80)),
            [(
                pane,
                Rect {
                    top: 0,
                    left: 0,
                    rows: 24,
                    cols: 80
                }
            )]
        );
        assert!(layout.borders((24, 80)).is_empty());
    }

    #[test]
    fn a_horizontal_split_puts_the_two_panes_side_by_side() {
        // `bind | split-window -h` (§2.1). 80 columns become 40, a border, 39 —
        // the sizes tmux gives, odd cell to the first pane.
        let layout = layout(Split::Horizontal, 2, (24, 80));
        assert_eq!(
            rects(&layout, (24, 80)),
            [
                Rect {
                    top: 0,
                    left: 0,
                    rows: 24,
                    cols: 40
                },
                Rect {
                    top: 0,
                    left: 41,
                    rows: 24,
                    cols: 39
                }
            ]
        );
    }

    #[test]
    fn a_vertical_split_stacks_the_two_panes() {
        // `bind - split-window -v` (§2.1).
        let layout = layout(Split::Vertical, 2, (23, 80));
        assert_eq!(
            rects(&layout, (23, 80)),
            [
                Rect {
                    top: 0,
                    left: 0,
                    rows: 11,
                    cols: 80
                },
                Rect {
                    top: 12,
                    left: 0,
                    rows: 11,
                    cols: 80
                }
            ]
        );
    }

    #[test]
    fn a_split_costs_exactly_one_line_of_cells() {
        // Every cell of the window belongs to exactly one pane or to a border,
        // which is the invariant a pane drawn one cell too wide would break.
        let area = (24, 80);
        for how in [Split::Horizontal, Split::Vertical] {
            for count in 1..5 {
                let layout = layout(how, count, area);
                let mut seen = vec![0_u8; area.0 * area.1];
                for at in rects(&layout, area) {
                    for row in at.top..at.top + at.rows {
                        for col in at.left..at.left + at.cols {
                            seen[row * area.1 + col] += 1;
                        }
                    }
                }
                for (row, col, _) in layout.borders(area) {
                    seen[row * area.1 + col] += 1;
                }
                assert!(seen.iter().all(|count| *count == 1), "{how:?} x {count}");
            }
        }
    }

    #[test]
    fn a_window_that_changes_size_scales_the_borders_it_was_given() {
        // The tree remembers where its borders are (see the module docs), so a
        // window that changes size has to bring them with it -- and a split
        // nobody has moved is still even afterwards, since an even split scaled
        // is an even split.
        let mut layout = layout(Split::Horizontal, 2, (24, 80));
        assert_eq!(rects(&layout, (24, 80))[1].cols, 39);
        layout.refit((24, 80), (24, 40));
        assert_eq!(rects(&layout, (24, 40))[1].cols, 19);
    }

    #[test]
    fn a_border_the_user_moved_keeps_its_proportion_across_a_resize() {
        // The whole reason the tree remembers anything: tmux keeps the shape a
        // user set up, where an always-even layout would put it back.
        //
        // A split leaves the *new* pane active, which is the right-hand one,
        // and `-L` moves the border between them 20 columns left.
        let mut layout = layout(Split::Horizontal, 2, (24, 80));
        assert!(layout.resize(Direction::Left, 20, (24, 80)));
        assert_eq!(rects(&layout, (24, 80))[0].cols, 20);

        // A quarter of the window before, a quarter of it after.
        layout.refit((24, 80), (24, 40));
        assert_eq!(rects(&layout, (24, 40))[0].cols, 10);
    }

    #[test]
    fn a_resize_moves_the_border_after_the_pane_even_when_it_is_not_the_nearest() {
        // tmux's rule (`layout_resize_pane`), and the case that tells a correct
        // implementation from a plausible one. Splitting the *first* pane of a
        // split builds ((a|b)|c): the border nearest b is the one it shares
        // with a, and the one tmux moves is the one after it, which is an
        // ancestor further up -- between b and c.
        let mut layout = Layout::new(PaneId::next());
        let area = (24, 80);
        assert!(layout.split(Split::Horizontal, PaneId::next(), area));
        let leftmost = layout.panes()[0];
        assert!(layout.focus(leftmost));
        assert!(layout.split(Split::Horizontal, PaneId::next(), area));
        // Left to right the panes are a|b|c, and b is the one just made.
        let middle = layout.panes()[1];
        assert!(layout.focus(middle));

        let before = rects(&layout, area);
        assert!(layout.resize(Direction::Right, 5, area));
        let after = rects(&layout, area);
        assert_eq!(after[0].cols, before[0].cols, "a moved, and it must not");
        assert_eq!(after[1].cols, before[1].cols + 5);
        assert_eq!(after[2].cols, before[2].cols - 5);
    }

    #[test]
    fn the_last_pane_along_an_axis_moves_the_border_before_it() {
        // The other half of the same rule. The right-hand pane has no border
        // after it, so what moves is the one before it -- and it still moves
        // the way the arrow points, so `-R` on that pane makes it *narrower*.
        // Checked against tmux, which is the only reason it is written this
        // way round (`conformance.rs`).
        let mut layout = layout(Split::Horizontal, 2, (24, 80));
        let area = (24, 80);
        let before = rects(&layout, area);
        assert!(layout.resize(Direction::Right, 5, area));
        let after = rects(&layout, area);
        assert_eq!(after[0].cols, before[0].cols + 5);
        assert_eq!(after[1].cols, before[1].cols - 5);
    }

    #[test]
    fn a_border_stops_at_the_edge_of_what_it_divides() {
        // Both panes keep a cell whatever is asked for, and a border already
        // against the edge says so by refusing to move -- which is what stops a
        // held-down key from making a pane that is not there.
        let mut layout = layout(Split::Horizontal, 2, (24, 80));
        let area = (24, 80);
        assert!(layout.resize(Direction::Left, 200, area));
        assert_eq!(rects(&layout, area)[0].cols, 1);
        assert!(!layout.resize(Direction::Left, 1, area));

        assert!(layout.resize(Direction::Right, 200, area));
        assert_eq!(rects(&layout, area)[1].cols, 1);
        assert!(!layout.resize(Direction::Right, 1, area));
    }

    #[test]
    fn a_resize_across_the_grain_finds_nothing_to_move() {
        // A window split only side by side has no horizontal border, so `-U`
        // has nothing to move and changes nothing.
        let mut layout = layout(Split::Horizontal, 2, (24, 80));
        let before = rects(&layout, (24, 80));
        assert!(!layout.resize(Direction::Up, 5, (24, 80)));
        assert_eq!(rects(&layout, (24, 80)), before);
    }

    #[test]
    fn a_pane_with_no_room_left_in_it_is_not_split() {
        // tmux's "no space for new pane". The caller asks before it spawns a
        // shell, so this is what stops a window filling up with orphans.
        let mut layout = Layout::new(PaneId::next());
        assert_eq!(layout.room_for(Split::Horizontal, (24, 2)), None);
        assert!(!layout.split(Split::Horizontal, PaneId::next(), (24, 2)));
        assert_eq!(layout.count(), 1);

        // One column each, and one for the border.
        assert_eq!(
            layout.room_for(Split::Horizontal, (24, 3)),
            Some(Rect {
                top: 0,
                left: 2,
                rows: 24,
                cols: 1
            })
        );
        assert!(layout.split(Split::Horizontal, PaneId::next(), (24, 3)));
        assert_eq!(layout.count(), 2);
    }

    #[test]
    fn the_pane_a_split_makes_is_the_one_in_front() {
        let mut layout = Layout::new(PaneId::next());
        let new = PaneId::next();
        assert!(layout.split(Split::Vertical, new, (24, 80)));
        assert_eq!(layout.active(), new);
    }

    #[test]
    fn a_split_divides_the_pane_in_front_and_not_the_window() {
        // Splitting twice the same way makes three panes of the window, but the
        // second split only takes cells from the pane that was in front.
        let layout = layout(Split::Horizontal, 3, (24, 80));
        let rects = rects(&layout, (24, 80));
        // The first pane keeps its 40 columns; the 39 the second had become 19,
        // a border, and 19.
        assert_eq!(rects[0].cols, 40);
        assert_eq!(rects[1].cols, 19);
        assert_eq!(rects[2].cols, 19);
        assert_eq!(rects[0].left, 0);
        assert_eq!(rects[1].left, 41);
        assert_eq!(rects[2].left, 61);
    }

    #[test]
    fn panes_are_listed_in_the_order_the_tree_holds_them() {
        // `prefix o` walks this order, so it has to be the layout's rather than
        // the order panes were created in.
        let mut layout = Layout::new(PaneId::next());
        let second = PaneId::next();
        assert!(layout.split(Split::Horizontal, second, (24, 80)));
        let third = PaneId::next();
        assert!(layout.split(Split::Vertical, third, (24, 80)));
        let panes = layout.panes();
        assert_eq!(panes.len(), 3);
        // The vertical split divided the second pane, so the third is its
        // neighbour and both come after the first.
        assert_eq!(panes[1], second);
        assert_eq!(panes[2], third);
    }

    /// What glyph, if any, a border puts at one cell.
    fn glyph(layout: &Layout, area: (usize, usize), row: usize, col: usize) -> Option<char> {
        layout
            .borders(area)
            .into_iter()
            .find(|(r, c, _)| (*r, *c) == (row, col))
            .map(|(_, _, ch)| ch)
    }

    #[test]
    fn a_border_that_runs_into_another_makes_a_tee_of_it() {
        // A vertical split inside a horizontal one. The row border spans only
        // the pane it divides, so it stops *against* the column border rather
        // than crossing it -- and the cell it stopped against says so (§7.1).
        let area = (5, 11);
        let mut layout = Layout::new(PaneId::next());
        assert!(layout.split(Split::Horizontal, PaneId::next(), area));
        assert!(layout.split(Split::Vertical, PaneId::next(), area));

        assert_eq!(glyph(&layout, area, 0, 5), Some('|'));
        assert_eq!(glyph(&layout, area, 4, 5), Some('|'));
        assert_eq!(glyph(&layout, area, 2, 6), Some('-'));
        assert_eq!(glyph(&layout, area, 2, 10), Some('-'));
        assert_eq!(glyph(&layout, area, 2, 5), Some('+'));
        // The tee is one of the cells the borders already had, not an extra.
        assert_eq!(layout.borders(area).len(), 5 + 5);
    }

    #[test]
    fn a_tee_is_made_the_other_way_round_too() {
        // A horizontal split inside a vertical one: now it is the column border
        // that stops against the row border, from below.
        let area = (5, 11);
        let mut layout = Layout::new(PaneId::next());
        assert!(layout.split(Split::Vertical, PaneId::next(), area));
        assert!(layout.split(Split::Horizontal, PaneId::next(), area));

        assert_eq!(glyph(&layout, area, 2, 0), Some('-'));
        assert_eq!(glyph(&layout, area, 3, 5), Some('|'));
        assert_eq!(glyph(&layout, area, 2, 5), Some('+'));
    }

    /// Three panes: `top-left`, `right` beside it, and `bottom` under both.
    ///
    /// The shape two of §7.2's rules need — `bottom` has two panes above it, so
    /// selecting up from it is a tie, and nothing about the tree says which.
    fn three(area: (usize, usize)) -> (Layout, PaneId, PaneId, PaneId) {
        let top_left = PaneId::next();
        let bottom = PaneId::next();
        let right = PaneId::next();
        let mut layout = Layout::new(top_left);
        assert!(layout.split(Split::Vertical, bottom, area));
        assert!(layout.focus(top_left));
        assert!(layout.split(Split::Horizontal, right, area));
        (layout, top_left, right, bottom)
    }

    #[test]
    fn killing_a_pane_gives_its_space_to_its_sibling() {
        // Which pane is left matters as much as how big it is: the space is the
        // sibling's, and a kill that kept the killed pane's leaf instead would
        // give exactly the same picture to the wrong shell.
        let area = (24, 80);
        let first = PaneId::next();
        let second = PaneId::next();
        let mut layout = Layout::new(first);
        assert!(layout.split(Split::Horizontal, second, area));
        assert!(layout.close(second));
        assert_eq!(layout.geometry(area), [(first, whole(area))]);
        assert!(layout.borders(area).is_empty());

        let mut layout = Layout::new(first);
        assert!(layout.split(Split::Horizontal, second, area));
        assert!(layout.close(first));
        assert_eq!(layout.geometry(area), [(second, whole(area))]);
    }

    #[test]
    fn killing_the_last_pane_says_the_window_is_over() {
        // The window is what goes, not the tree: a layout with nothing in it
        // could not answer `active`, and every caller asks that.
        let pane = PaneId::next();
        let mut layout = Layout::new(pane);
        assert!(!layout.close(pane));
        assert_eq!(layout.active(), pane);
        assert_eq!(layout.count(), 1);
    }

    #[test]
    fn the_pane_in_front_after_a_kill_is_the_one_used_before_it() {
        let area = (24, 80);
        let (mut layout, top_left, right, bottom) = three(area);
        assert!(layout.focus(bottom));
        assert!(layout.focus(right));
        assert!(layout.close(right));
        assert_eq!(layout.active(), bottom);
        // The order and the tree have to agree about who is left, or the pane
        // in front is one the window no longer has.
        assert_eq!(layout.panes(), [top_left, bottom]);
        assert!(layout.close(bottom));
        assert_eq!(layout.active(), top_left);
        assert_eq!(layout.panes(), [top_left]);
    }

    #[test]
    fn a_pane_is_chosen_by_where_it_is_and_not_by_tree_order() {
        // §7.2: `M-Left` and friends are geometric. The pane to the right of the
        // top-left one is its neighbour in the tree; the one below it is not,
        // and both have to be reachable.
        let area = (23, 80);
        let (mut layout, top_left, right, bottom) = three(area);
        assert!(layout.focus(top_left));
        assert!(layout.select(Direction::Right, area));
        assert_eq!(layout.active(), right);
        assert!(layout.select(Direction::Left, area));
        assert_eq!(layout.active(), top_left);
        assert!(layout.select(Direction::Down, area));
        assert_eq!(layout.active(), bottom);
    }

    #[test]
    fn a_neighbour_has_to_be_beside_a_pane_and_not_merely_in_line_with_it() {
        // Two columns of two. What is to the left of the top-right pane is the
        // top-left one; the bottom-left pane shares its edge's column and is not
        // next door to it at all, however recently it was used.
        let area = (23, 80);
        let (top_left, top_right) = (PaneId::next(), PaneId::next());
        let (bottom_left, bottom_right) = (PaneId::next(), PaneId::next());
        let mut layout = Layout::new(top_left);
        assert!(layout.split(Split::Horizontal, top_right, area));
        assert!(layout.split(Split::Vertical, bottom_right, area));
        assert!(layout.focus(top_left));
        assert!(layout.split(Split::Vertical, bottom_left, area));

        // In front of the pane the answer must be, so a tie would take it.
        assert!(layout.focus(bottom_left));
        assert!(layout.focus(top_right));
        assert!(layout.select(Direction::Left, area));
        assert_eq!(layout.active(), top_left);
    }

    #[test]
    fn selecting_past_the_edge_of_the_window_stays_where_it_is() {
        let area = (23, 80);
        let (mut layout, top_left, _right, _bottom) = three(area);
        assert!(layout.focus(top_left));
        assert!(!layout.select(Direction::Left, area));
        assert!(!layout.select(Direction::Up, area));
        assert_eq!(layout.active(), top_left);
    }

    #[test]
    fn a_tie_between_two_neighbours_goes_to_the_one_used_last() {
        // Two panes are above the bottom one, and the geometry has nothing to
        // say about which -- so the history does (§7.2).
        let area = (23, 80);
        let (mut layout, top_left, right, bottom) = three(area);
        assert!(layout.focus(right));
        assert!(layout.focus(bottom));
        assert!(layout.select(Direction::Up, area));
        assert_eq!(layout.active(), right);

        assert!(layout.focus(top_left));
        assert!(layout.focus(bottom));
        assert!(layout.select(Direction::Up, area));
        assert_eq!(layout.active(), top_left);
    }

    #[test]
    fn the_next_pane_is_the_next_one_in_the_tree_and_it_wraps() {
        // `prefix o`. Tree order, so going round reaches every pane once.
        let area = (23, 80);
        let (mut layout, top_left, right, bottom) = three(area);
        assert!(layout.focus(top_left));
        for expected in [right, bottom, top_left] {
            assert!(layout.next_pane());
            assert_eq!(layout.active(), expected);
        }
    }

    #[test]
    fn zoom_gives_one_pane_the_whole_window_and_gives_it_back() {
        let area = (23, 80);
        let (mut layout, _top_left, right, _bottom) = three(area);
        assert!(layout.focus(right));
        layout.zoom();
        assert!(layout.is_zoomed());
        assert_eq!(layout.geometry(area), [(right, whole(area))]);
        // The others are still there, they are simply not on screen.
        assert_eq!(layout.count(), 3);
        assert!(layout.borders(area).is_empty());

        layout.zoom();
        assert!(!layout.is_zoomed());
        assert_eq!(layout.geometry(area).len(), 3);
    }

    #[test]
    fn a_split_or_a_selection_puts_a_zoomed_window_back() {
        // A zoomed pane is the whole window, so what a split would divide is
        // not what the user is looking at, and a pane picked by direction may
        // be one the zoom is hiding. tmux unzooms for both.
        let area = (23, 80);
        let (mut layout, _top_left, _right, _bottom) = three(area);
        layout.zoom();
        assert!(layout.split(Split::Vertical, PaneId::next(), area));
        assert!(!layout.is_zoomed());

        let (mut layout, top_left, _right, bottom) = three(area);
        assert!(layout.focus(top_left));
        layout.zoom();
        assert!(layout.select(Direction::Down, area));
        assert!(!layout.is_zoomed());
        assert_eq!(layout.active(), bottom);
    }

    #[test]
    fn a_window_with_one_pane_has_nothing_to_zoom() {
        let mut layout = Layout::new(PaneId::next());
        layout.zoom();
        assert!(!layout.is_zoomed());
    }

    #[test]
    fn killing_the_zoomed_pane_puts_the_window_back() {
        let area = (23, 80);
        let (mut layout, _top_left, right, _bottom) = three(area);
        assert!(layout.focus(right));
        layout.zoom();
        assert!(layout.close(right));
        assert!(!layout.is_zoomed());
        assert_eq!(layout.geometry(area).len(), 2);
    }

    #[test]
    fn a_border_only_spans_the_pane_it_divides() {
        // The second split's border must not run the width of the window: the
        // left pane is untouched and a line across it would be drawn over it.
        let mut layout = Layout::new(PaneId::next());
        assert!(layout.split(Split::Horizontal, PaneId::next(), (5, 11)));
        assert!(layout.split(Split::Vertical, PaneId::next(), (5, 11)));
        let across: Vec<_> = layout
            .borders((5, 11))
            .into_iter()
            .filter(|(row, _, _)| *row == 2)
            .collect();
        assert!(across.iter().all(|(_, col, _)| *col >= 5), "{across:?}");
    }
}
