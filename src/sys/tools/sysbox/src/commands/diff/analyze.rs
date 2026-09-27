//! The edit script: which lines to delete from one file and insert from the
//! other to turn the first into the second.
//!
//! This is the analysis GNU `diff` does (its analyze.c, and gnulib's
//! diffseq.h), step for step, so that where there is more than one shortest
//! script, the one found here is the one GNU `diff` finds: the same lines set
//! aside before the search, the same middle snake search, and the same
//! sliding of runs of changes afterwards.

/// A run of changed lines: `deleted` lines of the first file from `line0`
/// on, replaced by `inserted` lines of the second from `line1` on.
pub(super) struct Change {
    pub line0: usize,
    pub line1: usize,
    pub deleted: usize,
    pub inserted: usize,
}

/// The edit script from `a` to `b`, whose lines are numbered by what they
/// compare equal to. `minimal` searches for a shortest script however long
/// that takes, and sets no lines aside first.
pub(super) fn edit_script(a: &[usize], b: &[usize], minimal: bool) -> Vec<Change> {
    // Search only the lines that are not set aside, then mark the changes
    // it finds, and the lines set aside, against all of them.
    let discarded = if minimal {
        [vec![false; a.len()], vec![false; b.len()]]
    } else {
        discard_confusing_lines([a, b])
    };
    let kept = |lines: &[usize], discarded: &[bool]| -> Vec<usize> {
        (0..lines.len()).filter(|i| !discarded[*i]).collect()
    };
    let (kept_a, kept_b) = (kept(a, &discarded[0]), kept(b, &discarded[1]));
    let search_a: Vec<usize> = kept_a.iter().map(|i| a[*i]).collect();
    let search_b: Vec<usize> = kept_b.iter().map(|i| b[*i]).collect();
    let mut search = Search::new(&search_a, &search_b);
    search.compare(
        0,
        search_a.len() as isize,
        0,
        search_b.len() as isize,
        minimal,
    );

    let changed = |discarded: &[bool], kept: &[usize], found: &Marks| {
        let mut changed = Marks::new(discarded.len());
        for (line, discarded) in discarded.iter().enumerate() {
            changed.set(line as isize, *discarded);
        }
        for (at, line) in kept.iter().enumerate() {
            if found.get(at as isize) {
                changed.set(*line as isize, true);
            }
        }
        changed
    };
    let mut changed_a = changed(&discarded[0], &kept_a, &search.changed_a);
    let mut changed_b = changed(&discarded[1], &kept_b, &search.changed_b);
    shift_boundaries(&mut changed_a, &changed_b, a);
    shift_boundaries(&mut changed_b, &changed_a, b);
    build_script(&changed_a, &changed_b, a.len(), b.len())
}

/// What the pass that sets lines aside makes of each one.
const KEEP: u8 = 0;
const DISCARD: u8 = 1;
const PROVISIONAL: u8 = 2;

/// The lines to set aside before the search, as GNU's `discard_confusing_lines`
/// picks them: a line with no match in the other file is a change whatever
/// the search finds, and a line with very many matches, amid lines like that,
/// would only slow it down.
fn discard_confusing_lines(files: [&[usize]; 2]) -> [Vec<bool>; 2] {
    let classes = files
        .iter()
        .flat_map(|lines| lines.iter())
        .max()
        .map_or(0, |max| max + 1);
    let mut counts = [vec![0_usize; classes], vec![0_usize; classes]];
    for (file, lines) in files.iter().enumerate() {
        for class in lines.iter() {
            counts[file][*class] += 1;
        }
    }
    std::array::from_fn(|file| discards(files[file], &counts[1 - file]))
}

/// The lines of one file to set aside, given how many lines of each class
/// the other file has.
fn discards(lines: &[usize], other_counts: &[usize]) -> Vec<bool> {
    // More matches than about five times the square root of lines / 64 make
    // a line only provisionally discardable.
    let mut many = 5;
    let mut tem = lines.len() / 64;
    while tem >= 4 {
        tem >>= 2;
        many *= 2;
    }
    let mut marks: Vec<u8> = lines
        .iter()
        .map(|class| match other_counts[*class] {
            0 => DISCARD,
            matches if matches > many => PROVISIONAL,
            _ => KEEP,
        })
        .collect();

    // A provisional discard stands only inside a run of discards that begins
    // and ends with a certain one.
    let end = marks.len();
    let mut i = 0;
    while i < end {
        if marks[i] == PROVISIONAL {
            marks[i] = KEEP;
        } else if marks[i] == DISCARD {
            let mut j = i;
            let mut provisional = 0;
            while j < end && marks[j] != KEEP {
                provisional += usize::from(marks[j] == PROVISIONAL);
                j += 1;
            }
            while j > i && marks[j - 1] == PROVISIONAL {
                j -= 1;
                marks[j] = KEEP;
                provisional -= 1;
            }
            let length = j - i;

            if provisional * 4 > length {
                // Too many of them: keep them all.
                for mark in &mut marks[i..j] {
                    if *mark == PROVISIONAL {
                        *mark = KEEP;
                    }
                }
            } else {
                cancel_long_subruns(&mut marks[i..j]);
                cancel_at_run_end(marks[i..j].iter_mut());
                cancel_at_run_end(marks[i..j].iter_mut().rev());
                i += length - 1;
            }
        }
        i += 1;
    }
    marks.iter().map(|mark| *mark != KEEP).collect()
}

/// Keeps every run of provisional discards of about the square root of a
/// quarter of the run's length or more.
fn cancel_long_subruns(run: &mut [u8]) {
    let mut minimum = 1;
    let mut tem = run.len() >> 2;
    while tem >= 4 {
        tem >>= 2;
        minimum <<= 1;
    }
    minimum += 1;

    let mut consec = 0;
    let mut j = 0;
    while j < run.len() {
        if run[j] != PROVISIONAL {
            consec = 0;
        } else {
            consec += 1;
            if consec == minimum {
                // Back up to cancel the subrun from its start.
                j = j + 1 - consec;
                continue;
            } else if consec > minimum {
                run[j] = KEEP;
            }
        }
        j += 1;
    }
}

/// Keeps provisional discards from one end of a run until three certain ones
/// in a row, or the first certain one at least eight lines in.
fn cancel_at_run_end<'a>(run: impl Iterator<Item = &'a mut u8>) {
    let mut consec = 0;
    for (j, mark) in run.enumerate() {
        if j >= 8 && *mark == DISCARD {
            break;
        }
        match *mark {
            PROVISIONAL => {
                consec = 0;
                *mark = KEEP;
            }
            KEEP => consec = 0,
            _ => consec += 1,
        }
        if consec == 3 {
            break;
        }
    }
}

/// Per-line change marks, readable one past either end, where there is never
/// a change: the boundary shifting below reads there.
struct Marks(Vec<bool>);

impl Marks {
    fn new(len: usize) -> Self {
        Self(vec![false; len + 2])
    }

    fn get(&self, line: isize) -> bool {
        self.0[(line + 1) as usize]
    }

    fn set(&mut self, line: isize, changed: bool) {
        self.0[(line + 1) as usize] = changed;
    }
}

/// The middle snake search of Myers' "An O(ND) Difference Algorithm and Its
/// Variations", structured as GNU `diff` structures it (gnulib's diffseq.h).
struct Search<'a> {
    a: &'a [usize],
    b: &'a [usize],
    /// The furthest-reaching x on each diagonal k = x - y, going forwards and
    /// backwards; stored from diagonal -(len of b) - 1 on.
    fd: Vec<isize>,
    bd: Vec<isize>,
    offset: isize,
    /// The cost past which to settle for a good split rather than the best.
    too_expensive: isize,
    changed_a: Marks,
    changed_b: Marks,
}

/// Where to split a comparison, and whether each half needs a minimal search.
struct Split {
    x: isize,
    y: isize,
    lo_minimal: bool,
    hi_minimal: bool,
}

impl<'a> Search<'a> {
    fn new(a: &'a [usize], b: &'a [usize]) -> Self {
        let diagonals = a.len() + b.len() + 3;
        // About the square root of the input size, but at least 4096: GNU's.
        let mut too_expensive: isize = 1;
        let mut left = diagonals;
        while left != 0 {
            too_expensive <<= 1;
            left >>= 2;
        }
        Self {
            a,
            b,
            fd: vec![0; diagonals],
            bd: vec![0; diagonals],
            offset: b.len() as isize + 1,
            too_expensive: too_expensive.max(4096),
            changed_a: Marks::new(a.len()),
            changed_b: Marks::new(b.len()),
        }
    }

    fn equal(&self, x: isize, y: isize) -> bool {
        self.a[x as usize] == self.b[y as usize]
    }

    /// Marks the changes between a[xoff..xlim] and b[yoff..ylim].
    fn compare(
        &mut self,
        mut xoff: isize,
        mut xlim: isize,
        mut yoff: isize,
        mut ylim: isize,
        minimal: bool,
    ) {
        while xoff < xlim && yoff < ylim && self.equal(xoff, yoff) {
            xoff += 1;
            yoff += 1;
        }
        while xoff < xlim && yoff < ylim && self.equal(xlim - 1, ylim - 1) {
            xlim -= 1;
            ylim -= 1;
        }

        if xoff == xlim {
            for y in yoff..ylim {
                self.changed_b.set(y, true);
            }
        } else if yoff == ylim {
            for x in xoff..xlim {
                self.changed_a.set(x, true);
            }
        } else {
            let split = self.split(xoff, xlim, yoff, ylim, minimal);
            self.compare(xoff, split.x, yoff, split.y, split.lo_minimal);
            self.compare(split.x, xlim, split.y, ylim, split.hi_minimal);
        }
    }

    /// Finds the midpoint of a shortest edit script for a[xoff..xlim] and
    /// b[yoff..ylim], searching from both ends at once.
    fn split(
        &mut self,
        xoff: isize,
        xlim: isize,
        yoff: isize,
        ylim: isize,
        minimal: bool,
    ) -> Split {
        let o = self.offset;
        let (dmin, dmax) = (xoff - ylim, xlim - yoff);
        let (fmid, bmid) = (xoff - yoff, xlim - ylim);
        let (mut fmin, mut fmax) = (fmid, fmid);
        let (mut bmin, mut bmax) = (bmid, bmid);
        let odd = (fmid - bmid) & 1 != 0;
        let found = |x, y| Split {
            x,
            y,
            lo_minimal: true,
            hi_minimal: true,
        };

        self.fd[(o + fmid) as usize] = xoff;
        self.bd[(o + bmid) as usize] = xlim;

        let mut cost = 1;
        loop {
            // Extend the forward search by one edit on each diagonal.
            if fmin > dmin {
                fmin -= 1;
                self.fd[(o + fmin - 1) as usize] = -1;
            } else {
                fmin += 1;
            }
            if fmax < dmax {
                fmax += 1;
                self.fd[(o + fmax + 1) as usize] = -1;
            } else {
                fmax -= 1;
            }
            let mut d = fmax;
            while d >= fmin {
                let (tlo, thi) = (self.fd[(o + d - 1) as usize], self.fd[(o + d + 1) as usize]);
                let mut x = if tlo < thi { thi } else { tlo + 1 };
                let mut y = x - d;
                while x < xlim && y < ylim && self.equal(x, y) {
                    x += 1;
                    y += 1;
                }
                self.fd[(o + d) as usize] = x;
                if odd && bmin <= d && d <= bmax && self.bd[(o + d) as usize] <= x {
                    return found(x, y);
                }
                d -= 2;
            }

            // And the backward search.
            if bmin > dmin {
                bmin -= 1;
                self.bd[(o + bmin - 1) as usize] = isize::MAX;
            } else {
                bmin += 1;
            }
            if bmax < dmax {
                bmax += 1;
                self.bd[(o + bmax + 1) as usize] = isize::MAX;
            } else {
                bmax -= 1;
            }
            let mut d = bmax;
            while d >= bmin {
                let (tlo, thi) = (self.bd[(o + d - 1) as usize], self.bd[(o + d + 1) as usize]);
                let mut x = if tlo < thi { tlo } else { thi - 1 };
                let mut y = x - d;
                while xoff < x && yoff < y && self.equal(x - 1, y - 1) {
                    x -= 1;
                    y -= 1;
                }
                self.bd[(o + d) as usize] = x;
                if !odd && fmin <= d && d <= fmax && x <= self.fd[(o + d) as usize] {
                    return found(x, y);
                }
                d -= 2;
            }

            if !minimal && cost >= self.too_expensive {
                return self.best_split(xoff, xlim, yoff, ylim, (fmin, fmax), (bmin, bmax));
            }
            cost += 1;
        }
    }

    /// Gives up on finding the midpoint of a costly comparison and splits at
    /// the furthest point either search reached instead, as GNU does.
    fn best_split(
        &self,
        xoff: isize,
        xlim: isize,
        yoff: isize,
        ylim: isize,
        (fmin, fmax): (isize, isize),
        (bmin, bmax): (isize, isize),
    ) -> Split {
        let o = self.offset;

        // The forward diagonal that got furthest: the largest x + y.
        let (mut fxybest, mut fxbest) = (-1, 0);
        let mut d = fmax;
        while d >= fmin {
            let mut x = self.fd[(o + d) as usize].min(xlim);
            let mut y = x - d;
            if ylim < y {
                (x, y) = (ylim + d, ylim);
            }
            if fxybest < x + y {
                (fxybest, fxbest) = (x + y, x);
            }
            d -= 2;
        }

        // The backward diagonal that got furthest: the smallest x + y.
        let (mut bxybest, mut bxbest) = (isize::MAX, 0);
        let mut d = bmax;
        while d >= bmin {
            let mut x = self.bd[(o + d) as usize].max(xoff);
            let mut y = x - d;
            if y < yoff {
                (x, y) = (yoff + d, yoff);
            }
            if x + y < bxybest {
                (bxybest, bxbest) = (x + y, x);
            }
            d -= 2;
        }

        if (xlim + ylim) - bxybest < fxybest - (xoff + yoff) {
            Split {
                x: fxbest,
                y: fxybest - fxbest,
                lo_minimal: true,
                hi_minimal: false,
            }
        } else {
            Split {
                x: bxbest,
                y: bxybest - bxbest,
                lo_minimal: false,
                hi_minimal: true,
            }
        }
    }
}

/// Slides each run of changes in one file as far down as lines equal to its
/// own allow, merging it with the runs it meets, and then back up to line up
/// with a run of changes in the other file if it can. This is GNU's
/// `shift_boundaries`, which is what makes, say, an inserted function end
/// with its closing brace rather than start with the previous one's.
fn shift_boundaries(changed: &mut Marks, other: &Marks, classes: &[usize]) {
    let end = classes.len() as isize;
    let class = |line: isize| classes[line as usize];
    let (mut i, mut j): (isize, isize) = (0, 0);

    loop {
        // Find the start of the next run, and the corresponding point in the
        // other file.
        while i < end && !changed.get(i) {
            while other.get(j) {
                j += 1;
            }
            j += 1;
            i += 1;
        }
        if i == end {
            break;
        }
        let mut start = i;

        // Find its end.
        i += 1;
        while changed.get(i) {
            i += 1;
        }
        while other.get(j) {
            j += 1;
        }

        let mut corresponding;
        loop {
            let run = i - start;

            // Move the run up while the line before it equals its last,
            // merging it with runs above.
            while start > 0 && class(start - 1) == class(i - 1) {
                start -= 1;
                changed.set(start, true);
                i -= 1;
                changed.set(i, false);
                while changed.get(start - 1) {
                    start -= 1;
                }
                j -= 1;
                while other.get(j) {
                    j -= 1;
                }
            }

            // Where the run last lined up with changes in the other file;
            // `end` for nowhere.
            corresponding = if other.get(j - 1) { i } else { end };

            // Then down while its first line equals the line after it, as far
            // as that goes.
            while i != end && class(start) == class(i) {
                changed.set(start, false);
                start += 1;
                changed.set(i, true);
                i += 1;
                while changed.get(i) {
                    i += 1;
                }
                j += 1;
                while other.get(j) {
                    corresponding = i;
                    j += 1;
                }
            }

            if run == i - start {
                break;
            }
        }

        // Back up to line up with changes in the other file, if it did.
        while corresponding < i {
            start -= 1;
            changed.set(start, true);
            i -= 1;
            changed.set(i, false);
            j -= 1;
            while other.get(j) {
                j -= 1;
            }
        }
    }
}

fn build_script(changed_a: &Marks, changed_b: &Marks, len_a: usize, len_b: usize) -> Vec<Change> {
    let mut script = Vec::new();
    let (mut i0, mut i1): (isize, isize) = (0, 0);
    while i0 < len_a as isize || i1 < len_b as isize {
        if changed_a.get(i0) || changed_b.get(i1) {
            let (line0, line1) = (i0, i1);
            while changed_a.get(i0) {
                i0 += 1;
            }
            while changed_b.get(i1) {
                i1 += 1;
            }
            script.push(Change {
                line0: line0 as usize,
                line1: line1 as usize,
                deleted: (i0 - line0) as usize,
                inserted: (i1 - line1) as usize,
            });
        }
        i0 += 1;
        i1 += 1;
    }
    script
}
