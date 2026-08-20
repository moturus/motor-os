//! The sender-side transmission scoreboard: a bounded partition of the
//! in-flight sequence space [SND.UNA, SND.NXT) into runs that share a
//! transmit timestamp and delivery state. RFC 2018 SACK processing marks
//! it; RACK-TLP (RFC 8985) reads it to time-order loss detection.
//!
//! Degradation is always in the safe direction: an overflow merge may
//! forget that octets were SACKed (worst case a spurious retransmit) or
//! overstate how recently they were sent (worst case a delayed loss
//! mark), but it never invents delivery state and never drops coverage.

use crate::time::Instant;
use crate::wire::TcpSeqNumber;

/// The run bound. 64 runs cover 32 distinct SACK islands; peers report
/// at most 3 per segment, so real feedback fragments far below this.
pub(crate) const SCOREBOARD_RUNS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TxRun {
    pub start: TcpSeqNumber,
    /// Exclusive.
    pub end: TcpSeqNumber,
    /// When some octet of the run was last sent. Merges and burst
    /// extensions keep the later stamp.
    pub xmit_ts: Instant,
    pub sacked: bool,
    pub lost: bool,
    pub retransmitted: bool,
}

impl TxRun {
    const EMPTY: TxRun = TxRun {
        start: TcpSeqNumber(0),
        end: TcpSeqNumber(0),
        xmit_ts: Instant::ZERO,
        sacked: false,
        lost: false,
        retransmitted: false,
    };

    fn flags(&self) -> (bool, bool, bool) {
        (self.sacked, self.lost, self.retransmitted)
    }
}

#[derive(Debug)]
pub(crate) struct Scoreboard {
    runs: [TxRun; SCOREBOARD_RUNS],
    len: usize,
}

impl Scoreboard {
    pub const fn new() -> Self {
        Scoreboard {
            runs: [TxRun::EMPTY; SCOREBOARD_RUNS],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[allow(dead_code)] // read by tests and later series patches
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[allow(dead_code)] // read by tests and later series patches
    pub fn runs(&self) -> &[TxRun] {
        &self.runs[..self.len]
    }

    /// The covered span, [SND.UNA, SND.NXT) as this board last saw it.
    #[allow(dead_code)] // read by tests and later series patches
    pub fn coverage(&self) -> Option<(TcpSeqNumber, TcpSeqNumber)> {
        if self.len == 0 {
            None
        } else {
            Some((self.runs[0].start, self.runs[self.len - 1].end))
        }
    }

    /// Record a transmission of [start, end). Octets already covered are a
    /// retransmission: they keep their runs, restamped and marked; octets
    /// past the coverage extend it as a fresh run. Returns whether any
    /// octet was fresh -- the signal that this was an original send.
    pub fn on_transmit(&mut self, start: TcpSeqNumber, end: TcpSeqNumber, now: Instant) -> bool {
        if start >= end {
            return false;
        }

        let cov_end = match self.coverage() {
            None => {
                self.push_fresh(start, end, now);
                return true;
            }
            Some((_, cov_end)) => cov_end,
        };

        if start >= cov_end {
            self.push_fresh(start, end, now);
            return true;
        }

        let old_end = if end < cov_end { end } else { cov_end };
        self.mark(start, old_end, |run| {
            run.xmit_ts = now;
            run.retransmitted = true;
            // Back in the network: the previous loss verdict is served.
            run.lost = false;
        });
        if end > cov_end {
            self.push_fresh(cov_end, end, now);
            return true;
        }
        false
    }

    /// Drop everything the cumulative ACK is past.
    pub fn on_cumulative_ack(&mut self, una: TcpSeqNumber) {
        let mut drop = 0;
        while drop < self.len && self.runs[drop].end <= una {
            drop += 1;
        }
        if drop > 0 {
            self.runs.copy_within(drop..self.len, 0);
            self.len -= drop;
        }
        if self.len > 0 && self.runs[0].start < una {
            self.runs[0].start = una;
        }
    }

    /// Mark [start, end) as SACKed by the peer, reporting whether any
    /// octet was newly marked (the RFC 6675 dupack signal). Clamped to
    /// the coverage: a block past SND.NXT is the peer's error, not new
    /// state.
    pub fn mark_sacked(&mut self, start: TcpSeqNumber, end: TcpSeqNumber) -> bool {
        let Some((cov_start, cov_end)) = self.coverage() else {
            return false;
        };
        let start = if start > cov_start { start } else { cov_start };
        let end = if end < cov_end { end } else { cov_end };
        if start >= end {
            return false;
        }
        let mut newly = false;
        self.mark(start, end, |run| {
            if !run.sacked {
                newly = true;
            }
            run.sacked = true;
            run.lost = false;
        });
        newly
    }

    pub fn has_lost(&self) -> bool {
        self.runs[..self.len].iter().any(|r| r.lost)
    }

    /// Whether `seq` is covered by an outstanding run that the peer has
    /// not reported through SACK.
    pub fn contains_unsacked(&self, seq: TcpSeqNumber) -> bool {
        self.runs[..self.len]
            .iter()
            .any(|run| run.start <= seq && seq < run.end && !run.sacked)
    }

    /// The first (lowest-sequence) run marked lost.
    pub fn first_lost_run(&self) -> Option<(TcpSeqNumber, TcpSeqNumber)> {
        self.runs[..self.len]
            .iter()
            .find(|r| r.lost)
            .map(|r| (r.start, r.end))
    }

    pub fn sacked_octets(&self) -> usize {
        self.runs[..self.len]
            .iter()
            .filter(|r| r.sacked)
            .map(|r| r.end - r.start)
            .sum()
    }

    /// Octets SACKed above the first hole -- RFC 8985's DupThresh
    /// evidence: enough delivered past a gap says the gap is loss, not
    /// reordering, and the reorder window need not wait.
    pub fn sacked_octets_above_first_hole(&self) -> usize {
        let mut seen_hole = false;
        let mut sum = 0;
        for r in &self.runs[..self.len] {
            if r.sacked {
                if seen_hole {
                    sum += r.end - r.start;
                }
            } else {
                seen_hole = true;
            }
        }
        sum
    }

    pub fn lost_octets(&self) -> usize {
        self.runs[..self.len]
            .iter()
            .filter(|r| r.lost)
            .map(|r| r.end - r.start)
            .sum()
    }

    /// Mark [start, end) lost, splitting at the boundaries. SACKed runs
    /// are left alone: the peer holds them.
    pub fn mark_lost(&mut self, start: TcpSeqNumber, end: TcpSeqNumber) {
        let Some((cov_start, cov_end)) = self.coverage() else {
            return;
        };
        let start = if start > cov_start { start } else { cov_start };
        let end = if end < cov_end { end } else { cov_end };
        if start >= end {
            return;
        }
        self.mark(start, end, |run| {
            if !run.sacked {
                run.lost = true;
            }
        });
    }

    /// Mark runs lost where `verdict` says so, skipping delivered and
    /// already-lost runs. Returns how many runs were newly marked.
    pub fn apply_loss_marks(&mut self, mut verdict: impl FnMut(&TxRun) -> bool) -> usize {
        let mut newly = 0;
        for i in 0..self.len {
            let run = &mut self.runs[i];
            if !run.sacked && !run.lost && verdict(run) {
                run.lost = true;
                newly += 1;
            }
        }
        self.coalesce();
        newly
    }

    /// Apply `f` to exactly [start, end), splitting boundary runs, then
    /// coalesce identical neighbors. Callers pass bounds inside coverage.
    fn mark(&mut self, start: TcpSeqNumber, end: TcpSeqNumber, mut f: impl FnMut(&mut TxRun)) {
        self.split_at(start);
        self.split_at(end);
        for i in 0..self.len {
            if self.runs[i].start >= start && self.runs[i].end <= end {
                f(&mut self.runs[i]);
            }
        }
        self.coalesce();
    }

    /// Split the run containing `seq` so a run boundary lands on it.
    fn split_at(&mut self, seq: TcpSeqNumber) {
        let Some(_) = (0..self.len).find(|&i| self.runs[i].start < seq && seq < self.runs[i].end)
        else {
            return;
        };
        if self.len == SCOREBOARD_RUNS {
            self.degrade_merge();
        }
        // The merge above may have moved or coalesced the target run.
        let Some(i) = (0..self.len).find(|&i| self.runs[i].start < seq && seq < self.runs[i].end)
        else {
            return;
        };
        self.runs.copy_within(i..self.len, i + 1);
        self.len += 1;
        self.runs[i].end = seq;
        self.runs[i + 1].start = seq;
    }

    fn push_fresh(&mut self, start: TcpSeqNumber, end: TcpSeqNumber, now: Instant) {
        // A burst extending the newest fresh run joins it; the whole run
        // takes the newer stamp (overstating recency is the safe side).
        if self.len > 0 {
            let last = &mut self.runs[self.len - 1];
            if last.end == start && !last.sacked && !last.lost && !last.retransmitted {
                last.end = end;
                last.xmit_ts = now;
                return;
            }
        }
        if self.len == SCOREBOARD_RUNS {
            self.degrade_merge();
        }
        self.runs[self.len] = TxRun {
            start,
            end,
            xmit_ts: now,
            sacked: false,
            lost: false,
            retransmitted: false,
        };
        self.len += 1;
    }

    /// Merge one adjacent pair to free a slot: an identical-state pair if
    /// any exists (lossless), else the shortest pair, conservatively --
    /// SACKed only if both were, lost never survives, the later stamp
    /// wins.
    fn degrade_merge(&mut self) {
        debug_assert!(self.len >= 2);
        let mut best = 0;
        let mut best_score = usize::MAX;
        for i in 0..self.len - 1 {
            let (a, b) = (&self.runs[i], &self.runs[i + 1]);
            let score = if a.flags() == b.flags() {
                0
            } else {
                (a.end - a.start) + (b.end - b.start)
            };
            if score < best_score {
                best_score = score;
                best = i;
            }
        }
        let b = self.runs[best + 1];
        let a = &mut self.runs[best];
        a.end = b.end;
        a.xmit_ts = if b.xmit_ts > a.xmit_ts {
            b.xmit_ts
        } else {
            a.xmit_ts
        };
        a.sacked = a.sacked && b.sacked;
        a.lost = false;
        a.retransmitted = a.retransmitted || b.retransmitted;
        self.runs.copy_within(best + 2..self.len, best + 1);
        self.len -= 1;
    }

    fn coalesce(&mut self) {
        let mut w = 0;
        for r in 1..self.len {
            let prev = self.runs[w];
            let cur = self.runs[r];
            if prev.end == cur.start && prev.flags() == cur.flags() && prev.xmit_ts == cur.xmit_ts {
                self.runs[w].end = cur.end;
            } else {
                w += 1;
                self.runs[w] = cur;
            }
        }
        if self.len > 0 {
            self.len = w + 1;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const S: fn(i32) -> TcpSeqNumber = TcpSeqNumber;
    const T: fn(i64) -> Instant = Instant::from_millis_const;

    #[test]
    fn burst_extension_merges_and_restamps() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(100), S(200), T(1));
        b.on_transmit(S(200), S(300), T(2));
        assert_eq!(b.runs().len(), 1);
        assert_eq!(b.coverage(), Some((S(100), S(300))));
        assert_eq!(b.runs()[0].xmit_ts, T(2));
        assert!(!b.runs()[0].retransmitted);
    }

    #[test]
    fn cumulative_ack_prunes_and_truncates() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(100), S(300), T(1));
        b.on_transmit(S(300), S(400), T(5));
        b.mark_sacked(S(300), S(400));
        b.on_cumulative_ack(S(250));
        assert_eq!(b.coverage(), Some((S(250), S(400))));
        b.on_cumulative_ack(S(400));
        assert!(b.is_empty());
    }

    #[test]
    fn retransmission_splits_and_marks() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(100), S(400), T(1));
        b.on_transmit(S(100), S(200), T(9));
        let runs = b.runs();
        assert_eq!(runs.len(), 2);
        assert_eq!((runs[0].start, runs[0].end), (S(100), S(200)));
        assert!(runs[0].retransmitted);
        assert_eq!(runs[0].xmit_ts, T(9));
        assert!(!runs[1].retransmitted);
        assert_eq!(runs[1].xmit_ts, T(1));
    }

    #[test]
    fn retransmission_spanning_past_coverage_appends_fresh() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(100), S(200), T(1));
        b.on_transmit(S(150), S(250), T(2));
        let runs = b.runs();
        assert_eq!(b.coverage(), Some((S(100), S(250))));
        assert!(runs.iter().any(|r| r.retransmitted));
        assert!(!runs.last().unwrap().retransmitted);
    }

    #[test]
    fn sack_marks_inside_coverage_only() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(100), S(400), T(1));
        b.mark_sacked(S(200), S(500));
        let runs = b.runs();
        assert_eq!(runs.len(), 2);
        assert!(!runs[0].sacked);
        assert!(runs[1].sacked);
        assert_eq!((runs[1].start, runs[1].end), (S(200), S(400)));
    }

    #[test]
    fn unsacked_lookup_observes_bounds_ack_and_sack() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(100), S(400), T(1));
        assert!(!b.contains_unsacked(S(99)));
        assert!(b.contains_unsacked(S(100)));
        assert!(b.contains_unsacked(S(399)));
        assert!(!b.contains_unsacked(S(400)));

        b.mark_sacked(S(200), S(300));
        assert!(b.contains_unsacked(S(199)));
        assert!(!b.contains_unsacked(S(200)));
        assert!(!b.contains_unsacked(S(299)));
        assert!(b.contains_unsacked(S(300)));

        b.on_cumulative_ack(S(150));
        assert!(!b.contains_unsacked(S(149)));
        assert!(b.contains_unsacked(S(150)));
    }

    #[test]
    fn unsacked_lookup_wraps_with_sequence_space() {
        let mut b = Scoreboard::new();
        let start = S(i32::MAX - 2);
        let end = start + 6;
        b.on_transmit(start, end, T(1));

        assert!(b.contains_unsacked(start));
        assert!(b.contains_unsacked(start + 5));
        assert!(!b.contains_unsacked(start - 1));
        assert!(!b.contains_unsacked(end));
    }

    #[test]
    fn sack_then_retransmit_between_islands() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(0), S(1000), T(1));
        b.mark_sacked(S(200), S(400));
        b.mark_sacked(S(600), S(800));
        assert_eq!(b.runs().len(), 5);
        b.on_transmit(S(400), S(600), T(7));
        let mid = b
            .runs()
            .iter()
            .find(|r| r.start == S(400) && r.end == S(600))
            .unwrap();
        assert!(mid.retransmitted && !mid.sacked);
        assert_eq!(mid.xmit_ts, T(7));
    }

    #[test]
    fn overflow_degrades_without_inventing_sack_state() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(0), S(100_000), T(1));
        // Fragment far past the bound: every second 100-octet block SACKed.
        for i in 0..SCOREBOARD_RUNS as i32 * 4 {
            let start = i * 200;
            b.mark_sacked(S(start), S(start + 100));
        }
        assert!(b.runs().len() <= SCOREBOARD_RUNS);
        assert_eq!(b.coverage(), Some((S(0), S(100_000))));
        // Conservative degrade: SACK coverage may shrink, never grow. The
        // marks totaled half the span; whatever survived stays inside it.
        let sacked: usize = b
            .runs()
            .iter()
            .filter(|r| r.sacked)
            .map(|r| r.end - r.start)
            .sum();
        assert!(sacked <= 100_000 / 2, "sacked coverage grew: {sacked}");
        // Runs still partition the coverage.
        for w in b.runs().windows(2) {
            assert_eq!(w[0].end, w[1].start);
        }
    }

    #[test]
    fn clear_empties() {
        let mut b = Scoreboard::new();
        b.on_transmit(S(0), S(100), T(1));
        b.clear();
        assert!(b.is_empty());
        assert_eq!(b.coverage(), None);
    }
}
