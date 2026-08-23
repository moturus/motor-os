//! A token bucket for the answers this interface sends with no socket behind
//! them -- ICMP errors, the no-listener reset, and the cookie SYN|ACK. Each is
//! one reply per unsolicited packet, so a peer spraying packets with spoofed
//! source addresses would otherwise turn this machine into a reflector aimed
//! at whoever those addresses name. Independent buckets bound each reply
//! kind's reflected rate; what one refuses is simply not answered.

use crate::time::Instant;

/// What one reply costs, in the micro-tokens the bucket holds. One token per
/// microsecond of refill keeps the arithmetic exact: a rate that does not
/// divide the poll cadence loses nothing to rounding, however the polls land.
const COST: u64 = 1_000_000;

/// Refill credited for one gap between replies is capped at one second --
/// the full bucket -- so idle time cannot overbank and the product below
/// cannot overflow.
const MAX_ELAPSED_MICROS: i64 = 1_000_000;

pub(super) struct TokenBucket {
    /// Replies per second; zero means unlimited.
    rate: u32,
    /// Micro-tokens on hand, at most one second's worth (`rate * COST`).
    tokens: u64,
    /// When the tokens were last brought current.
    refilled: Instant,
}

impl TokenBucket {
    /// A bucket allowing `rate` replies per second, with bursts up to one
    /// second's worth, starting full. Zero never limits.
    pub(super) fn new(rate: u32, now: Instant) -> Self {
        Self {
            rate,
            tokens: rate as u64 * COST,
            refilled: now,
        }
    }

    /// Whether a reply may go out at `now`; `true` spends the token.
    pub(super) fn try_take(&mut self, now: Instant) -> bool {
        self.try_take_above_reserve(now, 0)
    }

    /// Spend a token without dipping into `reserve` whole tokens. This lets
    /// trusted work retain a small floor inside one aggregate rate limit.
    pub(super) fn try_take_above_reserve(&mut self, now: Instant, reserve: u32) -> bool {
        if self.rate == 0 {
            return true;
        }

        // A clock that steps backward credits nothing and keeps the refill
        // point where it was, so the retreat cannot bank credit either way.
        let elapsed = now.total_micros() - self.refilled.total_micros();
        if elapsed > 0 {
            let credit = elapsed.min(MAX_ELAPSED_MICROS) as u64 * self.rate as u64;
            let capacity = self.rate as u64 * COST;
            self.tokens = capacity.min(self.tokens + credit);
            self.refilled = now;
        }

        let floor = reserve.min(self.rate) as u64 * COST;
        if self.tokens >= floor + COST {
            self.tokens -= COST;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(micros: i64) -> Instant {
        Instant::from_micros(micros)
    }

    /// Zero is the unlimited configuration, not a bucket that never fills.
    #[test]
    fn zero_rate_never_limits() {
        let mut bucket = TokenBucket::new(0, at(0));
        for _ in 0..10_000 {
            assert!(bucket.try_take(at(0)));
        }
    }

    /// A fresh bucket carries exactly one second's burst.
    #[test]
    fn the_burst_is_one_seconds_worth() {
        let mut bucket = TokenBucket::new(5, at(0));
        for _ in 0..5 {
            assert!(bucket.try_take(at(0)));
        }
        assert!(!bucket.try_take(at(0)));
    }

    /// Refill is continuous and exact: at 2 per second the next token exists
    /// at 500 ms, not a microsecond earlier, no matter how often the dry
    /// bucket is asked in between.
    #[test]
    fn refill_is_continuous_and_exact() {
        let mut bucket = TokenBucket::new(2, at(0));
        assert!(bucket.try_take(at(0)));
        assert!(bucket.try_take(at(0)));

        for micros in [1, 250_000, 499_998, 499_999] {
            assert!(!bucket.try_take(at(micros)));
        }
        assert!(bucket.try_take(at(500_000)));
        assert!(!bucket.try_take(at(500_000)));
    }

    /// Idle time banks at most the burst: a quiet hour is not an hour of
    /// stored replies.
    #[test]
    fn idle_time_does_not_overbank() {
        let mut bucket = TokenBucket::new(3, at(0));
        for _ in 0..3 {
            assert!(bucket.try_take(at(3_600_000_000)));
        }
        assert!(!bucket.try_take(at(3_600_000_000)));
    }

    /// A drained bucket sustains exactly its rate: one reply per period,
    /// asked twice per period.
    #[test]
    fn the_sustained_rate_is_the_configured_rate() {
        let mut bucket = TokenBucket::new(4, at(0));
        for _ in 0..4 {
            assert!(bucket.try_take(at(0)));
        }
        for period in 1..=8 {
            let now = at(period * 250_000);
            assert!(bucket.try_take(now));
            assert!(!bucket.try_take(now));
        }
    }

    /// A clock stepping backward neither panics nor refills.
    #[test]
    fn a_backward_clock_refills_nothing() {
        let mut bucket = TokenBucket::new(1, at(1_000_000));
        assert!(bucket.try_take(at(1_000_000)));
        assert!(!bucket.try_take(at(500_000)));
        // And the retreat did not push the refill point back either.
        assert!(bucket.try_take(at(2_000_000)));
    }

    #[test]
    fn a_reserve_is_only_available_to_unrestricted_callers() {
        let mut bucket = TokenBucket::new(5, at(0));
        for _ in 0..3 {
            assert!(bucket.try_take_above_reserve(at(0), 2));
        }
        assert!(!bucket.try_take_above_reserve(at(0), 2));
        assert!(bucket.try_take(at(0)));
        assert!(bucket.try_take(at(0)));
        assert!(!bucket.try_take(at(0)));

        assert!(!bucket.try_take_above_reserve(at(200_000), 2));
        assert!(bucket.try_take(at(200_000)));
    }
}
