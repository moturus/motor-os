use crate::time::Instant;

// Constants for the Cubic congestion control algorithm.
// See RFC 8312.
const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(in crate::socket::tcp) struct Cubic {
    cwnd: usize,     // Congestion window
    min_cwnd: usize, // The minimum size of congestion window
    w_max: usize,    // Window size just before congestion
    /// RFC 8312's K: how long the curve takes to climb back to `w_max`. Cached
    /// because only a congestion event moves `w_max`, while `pre_transmit` runs
    /// on every dispatch -- recomputing a Newton-Raphson cube root there is what
    /// made an update floor necessary in the first place.
    k: f64,
    /// RFC 8312 section 4.2's TCP-friendly region: the window Reno would have
    /// reached by now. Cubic must not be slower than Reno, and on a short-RTT
    /// path the curve alone is far slower, so the window is the larger of the
    /// two.
    w_est: usize,
    recovery_start: Option<Instant>,
    rwnd: usize, // Remote window
    ssthresh: usize,
}

impl Cubic {
    pub(in crate::socket::tcp) fn new() -> Cubic {
        Cubic {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            w_max: 1024 * 2,
            k: 0.0,
            w_est: 1024 * 2,
            recovery_start: None,
            rwnd: 64 * 1024,
            ssthresh: usize::MAX,
        }
    }

    /// Record the common CUBIC epoch state for either loss signal. The caller
    /// selects fast recovery or an RTO slow-start restart afterward.
    fn on_congestion(&mut self, now: Instant) {
        self.w_max = self.cwnd;
        // RFC 8312 section 4.7: ssthresh = cwnd * beta. Halving (Reno's
        // formula) put the avoidance boundary below the window the epoch
        // restarts from, so every epoch re-entered its curve from a
        // needlessly deep slow-start exit.
        self.ssthresh = ((self.cwnd as f64) * BETA_CUBIC) as usize;
        self.k = cube_root(((self.w_max as f64) * (1.0 - BETA_CUBIC)) / C).unwrap_or(0.0);
        // Fast recovery restarts both regions from the reduced window. An RTO
        // overrides this estimate with one MSS below.
        self.w_est = ((self.w_max as f64) * BETA_CUBIC) as usize;
        self.recovery_start = Some(now);
    }
}

impl Cubic {
    pub(in crate::socket::tcp) fn window(&self) -> usize {
        self.cwnd
    }

    pub(in crate::socket::tcp) fn on_retransmission_timeout(&mut self, now: Instant) {
        self.on_congestion(now);
        // RFC 5681 section 3.1: after an RTO, restart with one segment and
        // slow-start back to the congestion threshold.
        self.cwnd = self.min_cwnd;
        self.w_est = self.min_cwnd;
    }

    pub(in crate::socket::tcp) fn on_duplicate_ack(&mut self, now: Instant) {
        self.on_congestion(now);
    }

    pub(in crate::socket::tcp) fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }

    pub(in crate::socket::tcp) fn on_ack(
        &mut self,
        _now: Instant,
        len: usize,
        _rtt: &crate::socket::tcp::RttEstimator,
    ) {
        if self.cwnd < self.ssthresh {
            // Slow start; both regions are just the window itself here.
            self.cwnd = self
                .cwnd
                .saturating_add(len)
                .min(self.rwnd)
                .max(self.min_cwnd);
            self.w_est = self.cwnd;
        } else {
            // Congestion avoidance, Reno's half of it: one MSS per window of
            // data acknowledged. `pre_transmit` takes whichever of this and the
            // cubic curve is larger, which is what keeps Cubic from being the
            // slower of the two on a short-RTT path.
            let w_est = self.w_est.max(self.min_cwnd).max(1);
            self.w_est = w_est
                .saturating_add(self.min_cwnd.saturating_mul(len) / w_est)
                .min(self.rwnd);
        }
    }

    pub(in crate::socket::tcp) fn pre_transmit(&mut self, now: Instant) {
        let Some(recovery_start) = self.recovery_start else {
            self.recovery_start = Some(now);
            return;
        };

        // Slow start belongs to `on_ack`; the curve only describes recovery.
        if self.cwnd < self.ssthresh {
            return;
        }

        // Elapsed time since the start of the recovery epoch. Microseconds, not
        // milliseconds: a round trip on this class of link is tens of
        // microseconds, so millisecond time quantises the curve into steps
        // thousands of RTTs wide.
        let t = now
            .total_micros()
            .saturating_sub(recovery_start.total_micros());
        if t < 0 {
            return;
        }

        // w_cubic = C(t - K)^3 + w_max, with t in seconds. K is cached, so this
        // is a handful of multiplies and runs as often as we transmit.
        let s = (t as f64) / 1_000_000.0 - self.k;
        let w_cubic = C * s * s * s + self.w_max as f64;
        // Float-to-int casts saturate, so a negative or enormous curve lands on
        // the bounds below rather than wrapping.
        let w_cubic = w_cubic as usize;

        self.cwnd = w_cubic.max(self.w_est).max(self.min_cwnd).min(self.rwnd);
    }

    pub(in crate::socket::tcp) fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
        // The peer's MSS becomes known exactly once, in the handshake, which is
        // also the only moment an *initial* window means anything: nothing has
        // been sent or acknowledged yet, so `cwnd` is still the constructor's
        // placeholder and this is not overwriting anything earned. Assigning
        // rather than taking the larger of the two is deliberate: for a small
        // enough MSS the placeholder is the bigger number, and keeping it there
        // would be a window of many segments on a link whose segments are tiny.
        self.cwnd = super::initial_window(mss);
        // The constructor starts all three equal, so keep them that way. Only
        // `w_est` has to be: slow start's `on_ack` holds it equal to `cwnd`, and
        // leaving it behind would put the TCP-friendly floor below the window it
        // is meant to track. `w_max` is a congestion event's memory and is
        // rewritten before it is ever read, so it follows for consistency alone.
        self.w_est = self.cwnd;
        self.w_max = self.cwnd;
    }
}

#[inline]
fn abs(a: f64) -> f64 {
    if a < 0.0 { -a } else { a }
}

/// Calculate cube root by using the Newton-Raphson method.
fn cube_root(a: f64) -> Option<f64> {
    if a <= 0.0 {
        return None;
    }

    let init = if a < 1_000.0 {
        8.879040017426005 // cube_root(700.0)
    } else if a < 1_000_000.0 {
        88.79040017426004 // cube_root(700_000.0)
    } else if a < 1_000_000_000.0 {
        887.9040017426004 // cube_root(700_000_000.0)
    } else if a < 1_000_000_000_000.0 {
        8879.040017426003 // cube_root(700_000_000_000.0)
    } else if a < 1_000_000_000_000_000.0 {
        88790.40017426001 // cube_root(700_000_000_000.0)
    } else {
        887904.0017426 // cube_root(700_000_000_000_000.0)
    };

    // The seed is chosen per magnitude, so this converges in a few steps. The
    // tolerance is relative: the absolute, per-decade one it replaces -- 5.0 on
    // a root near 90 -- left K about 0.16% high, which starts the curve *below*
    // `w_max * beta`, and so below the TCP-friendly window it is supposed to
    // meet exactly at t = 0. K is computed once per congestion epoch rather than
    // once per transmit now, so converging properly is affordable.
    let mut x = init;
    for _ in 0..64 {
        let next_x = (2.0 * x + a / (x * x)) / 3.0;
        if abs(next_x - x) <= 1e-12 * abs(next_x) {
            return Some(next_x);
        }
        x = next_x;
    }
    Some(x)
}

#[cfg(test)]
mod test {
    use crate::{socket::tcp::RttEstimator, time::Instant};

    use super::*;

    #[test]
    fn test_cubic() {
        let remote_window = 64 * 1024 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut cubic = Cubic::new();
                // Set remote window.
                cubic.set_remote_window(remote_window);

                cubic.set_mss(1480);

                if i & 1 == 0 {
                    cubic.on_retransmission_timeout(now);
                } else {
                    cubic.on_duplicate_ack(now);
                }

                cubic.pre_transmit(now);

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                let elapsed = Instant::from_millis(n);
                cubic.pre_transmit(elapsed);

                let cwnd = cubic.window();
                println!("Cubic: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= cubic.min_cwnd);
                assert!(cubic.window() <= remote_window);
            }
        }
    }

    #[test]
    fn cubic_time_inversion() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_duplicate_ack(t2);
        cubic.pre_transmit(t1);

        let cwnd = cubic.window();
        println!("Cubic:time_inversion: cwnd: {}, cubic: {cubic:?}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_long_elapsed_time() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_duplicate_ack(t1);
        cubic.pre_transmit(t2);

        let cwnd = cubic.window();
        println!("Cubic:long_elapsed_time: cwnd: {}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_last_update() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_millis(100);
        let t3 = Instant::from_millis(199);
        let t4 = Instant::from_millis(20000);

        cubic.on_duplicate_ack(t1);

        cubic.pre_transmit(t2);
        let cwnd2 = cubic.window();

        cubic.pre_transmit(t3);
        let cwnd3 = cubic.window();

        cubic.pre_transmit(t4);
        let cwnd4 = cubic.window();

        println!(
            "Cubic:last_update: cwnd2: {}, cwnd3: {}, cwnd4: {}",
            cwnd2, cwnd3, cwnd4
        );

        assert_eq!(cwnd2, cwnd3);
        assert_ne!(cwnd2, cwnd4);
    }

    #[test]
    fn cubic_rto_reenters_slow_start() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);

        let cwnd = cubic.window();
        let ack_len = 1024;

        cubic.on_ack(t1, ack_len, &RttEstimator::default());

        assert!(cubic.window() > cwnd);

        for i in 1..1000 {
            let t2 = Instant::from_micros(i);
            cubic.on_ack(t2, ack_len * 100, &RttEstimator::default());
            assert!(cubic.window() <= cubic.rwnd);
        }

        let t3 = Instant::from_micros(2000);

        let cwnd = cubic.window();
        cubic.on_retransmission_timeout(t3);
        // RFC 8312 section 4.7: the avoidance boundary is cwnd * beta, the
        // prior congestion window's Cubic reduction -- not Reno's half.
        assert_eq!(((cwnd as f64) * BETA_CUBIC) as usize, cubic.ssthresh);
        assert_eq!(cubic.window(), cubic.min_cwnd);

        cubic.on_ack(t3, cubic.min_cwnd, &RttEstimator::default());
        assert_eq!(cubic.window(), 2 * cubic.min_cwnd);
        assert!(cubic.window() < cubic.ssthresh);
    }

    #[test]
    fn cubic_pre_transmit() {
        let mut cubic = Cubic::new();
        cubic.pre_transmit(Instant::from_micros(2000));
    }

    #[test]
    fn test_cube_root() {
        for n in (1..1000000).step_by(99) {
            let a = n as f64;
            let a = a * a * a;
            let result = cube_root(a);
            println!("cube_root({a}) = {}", result.unwrap());
        }
    }

    #[test]
    #[should_panic]
    fn cube_root_zero() {
        cube_root(0.0).unwrap();
    }

    /// Drive slow start up to `target`, then take a loss, so the tests below
    /// start from a congestion epoch whose curve is well clear of `min_cwnd`.
    fn recovering_from(target: usize, now: Instant) -> Cubic {
        let mut cubic = Cubic::new();
        cubic.set_mss(1460);
        cubic.set_remote_window(16 * 1024 * 1024);
        // One segment at a time: acknowledging 64KB at a time overshoots
        // `target` by enough to change what the tests below are measuring.
        while cubic.window() < target {
            cubic.on_ack(now, 1460, &RttEstimator::default());
        }
        cubic.on_duplicate_ack(now);
        cubic
    }

    /// RFC 8312 section 4.2. The curve needs K seconds to climb back to
    /// `w_max`, and for a 20-segment window K is about 28 of them; Reno gets
    /// there in a few milliseconds of acknowledgements. Recovering inside this
    /// test's 5ms is therefore something only the TCP-friendly region can do,
    /// and without it Cubic is strictly the slower of the two on such a link.
    #[test]
    fn the_tcp_friendly_region_recovers_faster_than_the_curve() {
        let t0 = Instant::from_micros(0);
        let mut cubic = recovering_from(20 * 1460, t0);
        let w_max = cubic.w_max;
        cubic.pre_transmit(t0);
        assert!(cubic.window() < w_max, "no multiplicative decrease");

        // 150 acknowledged segments, one 46 usec round trip apart -- under 7ms
        // of link time in total.
        for i in 1..=150 {
            let now = Instant::from_micros(46 * i);
            cubic.on_ack(now, 1460, &RttEstimator::default());
            cubic.pre_transmit(now);
        }

        assert!(
            cubic.window() > w_max,
            "window {} still below w_max {w_max} after 150 acks; the curve alone \
             needs {:.0}s",
            cubic.window(),
            cubic.k
        );
    }

    /// The curve must advance inside the old 100ms update floor, which was
    /// thousands of round trips wide on a sub-millisecond link. The floor only
    /// engaged once an update had been taken *after* the epoch began, so this
    /// reads the window on the far side of one.
    #[test]
    fn the_curve_advances_inside_the_old_update_floor() {
        let t0 = Instant::from_micros(0);
        let mut cubic = recovering_from(1_000_000, t0);
        cubic.pre_transmit(t0);

        cubic.pre_transmit(Instant::from_millis(10));
        let armed = cubic.window();

        // 40ms later: inside the old floor, so the old code returned early.
        cubic.pre_transmit(Instant::from_millis(50));

        assert!(
            cubic.window() > armed,
            "curve pinned at {armed} between 10ms and 50ms into the epoch"
        );
    }

    /// Slow start has to survive `pre_transmit`: with no loss, the window may
    /// never shrink.
    ///
    /// The curve describes recovery from a congestion event, but it used to be
    /// applied unconditionally -- including before any loss had happened, while
    /// `w_max` was still its initial 2048, where it evaluates to below
    /// `min_cwnd`. Every update therefore dropped the window to a single
    /// segment and discarded whatever slow start had built. The 100ms floor
    /// meant this landed once per 100ms rather than continuously, so the shape
    /// to test for is a sawtooth on a link that never lost a packet, not a
    /// window pinned low throughout.
    #[test]
    fn slow_start_never_shrinks_without_a_loss() {
        let mut cubic = Cubic::new();
        cubic.set_mss(1460);
        cubic.set_remote_window(4 * 1024 * 1024);

        cubic.pre_transmit(Instant::from_millis(0)); // Arms the epoch.
        let mut previous = cubic.window();
        // Long enough to cross the old floor several times.
        for ms in 1..=500 {
            let now = Instant::from_millis(ms);
            cubic.on_ack(now, 1460, &RttEstimator::default());
            cubic.pre_transmit(now);
            let window = cubic.window();
            assert!(
                window >= previous,
                "window fell from {previous} to {window} at {ms}ms with no loss"
            );
            previous = window;
        }
    }

    /// K is computed once per congestion epoch, not once per transmit.
    #[test]
    fn k_is_cached_on_the_congestion_event() {
        let now = Instant::from_micros(0);
        let cubic = recovering_from(1_000_000, now);
        let expected = cube_root(((cubic.w_max as f64) * (1.0 - BETA_CUBIC)) / C).unwrap();
        assert!(abs(cubic.k - expected) < f64::EPSILON);
    }
}
