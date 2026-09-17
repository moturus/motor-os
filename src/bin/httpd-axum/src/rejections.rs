use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Rejections {
    next_report: Option<Instant>,
    pending: u64,
    total: u64,
}

impl Rejections {
    pub fn record(&mut self, now: Instant) -> Option<(u64, u64)> {
        self.pending = self.pending.saturating_add(1);
        self.total = self.total.saturating_add(1);
        // Report immediately on the first refusal, then at most once per five
        // seconds of overload. No background timer or work on admitted clients.
        if self.next_report.is_some_and(|deadline| now < deadline) {
            return None;
        }
        // Compare instants directly: a ticks-to-duration round trip can round
        // down at the exact boundary on Motor.
        self.next_report = Some(now + Duration::from_secs(5));
        Some((std::mem::take(&mut self.pending), self.total))
    }
}
