use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Rejections {
    last_report: Option<Instant>,
    pending: u64,
    total: u64,
}

impl Rejections {
    pub fn record(&mut self, now: Instant) -> Option<(u64, u64)> {
        self.pending = self.pending.saturating_add(1);
        self.total = self.total.saturating_add(1);
        // Report immediately on the first refusal, then at most once per five
        // seconds of overload. No background timer or work on admitted clients.
        if self
            .last_report
            .is_some_and(|last| now.duration_since(last) < Duration::from_secs(5))
        {
            return None;
        }
        self.last_report = Some(now);
        Some((std::mem::take(&mut self.pending), self.total))
    }
}
