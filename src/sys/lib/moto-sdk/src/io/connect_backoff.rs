//! How a client waits for sys-io to have a listener free.

use moto_rt::time::Instant;

/// A service such as sys-io keeps a few listeners waiting and adds one only
/// when a client takes one, so clients that connect together can find none
/// left; the kernel then answers `NotReady`. Such a client waits and tries
/// again: 50 usec at first, four times as long after each refusal, every wait
/// +/-50% so that clients refused together come back apart. A wait that would
/// take the total past 10 seconds is the last: it ends at a random moment
/// between 10 and 15 seconds in all, and the next refusal stands. A wait must
/// be a sleep, not a spin: the service needs the CPU to add its listener.
pub struct ConnectBackoff {
    wait_usec: u64,
    waited_usec: u64,
}

impl Default for ConnectBackoff {
    fn default() -> Self {
        Self {
            wait_usec: Self::FIRST_WAIT_USEC,
            waited_usec: 0,
        }
    }
}

impl ConnectBackoff {
    const FIRST_WAIT_USEC: u64 = 50;
    // The last wait ends between these two totals.
    const MIN_WAITED_USEC: u64 = 10_000_000;
    const MAX_WAITED_USEC: u64 = 15_000_000;

    /// When to try again after a `NotReady`, or `None` when it stands.
    pub fn next_wake(&mut self) -> Option<Instant> {
        let now = Instant::now();
        // The timestamp counter is the random number: it differs between
        // clients that were refused at the same moment.
        let wait_usec = self.next_wait_usec(now.as_u64())?;
        Some(now + core::time::Duration::from_micros(wait_usec))
    }

    fn next_wait_usec(&mut self, random: u64) -> Option<u64> {
        if self.waited_usec >= Self::MIN_WAITED_USEC {
            return None;
        }
        let mut wait_usec = self.wait_usec / 2 + random % (self.wait_usec + 1);
        if self.waited_usec + wait_usec > Self::MIN_WAITED_USEC {
            let waited = Self::MIN_WAITED_USEC
                + random % (Self::MAX_WAITED_USEC - Self::MIN_WAITED_USEC + 1);
            wait_usec = waited - self.waited_usec;
        }
        self.waited_usec += wait_usec;
        self.wait_usec *= 4;
        Some(wait_usec)
    }
}

/// Calls `connect` until it answers anything but `NotReady`, waiting in
/// between as [`ConnectBackoff`] says, on the caller's async runtime.
pub(crate) async fn retry_not_ready<T>(
    mut connect: impl FnMut() -> moto_rt::Result<T>,
) -> moto_rt::Result<T> {
    let mut backoff = ConnectBackoff::default();
    loop {
        match connect() {
            Err(moto_rt::Error::NotReady) => {}
            result => return result,
        }
        match backoff.next_wake() {
            Some(wake) => crate::async_runtime::sleep_until(wake).await,
            None => return Err(moto_rt::Error::NotReady),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectBackoff;
    use alloc::vec::Vec;

    #[test]
    fn waits_grow_fourfold_and_end_between_ten_and_fifteen_seconds() {
        // The least jitter, 25 usec * 4^n: ten waits take 8.7 seconds, so the
        // eleventh is the last, and it ends at 10 seconds.
        let mut backoff = ConnectBackoff::default();
        let waits: Vec<u64> = core::iter::from_fn(|| backoff.next_wait_usec(0)).collect();
        assert_eq!(waits[..4], [25, 100, 400, 1600]);
        assert_eq!(waits.len(), 11);
        assert_eq!(waits.iter().sum::<u64>(), 10_000_000);

        // The most jitter, 75 usec * 4^n: nine waits take 6.6 seconds and the
        // tenth would take 19.7 more, so it is the last. With the largest
        // random number it ends at 15 seconds.
        let mut backoff = ConnectBackoff::default();
        let mut nominal = ConnectBackoff::FIRST_WAIT_USEC;
        let mut waits = Vec::new();
        for _ in 0..9 {
            waits.push(backoff.next_wait_usec(nominal).unwrap());
            nominal *= 4;
        }
        assert_eq!(waits[..4], [75, 300, 1200, 4800]);
        waits.push(backoff.next_wait_usec(5_000_000).unwrap());
        assert_eq!(waits.iter().sum::<u64>(), 15_000_000);
        assert_eq!(backoff.next_wait_usec(0), None);
    }
}
