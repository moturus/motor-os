use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

const MAX_FORWARDS: usize = 16_384;

/// The SSH connection owns this scope. Dropping it cancels every reserved job.
pub struct Tasks {
    slots: Arc<Semaphore>,
    cancel: watch::Sender<()>,
}

impl Default for Tasks {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(MAX_FORWARDS)),
            cancel: watch::channel(()).0,
        }
    }
}

impl Tasks {
    /// Connecting jobs count too; admission never waits for a slot.
    pub fn reserve(&self, pressure: bool) -> Option<Reservation> {
        if pressure {
            return None;
        }
        Some(Reservation {
            _slot: self.slots.clone().try_acquire_owned().ok()?,
            cancelled: self.cancel.subscribe(),
        })
    }
}

/// A job owns its slot and a receiver that keeps no connection owner alive.
pub struct Reservation {
    _slot: OwnedSemaphorePermit,
    cancelled: watch::Receiver<()>,
}

impl Reservation {
    pub fn spawn(self, work: impl Future<Output = io::Result<()>> + Send + 'static) {
        // Tokio releases each detached task and its result on completion. The
        // connection retains only admission and cancellation state.
        drop(tokio::spawn(async move {
            let Self {
                _slot,
                mut cancelled,
            } = self;
            tokio::select! {
                biased;
                _ = cancelled.changed() => {}
                result = work => {
                    if let Err(error) = result {
                        log::debug!("forward failed: {error}");
                    }
                }
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::oneshot;
    use tokio::time::{Duration, timeout};

    struct Dropped(Option<oneshot::Sender<()>>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }

    #[test]
    fn admission_counts_unstarted_jobs_and_releases_every_slot() {
        let tasks = Tasks::default();
        assert!(tasks.reserve(true).is_none());
        assert_eq!(tasks.slots.available_permits(), MAX_FORWARDS);
        let mut jobs: Vec<_> = (0..MAX_FORWARDS)
            .map(|_| tasks.reserve(false).unwrap())
            .collect();
        assert!(tasks.reserve(false).is_none());
        drop(jobs.pop());
        let replacement = tasks.reserve(false).unwrap();
        assert!(tasks.reserve(false).is_none());
        drop((jobs, replacement));
        assert_eq!(tasks.slots.available_permits(), MAX_FORWARDS);
        assert_eq!(tasks.cancel.receiver_count(), 0);
    }

    #[tokio::test]
    async fn dropping_the_connection_discards_a_pending_open_and_late_result() {
        let tasks = Tasks::default();
        let slots = tasks.slots.clone();
        let (entered, started) = oneshot::channel();
        let (resolution, resolved) = oneshot::channel::<()>();
        let (dropped, gone) = oneshot::channel();
        let guard = Dropped(Some(dropped));
        let dialled = Arc::new(AtomicBool::new(false));
        let observed = dialled.clone();
        tasks.reserve(false).unwrap().spawn(async move {
            let _guard = guard;
            entered.send(()).unwrap();
            resolved.await.unwrap();
            dialled.store(true, Ordering::Relaxed);
            Ok(())
        });
        started.await.unwrap();
        assert_eq!(slots.available_permits(), MAX_FORWARDS - 1);
        drop(tasks);
        timeout(Duration::from_secs(1), gone)
            .await
            .unwrap()
            .unwrap();
        assert!(resolution.send(()).is_err());
        assert!(!observed.load(Ordering::Relaxed));
        assert_eq!(slots.available_permits(), MAX_FORWARDS);
    }

    #[tokio::test]
    async fn a_cancelled_reservation_never_polls_the_job() {
        let tasks = Tasks::default();
        let reservation = tasks.reserve(false).unwrap();
        let slots = tasks.slots.clone();
        drop(tasks);
        let (dropped, gone) = oneshot::channel();
        let guard = Dropped(Some(dropped));
        let polled = Arc::new(AtomicBool::new(false));
        let observed = polled.clone();
        reservation.spawn(async move {
            let _guard = guard;
            polled.store(true, Ordering::Relaxed);
            Ok(())
        });
        timeout(Duration::from_secs(1), gone)
            .await
            .unwrap()
            .unwrap();
        assert!(!observed.load(Ordering::Relaxed));
        assert_eq!(slots.available_permits(), MAX_FORWARDS);
    }

    #[tokio::test]
    async fn completed_jobs_leave_no_slots_or_cancellation_records() {
        let tasks = Tasks::default();
        for _ in 0..128 {
            let (dropped, gone) = oneshot::channel();
            let guard = Dropped(Some(dropped));
            tasks.reserve(false).unwrap().spawn(async move {
                let _guard = guard;
                Ok(())
            });
            timeout(Duration::from_secs(1), gone)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(tasks.slots.available_permits(), MAX_FORWARDS);
            assert_eq!(tasks.cancel.receiver_count(), 0);
        }
    }
}
