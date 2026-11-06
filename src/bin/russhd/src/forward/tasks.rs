use std::future::Future;
use std::io;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

const MAX_FORWARDS: usize = 16_384;

/// The SSH connection owns this scope. Dropping it cancels every reserved job.
pub struct Tasks {
    slots: Arc<Semaphore>,
    cancel: watch::Sender<bool>,
}

impl Default for Tasks {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(MAX_FORWARDS)),
            cancel: watch::channel(false).0,
        }
    }
}

impl Tasks {
    /// Connecting jobs count too; admission never waits for a slot.
    pub fn reserve(&self, pressure: bool) -> Option<Reservation> {
        let cancelled = self.cancel.subscribe();
        if pressure || *cancelled.borrow() {
            return None;
        }
        Some(Reservation {
            _slot: self.slots.clone().try_acquire_owned().ok()?,
            cancelled,
        })
    }

    pub fn cancel(&self) {
        self.cancel.send_replace(true);
    }

    /// Stop accepting sockets before waiting. Pending opens count as active.
    pub async fn wait_idle(&self) {
        let _slots = self.slots.acquire_many(MAX_FORWARDS as u32).await.unwrap();
    }
}

/// A job owns its slot and a receiver that keeps no connection owner alive.
pub struct Reservation {
    _slot: OwnedSemaphorePermit,
    cancelled: watch::Receiver<bool>,
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
                _ = async {
                    if !*cancelled.borrow() {
                        let _ = cancelled.changed().await;
                    }
                } => {}
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

    #[tokio::test]
    async fn drain_waits_for_pending_and_running_work_without_cancelling_it() {
        let tasks = Tasks::default();
        let mut releases = Vec::new();
        for _ in 0..2 {
            let (release, released) = oneshot::channel();
            let (entered, started) = oneshot::channel();
            let (dropped, gone) = oneshot::channel();
            let guard = Dropped(Some(dropped));
            tasks.reserve(false).unwrap().spawn(async move {
                let _guard = guard;
                entered.send(()).unwrap();
                released.await.unwrap();
                Ok(())
            });
            started.await.unwrap();
            releases.push((release, gone));
        }
        let mut draining = Box::pin(tasks.wait_idle());
        for (release, gone) in releases {
            tokio::select! {
                biased;
                () = draining.as_mut() => panic!("drained with a live job"),
                () = std::future::ready(()) => {}
            }
            release.send(()).unwrap();
            gone.await.unwrap();
        }
        timeout(Duration::from_secs(1), draining).await.unwrap();
        assert_eq!(tasks.slots.available_permits(), MAX_FORWARDS);
        assert_eq!(tasks.cancel.receiver_count(), 0);
    }

    #[tokio::test]
    async fn explicit_cancellation_reaps_work_and_refuses_later_admission() {
        let tasks = Tasks::default();
        let reservation = tasks.reserve(false).unwrap();
        let (entered, started) = oneshot::channel();
        let (dropped, gone) = oneshot::channel();
        let guard = Dropped(Some(dropped));
        tasks.reserve(false).unwrap().spawn(async move {
            let _guard = guard;
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
            Ok(())
        });
        started.await.unwrap();
        tasks.cancel();
        assert!(tasks.reserve(false).is_none());
        // A reservation created before cancellation must never poll its open.
        reservation.spawn(async { panic!("cancelled work was polled") });
        timeout(Duration::from_secs(1), tasks.wait_idle())
            .await
            .unwrap();
        gone.await.unwrap();
        assert_eq!(tasks.slots.available_permits(), MAX_FORWARDS);
        assert_eq!(tasks.cancel.receiver_count(), 0);
    }
}
