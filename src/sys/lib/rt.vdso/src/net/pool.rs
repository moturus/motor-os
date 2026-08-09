//! The vDSO-owned channel pool and channel-thread entry (design 6.1, 6.2).
//!
//! Landed additively across Stage 4 and Stage 5's preparation patches:
//! production socket construction stays on the temporary `moto-io`
//! compatibility host until the Stage 5 ownership flip selects this host
//! and deletes that one, so nothing reaches the pool yet.
//!
//! The miss path coalesces provisioning (design 6.1 steps 2-5): an
//! unsatisfied `reserve` parks as a pool waiter, one channel is started per
//! `IO_SUBCHANNELS` of parked demand rather than one per caller, and a
//! published channel satisfies up to its whole capacity of waiters before
//! another is started. Waiters are cancellation-aware (design 6.1 step 2):
//! a dropped `reserve` future removes its queue entry, so a cancelled
//! caller stops counting as demand the moment it cancels -- channels
//! already provisioned for it are absorbed by the satisfy-or-shut-down
//! rules below, but no new one is started on its account.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use moto_io::net::NetClient;
use moto_io::net::Reservation;
use moto_rt::mutex::Mutex;
use moto_sys::SysHandle;

type WaiterTx = moto_async::oneshot::Sender<Result<Reservation, moto_rt::Error>>;

struct Waiter {
    id: u64,
    tx: WaiterTx,
}

/// Removes its waiter from the queue when a `reserve` future is dropped.
/// After ordinary delivery the entry is already gone (the satisfier pops
/// it under the pool lock before sending), so the sweep finds nothing.
struct WaiterGuard {
    pool: &'static NetPool,
    id: u64,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.pool.inner.lock().waiters.retain(|w| w.id != self.id);
    }
}

/// The process-wide pool. Design 6.1: it stores `NetClient`s and chooses
/// one by `try_reserve`; per-channel accounting (the subchannel bitmap,
/// full or not, teardown on the last release) stays behind that call in
/// `moto-io`.
pub static NET_POOL: NetPool = NetPool {
    inner: Mutex::new(PoolInner {
        clients: Vec::new(),
        waiters: VecDeque::new(),
        next_waiter_id: 0,
        provisions_in_flight: 0,
    }),
};

pub struct NetPool {
    inner: Mutex<PoolInner>,
}

struct PoolInner {
    clients: Vec<Arc<NetClient>>,
    /// Parked `reserve` callers, oldest first. Every waiter is covered by
    /// in-flight supply: `reserve` starts a channel whenever demand
    /// exceeds `provisions_in_flight * IO_SUBCHANNELS`, and a channel's
    /// publication consumes at least as much demand as the supply it
    /// retires, so no waiter is ever parked without a channel on the way.
    /// Cancellation only shrinks the queue, which only slackens that.
    waiters: VecDeque<Waiter>,
    next_waiter_id: u64,
    provisions_in_flight: usize,
}

impl PoolInner {
    /// Deliver `err` to every parked waiter. Failure policy (design 6.1
    /// step 6): one failed provision fails all current waiters, including
    /// any covered by other in-flight provisions -- sys-io is one process,
    /// so a connect that failed for one channel is failing for all of
    /// them, and over-failing keeps the accounting trivially hole-free (a
    /// later successful publish that finds no waiters shuts itself down).
    fn fail_waiters(&mut self, err: moto_rt::Error) {
        while let Some(waiter) = self.waiters.pop_front() {
            let _ = waiter.tx.send(Err(err));
        }
    }
}

impl NetPool {
    /// Reserve one socket slot, parking until a channel has room.
    /// Synchronous POSIX entry points bridge via
    /// `block_on_sync(NET_POOL.reserve())`; sys-io connect retries sleep
    /// on the new channel's own runtime thread, never on that bridge.
    ///
    /// A slot freed on an existing channel is found by the next caller's
    /// scan but does not wake parked waiters -- they are satisfied only by
    /// a channel publication. Waiters exist only while every channel is
    /// full and provisioning is already in flight, so the wasted window is
    /// one channel connect; if the connection-storm soak owed at the flip
    /// shows it matters, release notification is the follow-up.
    pub async fn reserve(&'static self) -> Result<Reservation, moto_rt::Error> {
        let (tx, rx) = moto_async::oneshot();
        let (need_spawn, id) = {
            let mut inner = self.inner.lock();
            for client in &inner.clients {
                if let Ok(reservation) = client.try_reserve() {
                    return Ok(reservation);
                }
            }

            let id = inner.next_waiter_id;
            inner.next_waiter_id += 1;
            inner.waiters.push_back(Waiter { id, tx });
            let supply =
                inner.provisions_in_flight * (moto_sys_io::api_net::IO_SUBCHANNELS as usize);
            if inner.waiters.len() > supply {
                inner.provisions_in_flight += 1;
                (true, id)
            } else {
                (false, id)
            }
        };
        let _guard = WaiterGuard { pool: self, id };

        // The spawn itself runs outside the pool lock (design 6.1 step 3).
        if need_spawn && let Err(code) = spawn_channel_thread(self) {
            let mut inner = self.inner.lock();
            inner.provisions_in_flight -= 1;
            // This caller's waiter is in the queue too: the error arrives
            // through its own oneshot below.
            inner.fail_waiters(code.into());
        }

        rx.await
            .expect("the pool dropped a parked reservation waiter")
    }

    fn remove(&self, client: &Arc<NetClient>) {
        let mut inner = self.inner.lock();
        let len_before = inner.clients.len();
        inner.clients.retain(|c| !Arc::ptr_eq(c, client));
        debug_assert_eq!(len_before, inner.clients.len() + 1);
    }
}

impl NetPool {
    /// Published channels right now (the cold-start coalescing regression
    /// reads this through `internal_helper(0, 1, ..)`).
    pub fn client_count(&self) -> usize {
        self.inner.lock().clients.len()
    }

    /// Panic unless the pool is quiescent: no published channels, no parked
    /// callers, no provisioning in flight. The leak check behind
    /// `internal_helper(0, ..)`; channels unpublish when their last
    /// reservation releases, so a leaked socket shows up here.
    pub fn assert_empty(&self) {
        let inner = self.inner.lock();
        assert!(
            inner.clients.is_empty(),
            "NET_POOL: {} channel(s) still published",
            inner.clients.len()
        );
        assert!(inner.waiters.is_empty());
        assert_eq!(0, inner.provisions_in_flight);
    }
}

const CHANNEL_THREAD_STACK_SIZE: u64 = 4096 * 16;

fn spawn_channel_thread(pool: &'static NetPool) -> Result<(), moto_rt::ErrorCode> {
    moto_sys::SysCpu::spawn(
        SysHandle::SELF,
        CHANNEL_THREAD_STACK_SIZE,
        channel_thread_entry as *const () as usize as u64,
        pool as *const NetPool as usize as u64,
    )
    .map(|_| ())
}

/// One pool channel's whole vDSO lifecycle (design 6.2): connect, satisfy
/// waiters, publish, drive, unpublish, thread teardown.
extern "C" fn channel_thread_entry(ctx: u64) {
    // Safety: the pool is a static; see spawn_channel_thread().
    let pool: &'static NetPool = unsafe { &*(ctx as usize as *const NetPool) };
    moto_sys::set_current_thread_name("rt_net::pool_channel").unwrap();

    moto_async::LocalRuntime::new().block_on(async move {
        let (client, driver) = match moto_io::net::connect().await {
            Ok(pair) => pair,
            Err(err) => {
                let mut inner = pool.inner.lock();
                inner.provisions_in_flight -= 1;
                inner.fail_waiters(err);
                return;
            }
        };

        let client = Arc::new(client);
        let satisfied = {
            let mut inner = pool.inner.lock();
            inner.provisions_in_flight -= 1;

            // Satisfy up to the channel's capacity of waiters (design 6.1
            // step 5). `next` pins the channel open between sends: a
            // reservation bounced by a dead waiter (cancelled between its
            // guard sweep and this send -- the guard makes that window
            // small but not empty) is reused for the next one instead of
            // dropped, so the count cannot touch zero mid-loop and close
            // the channel under us. The sends run under the pool lock;
            // the wakers they run flag and wake a parked thread and take
            // no pool re-entry.
            let mut next = client.try_reserve().ok();
            debug_assert!(
                next.is_some(),
                "a fresh channel refused its first reservation"
            );
            let mut satisfied = 0usize;
            while let Some(reservation) = next.take() {
                let Some(waiter) = inner.waiters.pop_front() else {
                    // Drops the spare slot; with `satisfied == 0` that is
                    // the last release, and the never-published channel
                    // shuts itself down.
                    break;
                };
                match waiter.tx.send(Ok(reservation)) {
                    Ok(()) => {
                        satisfied += 1;
                        next = client.try_reserve().ok();
                    }
                    Err(returned) => {
                        next = returned.ok();
                    }
                }
            }

            if satisfied > 0 {
                inner.clients.push(client.clone());
            }
            satisfied
        };

        driver.run().await;
        if satisfied > 0 {
            pool.remove(&client);
        }
    });

    // What the compatibility host's thread-exit hook used to do: reclaim
    // TLS, then exit; the kernel reaps the thread.
    unsafe { crate::rt_tls::on_thread_exiting() };
    let _ = moto_sys::SysObj::put(SysHandle::SELF);
    unreachable!("the pool channel thread exited");
}
