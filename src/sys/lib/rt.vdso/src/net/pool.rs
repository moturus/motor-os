//! The vDSO-owned channel pool and channel-thread entry (design 6.1, 6.2).
//!
//! Stage 4 preparation, landed additively: production socket construction
//! stays on the temporary `moto-io` compatibility host until the Stage 5
//! ownership flip selects this host and deletes that one, so nothing
//! reaches the pool yet.
//!
//! This Stage 4 shape provisions one channel per unsatisfied `reserve`
//! caller. Sharing an in-flight provision among up to `IO_SUBCHANNELS`
//! waiters (coalescing) and the queued cancellation-aware pool waiters are
//! the two Stage 5 patches the re-scope sized; both replace only the miss
//! path of [`NetPool::reserve`].

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use moto_io::net::NetClient;
use moto_io::net::Reservation;
use moto_rt::mutex::Mutex;
use moto_sys::SysHandle;

/// The process-wide pool. Design 6.1: it stores `NetClient`s and chooses
/// one by `try_reserve`; per-channel accounting (the subchannel bitmap,
/// full or not, teardown on the last release) stays behind that call in
/// `moto-io`.
pub static NET_POOL: NetPool = NetPool {
    clients: Mutex::new(Vec::new()),
};

pub struct NetPool {
    clients: Mutex<Vec<Arc<NetClient>>>,
}

impl NetPool {
    /// Reserve one socket slot, connecting a new channel when no open
    /// client has room. Synchronous POSIX entry points bridge via
    /// `block_on_sync(NET_POOL.reserve())`; sys-io connect retries sleep
    /// on the new channel's own runtime thread, never on that bridge.
    pub async fn reserve(&'static self) -> Result<Reservation, moto_rt::Error> {
        if let Some(reservation) = self.try_reserve_open() {
            return Ok(reservation);
        }

        // Miss: provision a channel. The sender travels to the channel
        // thread, which takes this caller's reservation *before* publishing
        // the client, so the caller cannot lose its own channel to a
        // concurrent scan. A caller that cancels instead fails the send,
        // and the reservation returned by the failed send drops on the
        // channel thread: if it was the only one, dropping it closes the
        // fresh channel again.
        let (tx, rx) = moto_async::oneshot();
        spawn_channel_thread(ChannelThreadCtx { pool: self, tx })?;
        rx.await
            .expect("the channel thread dropped its caller's oneshot")
    }

    /// One pass over the listed clients; full or shutting-down clients
    /// refuse and are skipped (a client stays listed while its driver
    /// drains).
    fn try_reserve_open(&self) -> Option<Reservation> {
        self.clients
            .lock()
            .iter()
            .find_map(|client| client.try_reserve().ok())
    }

    fn publish(&self, client: Arc<NetClient>) {
        self.clients.lock().push(client);
    }

    fn remove(&self, client: &Arc<NetClient>) {
        let mut clients = self.clients.lock();
        let len_before = clients.len();
        clients.retain(|c| !Arc::ptr_eq(c, client));
        debug_assert_eq!(len_before, clients.len() + 1);
    }
}

struct ChannelThreadCtx {
    pool: &'static NetPool,
    tx: moto_async::oneshot::Sender<Result<Reservation, moto_rt::Error>>,
}

const CHANNEL_THREAD_STACK_SIZE: u64 = 4096 * 16;

fn spawn_channel_thread(ctx: ChannelThreadCtx) -> Result<(), moto_rt::Error> {
    let ctx = Box::into_raw(Box::new(ctx));
    match moto_sys::SysCpu::spawn(
        SysHandle::SELF,
        CHANNEL_THREAD_STACK_SIZE,
        channel_thread_entry as *const () as usize as u64,
        ctx as usize as u64,
    ) {
        Ok(_) => Ok(()),
        Err(code) => {
            // Failed provisioning must not leave a permanent hole (design
            // 6.1 step 6): reclaim the context and report to the caller.
            drop(unsafe { Box::from_raw(ctx) });
            Err(code.into())
        }
    }
}

/// One pool channel's whole vDSO lifecycle (design 6.2): connect, publish,
/// drive, unpublish, thread teardown.
extern "C" fn channel_thread_entry(ctx: u64) {
    // Safety: uniquely owned; see spawn_channel_thread().
    let ChannelThreadCtx { pool, tx } =
        *unsafe { Box::from_raw(ctx as usize as *mut ChannelThreadCtx) };
    moto_sys::set_current_thread_name("rt_net::pool_channel").unwrap();

    moto_async::LocalRuntime::new().block_on(async move {
        let (client, driver) = match moto_io::net::connect().await {
            Ok(pair) => pair,
            Err(err) => {
                // Startup failure propagates to the waiter (design 6.1
                // step 6); it never panics and leaves no state behind.
                if tx.send(Err(err)).is_err() {
                    crate::moto_log!(
                        "rt_net: sys-io connect failed ({err:?}) after its caller cancelled"
                    );
                }
                return;
            }
        };

        let client = Arc::new(client);
        let reservation = client
            .try_reserve()
            .expect("a fresh channel refused its first reservation");
        pool.publish(client.clone());
        if let Err(unclaimed) = tx.send(Ok(reservation)) {
            drop(unclaimed); // The caller cancelled; release its slot.
        }

        driver.run().await;
        pool.remove(&client);
    });

    // What the compatibility host's thread-exit hook used to do: reclaim
    // TLS, then exit; the kernel reaps the thread.
    unsafe { crate::rt_tls::on_thread_exiting() };
    let _ = moto_sys::SysObj::put(SysHandle::SELF);
    unreachable!("the pool channel thread exited");
}
