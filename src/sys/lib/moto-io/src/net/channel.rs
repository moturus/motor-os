//! The net channel runtime (design section 5.2).
//!
//! A `NetChannel` per sys-io connection, each hosting rx/tx tasks on a
//! dedicated runtime thread, plus the channel pool (`NetRuntime`), the
//! per-socket reservations, and the in-flight RPC map. The socket state
//! machines whose `Weak` references this layer dispatches to live in
//! tcp/udp; the two halves form one mutually-recursive cluster and
//! move to moto-io together in Stage F.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::future::Future;
use core::sync::atomic::*;
use core::task::Poll;
use crossbeam::utils::CachePadded;
use moto_async::AsFuture;
use moto_ipc::io_channel;
use moto_rt::mutex::Mutex;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;
use moto_sys_io::api_net;
use moto_sys_io::api_net::IO_SUBCHANNELS;

use super::tcp::TcpListener;
use super::tcp::TcpStream;
use super::udp::UdpSocket;

/// The stage-E leak check (design 5.5): a quiescent runtime holds no
/// channels and no sockets. Reached only from the vdso's netdev-gated
/// internal helper, so it is gated the same way as the counters it reads.
#[cfg(feature = "netdev")]
pub fn assert_runtime_empty() {
    NET.lock().assert_empty();
}

/// Host-installed hook run by the channel runtime thread just before it
/// exits, so the host (the vdso) can run its thread-local destructors -- a
/// concern the channel layer itself must not reach into. A native host that
/// needs no such cleanup leaves it unset.
static THREAD_EXIT_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn set_thread_exit_hook(hook: fn()) {
    THREAD_EXIT_HOOK.store(hook as usize, Ordering::Release);
}

fn run_thread_exit_hook() {
    let hook = THREAD_EXIT_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        let hook: fn() = unsafe { core::mem::transmute(hook) };
        hook();
    }
}

/// Connect to sys-io, retrying the transient `NotFound` that its per-accept
/// listener re-arm briefly exposes under connection churn. sys-io spawns its
/// replacement listener only after accepting the previous client, so a
/// `connect` landing in that window finds no registered URL and fails with
/// `NotFound` instead of waiting (see io_channel's listen/connect race note).
///
/// A bare `sched_yield()` spin recovers the microsecond window, but under a
/// sustained connection/process storm a herd of spinning clients starves
/// sys-io's single-threaded runtime of the CPU it needs to re-arm the
/// listener, so the window never closes and the retry budget is burned (a
/// stress soak panicked systest/mio-test this way). We instead sleep with
/// exponential backoff (10ms, 100ms, then 1s, capped) and +/-50% jitter,
/// handing sys-io the CPU and de-synchronising the herd. `NotFound` persisting
/// past a ~10s budget (sys-io genuinely gone), or any other error, stays fatal.
fn connect_to_sys_io() -> io_channel::ClientConnection {
    let deadline = moto_rt::time::Instant::now() + core::time::Duration::from_secs(10);
    let mut backoff_ms: u64 = 10;
    loop {
        match io_channel::ClientConnection::connect("sys-io") {
            Ok(conn) => return conn,
            Err(moto_rt::Error::NotFound) if moto_rt::time::Instant::now() < deadline => {
                // +/-50% jitter, seeded from the TSC (which also differs across
                // processes), spreads the retrying herd instead of lock-stepping it.
                let seed = moto_rt::time::Instant::now().as_u64();
                let delay_ms = backoff_ms / 2 + seed % (backoff_ms + 1);
                let wake =
                    moto_rt::time::Instant::now() + core::time::Duration::from_millis(delay_ms);
                let wake = if wake < deadline { wake } else { deadline };
                moto_rt::thread::sleep_until(wake);
                backoff_ms = (backoff_ms * 10).min(1000);
            }
            Err(err) => panic!("connect to sys-io failed: {err:?}"),
        }
    }
}

// -------------------------------- implementation details ------------------------------ //

// Note: we have an IO thread per net channel instead of a single IO thread:
// - simpler/easier to code here: no need to "schedule" between channels
// - will scale better in the future when the driver side is also multithreaded
// - the usually assumed negatives are not necessarily as bad in Motor OS
//   as in e.g. Linux:
//   - threads are "lighter", i.e. they consume less memory
//   - thread scheduling is potentially better, as Motor OS is designed
//     for the cloud use case vs a general purpose thingy, whatever that is,
//     that Linux targets.
//
// Note: there are several fence(SeqCst) below that appear unneeded. However,
//       without them (at least some of them; all permutations haven't been tested)
//       weird things happens that are not happening with them, related to
//       memory on stack. Maybe there is a bug in _this_ code that these fences
//       hide, or maybe the compiler is too aggressive (the compiler is not
//       aware of cross-process shared memory, for example). The design calls
//       for removing them (the wake edges now carry their own ordering), but
//       that is a separate, independently-tested step: the fences stay through
//       the D4b flip so a hang cannot be blamed on two changes at once.

/// How the rx task completes an in-flight RPC (`msg.id != 0`).
///
/// Plain responses resolve a oneshot whose receiver a blocked caller
/// thread polls. Connect and accept completions run inline in rx
/// dispatch — not in a control task as design 5.3 sketches — because
/// they create message-routing state (the stream's `tcp_streams` entry,
/// the listener's pending-accept queue) that must exist before the next
/// message for the same stream handle is dispatched; a task hop would
/// race that and lose early state changes.
pub(super) enum RpcWaiter {
    /// Resolved by send(); the receiver side is a caller thread.
    Response(moto_async::oneshot::Sender<io_channel::Msg>),
    /// TcpStream::connect completion. A blocking connect's caller
    /// additionally learns the outcome through the sender; the
    /// registration itself always runs inline here, so a message
    /// arriving right behind the response finds the stream.
    Connect(
        Weak<TcpStream>,
        Option<moto_async::oneshot::Sender<io_channel::Msg>>,
    ),
    /// TcpListener accept completion; a blocking accept's caller gets
    /// the PendingAccept through the sender.
    Accept(
        Weak<TcpListener>,
        Option<moto_async::oneshot::Sender<super::tcp::PendingAccept>>,
    ),
}

static NET: Mutex<NetRuntime> = Mutex::new(NetRuntime {
    full_channels: BTreeMap::new(),
    channels: BTreeMap::new(),

    #[cfg(feature = "netdev")]
    num_tcp_listeners: AtomicU64::new(0),
    #[cfg(feature = "netdev")]
    num_tcp_streams: AtomicU64::new(0),
    #[cfg(feature = "netdev")]
    num_udp_sockets: AtomicU64::new(0),
});

// Deterministic netdev regression hook for listener destruction under channel
// backpressure. The accept-response path temporarily owns the listener's last
// Arc, just like ordinary incoming dispatch can. The hook fills the private
// send queue while the rx task is running, then lets the test drop its Arc and
// release that temporary reference. Placeholder messages are removed before
// the tx task can run, so they never reach sys-io.
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_IDLE: u8 = 0;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_ARMED: u8 = 1;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_HELD: u8 = 2;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_RELEASED: u8 = 3;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_DONE: u8 = 4;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_MSG_ID: u64 = u64::MAX;
#[cfg(feature = "netdev")]
static LISTENER_DROP_TEST_HANDLE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "netdev")]
static LISTENER_DROP_TEST_STATE: AtomicU8 = AtomicU8::new(LISTENER_DROP_TEST_IDLE);

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn arm_listener_drop_backpressure_test(handle: u64) {
    assert_ne!(0, handle);
    LISTENER_DROP_TEST_HANDLE.store(handle, Ordering::Relaxed);
    LISTENER_DROP_TEST_STATE
        .compare_exchange(
            LISTENER_DROP_TEST_IDLE,
            LISTENER_DROP_TEST_ARMED,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .unwrap();
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn listener_drop_backpressure_test_is_held() -> bool {
    LISTENER_DROP_TEST_STATE.load(Ordering::Acquire) == LISTENER_DROP_TEST_HELD
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn release_listener_drop_backpressure_test() {
    LISTENER_DROP_TEST_STATE
        .compare_exchange(
            LISTENER_DROP_TEST_HELD,
            LISTENER_DROP_TEST_RELEASED,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .unwrap();
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn listener_drop_backpressure_test_is_done() -> bool {
    LISTENER_DROP_TEST_STATE.load(Ordering::Acquire) == LISTENER_DROP_TEST_DONE
}

pub fn stats_tcp_listener_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_listeners.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_tcp_listener_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_listeners.fetch_sub(1, Ordering::Relaxed);
}

pub fn stats_tcp_stream_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_streams.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_tcp_stream_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_tcp_streams.fetch_sub(1, Ordering::Relaxed);
}

pub fn stats_udp_socket_created() {
    #[cfg(feature = "netdev")]
    NET.lock().num_udp_sockets.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_udp_socket_dropped() {
    #[cfg(feature = "netdev")]
    NET.lock().num_udp_sockets.fetch_sub(1, Ordering::Relaxed);
}

struct NetRuntime {
    // Channels at capacity. We need sets, but this is rustc-dep-of-std, and our options are limited.
    full_channels: BTreeMap<u64, Arc<NetChannel>>,
    // Channels that can accommodate more sockets.
    channels: BTreeMap<u64, Arc<NetChannel>>,

    #[cfg(feature = "netdev")]
    num_tcp_listeners: AtomicU64,
    #[cfg(feature = "netdev")]
    num_tcp_streams: AtomicU64,
    #[cfg(feature = "netdev")]
    num_udp_sockets: AtomicU64,
}

impl NetRuntime {
    #[cfg(feature = "netdev")]
    fn assert_empty(&self) {
        assert_eq!(0, self.num_tcp_listeners.load(Ordering::Acquire));
        assert_eq!(0, self.num_tcp_streams.load(Ordering::Acquire));
        assert_eq!(0, self.num_udp_sockets.load(Ordering::Acquire));
        // With stage-E teardown a channel is removed from the pool the moment
        // its last reservation is released, so a quiescent runtime holds no
        // channels at all -- the meaningful leak check (design 5.5).
        assert!(self.full_channels.is_empty());
        assert!(self.channels.is_empty());
    }

    fn reserve_channel(&mut self) -> ChannelReservation {
        // Note: it is fine to use Relaxed ordering because the fn is called under NET.lock().
        if let Some(entry) = self.channels.first_entry() {
            let channel = entry.get().clone();
            let reservations = 1 + channel.reservations.fetch_add(1, Ordering::Relaxed);
            if reservations == IO_SUBCHANNELS {
                self.channels.remove(&channel.id());
                self.full_channels.insert(channel.id(), channel.clone());
            }

            ChannelReservation {
                channel,
                subchannel_idx: None,
            }
        } else {
            let channel = NetChannel::new();
            channel.reservations.fetch_add(1, Ordering::Relaxed);
            self.channels.insert(channel.id(), channel.clone());
            ChannelReservation {
                channel,
                subchannel_idx: None,
            }
        }
    }

    fn release_channel_reservation(&mut self, channel: &NetChannel) {
        // Note: it is fine to use Relaxed ordering because the fn is called under NET.lock().
        let prev = channel.reservations.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(prev > 0, "released a channel with no reservations");

        if prev == 1 {
            // Last reservation released: tear the channel down (design 5.5).
            // Drop it from the pool so it is never reused, then signal its
            // runtime to drain and exit. The runtime thread holds its own
            // Arc<Self>, so the channel stays alive until it exits -- there
            // is nothing to join and no self-join hazard even when this runs
            // on the channel's own runtime thread (a socket dropped by rx).
            self.full_channels.remove(&channel.id());
            self.channels.remove(&channel.id());
            channel.begin_exit();
            return;
        }

        // Still in use; a channel that was full now has room again.
        if let Some(channel) = self.full_channels.remove(&channel.id()) {
            self.channels.insert(channel.id(), channel);
        }
    }

    #[cfg(feature = "netdev")]
    fn print_stats(&self) {
        log::info!(
            "NET runtime: {} TCP Listeners; {} TCP sockets; {} UDP sockets.",
            self.num_tcp_listeners.load(Ordering::Relaxed),
            self.num_tcp_streams.load(Ordering::Relaxed),
            self.num_udp_sockets.load(Ordering::Relaxed)
        );
    }
}

/// The `Msg::flags` value marking a client-internal TcpStreamTx marker: it
/// tells the IO thread to claim and send the stream's pending TX pages (see
/// `tcp::PendingTxPage`), and never reaches sys-io. The value cannot occur
/// in a real Tx message: the classic format keeps `flags` zero and the
/// multi-page format stores `total_len <= TCP_TX_MAX_BYTES` there.
pub(super) const TCP_TX_MARKER_FLAGS: u32 = u32::MAX;

/// A marker message for stream `handle` (see [`TCP_TX_MARKER_FLAGS`]).
pub(super) fn tcp_tx_marker_msg(handle: u64) -> io_channel::Msg {
    let mut msg = io_channel::Msg::new();
    msg.command = api_net::NetCmd::TcpStreamTx as u16;
    msg.handle = handle;
    msg.flags = TCP_TX_MARKER_FLAGS;
    msg
}

/// How a TX send batch ended; each outcome needs a different reaction
/// (park / await ring space / yield), so the batch reports it instead
/// of acting on it.
enum TxBatch {
    /// `carry` and `send_queue` are both empty.
    Drained { sent_any: bool },
    /// `conn.send` returned NotReady; the unsent head is back in `carry`.
    RingFull,
    /// 32 messages sent with more still queued.
    BatchLimit,
}

/// A communication channel between the current process and sys-io.
///
/// Each channel has a dedicated runtime thread hosting its rx and tx
/// tasks (design 5.2); thread-per-channel is kept per the scaling
/// rationale at the top of this section.
///
/// Each ~socket~ has a dedicated "subchannel", so that sockets don't interfere
/// with each other.
pub struct NetChannel {
    conn: io_channel::ClientConnection,
    reservations: AtomicU8,

    subchannels_in_use: Vec<AtomicBool>,

    // TODO: we will only have at most IO_SUBCHANNELS streams per connection. Maybe
    //       we should get rid of spinlocks below and have simple vectors?
    //
    // We use weak references to TcpStream below because ultimately the user
    // owns tcp streams, and we want to clear things away when the user drops them.
    tcp_streams: Mutex<BTreeMap<u64, Weak<TcpStream>>>,
    tcp_listeners: Mutex<BTreeMap<u64, Weak<TcpListener>>>,
    udp_sockets: Mutex<BTreeMap<u64, Weak<UdpSocket>>>,

    next_msg_id: CachePadded<AtomicU64>, // A counter.

    // This is a multi-producer, single-consumer queue.
    send_queue: crossbeam_queue::ArrayQueue<io_channel::Msg>,

    // Threads waiting to add their msg to send_queue. Signaled one per
    // quiescent tx poll; a stale or duplicate entry costs a spurious
    // signal the waiter's re-check absorbs.
    send_waiters: Mutex<VecDeque<Arc<moto_async::SyncWaiter>>>,

    // Streams waiting for "can write" notification.
    write_waiters: Mutex<VecDeque<Weak<TcpStream>>>,

    // Wakers of parked TCP write futures, drained on every channel pass
    // (broad wake-and-recheck: progress may be a freed io_page — sys-io
    // wakes the channel when it frees one whose page-wait bit is set —
    // or send-queue room).
    tx_wakers: Mutex<Vec<core::task::Waker>>,

    // The channel runtime's send-room notify (a leaked LocalNotify),
    // signaled by the tx task whenever the send queue has room; awaited by
    // guaranteed-send tasks (see `send_msg_guaranteed`). LocalNotify is not
    // Sync: the pointer is published once at runtime startup and only ever
    // dereferenced on the runtime thread.
    send_room: AtomicUsize,

    // In-flight RPCs: req_id => the waiter the rx task resolves with the
    // response. Insert-before-queue is the ordering rule: the response
    // must never beat its waiter into the map.
    rpc_map: Mutex<BTreeMap<u64, RpcWaiter>>,

    // The tx task's cross-thread waker, published by `park_until_send_work`;
    // waking it is cheap while the runtime is polling (A5 wake elision).
    tx_task_waker: Mutex<Option<core::task::Waker>>,

    // The rx task's cross-thread waker, published by `rx_park`. The rx task
    // otherwise parks on the connection handle, which teardown cannot signal
    // (it is sys-io's); this lets `begin_exit` wake it to observe `exiting`.
    rx_task_waker: Mutex<Option<core::task::Waker>>,

    // Guaranteed sends still awaiting send-queue room on the runtime thread
    // (the `send_msg_guaranteed` detached-task path). Teardown's tx task
    // will not exit until this reaches zero, so no close is ever dropped.
    guaranteed_inflight: AtomicUsize,

    io_thread_join_handle: AtomicU64,
    io_thread_wake_handle: AtomicU64,

    exiting: CachePadded<AtomicBool>,
}

impl Drop for NetChannel {
    fn drop(&mut self) {
        // Reached only after the runtime thread has exited: it holds an
        // Arc<Self> for its whole life (see runtime_thread_init), so this
        // last drop cannot run while a task still borrows `self`. Teardown
        // (begin_exit + the tasks draining) already happened; the conn,
        // maps and queues drop with the struct. The kernel reaps the
        // exited thread on its own (no join needed).
        debug_assert!(self.exiting.load(Ordering::Acquire));
        debug_assert_eq!(0, self.reservations.load(Ordering::Relaxed));

        // Free the send-room notify leaked at runtime startup. Safe: the
        // runtime thread has exited, so no task dereferences it.
        let addr = self.send_room.load(Ordering::Acquire);
        if addr != 0 {
            core::mem::drop(unsafe {
                alloc::boxed::Box::from_raw(addr as *mut moto_async::LocalNotify)
            });
        }
    }
}

impl NetChannel {
    fn id(&self) -> u64 {
        self.conn.server_handle().into()
    }

    // Per-channel invariant check. Unreachable since stage-E teardown drops a
    // channel from the pool the moment its last reservation is released (so a
    // quiescent runtime holds none to check -- NetRuntime::assert_empty covers
    // that); kept as a debugging aid.
    #[allow(dead_code)]
    fn assert_empty(&self) {
        assert_eq!(0, self.reservations.load(Ordering::Relaxed));
        self.conn.assert_empty();

        for sub in &self.subchannels_in_use {
            assert!(!sub.load(Ordering::Relaxed));
        }
    }

    /// Dispatch one incoming message to its stream/socket/listener
    /// (`msg.id == 0`) or its RPC waiter (`msg.id != 0`); all reader/
    /// waiter wakes happen inside the handlers.
    fn dispatch_incoming(&self, msg: io_channel::Msg) {
        fence(Ordering::SeqCst);

        #[cfg(debug_assertions)]
        {
            if let Ok(cmd) = api_net::NetCmd::try_from(msg.command) {
                log::debug!("got msg {}:0x{:x}:{cmd:?}", msg.id, msg.handle,);
            } else {
                log::debug!("got msg {}:0x{:x}:{}", msg.id, msg.handle, msg.command);
            }
        }

        let cmd = api_net::NetCmd::try_from(msg.command).unwrap();

        if msg.id == 0 {
            if cmd.is_udp() {
                self.on_udp_msg(msg);
                return;
            }

            // This is an incoming packet, or similar, without a dedicated waiter.
            let stream_handle = msg.handle;
            // Upgraded listener Arcs are held here and dropped only after the
            // tcp_streams/tcp_listeners locks below are released: if such a
            // temporary is a listener's last strong ref (the owner dropped it
            // concurrently), its Drop runs tcp_listener_dropped(), which
            // re-locks tcp_listeners -- self-deadlocking this rx task if the
            // drop happened while we still held that lock (the channel wedges
            // mid-dispatch and every socket on it hangs).
            let mut queued_to_listener = false;
            let mut upgraded_listeners: Vec<Arc<TcpListener>> = Vec::new();
            let stream = {
                let mut tcp_streams = self.tcp_streams.lock();
                if let Some(stream) = tcp_streams.get_mut(&stream_handle) {
                    stream.upgrade()
                } else {
                    // No stream for the packet. But it is possible that there is a pending
                    // accept for the stream, so we must not just drop the packet in
                    // on_orphan_message() below. And we should check the pending accept queues
                    // while holding the tcp streams lock, otherwise we could race with
                    // the accept converting into a stream...
                    let tcp_listeners = self.tcp_listeners.lock();
                    for listener in tcp_listeners.values() {
                        let Some(listener) = listener.upgrade() else {
                            continue;
                        };
                        let did_queue = listener.add_to_pending_queue(msg);
                        upgraded_listeners.push(listener);
                        if did_queue {
                            queued_to_listener = true;
                            break;
                        }
                    }
                    None
                }
            };
            // Both locks are released; dropping the upgraded listener Arcs
            // (and a possible last-ref tcp_listener_dropped()) is now safe.
            drop(upgraded_listeners);
            if queued_to_listener {
                return;
            }
            if let Some(stream) = stream {
                stream.process_incoming_msg(msg);
            } else {
                self.on_orphan_message(msg);
            }
        } else {
            // An RPC response: resolve through the RPC map. The binding
            // drops the map lock before the match: accept completions
            // re-post accepts, which re-enters the map.
            let waiter = self.rpc_map.lock().remove(&msg.id);
            match waiter {
                Some(RpcWaiter::Response(tx)) => {
                    // The send wakes the receiver — a caller thread
                    // parked in block_on_sync.
                    if tx.send(msg).is_err() {
                        // Receivers are never dropped before completion
                        // (block_on_sync polls to Ready; teardown is
                        // stage E).
                        panic!("RPC receiver gone for msg {}", msg.id);
                    }
                }
                Some(RpcWaiter::Connect(stream, tx)) => {
                    if let Some(stream) = stream.upgrade() {
                        let _ = stream.on_connect_response(msg);
                    } else if msg.status().is_ok() {
                        // The connecting future and its last stream owner were
                        // dropped before sys-io transferred the new handle to
                        // us. Complete the ownership transfer by closing it.
                        self.close_tcp_stream(msg.handle);
                    }
                    if let Some(tx) = tx {
                        let _ = tx.send(msg);
                    }
                }
                Some(RpcWaiter::Accept(listener, tx)) => {
                    if let Some(listener) = listener.upgrade() {
                        listener.on_accept_response(msg, tx);
                        #[cfg(feature = "netdev")]
                        self.maybe_run_listener_drop_backpressure_test(listener);
                    } else if msg.status().is_ok() {
                        // The listener went away after posting this accept but
                        // before sys-io returned the accepted stream.
                        self.close_tcp_stream(msg.handle);
                    }
                }
                None => panic!("unexpected msg"),
            }
        }
    }

    #[cfg(feature = "netdev")]
    fn maybe_run_listener_drop_backpressure_test(&self, listener: Arc<TcpListener>) {
        if LISTENER_DROP_TEST_HANDLE.load(Ordering::Relaxed) != listener.handle()
            || LISTENER_DROP_TEST_STATE
                .compare_exchange(
                    LISTENER_DROP_TEST_ARMED,
                    LISTENER_DROP_TEST_HELD,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }

        let mut placeholder = io_channel::Msg::new();
        placeholder.id = LISTENER_DROP_TEST_MSG_ID;
        placeholder.command = u16::MAX;
        placeholder.handle = u64::MAX;
        while self.send_queue.push(placeholder).is_ok() {}
        assert!(self.send_queue.is_full());

        // The test drops its owning Arc while this rx-task Arc is held, then
        // releases us to perform the last drop with a full send queue.
        while LISTENER_DROP_TEST_STATE.load(Ordering::Acquire) != LISTENER_DROP_TEST_RELEASED {
            core::hint::spin_loop();
        }
        drop(listener);

        // The runtime-safe destructor returns here. Remove only this hook's
        // placeholders, preserving real closes that were already queued.
        let mut retained = VecDeque::new();
        while let Some(msg) = self.send_queue.pop() {
            if msg.id != LISTENER_DROP_TEST_MSG_ID {
                retained.push_back(msg);
            }
        }
        for msg in retained {
            self.send_queue.push(msg).unwrap();
        }
        LISTENER_DROP_TEST_STATE.store(LISTENER_DROP_TEST_DONE, Ordering::Release);
        self.maybe_wake_io_thread();
    }

    fn on_udp_msg(&self, msg: io_channel::Msg) {
        assert_eq!(0, msg.id); // UDP is now always async.

        let socket: Option<Arc<UdpSocket>> = self
            .udp_sockets
            .lock()
            .get_mut(&msg.handle)
            .and_then(|s| s.upgrade());

        if let Some(udp_socket) = socket {
            udp_socket.process_incoming_msg(msg);
        } else {
            self.on_orphan_message(msg);
        }
    }

    /// Send one batch from `carry` + `send_queue`, expanding TX markers.
    /// `carry` holds messages already popped from `send_queue` but not yet
    /// sent; they are older than anything in the queue and are sent first.
    fn tx_send_batch(&self, carry: &mut VecDeque<io_channel::Msg>) -> TxBatch {
        let mut sent_messages = 0;
        while let Some(msg) = carry.pop_front().or_else(|| self.send_queue.pop()) {
            let msg = if msg.command == api_net::NetCmd::TcpStreamTx as u16
                && msg.flags == TCP_TX_MARKER_FLAGS
            {
                // A TX marker: claim the stream's pending pages and send
                // them as one message, binding their lengths now (see
                // tcp::PendingTxPage). An empty pending queue — an
                // earlier marker or the stream's drop claimed the pages
                // already — is a no-op.
                match self.claim_tcp_tx(msg.handle) {
                    Some(msg) => msg,
                    None => continue,
                }
            } else {
                msg
            };
            fence(Ordering::SeqCst);
            if let Err(err) = self.conn.send(msg) {
                assert_eq!(err, moto_rt::Error::NotReady);
                carry.push_front(msg);
                return TxBatch::RingFull;
            }

            sent_messages += 1;
            if sent_messages > 32 {
                return TxBatch::BatchLimit;
            }
        }

        TxBatch::Drained {
            sent_any: sent_messages > 0,
        }
    }

    /// Claim stream `handle`'s pending TX pages in response to a marker.
    /// None if the stream is gone (its drop flushed the pages) or the
    /// pending queue is empty.
    fn claim_tcp_tx(&self, handle: u64) -> Option<io_channel::Msg> {
        let stream = self.tcp_streams.lock().get(&handle)?.upgrade()?;
        stream.claim_pending_tx()
    }

    /// Wake the channel's registered waiters. Runs after every pass of
    /// the IO thread (and, after the C2 flip, at every rx/tx task edge),
    /// so waiters registered against any progress event get re-checked.
    fn wake_waiters(&self) {
        if !self.send_queue.is_full() {
            // Take waiters because maybe_can_write() may push into write_waiters.
            let mut waiters = VecDeque::new();
            core::mem::swap(&mut waiters, &mut *self.write_waiters.lock());
            for waiter in waiters {
                if let Some(waiter) = waiter.upgrade() {
                    waiter.maybe_can_write();
                }
            }
        } else {
            self.wake_driver();
        }

        // Wake writers blocked on io_page exhaustion or send-queue room;
        // they re-check and re-register if still stuck. This pass runs
        // after every wake of this thread, including sys-io's page-freed
        // wake.
        self.wake_tx_wakers();
    }

    /// Wake parked write futures. drain() keeps the Vec's capacity: no
    /// allocation per park/wake cycle. Waking under the lock is fine
    /// (a bridge-waker wake never blocks).
    pub(super) fn wake_tx_wakers(&self) {
        let mut wakers = self.tx_wakers.lock();
        for waker in wakers.drain(..) {
            waker.wake();
        }
    }

    /// The rx task: the receive half of the old IO thread loop as a
    /// resident of the channel runtime. Receives and dispatches inline;
    /// yields to the tx task at batch boundaries; parks awaiting the
    /// connection handle when the ring is empty.
    async fn rx_task(&self) {
        #[cfg(feature = "netdev")]
        let mut loop_counter = 0_u64;

        loop {
            #[cfg(feature = "netdev")]
            {
                loop_counter += 1;
                if loop_counter.is_multiple_of(1_000_000) {
                    NET.lock().print_stats();
                }
            }

            let mut received_messages = 0_u32;
            while let Ok(msg) = self.conn.recv() {
                received_messages += 1;
                self.dispatch_incoming(msg);
                if received_messages > 32 {
                    self.wake_waiters();
                    moto_async::yield_now().await;
                    received_messages = 0;
                }
            }
            self.wake_waiters();
            if received_messages > 0 {
                // Ring entries were consumed: sys-io gets the wake the old
                // loop folded into its sleep syscall (design 3.3) — either
                // folded into the executor's park or issued at the next
                // poll edge.
                moto_async::LocalRuntime::set_wake_on_sleep(self.conn.server_handle());
            }
            if self.exiting.load(Ordering::Acquire) {
                // Teardown (design 5.5): incoming is drained above, so every
                // in-flight response has been dispatched. Exit; the tx task
                // still delivers the pending closes.
                return;
            }
            self.rx_park().await;
        }
    }

    /// Park the rx task until sys-io signals the connection handle or
    /// teardown requests exit. sys-io's handle is not something teardown can
    /// signal, so the wrapper also publishes the task's cross-thread waker
    /// (`begin_exit`'s target) and completes as soon as `exiting` is set.
    ///
    /// A signal arriving between the failed recv above and the executor's
    /// wait stays latched on the handle; the wait returns immediately.
    async fn rx_park(&self) {
        let mut conn_fut = core::pin::pin!(self.conn.server_handle().as_future());
        core::future::poll_fn(|cx| {
            *self.rx_task_waker.lock() = Some(cx.waker().clone());
            if self.exiting.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            conn_fut.as_mut().poll(cx).map(|_| ())
        })
        .await;
    }

    /// The tx task: the send half of the old IO thread loop as a resident
    /// of the channel runtime. Drains the send queue, signaling `send_room`
    /// as room appears; on ring-full awaits the connection handle (sys-io
    /// signals as it consumes); at batch boundaries yields to the rx task;
    /// when drained, parks until a caller queues work (see
    /// `park_until_send_work`).
    async fn tx_task(&self) {
        // Messages already popped from `send_queue` but not yet sent (a
        // full-ring leftover or a coalescing run terminator); older than
        // anything in `send_queue`, so always sent first.
        let mut carry: VecDeque<io_channel::Msg> = VecDeque::new();

        loop {
            let batch = self.tx_send_batch(&mut carry);

            // Any batch that popped messages may have made send-queue room;
            // release guaranteed-send tasks awaiting it (they re-check and
            // re-await on a still-full queue).
            if !self.send_queue.is_full() {
                self.send_room().notify_all();
            }

            match batch {
                TxBatch::Drained { sent_any } => {
                    if sent_any {
                        // The batch-boundary driver wake stays explicit, as
                        // in the old loop (design 5.2): sys-io must start on
                        // this batch while we head to park. Folding it into
                        // the park alone (A6) cost ~9% of default-buffer
                        // bulk TX at the stage-C gate: the driver idled
                        // until the park committed — a bubble per
                        // pending-page marker on the single-writer path.
                        self.wake_driver();
                        // The old sleep-edge fold, kept in addition (the
                        // second wake coalesces on the latched handle).
                        moto_async::LocalRuntime::set_wake_on_sleep(self.conn.server_handle());
                        self.wake_waiters();

                        // Linger before parking, standing in for the old
                        // loop's wake_requested hysteresis: the single-
                        // writer TX path posts its next pending-page marker
                        // within a few microseconds, and catching it while
                        // still polling keeps the caller's wake syscall-
                        // free (A5 elision) and skips a park/unpark round-
                        // trip per marker. The driver wake already went
                        // out, so a lone send (RR) loses no latency; each
                        // empty pass is a sub-microsecond re-poll.
                        for _ in 0..16 {
                            moto_async::yield_now().await;
                            if !self.send_queue.is_empty() {
                                break;
                            }
                        }
                        continue;
                    }
                    self.wake_waiters();
                    if self.exiting.load(Ordering::Acquire) {
                        // Teardown (design 5.5): all closes are delivered once
                        // the send queue, the carry, and any in-flight
                        // guaranteed sends are drained. Only then may the tx
                        // task exit.
                        if carry.is_empty()
                            && self.send_queue.is_empty()
                            && self.guaranteed_inflight.load(Ordering::Acquire) == 0
                        {
                            return;
                        }
                        // Still draining a guaranteed-send task: the batch's
                        // `send_room().notify_all()` above already nudged it
                        // (the queue is empty, so not full); yield so it runs
                        // -- it pushes its close and decrements the count --
                        // before we re-check.
                        moto_async::yield_now().await;
                        continue;
                    }
                    self.park_until_send_work().await;
                }
                TxBatch::RingFull => {
                    // Wait for sys-io to consume ring entries; it signals
                    // the connection handle as it processes messages.
                    self.wake_driver();
                    self.wake_waiters();
                    let _ = self.conn.server_handle().as_future().await;
                }
                TxBatch::BatchLimit => {
                    self.wake_driver();
                    self.wake_waiters();
                    moto_async::yield_now().await;
                }
            }
        }
    }

    /// The channel runtime's send-room notify. Runtime thread only (the
    /// pointee is a LocalNotify, which is not Sync).
    fn send_room(&self) -> &'static moto_async::LocalNotify {
        debug_assert!(self.on_io_thread());
        let addr = self.send_room.load(Ordering::Acquire);
        debug_assert_ne!(addr, 0);
        // Safety: published once at runtime startup, leaked, never freed.
        unsafe { &*(addr as *const moto_async::LocalNotify) }
    }

    /// Park the tx task until a caller queues send work. Publishes the
    /// task's waker in `tx_task_waker` (the wake target of `send_msg` and
    /// friends), then re-checks for work: a push that raced the publish
    /// either lands before the check or wakes the published waker.
    ///
    /// The old loop's sleep-edge send-waiter release lives here — at every
    /// quiescent poll, not just the batch-drained edge — so a sender that
    /// enlists after the tx task drained the queue but before it parked is
    /// still released (its `maybe_wake_io_thread` re-runs this poll).
    fn park_until_send_work(&self) -> impl Future<Output = ()> + '_ {
        core::future::poll_fn(move |cx| {
            *self.tx_task_waker.lock() = Some(cx.waker().clone());
            // Teardown wakes this waker after setting `exiting`; return so the
            // tx loop re-checks its exit condition instead of re-parking.
            if !self.send_queue.is_empty() || self.exiting.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            // Quiescent and the queue is empty: one blocked sender can
            // proceed; its retried push wakes us again for the next one.
            let waiter = { self.send_waiters.lock().pop_front() };
            if let Some(waiter) = waiter {
                waiter.signal();
            }
            Poll::Pending
        })
    }

    /// Block the calling thread until the send queue likely has room
    /// (mirrors the wait in [`Self::send_msg`]).
    pub(super) fn wait_can_send(&self, waiter: &Arc<moto_async::SyncWaiter>) {
        self.send_waiters.lock().push_back(waiter.clone());
        self.maybe_wake_io_thread();
        waiter.wait(None);
    }

    pub fn add_write_waiter(&self, stream: &TcpStream) {
        self.write_waiters.lock().push_back(stream.weak());
    }

    /// Register a write future's waker for the next channel pass. The
    /// caller must re-check its condition after registering (the pass
    /// that made room may already have drained the list).
    pub(super) fn add_tx_waker(&self, waker: &core::task::Waker) {
        let mut wakers = self.tx_wakers.lock();
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    pub(super) fn send_queue_is_full(&self) -> bool {
        self.send_queue.is_full()
    }

    /// Wake the tx task: callers do this after queuing send work. The
    /// wake is a runqueue push plus, only when the runtime is parked or
    /// committing to park, a wake syscall (A5 wake elision). A None waker
    /// means the tx task has not been polled yet; its first poll sees the
    /// queued work.
    pub fn maybe_wake_io_thread(&self) {
        // Waking under the lock is fine: a wake never blocks (a runqueue
        // push and at most one wake syscall).
        if let Some(waker) = &*self.tx_task_waker.lock() {
            waker.wake_by_ref();
        }
    }

    /// Begin channel teardown (design 5.5): mark `exiting` then wake both
    /// tasks so they observe it. Called under NET.lock() when the last
    /// reservation is released. The Release store pairs with the tasks'
    /// Acquire loads; the wakes must follow it so a task that re-checks
    /// after waking always sees `exiting`.
    fn begin_exit(&self) {
        self.exiting.store(true, Ordering::Release);
        if let Some(waker) = &*self.tx_task_waker.lock() {
            waker.wake_by_ref();
        }
        if let Some(waker) = &*self.rx_task_waker.lock() {
            waker.wake_by_ref();
        }
    }

    extern "C" fn runtime_thread_init(self_addr: usize) {
        // Reclaim the strong ref new() leaked via into_raw and HOLD it for
        // the whole thread: every task borrows `self_`, so the channel must
        // outlive block_on. `self_` is `&'static` only in the unsafe sense
        // the codebase uses -- it points into `self_arc`, which lives until
        // this function's end, past every use.
        let self_arc: Arc<Self> = unsafe { Arc::from_raw(self_addr as *const Self) };
        let self_: &'static Self = unsafe { &*Arc::as_ptr(&self_arc) };

        self_.io_thread_wake_handle.store(
            moto_sys::UserThreadControlBlock::get().self_handle,
            Ordering::Release,
        );

        moto_sys::set_current_thread_name("rt_net::channel_runtime").unwrap();

        // The send-room notify is leaked here (LocalNotify is not Sync, so it
        // cannot be a field) and freed in NetChannel::drop, safe because that
        // runs only after the thread has exited. Published before the tasks
        // that use it spawn.
        let send_room: &'static moto_async::LocalNotify =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(moto_async::LocalNotify::new()));
        self_
            .send_room
            .store(send_room as *const _ as usize, Ordering::Release);

        // Still a sys-io wake target, never a swap target: a direct
        // switch would pull sys-io onto this CPU, off its warm one —
        // measured +11 usec on the set_nodelay IO latency (sys-io is a
        // heavyweight multiplexer; warm-CPU placement beats the handoff).
        moto_async::LocalRuntime::new().block_on(async {
            let rx = moto_async::LocalRuntime::spawn(self_.rx_task());
            let tx = moto_async::LocalRuntime::spawn(self_.tx_task());
            // Both tasks return once `exiting` is set and their queues drain
            // (design 5.5); then block_on returns and the thread exits.
            let _ = rx.await;
            let _ = tx.await;
        });

        // Drop the thread's Arc before exiting: if it is the last strong ref
        // NetChannel::drop runs here (no task borrows `self_` anymore); if a
        // releasing thread still holds one, drop runs there, also after this
        // thread is gone. Then reclaim TLS and exit; the kernel reaps us.
        core::mem::drop(self_arc);
        run_thread_exit_hook();
        let _ = moto_sys::SysObj::put(SysHandle::SELF);
        unreachable!("the channel runtime thread exited");
    }

    fn new() -> Arc<Self> {
        let mut subchannels_in_use = Vec::with_capacity(IO_SUBCHANNELS as usize);
        for _ in 0..IO_SUBCHANNELS {
            subchannels_in_use.push(AtomicBool::new(false));
        }

        let self_ = Arc::new(NetChannel {
            conn: connect_to_sys_io(),
            subchannels_in_use,
            tcp_streams: Mutex::new(BTreeMap::new()),
            tcp_listeners: Mutex::new(BTreeMap::new()),
            udp_sockets: Mutex::new(BTreeMap::new()),
            reservations: AtomicU8::new(0),
            next_msg_id: CachePadded::new(AtomicU64::new(1)),
            send_queue: crossbeam_queue::ArrayQueue::new(io_channel::CHANNEL_PAGE_COUNT),
            send_waiters: Mutex::new(VecDeque::new()),
            write_waiters: Mutex::new(VecDeque::new()),
            tx_wakers: Mutex::new(Vec::new()),
            rpc_map: Mutex::new(BTreeMap::new()),
            send_room: AtomicUsize::new(0),
            tx_task_waker: Mutex::new(None),
            rx_task_waker: Mutex::new(None),
            guaranteed_inflight: AtomicUsize::new(0),
            io_thread_join_handle: AtomicU64::new(SysHandle::NONE.into()),
            io_thread_wake_handle: AtomicU64::new(SysHandle::NONE.into()),
            exiting: CachePadded::new(AtomicBool::new(false)),
        });

        let self_ptr = Arc::into_raw(self_.clone());
        let thread_handle = moto_sys::SysCpu::spawn(
            SysHandle::SELF,
            4096 * 16,
            Self::runtime_thread_init as *const () as usize as u64,
            self_ptr as usize as u64,
        )
        .unwrap();
        self_
            .io_thread_join_handle
            .store(thread_handle.into(), Ordering::Release);

        while self_.io_thread_wake_handle.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop()
        }

        self_
    }

    /// Returns the index of the subchannel in [0..IO_SUBCHANNELS).
    fn reserve_subchannel_impl(&self) -> u8 {
        for idx in 0..IO_SUBCHANNELS {
            if self.subchannels_in_use[idx as usize].swap(true, Ordering::AcqRel) {
                continue; // Was already reserved.
            }
            return idx;
        }
        panic!("Failed to reserve IO subchannel.")
    }

    fn release_subchannel(&self, idx: u8) {
        assert!(idx < IO_SUBCHANNELS);
        assert!(self.subchannels_in_use[idx as usize].swap(false, Ordering::AcqRel));
    }

    pub fn tcp_stream_created(&self, stream: &TcpStream) {
        assert!(
            self.tcp_streams
                .lock()
                .insert(stream.handle(), stream.weak())
                .is_none()
        );
    }

    pub fn udp_socket_created(&self, socket: &UdpSocket) {
        assert!(
            self.udp_sockets
                .lock()
                .insert(socket.handle(), socket.weak())
                .is_none()
        );
    }

    pub fn tcp_stream_dropped(&self, handle: u64) {
        let stream = self.tcp_streams.lock().remove(&handle).unwrap();
        assert_eq!(0, stream.strong_count());
    }

    pub fn tcp_listener_created(&self, listener: &Arc<super::tcp::TcpListener>) {
        self.tcp_listeners
            .lock()
            .insert(listener.handle(), Arc::downgrade(listener));
    }

    pub fn tcp_listener_dropped(&self, handle: u64) {
        assert_eq!(
            0,
            self.tcp_listeners
                .lock()
                .remove(&handle)
                .unwrap()
                .strong_count()
        );
    }

    pub fn send_msg(&self, msg: io_channel::Msg) {
        // The waiter is created only on backpressure (the fast path
        // stays allocation-free) and lives for this call: entries left
        // in send_waiters after we return absorb signals harmlessly.
        let mut waiter = None;
        loop {
            if self.send_queue.push(msg).is_ok() {
                self.maybe_wake_io_thread();
                return;
            }

            let waiter =
                waiter.get_or_insert_with(|| Arc::new(moto_async::SyncWaiter::new()));
            self.wait_can_send(waiter);
        }
    }

    /// Close a stream handle that sys-io created but no client-side stream
    /// took ownership of. Response dispatch runs on this channel's runtime,
    /// so the guaranteed path is required when its staging queue is full.
    pub(super) fn close_tcp_stream(&self, handle: u64) {
        debug_assert_ne!(0, handle);
        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::TcpStreamClose as u16;
        req.handle = handle;
        self.send_msg_guaranteed(req);
    }

    /// Insert `waiter` and queue `req`, blocking if the send queue is
    /// full. The waiter goes in first: the response must never beat it
    /// into the map.
    pub(super) fn send_rpc(&self, req: io_channel::Msg, waiter: RpcWaiter) {
        assert_ne!(0, req.id);
        assert!(self.rpc_map.lock().insert(req.id, waiter).is_none());
        self.send_msg(req);
    }

    /// [`Self::send_rpc`] with guaranteed delivery. The waiter is inserted
    /// first (the ordering rule: a response must never beat its waiter into
    /// the map), then the request goes out via `send_msg_guaranteed`: a full
    /// send queue parks a caller thread or, when we already run on the
    /// channel's own runtime, hands the retry to a task — the request is
    /// never dropped and the runtime never self-deadlocks. Used by the
    /// accept re-post path (design 5.2), which must keep its slot alive.
    pub(super) fn send_rpc_guaranteed(&self, req: io_channel::Msg, waiter: RpcWaiter) {
        assert_ne!(0, req.id);
        assert!(self.rpc_map.lock().insert(req.id, waiter).is_none());
        self.send_msg_guaranteed(req);
    }

    /// Nonblocking [`Self::send_rpc`]: on a full send queue the waiter
    /// is removed again and the caller gets `E_NOT_READY`.
    pub(super) fn post_rpc(&self, req: io_channel::Msg, waiter: RpcWaiter) -> Result<(), ErrorCode> {
        assert_ne!(0, req.id);
        assert!(self.rpc_map.lock().insert(req.id, waiter).is_none());
        if self.post_msg(req).is_ok() {
            Ok(())
        } else {
            self.rpc_map.lock().remove(&req.id);
            Err(moto_rt::E_NOT_READY)
        }
    }

    // Send message and wait for response.
    pub fn send_receive(&self, mut req: io_channel::Msg) -> io_channel::Msg {
        let (tx, rx) = moto_async::oneshot();
        req.id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);
        self.send_rpc(req, RpcWaiter::Response(tx));

        // Completes without a syscall if the response already arrived.
        moto_async::block_on_sync(rx).expect("RPC sender dropped")
    }

    pub fn new_req_id(&self) -> u64 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn post_msg(&self, req: io_channel::Msg) -> Result<(), io_channel::Msg> {
        if self.send_queue.push(req).is_ok() {
            self.maybe_wake_io_thread();
            Ok(())
        } else {
            Err(req)
        }
    }

    fn on_io_thread(&self) -> bool {
        self.io_thread_wake_handle.load(Ordering::Relaxed)
            == moto_sys::UserThreadControlBlock::get().self_handle
    }

    /// Enqueue a fire-and-forget message (e.g. TcpStreamClose) for delivery to
    /// sys-io. Unlike `post_msg`, the message is never dropped (sys-io would
    /// otherwise leak the stream), it never panics on a full send queue, and it
    /// never deadlocks when called from the IO thread.
    ///
    /// A TcpStream can be dropped on the IO thread itself: the IO thread briefly
    /// upgrades the Weak it keeps in `tcp_streams`, and if the application has
    /// already closed its fd, that upgrade holds the last strong reference, so
    /// `TcpStream::drop` (and this call) runs on the IO thread. Blocking there to
    /// wait for the send queue to drain would deadlock, since the IO thread is
    /// the only party that drains it.
    pub fn send_msg_guaranteed(&self, msg: io_channel::Msg) {
        // Fast path: there is room in the staging queue.
        if self.post_msg(msg).is_ok() {
            return;
        }

        if !self.on_io_thread() {
            // A different thread drains the send queue, so blocking is safe.
            // This is the same path that write()/send_receive() already use.
            self.send_msg(msg);
            return;
        }

        // We are on the runtime thread and the queue is full: hand the
        // message to a task that retries the push whenever the tx task
        // signals send-queue room. Registration cannot lose a notify: the
        // failed push and the waiter registration happen within one poll,
        // and the tx task (same thread) cannot run in between.
        //
        // The &'static borrow is sound because the runtime thread holds an
        // Arc<Self> for its whole life (runtime_thread_init) and teardown's
        // tx task waits out `guaranteed_inflight` before letting block_on
        // return, so this task always completes while `self` is still alive.
        self.guaranteed_inflight.fetch_add(1, Ordering::Relaxed);
        let self_: &'static Self = unsafe { &*(self as *const Self) };
        core::mem::drop(moto_async::LocalRuntime::spawn(async move {
            let mut msg = msg;
            loop {
                match self_.post_msg(msg) {
                    Ok(()) => break,
                    Err(rejected) => msg = rejected,
                }
                self_.send_room().notified().await;
            }
            // The push may be the last unsent close a teardown is waiting on;
            // drop the count and wake the tx task so it re-checks and exits.
            self_.guaranteed_inflight.fetch_sub(1, Ordering::Release);
            self_.maybe_wake_io_thread();
        }));
    }

    // Note: this is called from the IO thread, so must not sleep/block.
    fn on_orphan_message(&self, msg: io_channel::Msg) {
        /*
        #[cfg(debug_assertions)]
        moto_log!(
            "{}:{} orphan incoming message {:?} for 0x{:x}",
            file!(),
            line!(),
            api_net::NetCmd::try_from(msg.command).unwrap(),
            msg.handle
        );
        */
        let Ok(cmd) = api_net::NetCmd::try_from(msg.command) else {
            // This is logged always because if a new incoming message is added that
            // has to be handled but is not, we may have a problem.
            log::warn!(
                "orphan incoming message {} for 0x{:x}; release i/o page?",
                msg.command,
                msg.handle
            );
            return;
        };

        match cmd {
            api_net::NetCmd::TcpStreamTx => {
                // TX didn't complete. The driver cleared the page.
                log::debug!("Orphan TX reply for socket 0x{:x}", msg.handle);
            }
            api_net::NetCmd::TcpStreamRx => {
                // RX raced with the client dropping the stream. Claim the
                // page(s) so that they are properly dropped (freed).
                log::debug!("Orphan RX for socket 0x{:x}", msg.handle);
                claim_rx_page(self, &msg, &mut |_page, _len| {});
            }
            api_net::NetCmd::EvtTcpStreamStateChanged => {}
            api_net::NetCmd::TcpStreamClose => {}
            api_net::NetCmd::UdpSocketTxRx => {
                // RX raced with the client dropping the sream. Need to get page to free it.
                // Get the page so that it is properly dropped.
                let sz = msg.payload.args_16()[10];
                if sz != 0 {
                    let _ = self.conn.get_page(msg.payload.shared_pages()[11]);
                }
            }
            api_net::NetCmd::UdpSocketTxRxAck => {}
            _ => {
                // This is logged always because if a new incoming message is added that
                // has to be handled but is not, we may have a problem.
                log::warn!(
                    "orphan incoming message {:?} for 0x{:x}; release i/o page?",
                    cmd,
                    msg.handle
                );
            }
        }
    }

    #[inline]
    fn wake_driver(&self) {
        let _ = moto_sys::SysCpu::wake(self.conn.server_handle());
    }

    pub fn alloc_page(&self, subchannel_mask: u64) -> Result<io_channel::IoPage, ErrorCode> {
        self.conn
            .alloc_page(subchannel_mask)
            .map_err(|err| err.into())
    }

    pub fn may_alloc_page(&self, subchannel_mask: u64) -> bool {
        self.conn.may_alloc_page(subchannel_mask)
    }

    pub fn get_page(&self, page_idx: u16) -> Result<io_channel::IoPage, u16> {
        self.conn.get_page(page_idx).map_err(|err| err.into())
    }
}

pub struct ChannelReservation {
    channel: Arc<NetChannel>,
    subchannel_idx: Option<u8>,
}

impl Drop for ChannelReservation {
    fn drop(&mut self) {
        if let Some(idx) = self.subchannel_idx {
            self.channel.release_subchannel(idx);
        }

        NET.lock().release_channel_reservation(&self.channel);
    }
}

impl ChannelReservation {
    pub fn channel(&self) -> &Arc<NetChannel> {
        &self.channel
    }

    pub fn reserve_subchannel(&mut self) {
        assert!(self.subchannel_idx.is_none());
        self.subchannel_idx = Some(self.channel.reserve_subchannel_impl());
    }

    pub fn subchannel_mask(&self) -> u64 {
        api_net::io_subchannel_mask(self.subchannel_idx.unwrap())
    }

    pub fn subchannel_idx(&self) -> u8 {
        self.subchannel_idx.unwrap()
    }
}

/// Claim the io_page of a TcpStreamRx message (one page, length in
/// `args_64[1]`; zero-length messages carry no page). Calls `f(page, len)`;
/// dropping a claimed page frees it back to the channel.
pub fn claim_rx_page(
    channel: &NetChannel,
    msg: &io_channel::Msg,
    f: &mut dyn FnMut(io_channel::IoPage, usize),
) {
    debug_assert_eq!(msg.command, api_net::NetCmd::TcpStreamRx as u16);

    let sz = msg.payload.args_64()[1] as usize;
    assert!(sz <= io_channel::PAGE_SIZE);
    if sz > 0 {
        let page = channel.get_page(msg.payload.shared_pages()[0]).unwrap();
        f(page, sz);
    }
}

pub fn clear_rx_queue(
    rx_queue: &Arc<Mutex<crate::net::inner_rx_stream::InnerRxStream>>,
    channel: &NetChannel,
) {
    // Clear RX queue: basically, free up server-allocated pages.
    let mut rxq = rx_queue.lock();
    while let Some(msg) = rxq.pop_front() {
        if msg.command == (api_net::NetCmd::EvtTcpStreamStateChanged as u16) {
            continue;
        }
        assert_eq!(msg.command, api_net::NetCmd::TcpStreamRx as u16);
        claim_rx_page(channel, &msg, &mut |_page, _len| {});
    }

    rxq.clear_rx_bufs();
}

pub fn reserve_channel() -> ChannelReservation {
    NET.lock().reserve_channel()
}
