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
use moto_rt::moto_log;
use moto_rt::mutex::Mutex;
use moto_rt::time::Instant;
use moto_sys::ErrorCode;
use moto_sys_io::api_net;
use moto_sys_io::api_net::IO_SUBCHANNELS;

use super::tcp::TcpListener;
use super::tcp::TcpStream;
use super::udp::UdpSocket;
use super::wait::{WaitSet, WaiterId};

/// The stage-E leak check (design 5.5): a quiescent runtime holds no
/// channels and no sockets. Reached only from the vdso's netdev-gated
/// internal helper, so it is gated the same way as the counters it reads.
#[cfg(feature = "netdev")]
pub fn assert_runtime_empty() {
    #[cfg(feature = "netdev")]
    {
        assert_eq!(0, NUM_TCP_LISTENERS.load(Ordering::Acquire));
        assert_eq!(0, NUM_TCP_STREAMS.load(Ordering::Acquire));
        assert_eq!(0, NUM_UDP_SOCKETS.load(Ordering::Acquire));
    }
}

/// While set, `connect()` fails immediately -- the sys-io-unavailable
/// regression pins the pool's fail-all policy with it.
#[cfg(feature = "netdev")]
static POISON_CONNECT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "netdev")]
pub fn poison_connect_for_test(poisoned: bool) {
    POISON_CONNECT.store(poisoned, Ordering::Release);
}

/// The sys-io connect retry policy, shared by the sync and async connect
/// paths so neither can drift from it.
///
/// It exists to absorb the transient `NotFound` that sys-io's per-accept
/// listener re-arm briefly exposes under connection churn: sys-io spawns its
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
/// handing sys-io the CPU and de-synchronising the herd. `NotFound`
/// persisting past a ~10s budget means sys-io is genuinely gone.
struct ConnectBackoff {
    deadline: moto_rt::time::Instant,
    backoff_ms: u64,
}

impl ConnectBackoff {
    fn new() -> Self {
        Self {
            deadline: moto_rt::time::Instant::now() + core::time::Duration::from_secs(10),
            backoff_ms: 10,
        }
    }

    /// When to retry next, or `None` once the budget is spent.
    fn next_wake(&mut self) -> Option<moto_rt::time::Instant> {
        let now = moto_rt::time::Instant::now();
        if now >= self.deadline {
            return None;
        }
        // +/-50% jitter, seeded from the TSC (which also differs across
        // processes), spreads the retrying herd instead of lock-stepping it.
        let delay_ms = self.backoff_ms / 2 + now.as_u64() % (self.backoff_ms + 1);
        let wake = now + core::time::Duration::from_millis(delay_ms);
        self.backoff_ms = (self.backoff_ms * 10).min(1000);
        Some(if wake < self.deadline {
            wake
        } else {
            self.deadline
        })
    }
}

/// Connect one new channel to sys-io (design section 4).
///
/// Returns the host-facing pair: the `NetClient` handle and the `NetDriver`
/// the host must drive on its `moto_async::LocalRuntime` for the channel to
/// make progress. No thread is spawned, no global state is touched, and no
/// caller thread sleeps: transient `NotFound` retries follow the documented
/// [`ConnectBackoff`] policy through `moto_async::sleep_until`, and budget
/// exhaustion or any other error is returned rather than panicked -- the
/// host decides what sys-io being unavailable means for it.
pub async fn connect() -> Result<(NetClient, NetDriver), moto_rt::Error> {
    #[cfg(feature = "netdev")]
    if POISON_CONNECT.load(Ordering::Acquire) {
        return Err(moto_rt::Error::TimedOut);
    }
    let mut backoff = ConnectBackoff::new();
    let conn = loop {
        match io_channel::ClientConnection::connect("sys-io") {
            Ok(conn) => break conn,
            Err(moto_rt::Error::NotFound) => match backoff.next_wake() {
                Some(wake) => moto_async::sleep_until(wake).await,
                None => return Err(moto_rt::Error::NotFound),
            },
            Err(err) => return Err(err),
        }
    };

    let channel = NetChannel::with_conn(conn);
    Ok((
        NetClient {
            channel: channel.clone(),
        },
        NetDriver { channel },
    ))
}

/// `client_state` layout: reservation count below `CLIENT_EVER`.
const CLIENT_COUNT_MASK: u32 = 0xFFFF;
/// Set by the first reserve; a count that returns to zero with it set is
/// what closes the channel (a new client may sit at zero while its host
/// publishes it).
const CLIENT_EVER: u32 = 1 << 16;
/// No new reservations; the driver is draining (or will be told to).
const CLIENT_CLOSED: u32 = 1 << 17;

/// Why [`NetClient::try_reserve`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    /// All `capacity()` slots are reserved. Try another channel, or retry
    /// after a release.
    AtCapacity,
    /// The channel is shutting down -- its last reservation was released or
    /// the host requested shutdown -- and takes no new reservations.
    ShuttingDown,
}

/// One reserved socket slot on a host-owned channel (design section 4).
///
/// Dropping it releases the slot; releasing the last one closes the channel
/// to new reservations and asks its driver to drain and exit. The socket
/// constructors' explicit-reservation variants consume one, and the socket
/// then carries it for its whole life, so a socket keeps its channel alive.
pub struct Reservation(ChannelReservation);

impl Reservation {
    /// Unwrap for the socket constructors. The inner reservation keeps the
    /// `Client` owner tag, so its eventual drop still releases through the
    /// host protocol wherever it ends up (a socket, an RPC waiter, a
    /// teardown record).
    pub(super) fn into_channel_reservation(self) -> ChannelReservation {
        self.0
    }
}

/// The host-facing handle to one sys-io channel (design section 4).
///
/// Sockets on a host-owned channel are created against a [`Reservation`]
/// from `try_reserve` (the explicit-reservation socket constructors are the
/// next patch); the global pool keeps its own accounting and never uses one.
pub struct NetClient {
    channel: Arc<NetChannel>,
}

impl NetClient {
    /// Reserve one socket slot, unless the channel is full or shutting
    /// down. The last [`Reservation`] to drop closes the channel, so a
    /// host that wants it back must connect a new one.
    pub fn try_reserve(&self) -> Result<Reservation, ReserveError> {
        self.channel.client_try_reserve()
    }

    /// Socket slots per channel.
    pub fn capacity(&self) -> usize {
        IO_SUBCHANNELS as usize
    }

    /// Currently reserved slots; primarily diagnostics.
    pub fn reservations(&self) -> usize {
        (self.channel.client_state.load(Ordering::Acquire) & CLIENT_COUNT_MASK) as usize
    }

    /// Ask the channel's driver to drain and exit. The host calls this once,
    /// with no reservations outstanding -- ordinarily only for a channel it
    /// never reserved on, since the last release shuts the channel down by
    /// itself. (The pool path never calls it.)
    pub fn request_shutdown(&self) {
        self.channel
            .client_state
            .fetch_or(CLIENT_CLOSED, Ordering::AcqRel);
        self.channel.begin_exit();
    }
}

/// One channel's progress driver (design section 5.2): the rx and tx tasks
/// of the old IO thread, hosted by whoever owns the LocalRuntime -- a native
/// host directly, or the temporary compatibility thread `NetChannel::new`
/// still spawns for the vDSO path.
pub struct NetDriver {
    channel: Arc<NetChannel>,
}

impl NetDriver {
    /// Drive the channel until teardown completes. Must be polled on a
    /// `moto_async::LocalRuntime`; returns after `request_shutdown` (or the
    /// last reservation release) once both tasks drain their queues.
    pub async fn run(self) {
        // Observation-only PDIAG watchdog (networking-remaining-steps.md
        // step 1). Holds a `Weak` so it never delays channel teardown;
        // dies with the channel or the runtime, whichever goes first.
        {
            let channel = Arc::downgrade(&self.channel);
            drop(moto_async::LocalRuntime::spawn(async move {
                let mut prev = BTreeMap::new();
                loop {
                    moto_async::sleep(DIAG_TICK).await;
                    let Some(channel) = channel.upgrade() else {
                        return;
                    };
                    if channel.exiting.load(Ordering::Acquire) {
                        return;
                    }
                    channel.diag_tick(&mut prev, Instant::now());
                }
            }));
        }
        let rx = {
            let channel = self.channel.clone();
            moto_async::LocalRuntime::spawn(async move { channel.rx_task().await })
        };
        let tx = {
            let channel = self.channel.clone();
            moto_async::LocalRuntime::spawn(async move { channel.tx_task().await })
        };
        rx.await;
        tx.await;
    }
}

/// PDIAG watchdog sampling interval; a stall signature must hold across a
/// full tick before it is logged.
const DIAG_TICK: core::time::Duration = core::time::Duration::from_secs(15);

/// Per-stream sample the PDIAG watchdog compares across ticks.
struct DiagSample {
    rx_bytes: u64,
    readable_raised: u64,
    had_rx_queued: bool,
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
    Connect {
        stream: Weak<TcpStream>,
        tx: Option<moto_async::oneshot::Sender<io_channel::Msg>>,
    },
    /// TcpListener accept completion. The listener owns the dispatch: an
    /// awaiting `accept()` caller is served from its waiter queue, because
    /// the response sys-io sends first need not belong to that caller's own
    /// request.
    Accept { listener: Weak<TcpListener> },
    /// TcpListener/UdpSocket bind completion. The reservation rides in the
    /// waiter so a bind future cancelled after its request was queued still
    /// has the channel slot needed to roll the new handle back.
    Bind {
        reservation: ChannelReservation,
        drop_command: u16,
        tx: moto_async::oneshot::Sender<PendingBind>,
    },
}

/// A bind response whose handle is not owned by a socket object yet.
///
/// Holding it keeps the rollback armed: unless the awaiting bind commits it
/// with [`PendingBind::into_result`], dropping it closes the handle sys-io
/// created. This covers both a receiver that went away before delivery and a
/// bind future cancelled after the response landed (design 5.5).
pub(super) struct PendingBind {
    reservation: Option<ChannelReservation>,
    drop_command: u16,
    resp: io_channel::Msg,
}

impl PendingBind {
    /// Commit a successful bind: the caller takes over the handle and the
    /// reservation, disarming the rollback. On a failed bind nothing was
    /// created, so dropping the error case is enough.
    pub(super) fn into_result(
        mut self,
    ) -> Result<(ChannelReservation, io_channel::Msg), ErrorCode> {
        self.resp.status()?;
        Ok((self.reservation.take().unwrap(), self.resp))
    }
}

impl Drop for PendingBind {
    fn drop(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return; // Committed by into_result().
        };
        if self.resp.status().is_err() {
            return; // sys-io created nothing to roll back.
        }

        let mut msg = io_channel::Msg::new();
        msg.command = self.drop_command;
        msg.handle = self.resp.handle;
        let channel = reservation.channel().clone();
        channel.enqueue_teardown(reservation, msg);
    }
}

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
const LISTENER_DROP_TEST_PREPARING: u8 = 2;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_HELD: u8 = 3;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_RELEASED: u8 = 4;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_DONE: u8 = 5;
#[cfg(feature = "netdev")]
const LISTENER_DROP_TEST_MSG_ID: u64 = u64::MAX;
#[cfg(feature = "netdev")]
static LISTENER_DROP_TEST_HANDLE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "netdev")]
static LISTENER_DROP_TEST_STATE: AtomicU8 = AtomicU8::new(LISTENER_DROP_TEST_IDLE);

// Deterministic netdev regression hook for stream destruction with pending TX
// under channel backpressure. Unlike the listener hook, the test fills the
// staging queue after the runtime is held so it can first queue real TX
// markers. Placeholder messages are removed before the tx task can run.
#[cfg(feature = "netdev")]
const STREAM_DROP_TEST_IDLE: u8 = 0;
#[cfg(feature = "netdev")]
const STREAM_DROP_TEST_ARMED: u8 = 1;
#[cfg(feature = "netdev")]
const STREAM_DROP_TEST_PREPARING: u8 = 2;
#[cfg(feature = "netdev")]
const STREAM_DROP_TEST_HELD: u8 = 3;
#[cfg(feature = "netdev")]
const STREAM_DROP_TEST_RELEASED: u8 = 4;
#[cfg(feature = "netdev")]
const STREAM_DROP_TEST_DONE: u8 = 5;
#[cfg(feature = "netdev")]
const STREAM_DROP_TEST_MSG_ID: u64 = u64::MAX - 1;
#[cfg(feature = "netdev")]
static STREAM_DROP_TEST_HANDLE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "netdev")]
static STREAM_DROP_TEST_STATE: AtomicU8 = AtomicU8::new(STREAM_DROP_TEST_IDLE);

// Hold one ordinary RPC response between map removal and oneshot delivery,
// allowing systest to cancel the receiver at that exact ownership boundary.
#[cfg(feature = "netdev")]
const RPC_CANCEL_TEST_IDLE: u8 = 0;
#[cfg(feature = "netdev")]
const RPC_CANCEL_TEST_ARMED: u8 = 1;
#[cfg(feature = "netdev")]
const RPC_CANCEL_TEST_HELD: u8 = 2;
#[cfg(feature = "netdev")]
const RPC_CANCEL_TEST_RELEASED: u8 = 3;
#[cfg(feature = "netdev")]
const RPC_CANCEL_TEST_DONE: u8 = 4;
#[cfg(feature = "netdev")]
static RPC_CANCEL_TEST_STATE: AtomicU8 = AtomicU8::new(RPC_CANCEL_TEST_IDLE);

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

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn arm_stream_drop_backpressure_test(handle: u64) {
    assert_ne!(0, handle);
    STREAM_DROP_TEST_HANDLE.store(handle, Ordering::Relaxed);
    STREAM_DROP_TEST_STATE
        .compare_exchange(
            STREAM_DROP_TEST_IDLE,
            STREAM_DROP_TEST_ARMED,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .unwrap();
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn stream_drop_backpressure_test_is_held() -> bool {
    STREAM_DROP_TEST_STATE.load(Ordering::Acquire) == STREAM_DROP_TEST_HELD
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn release_stream_drop_backpressure_test() {
    STREAM_DROP_TEST_STATE
        .compare_exchange(
            STREAM_DROP_TEST_HELD,
            STREAM_DROP_TEST_RELEASED,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .unwrap();
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn stream_drop_backpressure_test_is_done() -> bool {
    STREAM_DROP_TEST_STATE.load(Ordering::Acquire) == STREAM_DROP_TEST_DONE
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn arm_rpc_response_cancel_test() {
    let state = RPC_CANCEL_TEST_STATE.load(Ordering::Acquire);
    assert!(state == RPC_CANCEL_TEST_IDLE || state == RPC_CANCEL_TEST_DONE);
    RPC_CANCEL_TEST_STATE
        .compare_exchange(
            state,
            RPC_CANCEL_TEST_ARMED,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .unwrap();
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn rpc_response_cancel_test_is_held() -> bool {
    RPC_CANCEL_TEST_STATE.load(Ordering::Acquire) == RPC_CANCEL_TEST_HELD
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn release_rpc_response_cancel_test() {
    RPC_CANCEL_TEST_STATE
        .compare_exchange(
            RPC_CANCEL_TEST_HELD,
            RPC_CANCEL_TEST_RELEASED,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .unwrap();
}

#[doc(hidden)]
#[cfg(feature = "netdev")]
pub fn rpc_response_cancel_test_is_done() -> bool {
    RPC_CANCEL_TEST_STATE.load(Ordering::Acquire) == RPC_CANCEL_TEST_DONE
}

#[cfg(feature = "netdev")]
static NUM_TCP_LISTENERS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "netdev")]
static NUM_TCP_STREAMS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "netdev")]
static NUM_UDP_SOCKETS: AtomicU64 = AtomicU64::new(0);

pub fn stats_tcp_listener_created() {
    #[cfg(feature = "netdev")]
    NUM_TCP_LISTENERS.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_tcp_listener_dropped() {
    #[cfg(feature = "netdev")]
    NUM_TCP_LISTENERS.fetch_sub(1, Ordering::Relaxed);
}

pub fn stats_tcp_stream_created() {
    #[cfg(feature = "netdev")]
    NUM_TCP_STREAMS.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_tcp_stream_dropped() {
    #[cfg(feature = "netdev")]
    NUM_TCP_STREAMS.fetch_sub(1, Ordering::Relaxed);
}

pub fn stats_udp_socket_created() {
    #[cfg(feature = "netdev")]
    NUM_UDP_SOCKETS.fetch_add(1, Ordering::Relaxed);
}

pub fn stats_udp_socket_dropped() {
    #[cfg(feature = "netdev")]
    NUM_UDP_SOCKETS.fetch_sub(1, Ordering::Relaxed);
}

/// The `Msg::flags` value marking a client-internal TcpStreamTx marker: it
/// tells the IO thread to claim and send the stream's pending TX pages (see
/// `tcp::PendingTxPage`), and never reaches sys-io. The value cannot occur
/// in a real Tx message: the classic format keeps `flags` zero and the
/// multi-page format stores `total_len <= TCP_TX_MAX_BYTES` there.
pub(super) const TCP_TX_MARKER_FLAGS: u32 = u32::MAX;

pub(super) fn tcp_stream_close_msg(handle: u64) -> io_channel::Msg {
    debug_assert_ne!(0, handle);
    let mut msg = io_channel::Msg::new();
    msg.command = api_net::NetCmd::TcpStreamClose as u16;
    msg.handle = handle;
    msg
}

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

/// Driver-owned control or teardown work. A teardown record retains its
/// reservation until every message has reached sys-io; the driver drains
/// control work even after the channel's last reservation requests exit.
struct DriverRecord {
    messages: VecDeque<io_channel::Msg>,

    /// The staging queue's push count when this record was enqueued: work
    /// staged before it was queued for sys-io first and must reach it first.
    /// A UDP socket's datagrams sit in the staging queue when its close is
    /// enqueued, and sys-io discards a datagram addressed to a socket it has
    /// already dropped. The record becomes eligible once the tx task has
    /// drained that many messages -- never later, so nothing staged after it
    /// (the caller's next bind of the same address) can overtake it either.
    staged_fence: u64,

    _reservation: Option<ChannelReservation>,
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

    // The host-side reservation protocol (design section 4): count in the
    // low bits, plus CLIENT_EVER once anything reserved and CLIENT_CLOSED
    // when the count returns to zero afterwards. One atomic word, because
    // unlike `reservations` -- whose transitions all run under `NET.lock()`
    // -- nothing serializes a host's threads: closing must land in the same
    // CAS as the final decrement so a `try_reserve` cannot race the channel
    // from idle into teardown. Only host-owned channels use it; a pooled
    // channel's word stays zero.
    client_state: AtomicU32,

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

    // Lifetime push/pop counts for `send_queue`, maintained by stage_msg and
    // unstage_msg. They order a driver record against the work staged
    // before it (see DriverRecord::staged_fence); nothing else reads them.
    staged_pushed: AtomicU64,
    staged_popped: AtomicU64,

    // Destructors and inline response dispatch cannot await send-queue room.
    // They transfer guaranteed work here for the channel driver to deliver.
    driver_queue: crossbeam_queue::SegQueue<DriverRecord>,

    // Streams waiting for "can write" notification.
    write_waiters: Mutex<VecDeque<Weak<TcpStream>>>,

    // Cancellation-aware registrations of parked async sends and TCP write
    // futures. Drained on every channel pass (broad wake-and-recheck:
    // progress may be a freed io_page or send-queue room).
    tx_waiters: WaitSet,

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

    exiting: CachePadded<AtomicBool>,
}

/// Cancellation-aware wait to place one message in the staging queue.
pub(super) struct SendFuture<'a> {
    channel: &'a NetChannel,
    msg: Option<io_channel::Msg>,
    waiter_id: Option<WaiterId>,
}

impl Drop for SendFuture<'_> {
    fn drop(&mut self) {
        self.channel.remove_tx_waker(&mut self.waiter_id);
    }
}

impl Future for SendFuture<'_> {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let msg = this.msg.take().expect("polled SendFuture after completion");
            match this.channel.post_msg(msg) {
                Ok(()) => {
                    this.channel.remove_tx_waker(&mut this.waiter_id);
                    return Poll::Ready(());
                }
                Err(msg) => this.msg = Some(msg),
            }

            this.channel.add_tx_waker(&mut this.waiter_id, cx.waker());
            if this.channel.send_queue_is_full() {
                return Poll::Pending;
            }
        }
    }
}

struct RpcRegistration<'a> {
    channel: &'a NetChannel,
    id: u64,
    sent: bool,
}

impl Drop for RpcRegistration<'_> {
    fn drop(&mut self) {
        if !self.sent {
            let removed = self.channel.rpc_map.lock().remove(&self.id);
            debug_assert!(matches!(
                removed,
                Some(RpcWaiter::Response(_) | RpcWaiter::Connect { .. } | RpcWaiter::Bind { .. })
            ));
        }
    }
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
        debug_assert_eq!(
            0,
            self.client_state.load(Ordering::Relaxed) & CLIENT_COUNT_MASK
        );
    }
}

impl NetChannel {
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
                #[cfg(feature = "netdev")]
                self.maybe_run_stream_drop_backpressure_test(stream);
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
                    #[cfg(feature = "netdev")]
                    if RPC_CANCEL_TEST_STATE
                        .compare_exchange(
                            RPC_CANCEL_TEST_ARMED,
                            RPC_CANCEL_TEST_HELD,
                            Ordering::Release,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        while RPC_CANCEL_TEST_STATE.load(Ordering::Acquire)
                            != RPC_CANCEL_TEST_RELEASED
                        {
                            core::hint::spin_loop();
                        }
                        RPC_CANCEL_TEST_STATE.store(RPC_CANCEL_TEST_DONE, Ordering::Release);
                    }

                    // An async caller may cancel after the request was sent.
                    // The response still completes protocol ownership; only
                    // delivery to the dropped receiver is skipped.
                    let _ = tx.send(msg);
                }
                Some(RpcWaiter::Connect { stream, tx }) => {
                    if let Some(stream) = stream.upgrade() {
                        let _ = stream.on_connect_response(msg);
                    } else if msg.status().is_ok() {
                        // The caller cancelled after sending the request. The
                        // driver remains alive long enough to send this close
                        // even if that released the channel's last reservation.
                        self.enqueue_control(tcp_stream_close_msg(msg.handle));
                    }
                    if let Some(tx) = tx {
                        let _ = tx.send(msg);
                    }
                }
                Some(RpcWaiter::Accept { listener }) => {
                    if let Some(listener) = listener.upgrade() {
                        listener.on_accept_response(msg);
                        #[cfg(feature = "netdev")]
                        self.maybe_run_listener_drop_backpressure_test(listener);
                    } else if msg.status().is_ok() {
                        // The listener went away after posting this accept but
                        // before sys-io returned the accepted stream.
                        self.enqueue_control(tcp_stream_close_msg(msg.handle));
                    }
                }
                Some(RpcWaiter::Bind {
                    reservation,
                    drop_command,
                    tx,
                }) => {
                    let pending = PendingBind {
                        reservation: Some(reservation),
                        drop_command,
                        resp: msg,
                    };
                    // A cancelled bind leaves no receiver; dropping the
                    // undelivered PendingBind rolls the new handle back.
                    let _ = tx.send(pending);
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
                    LISTENER_DROP_TEST_PREPARING,
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
        while self.stage_msg(placeholder).is_ok() {}
        assert!(self.send_queue.is_full());

        // Release the rx task's Arc before publishing HELD. The test can now
        // perform the last listener drop from a different thread while this
        // runtime remains unable to drain its full staging queue.
        drop(listener);
        LISTENER_DROP_TEST_STATE.store(LISTENER_DROP_TEST_HELD, Ordering::Release);
        while LISTENER_DROP_TEST_STATE.load(Ordering::Acquire) != LISTENER_DROP_TEST_RELEASED {
            core::hint::spin_loop();
        }

        // The nonblocking destructor returned. Remove only this hook's
        // placeholders, preserving real closes that were already queued.
        let mut retained = VecDeque::new();
        while let Some(msg) = self.unstage_msg() {
            if msg.id != LISTENER_DROP_TEST_MSG_ID {
                retained.push_back(msg);
            }
        }
        for msg in retained {
            self.stage_msg(msg).unwrap();
        }
        LISTENER_DROP_TEST_STATE.store(LISTENER_DROP_TEST_DONE, Ordering::Release);
        self.maybe_wake_io_thread();
    }

    #[cfg(feature = "netdev")]
    fn maybe_run_stream_drop_backpressure_test(&self, stream: Arc<TcpStream>) {
        if STREAM_DROP_TEST_HANDLE.load(Ordering::Relaxed) != stream.handle()
            || STREAM_DROP_TEST_STATE
                .compare_exchange(
                    STREAM_DROP_TEST_ARMED,
                    STREAM_DROP_TEST_PREPARING,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }

        // Release the rx task's temporary Arc before publishing HELD. The
        // test can then perform the final stream drop while both channel
        // tasks remain unable to drain the staging queue.
        drop(stream);
        STREAM_DROP_TEST_STATE.store(STREAM_DROP_TEST_HELD, Ordering::Release);
        while STREAM_DROP_TEST_STATE.load(Ordering::Acquire) != STREAM_DROP_TEST_RELEASED {
            core::hint::spin_loop();
        }

        // Remove only the hook's placeholders. Preserve real TX markers
        // queued before the stream was dropped; they become harmless no-ops
        // after the teardown record claims all pending pages.
        let mut retained = VecDeque::new();
        while let Some(msg) = self.unstage_msg() {
            if msg.id != STREAM_DROP_TEST_MSG_ID {
                retained.push_back(msg);
            }
        }
        for msg in retained {
            self.stage_msg(msg).unwrap();
        }
        STREAM_DROP_TEST_STATE.store(STREAM_DROP_TEST_DONE, Ordering::Release);
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
    fn tx_send_batch(
        &self,
        carry: &mut VecDeque<io_channel::Msg>,
        driver_record: &mut Option<DriverRecord>,
    ) -> TxBatch {
        let mut sent_messages = 0;
        while let Some(msg) = carry
            .pop_front()
            // Driver work outranks the staging work queued after it, so a
            // reservation-pinning record cannot starve under sustained send
            // load; work staged before it still goes first (see
            // DriverRecord::staged_fence). This may put a close ahead of an
            // already-queued, subsequently-cancelled RPC for the same handle.
            // sys-io allocates handles monotonically and does not reuse them;
            // its option handlers return NotFound after close, and the
            // resulting response safely completes the cancelled RPC.
            .or_else(|| self.next_driver_msg(driver_record))
            .or_else(|| self.unstage_msg())
        {
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

    fn next_driver_msg(&self, driver_record: &mut Option<DriverRecord>) -> Option<io_channel::Msg> {
        loop {
            if let Some(record) = driver_record.as_mut()
                && !record.messages.is_empty()
            {
                if self.staged_popped.load(Ordering::Relaxed) < record.staged_fence {
                    // The staging queue still holds work queued before this
                    // record; the caller sends that instead and asks again.
                    return None;
                }
                return record.messages.pop_front();
            }

            // Replacing an exhausted teardown record drops its reservation
            // only after its final message was accepted by the sys-io ring.
            *driver_record = self.driver_queue.pop();
            driver_record.as_ref()?;
        }
    }

    /// Add one message to the staging queue, counting it. The count is what
    /// a driver record is ordered against, so it must cover every push.
    fn stage_msg(&self, msg: io_channel::Msg) -> Result<(), io_channel::Msg> {
        self.send_queue.push(msg)?;
        self.staged_pushed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Take one message from the staging queue, counting it. Only the tx
    /// task and the netdev drop hooks consume the queue; both come here, so
    /// the two counts stay balanced.
    fn unstage_msg(&self) -> Option<io_channel::Msg> {
        let msg = self.send_queue.pop()?;
        self.staged_popped.fetch_add(1, Ordering::Relaxed);
        Some(msg)
    }

    /// Claim stream `handle`'s pending TX pages in response to a marker.
    /// None if the stream is gone (its drop flushed the pages) or the
    /// pending queue is empty.
    fn claim_tcp_tx(&self, handle: u64) -> Option<io_channel::Msg> {
        let stream = self.tcp_streams.lock().get(&handle)?.upgrade()?;
        stream.claim_pending_tx()
    }

    fn progress_udp_tx(&self) {
        // Upgrade under the map lock, but invoke socket code after releasing it.
        // Live entries are bounded by the channel's subchannel count.
        let sockets: Vec<Arc<UdpSocket>> = self
            .udp_sockets
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for socket in sockets {
            socket.on_channel_tx_progress();
        }
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
        self.progress_udp_tx();
    }

    /// One PDIAG watchdog pass: log streams matching a lost-readiness-edge
    /// signature (see `StreamDiag`), plus channel gauges when any do.
    fn diag_tick(&self, prev: &mut BTreeMap<u64, DiagSample>, now: Instant) {
        let streams: Vec<Arc<TcpStream>> = self
            .tcp_streams
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();

        let mut next = BTreeMap::new();
        let mut stalled = false;
        for stream in streams {
            let handle = stream.handle();
            let diag = stream.diag();
            let cur = DiagSample {
                rx_bytes: diag.rx_bytes.load(Ordering::Relaxed),
                readable_raised: diag.readable_raised.load(Ordering::Relaxed),
                had_rx_queued: stream.has_rx_bytes(),
            };
            if let Some(old) = prev.get(&handle) {
                // RX bytes queued across the whole tick with no reader
                // progress and no READABLE edge: a lost edge, or a reader
                // that stopped reading -- the listener state logged
                // alongside discriminates.
                if old.had_rx_queued
                    && cur.had_rx_queued
                    && cur.rx_bytes == old.rx_bytes
                    && cur.readable_raised == old.readable_raised
                {
                    stream.log_diag("RXSTALL", now);
                    stalled = true;
                }
                // A writer saw WouldBlock, no WRITABLE edge answered it for
                // a full tick, yet buffer space exists now.
                let not_ready_ts = diag.last_tx_not_ready_ts.load(Ordering::Relaxed);
                if not_ready_ts != 0
                    && diag.last_writable_ts.load(Ordering::Relaxed) < not_ready_ts
                    && now.duration_since(Instant::from_u64(not_ready_ts)) >= DIAG_TICK
                    && stream.have_write_buffer_space()
                {
                    stream.log_diag("TXSTALL", now);
                    stalled = true;
                }
            }
            next.insert(handle, cur);
        }
        *prev = next;

        if stalled {
            moto_log!(
                "PDIAG chan txw={} wrw={} sqf={} rpc={}",
                self.tx_waiters.len(),
                self.write_waiters.lock().len(),
                self.send_queue.is_full() as u8,
                self.rpc_map.lock().len(),
            );
        }
    }

    #[cfg(feature = "netdev")]
    pub(super) fn wake_waiters_for_test(&self) {
        self.wake_waiters();
    }

    #[cfg(feature = "netdev")]
    pub(super) fn udp_socket_count_for_test(&self) -> usize {
        self.udp_sockets.lock().len()
    }

    /// Wake parked write futures, removing registrations before invoking
    /// arbitrary waker code.
    pub(super) fn wake_tx_wakers(&self) {
        self.tx_waiters.wake_all();
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
                    log::info!(
                        "NET: {} TCP Listeners; {} TCP sockets; {} UDP sockets.",
                        NUM_TCP_LISTENERS.load(Ordering::Relaxed),
                        NUM_TCP_STREAMS.load(Ordering::Relaxed),
                        NUM_UDP_SOCKETS.load(Ordering::Relaxed)
                    );
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
    /// of the channel runtime. Drains the send and driver queues; on ring-full
    /// awaits the connection handle (sys-io signals as it consumes); at batch
    /// boundaries yields to the rx task; when drained, parks until a caller
    /// queues work (see `park_until_send_work`).
    async fn tx_task(&self) {
        // Messages already popped from `send_queue` but not yet sent (a
        // full-ring leftover or a coalescing run terminator); older than
        // anything in `send_queue`, so always sent first.
        let mut carry: VecDeque<io_channel::Msg> = VecDeque::new();
        let mut driver_record = None;

        loop {
            let batch = self.tx_send_batch(&mut carry, &mut driver_record);

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
                        // Teardown (design 5.5): all work is delivered once
                        // the send queue, carry, and driver records are
                        // drained. Records are checked explicitly rather than
                        // inferred from the batch: one can be held back by its
                        // staging fence.
                        if carry.is_empty()
                            && self.send_queue.is_empty()
                            && self.driver_queue.is_empty()
                            && driver_record
                                .as_ref()
                                .is_none_or(|record| record.messages.is_empty())
                        {
                            return;
                        }
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

    /// Park the tx task until a caller queues send work. Publishes the
    /// task's waker in `tx_task_waker`, then re-checks for work: a push that
    /// raced the publish
    /// either lands before the check or wakes the published waker.
    ///
    fn park_until_send_work(&self) -> impl Future<Output = ()> + '_ {
        core::future::poll_fn(move |cx| {
            *self.tx_task_waker.lock() = Some(cx.waker().clone());
            // Teardown wakes this waker after setting `exiting`; return so the
            // tx loop re-checks its exit condition instead of re-parking.
            if !self.send_queue.is_empty()
                || !self.driver_queue.is_empty()
                || self.exiting.load(Ordering::Acquire)
            {
                return Poll::Ready(());
            }
            Poll::Pending
        })
    }

    pub fn add_write_waiter(&self, stream: &TcpStream) {
        self.write_waiters.lock().push_back(stream.weak());
    }

    /// Register an async sender's waker for the next channel pass. The caller
    /// must re-check its condition after registering (the pass that made room
    /// may already have drained the list).
    pub(super) fn add_tx_waker(&self, id: &mut Option<WaiterId>, waker: &core::task::Waker) {
        self.tx_waiters.register(id, waker);
    }

    pub(super) fn remove_tx_waker(&self, id: &mut Option<WaiterId>) {
        self.tx_waiters.unregister(id);
    }

    #[cfg(feature = "netdev")]
    pub(super) fn tx_waiter_count(&self) -> usize {
        self.tx_waiters.len()
    }

    #[cfg(feature = "netdev")]
    pub(super) fn rpc_waiter_count(&self) -> usize {
        self.rpc_map.lock().len()
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

    /// Reserve one host-side slot (see `client_state`). The count and the
    /// closed bit travel in one CAS, so a reserve and the closing release
    /// serialize: whichever lands first decides whether the channel stays
    /// open with the new reservation or refuses it.
    fn client_try_reserve(self: &Arc<Self>) -> Result<Reservation, ReserveError> {
        let mut state = self.client_state.load(Ordering::Acquire);
        loop {
            if state & CLIENT_CLOSED != 0 {
                return Err(ReserveError::ShuttingDown);
            }
            if state & CLIENT_COUNT_MASK >= IO_SUBCHANNELS as u32 {
                return Err(ReserveError::AtCapacity);
            }
            match self.client_state.compare_exchange_weak(
                state,
                (state + 1) | CLIENT_EVER,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Reservation(ChannelReservation {
                        channel: self.clone(),
                        subchannel_idx: None,
                    }));
                }
                Err(current) => state = current,
            }
        }
    }

    /// Release one host-side slot. The final decrement sets `CLIENT_CLOSED`
    /// in the same CAS (`CLIENT_EVER` is necessarily set here), then begins
    /// driver teardown -- the design section 4 one-to-zero transition.
    fn client_release_reservation(&self) {
        let mut state = self.client_state.load(Ordering::Acquire);
        let prev = loop {
            let count = state & CLIENT_COUNT_MASK;
            debug_assert!(count > 0, "released a reservation the channel did not have");
            let next = state - 1;
            let next = if count == 1 {
                next | CLIENT_CLOSED
            } else {
                next
            };
            match self.client_state.compare_exchange_weak(
                state,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(prev) => break prev,
                Err(current) => state = current,
            }
        };
        if prev & CLIENT_COUNT_MASK == 1 {
            self.begin_exit();
        }
    }

    /// Begin channel teardown (design 5.5): mark `exiting` then wake both
    /// tasks so they observe it. Called under NET.lock() when the last
    /// reservation is released, or lock-free by
    /// [`NetClient::request_shutdown`] (a host-owned channel is not in the
    /// pool). The Release store pairs with the tasks' Acquire loads; the
    /// wakes must follow it so a task that re-checks after waking always
    /// sees `exiting`.
    fn begin_exit(&self) {
        self.exiting.store(true, Ordering::Release);
        if let Some(waker) = &*self.tx_task_waker.lock() {
            waker.wake_by_ref();
        }
        if let Some(waker) = &*self.rx_task_waker.lock() {
            waker.wake_by_ref();
        }
    }

    /// Build a channel over an established sys-io connection. No thread is
    /// spawned and no global state is touched: the caller decides who hosts
    /// the channel's [`NetDriver`].
    fn with_conn(conn: io_channel::ClientConnection) -> Arc<Self> {
        let mut subchannels_in_use = Vec::with_capacity(IO_SUBCHANNELS as usize);
        for _ in 0..IO_SUBCHANNELS {
            subchannels_in_use.push(AtomicBool::new(false));
        }

        Arc::new(NetChannel {
            conn,
            client_state: AtomicU32::new(0),
            subchannels_in_use,
            tcp_streams: Mutex::new(BTreeMap::new()),
            tcp_listeners: Mutex::new(BTreeMap::new()),
            udp_sockets: Mutex::new(BTreeMap::new()),
            reservations: AtomicU8::new(0),
            next_msg_id: CachePadded::new(AtomicU64::new(1)),
            send_queue: crossbeam_queue::ArrayQueue::new(io_channel::CHANNEL_PAGE_COUNT),
            staged_pushed: AtomicU64::new(0),
            staged_popped: AtomicU64::new(0),
            driver_queue: crossbeam_queue::SegQueue::new(),
            write_waiters: Mutex::new(VecDeque::new()),
            tx_waiters: WaitSet::new(),
            rpc_map: Mutex::new(BTreeMap::new()),
            tx_task_waker: Mutex::new(None),
            rx_task_waker: Mutex::new(None),
            exiting: CachePadded::new(AtomicBool::new(false)),
        })
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

    /// Stop routing for a socket. Called from `UdpSocket::close`, which runs
    /// while the caller still holds a reference, so unlike the TCP entries
    /// below this one cannot assert that the socket is already gone.
    pub fn udp_socket_dropped(&self, handle: u64) {
        assert!(self.udp_sockets.lock().remove(&handle).is_some());
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

    /// Enqueue one message without parking the polling thread.
    pub(super) fn send(&self, msg: io_channel::Msg) -> SendFuture<'_> {
        SendFuture {
            channel: self,
            msg: Some(msg),
            waiter_id: None,
        }
    }

    /// Send an ordinary request and await its response without blocking.
    ///
    /// Cancellation before queueing removes the RPC-map entry. Once queued,
    /// response dispatch owns completion and tolerates a dropped receiver.
    pub(super) async fn rpc(&self, req: io_channel::Msg) -> io_channel::Msg {
        self.rpc_after_send(req, || {}).await
    }

    /// Send an ordinary request, run `after_send` once the staging queue owns
    /// it, then await its response.
    ///
    /// There is no suspension point between the successful queue insertion
    /// and `after_send`, so cancellation either leaves both untouched or
    /// leaves the queued request and its local commit in place.
    pub(super) async fn rpc_after_send(
        &self,
        mut req: io_channel::Msg,
        after_send: impl FnOnce(),
    ) -> io_channel::Msg {
        let (tx, rx) = moto_async::oneshot();
        req.id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);
        assert!(
            self.rpc_map
                .lock()
                .insert(req.id, RpcWaiter::Response(tx))
                .is_none()
        );

        let mut registration = RpcRegistration {
            channel: self,
            id: req.id,
            sent: false,
        };
        self.send(req).await;
        registration.sent = true;
        after_send();

        rx.await.expect("RPC sender dropped")
    }

    /// Create a listener/socket handle without blocking the polling thread.
    ///
    /// `reservation` moves into the RPC map, so cancellation before the send
    /// releases it with nothing created, and cancellation after the send still
    /// leaves the response dispatch a channel slot to close the new handle on.
    pub(super) async fn rpc_bind(
        &self,
        mut req: io_channel::Msg,
        reservation: ChannelReservation,
        drop_command: u16,
    ) -> PendingBind {
        debug_assert!(core::ptr::eq(self, reservation.channel().as_ref()));
        let (tx, rx) = moto_async::oneshot();
        req.id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);
        assert!(
            self.rpc_map
                .lock()
                .insert(
                    req.id,
                    RpcWaiter::Bind {
                        reservation,
                        drop_command,
                        tx,
                    },
                )
                .is_none()
        );

        let mut registration = RpcRegistration {
            channel: self,
            id: req.id,
            sent: false,
        };
        self.send(req).await;
        registration.sent = true;

        rx.await.expect("bind RPC sender dropped")
    }

    /// Send a connect request without blocking the polling thread.
    ///
    /// A cancelled caller releases its reservation, while the weak RPC waiter
    /// remains to close a successful late response if the channel has other
    /// users. If it does not, sys-io reclaims the request on disconnect.
    pub(super) async fn rpc_connect(
        &self,
        mut req: io_channel::Msg,
        stream: Weak<TcpStream>,
    ) -> io_channel::Msg {
        let (tx, rx) = moto_async::oneshot();
        req.id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);
        assert!(
            self.rpc_map
                .lock()
                .insert(
                    req.id,
                    RpcWaiter::Connect {
                        stream,
                        tx: Some(tx),
                    },
                )
                .is_none()
        );

        let mut registration = RpcRegistration {
            channel: self,
            id: req.id,
            sent: false,
        };
        self.send(req).await;
        registration.sent = true;

        rx.await.expect("connect RPC sender dropped")
    }

    /// Queue an RPC from inline driver dispatch. The waiter is installed
    /// first, then the request moves to the driver's guaranteed FIFO.
    pub(super) fn enqueue_rpc(&self, req: io_channel::Msg, waiter: RpcWaiter) {
        assert_ne!(0, req.id);
        assert!(self.rpc_map.lock().insert(req.id, waiter).is_none());
        self.enqueue_driver_messages(VecDeque::from([req]), None);
    }

    /// Queue an RPC only if staging has immediate room. On backpressure the
    /// waiter is removed again and the caller gets `E_NOT_READY`.
    pub(super) fn post_rpc(
        &self,
        req: io_channel::Msg,
        waiter: RpcWaiter,
    ) -> Result<(), ErrorCode> {
        assert_ne!(0, req.id);
        assert!(self.rpc_map.lock().insert(req.id, waiter).is_none());
        if self.post_msg(req).is_ok() {
            Ok(())
        } else {
            self.rpc_map.lock().remove(&req.id);
            Err(moto_rt::E_NOT_READY)
        }
    }

    pub fn new_req_id(&self) -> u64 {
        self.next_msg_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn post_msg(&self, req: io_channel::Msg) -> Result<(), io_channel::Msg> {
        if self.stage_msg(req).is_ok() {
            self.maybe_wake_io_thread();
            Ok(())
        } else {
            Err(req)
        }
    }

    pub(super) fn enqueue_teardown(&self, reservation: ChannelReservation, msg: io_channel::Msg) {
        self.enqueue_teardown_messages(reservation, VecDeque::from([msg]));
    }

    pub(super) fn enqueue_teardown_messages(
        &self,
        reservation: ChannelReservation,
        messages: VecDeque<io_channel::Msg>,
    ) {
        debug_assert!(core::ptr::eq(self, reservation.channel().as_ref()));
        debug_assert!(!messages.is_empty());
        self.enqueue_driver_messages(messages, Some(reservation));
    }

    /// Queue infallible driver-owned control work. The runtime thread drains
    /// this queue before exit even if the caller releases the last reservation.
    pub(super) fn enqueue_control(&self, msg: io_channel::Msg) {
        self.enqueue_driver_messages(VecDeque::from([msg]), None);
    }

    fn enqueue_driver_messages(
        &self,
        messages: VecDeque<io_channel::Msg>,
        reservation: Option<ChannelReservation>,
    ) {
        self.driver_queue.push(DriverRecord {
            messages,
            staged_fence: self.staged_pushed.load(Ordering::Relaxed),
            _reservation: reservation,
        });
        self.maybe_wake_io_thread();
    }

    #[cfg(feature = "netdev")]
    pub(super) fn fill_stream_drop_send_queue_for_test(&self) {
        let mut placeholder = io_channel::Msg::new();
        placeholder.id = STREAM_DROP_TEST_MSG_ID;
        placeholder.command = u16::MAX;
        placeholder.handle = u64::MAX;
        while self.stage_msg(placeholder).is_ok() {}
        assert!(self.send_queue.is_full());
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

        self.channel.client_release_reservation();
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
