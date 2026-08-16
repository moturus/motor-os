use std::collections::VecDeque;
/*
  RFC 793: https://datatracker.ietf.org/doc/html/rfc793

  TCP states:

    LISTEN - represents waiting for a connection request from any remote
    TCP and port.

    SYN-SENT - represents waiting for a matching connection request
    after having sent a connection request.

    SYN-RECEIVED - represents waiting for a confirming connection
    request acknowledgment after having both received and sent a
    connection request.

    ESTABLISHED - represents an open connection, data received can be
    delivered to the user.  The normal state for the data transfer phase
    of the connection.

    FIN-WAIT-1 - represents waiting for a connection termination request
    from the remote TCP, or an acknowledgment of the connection
    termination request previously sent.

    FIN-WAIT-2 - represents waiting for a connection termination request
    from the remote TCP.

    CLOSE-WAIT - represents waiting for a connection termination request
    from the local user.

    CLOSING - represents waiting for a connection termination request
    acknowledgment from the remote TCP.

    LAST-ACK - represents waiting for an acknowledgment of the
    connection termination request previously sent to the remote TCP
    (which includes an acknowledgment of its connection termination
    request).


                             +---------+ ---------\      active OPEN
                             |  CLOSED |            \    -----------
                             +---------+<---------\   \   create TCB
                               |     ^              \   \  snd SYN
                  passive OPEN |     |   CLOSE        \   \
                  ------------ |     | ----------       \   \
                   create TCB  |     | delete TCB         \   \
                               V     |                      \   \
                             +---------+            CLOSE    |    \
                             |  LISTEN |          ---------- |     |
                             +---------+          delete TCB |     |
                  rcv SYN      |     |     SEND              |     |
                 -----------   |     |    -------            |     V
+---------+      snd SYN,ACK  /       \   snd SYN          +---------+
|         |<-----------------           ------------------>|         |
|   SYN   |                    rcv SYN                     |   SYN   |
|   RCVD  |<-----------------------------------------------|   SENT  |
|         |                    snd ACK                     |         |
|         |------------------           -------------------|         |
+---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
  |           --------------   |     |   -----------
  |                  x         |     |     snd ACK
  |                            V     V
  |  CLOSE                   +---------+
  | -------                  |  ESTAB  |
  | snd FIN                  +---------+
  |                   CLOSE    |     |    rcv FIN
  V                  -------   |     |    -------
+---------+          snd FIN  /       \   snd ACK          +---------+
|  FIN    |<-----------------           ------------------>|  CLOSE  |
| WAIT-1  |------------------                              |   WAIT  |
+---------+          rcv FIN  \                            +---------+
  | rcv ACK of FIN   -------   |                            CLOSE  |
  | --------------   snd ACK   |                           ------- |
  V        x                   V                           snd FIN V
+---------+                  +---------+                   +---------+
|FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
+---------+                  +---------+                   +---------+
  |                rcv ACK of FIN |                 rcv ACK of FIN |
  |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
  |  -------              x       V    ------------        x       V
   \ snd ACK                 +---------+delete TCB         +---------+
    ------------------------>|TIME WAIT|------------------>| CLOSED  |
                             +---------+                   +---------+
*/
use std::io::ErrorKind;
use std::rc::Weak;
use std::{cell::RefCell, net::SocketAddr, rc::Rc, task::Poll};

use moto_netstack::socket::tcp::CongestionControl;
use moto_netstack::socket::tcp::State as NetstackTcpState;
use moto_sys::SysHandle;
use moto_sys_io::api_net;
use moto_sys_io::stats::TcpProtocolState;

use crate::runtime::net::tcp_listener::TcpListener;

use super::super::EphemeralTcpPort;
use super::super::NetRuntime;
use super::MotoSocket;
use super::SocketBase;
use super::SocketState;

/// For how long sockets linger upon close.
const DEFAULT_LINGER_SECS: u32 = 60;

/// Per-direction TCP buffer sizes a socket is configured for, decoded from
/// the connect/bind request's spare payload bytes and clamped to sys-io's
/// floor and cap (requests outside the range clamp, POSIX-style; no error).
#[derive(Clone, Copy, Debug)]
pub(in crate::runtime::net) struct TcpBufferSizes {
    pub rx: usize,
    pub tx: usize,
}

impl TcpBufferSizes {
    /// 128 KiB buffers: the receive buffer caps the advertised TCP window
    /// and the send buffer caps unacked bytes in flight; 32 KiB sat exactly
    /// at the measured 321 MiB/s * ~100 us BDP. Raising the default further
    /// is a decision gate in docs/plans/networking-remaining-steps.md.
    const DEFAULT: usize = 128 * 1024;
    /// Below 16 KiB the TSO/page interplay wastes more than it saves. Also
    /// the ring a lazily-built backlog socket starts with, and therefore the
    /// window a cookie SYN|ACK advertises.
    pub(in crate::runtime::net) const FLOOR: usize = 16 * 1024;
    /// 8 MiB per direction is WAN-relevant (~670 Mbit/s at 100 ms) and
    /// bounds the per-socket worst case (affirmed in design review).
    const CAP: usize = 8 * 1024 * 1024;

    pub(in crate::runtime::net) fn from_payload(payload: &moto_ipc::io_channel::Payload) -> Self {
        let size = |pos: usize| match api_net::tcp_buf_size_from_code(payload.args_8()[pos]) {
            None => Self::DEFAULT,
            Some(bytes) => (bytes as usize).clamp(Self::FLOOR, Self::CAP),
        };
        Self {
            rx: size(api_net::TCP_BUF_SIZE_POS_RX),
            tx: size(api_net::TCP_BUF_SIZE_POS_TX),
        }
    }

    /// Normalize a setsockopt byte count: 0 asks for the default, anything
    /// else clamps to the floor and cap.
    pub(in crate::runtime::net) fn normalize(bytes: u64) -> usize {
        if bytes == 0 {
            Self::DEFAULT
        } else {
            (bytes as usize).clamp(Self::FLOOR, Self::CAP)
        }
    }
}

/// How a new socket's rings relate to its configured sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RingBuild {
    /// Rings allocated at the configured sizes.
    Configured,
    /// Floor-size rings announcing the configured window scale; the caller
    /// latches growth to the configured sizes after listen().
    LazyFloor,
}

/// What a close does with the connection under it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloseAction {
    /// Reset: RST out, socket gone, no waiting.
    Abort,
    /// The FIN is queued; wait for the connection to finish closing.
    Finish,
    /// The TX task still holds client writes. It sends the FIN once they are
    /// in the send buffer, and signals `TcpState::lingerer` when it is done.
    DrainThenFinish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectAction {
    Pending,
    Connected,
    Failed,
}

const fn connect_action(state: NetstackTcpState) -> ConnectAction {
    match state {
        // A bare SYN during an active open is RFC 9293 simultaneous open.
        NetstackTcpState::SynSent | NetstackTcpState::SynReceived => ConnectAction::Pending,
        // CLOSE-WAIT means the handshake completed before the peer's FIN.
        NetstackTcpState::Established | NetstackTcpState::CloseWait => ConnectAction::Connected,
        NetstackTcpState::Closed
        | NetstackTcpState::Listen
        | NetstackTcpState::FinWait1
        | NetstackTcpState::FinWait2
        | NetstackTcpState::Closing
        | NetstackTcpState::LastAck
        | NetstackTcpState::TimeWait => ConnectAction::Failed,
    }
}

const fn verify_connect_state_actions() {
    use ConnectAction::{Connected, Failed, Pending};
    use NetstackTcpState::*;

    assert!(matches!(connect_action(Closed), Failed));
    assert!(matches!(connect_action(Listen), Failed));
    assert!(matches!(connect_action(SynSent), Pending));
    assert!(matches!(connect_action(SynReceived), Pending));
    assert!(matches!(connect_action(Established), Connected));
    assert!(matches!(connect_action(FinWait1), Failed));
    assert!(matches!(connect_action(FinWait2), Failed));
    assert!(matches!(connect_action(CloseWait), Connected));
    assert!(matches!(connect_action(Closing), Failed));
    assert!(matches!(connect_action(LastAck), Failed));
    assert!(matches!(connect_action(TimeWait), Failed));
}

const _: () = verify_connect_state_actions();

/// Counts a listening socket while it waits for a peer to finish the handshake
/// that peer started. Such a socket holds its full 128 KiB receive and transmit
/// rings, so the count is the memory an unanswered SYN commands; only the
/// 15-second listening-socket timeout bounds how long that lasts. A guard,
/// rather than a pair of updates, because every exit from the wait must
/// decrement -- including the socket disappearing under the task.
struct HalfOpenGuard {
    stats: Rc<super::super::stats::NetStats>,
    budget: Rc<super::super::HalfOpenBudget>,
    listener_id: u64,
}

impl HalfOpenGuard {
    /// Count the socket as half-open, both for the gauge and against the cap.
    ///
    /// The returned flag is whether the listening pool may be refilled now;
    /// `false` means the caller must park its replenishment with
    /// [`super::super::half_open::HalfOpenBudget::defer`], which this guard
    /// resumes when it drops.
    fn admit(
        stats: Rc<super::super::stats::NetStats>,
        budget: Rc<super::super::HalfOpenBudget>,
        listener_id: u64,
    ) -> (Self, bool) {
        stats.tcp_half_open.set(stats.tcp_half_open.get() + 1);
        stats
            .tcp_half_open_total
            .set(stats.tcp_half_open_total.get() + 1);

        let may_replenish = budget.admit(listener_id);
        (
            Self {
                stats,
                budget,
                listener_id,
            },
            may_replenish,
        )
    }
}

impl Drop for HalfOpenGuard {
    fn drop(&mut self) {
        self.stats
            .tcp_half_open
            .set(self.stats.tcp_half_open.get() - 1);

        // The slot this socket held is what a deferred replenishment was
        // waiting for. `release` hands it back rather than sending it itself,
        // so nothing inside the budget is borrowed while a task is woken.
        if let Some(connected_tx) = self.budget.release(self.listener_id) {
            let _ = connected_tx.send(());
        }
    }
}

pub struct TcpState {
    ephemeral_port: Option<Rc<EphemeralTcpPort>>,
    subchannel_mask: u64,
    tcp_listener: Option<Weak<RefCell<TcpListener>>>,
    connect_req: Option<moto_ipc::io_channel::Msg>,

    remote_addr: Option<SocketAddr>,

    tx_queue: VecDeque<TcpTxBuf>,
    tx_queue_notify: Rc<moto_async::LocalNotify>,

    stat_tx_bytes: u64,
    stat_rx_bytes: u64,

    // The client has closed its RX (in posix sense).
    // The underlying moto-netstack socket can't have its RX closed.
    rx_closed: bool,

    // We cannot send RX bytes/messages to clients until
    // they are ready to process; otherwise if we start sending
    // RX bytes immediately after a listening socket accepted
    // a remote connection, and the client delays processing
    // the accept, the client won't know which connection the
    // incoming RX bytes should be routed to...
    rx_ready: Rc<moto_async::LocalNotify>,

    // The client has closed its TX (in posix sense).
    // The TX queue above may still have bytes to send.
    // The underlying moto-netstack socket may still have bytes to send.
    tx_closed: bool,

    // See SO_LINGER in Linux and TcpStream::set_linger() in Rust.
    linger_secs: Option<u32>,
    lingerer: Option<moto_async::oneshot::Sender<()>>,
}

impl TcpState {
    pub fn remote_addr(&self) -> &Option<SocketAddr> {
        &self.remote_addr
    }

    pub fn set_subchannel_mask(&mut self, subchannel_mask: u64) {
        self.subchannel_mask = subchannel_mask;
    }
}

impl MotoSocket {
    pub fn set_ttl(moto_socket: &Rc<RefCell<Self>>, ttl: u8) {
        Self::with_tcp_netstack_socket(moto_socket, |_socket_id, netstack_socket, _state| {
            netstack_socket.set_hop_limit(Some(ttl));
        });
    }

    /// Take a socket of `addr`'s listening pool out of `Listen`, as a sweep
    /// returning unused growth does, and say whether it was one.
    ///
    /// The state change wakes the listen task below, which runs the same
    /// teardown as for a socket that took a SYN and lost it. A socket in
    /// SYN-RECEIVED is a handshake, not pool slack, so it is left alone; a
    /// `Listen` socket has no remote endpoint, so nothing is sent.
    pub fn abort_if_listening(moto_socket: &Rc<RefCell<Self>>, addr: SocketAddr) -> bool {
        {
            let socket_ref = moto_socket.borrow();
            if !socket_ref.is_tcp() || socket_ref.base.local_addr != addr {
                return false;
            }
        }

        Self::with_tcp_socket_set(moto_socket, |socket_id, sockets, handle, _state| {
            let netstack_socket = sockets.get::<moto_netstack::socket::tcp::Socket>(handle);
            if netstack_socket.state() != moto_netstack::socket::tcp::State::Listen {
                return false;
            }
            log::debug!("tcp: listen: dropping unused listening socket 0x{socket_id:x}");
            sockets.tcp_abort(handle);
            true
        })
    }

    #[inline]
    pub(super) fn with_tcp_netstack_socket<F, T>(socket: &Rc<RefCell<Self>>, f: F) -> T
    where
        F: FnOnce(u64, &mut moto_netstack::socket::tcp::Socket<'static>, &mut TcpState) -> T,
    {
        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, state } = socket_mut;

        let tcp_state = state.unwrap_tcp_mut();

        let mut inner = base.runtime.inner.borrow_mut();
        let device = &mut inner.devices[base.device_idx];
        let netstack_socket = device
            .sockets
            .get_mut::<moto_netstack::socket::tcp::Socket<'static>>(base.handle());
        f(base.socket_id, netstack_socket, tcp_state)
    }

    /// Like [`Self::with_tcp_netstack_socket`], but hands the closure the
    /// device's socket set and this socket's handle instead of the bare
    /// socket: the identity-changing operations (listen/connect/close/abort/
    /// cookie restore) exist only on the set, so any path that may use one
    /// goes through here.
    #[inline]
    pub(super) fn with_tcp_socket_set<F, T>(socket: &Rc<RefCell<Self>>, f: F) -> T
    where
        F: FnOnce(
            u64,
            &mut moto_netstack::iface::SocketSet<'static>,
            moto_netstack::iface::SocketHandle,
            &mut TcpState,
        ) -> T,
    {
        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, state } = socket_mut;

        let tcp_state = state.unwrap_tcp_mut();

        let mut inner = base.runtime.inner.borrow_mut();
        let device = &mut inner.devices[base.device_idx];
        f(
            base.socket_id,
            &mut device.sockets,
            base.handle(),
            tcp_state,
        )
    }

    /// Build a best-effort stats snapshot for this TCP socket, used by the
    /// `sys-io-stats-service` socket listing (see [`crate::runtime::net::stats`]).
    pub(crate) fn collect_tcp_stats(
        moto_socket: &Rc<RefCell<Self>>,
    ) -> moto_sys_io::stats::TcpSocketStatsV1 {
        use moto_sys_io::stats::TcpSocketStatsV1;

        // Read the netstack state first: with_tcp_netstack_socket() borrows both the
        // socket and the runtime inner, so we must not hold a borrow across it.
        let netstack_state =
            Self::with_tcp_netstack_socket(moto_socket, |_socket_id, netstack_socket, _state| {
                netstack_socket.state()
            });

        let socket_ref = moto_socket.borrow();
        let Self { base, state } = &*socket_ref;
        let tcp_state = state.unwrap_tcp();

        let pid = base
            .runtime
            .connection_pid(base.client_sender.remote_handle());

        let (local_addr, local_port) = addr_to_octets(&base.local_addr);
        let (remote_addr, remote_port) = match tcp_state.remote_addr {
            Some(addr) => addr_to_octets(&addr),
            None => ([0u8; 16], 0),
        };

        TcpSocketStatsV1 {
            id: base.socket_id(),
            device_id: base.device_idx as u64,
            pid,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            tcp_state: api_tcp_state(
                netstack_state,
                tcp_state.rx_closed,
                tcp_state.tx_closed,
                tcp_state.tcp_listener.is_some(),
            ),
            protocol_state: tcp_protocol_state(netstack_state),
        }
    }

    fn create_tcp_socket(
        runtime: &NetRuntime,
        device_idx: usize,
        local_addr: SocketAddr,
        client_sender: moto_ipc::io_channel::Sender,
        subchannel_mask: u64,
        sizes: TcpBufferSizes,
        rings: RingBuild,
    ) -> std::io::Result<Rc<RefCell<MotoSocket>>> {
        // The out-of-order capacity this socket is built with, asserted here
        // because the netstack's own tests cannot see it: `lib.rs` compiles
        // `cfg(test)` against a hardcoded config, so the feature in Cargo.toml
        // reaches the deployed build and the test suite reaches a constant that
        // has to be edited to match. This is the half that fails loudly.
        const _: () = assert!(
            moto_netstack::config::ASSEMBLER_MAX_SEGMENT_COUNT == 32,
            "sys-io deploys assembler-max-segment-count-32; if that Cargo \
             feature changes, change the cfg(test) config in the netstack's \
             lib.rs to match, or its tests will cover a capacity nothing runs"
        );
        const _: () = assert!(
            moto_netstack::config::IFACE_NEIGHBOR_CACHE_COUNT == 64,
            "sys-io deploys iface-neighbor-cache-count-64. Unlike the two above, \
             the netstack's cfg(test) value is deliberately far smaller: its \
             eviction tests have to be able to fill the cache, so they cover the \
             policy and this assertion is the only check on the number"
        );
        let buffer = |bytes: usize| moto_netstack::socket::tcp::SocketBuffer::new(vec![0; bytes]);
        let mut netstack_socket = match rings {
            // The configured sizes are real from the first byte: the caller
            // committed to them (a connect request is on its way out).
            RingBuild::Configured => {
                moto_netstack::socket::tcp::Socket::new(buffer(sizes.rx), buffer(sizes.tx))
            }
            // Floor rings under the configured window scale: a listener-pool
            // socket costs its configured sizes only once a connection is
            // real. The caller latches the growth after listen().
            RingBuild::LazyFloor => moto_netstack::socket::tcp::Socket::new_with_win_shift(
                buffer(TcpBufferSizes::FLOOR),
                buffer(TcpBufferSizes::FLOOR),
                moto_netstack::socket::tcp::win_shift_for_capacity(sizes.rx),
            ),
        };
        // Named rather than left to the feature-derived default, so that the
        // choice is visible here rather than implied by a Cargo feature, and so
        // that dropping the feature fails the build instead of quietly restoring
        // the uncontrolled `usize::MAX` window.
        netstack_socket.set_congestion_control(CongestionControl::Cubic);
        // RFC 7323 timestamps. Offering them is what turns them on at all --
        // the netstack drops its own generator when a peer's SYN comes back
        // without the option, so this decides only what we ask for. It costs 12
        // bytes on every segment and buys PAWS, which is the only defence
        // against a wrapped sequence number on a link fast enough to wrap one.
        //
        // It does *not* buy the RTT half of RFC 7323: nothing reads the peer's
        // `TSecr`, and on this path nothing should. The netstack times its own
        // sends off a microsecond `Instant`, while section 5.4 bounds a
        // timestamp tick at a millisecond or coarser -- so sampling from the
        // option would be the truncation we just removed, reintroduced. What
        // the option would still add is a sample per ACK rather than one per
        // window, and one that survives a retransmission instead of being
        // discarded for Karn's ambiguity.
        netstack_socket.set_tsval_generator(Some(super::super::device::tsval::generator));
        // netstack_socket.bind(socket_addr).unwrap();

        let socket_id = {
            let mut inner = runtime.inner.borrow_mut();
            let socket_id = inner.next_socket_id();
            inner.devices[device_idx]
                .sockets
                .add(socket_id, netstack_socket);
            socket_id
        };

        let base = SocketBase::new(
            socket_id,
            runtime.clone(),
            device_idx,
            local_addr,
            client_sender,
        );

        let socket = MotoSocket::new(
            base,
            SocketState::Tcp(TcpState {
                ephemeral_port: None,
                subchannel_mask,
                tcp_listener: None,
                connect_req: None,
                remote_addr: None,
                tx_queue: VecDeque::new(),
                tx_queue_notify: Rc::new(moto_async::LocalNotify::new()),
                rx_ready: Rc::new(moto_async::LocalNotify::new()),
                stat_tx_bytes: 0,
                stat_rx_bytes: 0,
                rx_closed: false,
                tx_closed: false,
                linger_secs: None,
                lingerer: None,
            }),
        )?;

        runtime
            .stats
            .tcp_sockets
            .set(runtime.stats.tcp_sockets.get() + 1);
        runtime
            .stats
            .total_tcp_sockets
            .set(runtime.stats.total_tcp_sockets.get() + 1);

        Ok(socket)
    }

    pub async fn create_tcp_listening_socket(
        weak_listener: Weak<RefCell<TcpListener>>,
        device_idx: usize,
        socket_addr: SocketAddr,
    ) -> std::io::Result<()> {
        let Some(tcp_listener) = weak_listener.upgrade() else {
            return Err(ErrorKind::NotConnected.into());
        };

        // Create the socket.
        let (weak_socket, key, runtime) = {
            let mut tcp_listener_mut = tcp_listener.borrow_mut();

            // Read at construction time: a size configured on the listener
            // later applies to later backlog sockets, not this one.
            let sizes = tcp_listener_mut.buffer_sizes();
            let moto_socket = Self::create_tcp_socket(
                tcp_listener_mut.runtime(),
                device_idx,
                socket_addr,
                tcp_listener_mut.client_sender().clone(),
                0,
                sizes,
                RingBuild::LazyFloor,
            )?;

            tcp_listener_mut
                .runtime()
                .stats
                .tcp_listening_sockets
                .set(tcp_listener_mut.runtime().stats.tcp_listening_sockets.get() + 1);

            {
                let mut socket_ref = moto_socket.borrow_mut();
                let socket_mut = &mut *socket_ref;
                let Self { base, state } = socket_mut;
                let state = state.unwrap_tcp_mut();

                tcp_listener_mut.add_listening_socket(base.socket_id());
                state.ephemeral_port = tcp_listener_mut.ephemeral_port();
                state.tcp_listener = Some(weak_listener.clone());
            }

            Self::with_tcp_socket_set(&moto_socket, |socket_id, sockets, handle, _state| {
                // moto-netstack does not expire SynReceived sockets without a timeout.
                // Note: the numbers below are only for Listen/SynReceived sockets. They are
                // re-set to different numbers on established sockets.
                let netstack_socket = sockets.get_mut::<moto_netstack::socket::tcp::Socket>(handle);
                netstack_socket
                    .set_keep_alive(Some(moto_netstack::time::Duration::from_millis(5_000)));
                netstack_socket
                    .set_timeout(Some(moto_netstack::time::Duration::from_millis(15_000)));
                sockets.tcp_listen(handle, socket_addr).unwrap();
                // After listen(): its reset drops latches. The growth
                // applies inside the netstack at the ESTABLISHED edge.
                let netstack_socket = sockets.get_mut::<moto_netstack::socket::tcp::Socket>(handle);
                netstack_socket.grow_rx_capacity(sizes.rx);
                netstack_socket.grow_tx_capacity(sizes.tx);
                log::debug!(
                    "new TCP socket 0x{socket_id:x} listening on {socket_addr:?} for conn 0x{:x}",
                    tcp_listener_mut.client_sender().remote_handle().as_u64(),
                );
            });

            let key = (tcp_listener_mut.listener_id(), socket_addr);
            let runtime = tcp_listener_mut.runtime().clone();
            runtime.backlog.entered_listen(key);

            (Rc::downgrade(&moto_socket), key, runtime)
        };

        // A fresh listening socket resumes stateful admission for this
        // endpoint: minting stops, in-flight cookies keep verifying.
        runtime.inner.borrow_mut().devices[device_idx].disengage_syn_cookies(socket_addr);

        // Spawn the listening task.
        moto_async::LocalRuntime::spawn(async move {
            let (connected_tx, connected_rx) = moto_async::oneshot();

            // Replenish the listening pool as soon as this socket leaves the
            // Listen state -- or, at the half-open cap, as soon as a slot frees.
            moto_async::LocalRuntime::spawn(async move {
                let _ = connected_rx.await;
                spawn_pool_replenish(runtime, weak_listener, device_idx, socket_addr, key);
            });

            Self::tcp_listen_task(connected_tx, weak_socket, device_idx, key).await;
        });

        Ok(())
    }

    /// Build and enroll the connection a verified SYN-cookie ACK proved: the
    /// stateless replacement for the handshake a pool socket would have
    /// carried. The socket goes straight to ESTABLISHED and flows into the
    /// normal accept path. Any refusal here just drops the restoration --
    /// the peer's retransmission earns another verification.
    pub(in crate::runtime::net) async fn create_tcp_restored_socket(
        runtime: &NetRuntime,
        device_idx: usize,
        restore: moto_netstack::socket::tcp::TcpCookieRestore,
    ) {
        let drop_restore = |reason: &str| {
            log::debug!("tcp: cookie restore refused: {reason}");
            runtime
                .stats
                .tcp_cookie_restores_dropped
                .set(runtime.stats.tcp_cookie_restores_dropped.get() + 1);
        };
        if runtime.pressure.admit().is_err() {
            return drop_restore("memory pressure");
        }

        let local_addr = crate::runtime::net::config::socket_addr_from_endpoint(restore.local);
        let tcp_listener = {
            let inner = runtime.inner.borrow();
            inner
                .tcp_listeners
                .values()
                .find(|listener| listener.borrow().listens_on(local_addr, device_idx))
                .cloned()
        };
        let Some(tcp_listener) = tcp_listener else {
            // Torn down between the ACK and this drain.
            return drop_restore("listener gone");
        };

        // Mirrors create_tcp_listening_socket's construction, minus listening
        // accounting: this socket is never in Listen and never in a pool.
        let (moto_socket, sizes) = {
            let mut listener_mut = tcp_listener.borrow_mut();
            let sizes = listener_mut.buffer_sizes();
            let Ok(moto_socket) = Self::create_tcp_socket(
                listener_mut.runtime(),
                device_idx,
                local_addr,
                listener_mut.client_sender().clone(),
                0,
                sizes,
                RingBuild::LazyFloor,
            ) else {
                return drop_restore("socket creation failed");
            };

            let mut socket_ref = moto_socket.borrow_mut();
            let socket_mut = &mut *socket_ref;
            let Self { base, state } = socket_mut;
            let state = state.unwrap_tcp_mut();
            // On the listener's books before on_incoming_connection takes it
            // off them, exactly as a pool socket would be.
            listener_mut.add_listening_socket(base.socket_id());
            state.ephemeral_port = listener_mut.ephemeral_port();
            state.tcp_listener = Some(Rc::downgrade(&tcp_listener));
            drop(socket_ref);
            (moto_socket, sizes)
        };

        let handle = moto_socket.borrow().base.handle();
        let restored = runtime.inner.borrow_mut().devices[device_idx]
            .tcp_restore(handle, &restore, sizes)
            .is_ok();
        if !restored {
            drop_restore("netstack restore failed");
            Self::drop_tcp_socket(moto_socket).await;
            return;
        }

        runtime
            .stats
            .tcp_syn_cookies_accepted
            .set(runtime.stats.tcp_syn_cookies_accepted.get() + 1);
        log::debug!(
            "tcp: cookie handshake completed: {:?} => {local_addr:?}",
            restore.remote
        );
        Self::on_incoming_connection(Rc::downgrade(&moto_socket)).await;
    }

    async fn tcp_listen_task(
        connected_tx: moto_async::oneshot::Sender<()>,
        weak_socket: Weak<RefCell<Self>>, // Weak because called asynchronously.
        device_idx: usize,
        key: super::super::backlog::PoolKey,
    ) {
        let (listener_id, _) = key;
        let (socket_id, runtime) = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };
            (
                moto_socket.borrow().socket_id(),
                moto_socket.borrow().base.runtime.clone(),
            )
        };

        log::debug!("listen task for 0x{socket_id:x}");

        // First, wait for a state change.
        let weak_clone = weak_socket.clone();
        let socket_state = std::future::poll_fn(move |cx| {
            let Some(moto_socket) = weak_clone.upgrade() else {
                return Poll::Ready(None);
            };

            Self::with_tcp_netstack_socket(&moto_socket, |socket_id, netstack_socket, _state| {
                match netstack_socket.state() {
                    moto_netstack::socket::tcp::State::Listen => {
                        #[cfg(debug_assertions)]
                        log::debug!(
                            "Socket 0x{socket_id:x} in state Listen: task_id: {}",
                            moto_async::task_id(cx)
                        );
                        netstack_socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }
                    val => Poll::Ready(Some(val)),
                }
            })
        })
        .await;

        runtime
            .stats
            .tcp_listening_sockets
            .set(runtime.stats.tcp_listening_sockets.get() - 1);
        // However this wait ended, the pool is one socket shallower, and a pool
        // that just ran out was too shallow for the burst it met. Growth is
        // charged against a global bound, so the first of it starts the sweep
        // task that gives it back.
        runtime.backlog.left_listen(key);
        if runtime.backlog.needs_sweeper() {
            super::super::backlog::spawn_sweeper(runtime.clone());
        }

        let Some(socket_state) = socket_state else {
            let _ = connected_tx.send(());
            log::debug!("tcp: listen: socket gone.");
            return;
        };

        log::debug!("tcp: listen: socket 0x{socket_id:x}: {socket_state:?}");

        if socket_state == moto_netstack::socket::tcp::State::Established {
            let _ = connected_tx.send(());
            Self::on_incoming_connection(weak_socket).await;
            return;
        }

        // The socket took a SYN and now owes the peer nothing but patience: it
        // is half-open for exactly as long as the wait below lasts, however
        // that wait ends. Refilling the pool is what the cap holds back, so the
        // replacement is spawned only if there is room for another half-open
        // socket; otherwise the budget resumes it when a slot frees.
        let half_open = if socket_state == moto_netstack::socket::tcp::State::SynReceived {
            let (guard, may_replenish) = HalfOpenGuard::admit(
                runtime.stats.clone(),
                runtime.half_open.clone(),
                listener_id,
            );
            if may_replenish {
                let _ = connected_tx.send(());
            } else {
                log::debug!("tcp: listen: half-open cap reached; deferring pool replenishment");
                runtime.half_open.defer(listener_id, connected_tx);
                // The cap is what engages SYN cookies: while it holds the
                // pool empty, this endpoint answers requests statelessly.
                let sizes = weak_socket
                    .upgrade()
                    .and_then(|s| s.borrow().unwrap_tcp().tcp_listener.clone()?.upgrade())
                    .map(|listener| listener.borrow().buffer_sizes());
                if let Some(sizes) = sizes {
                    let (_, socket_addr) = key;
                    runtime.inner.borrow_mut().devices[device_idx]
                        .engage_syn_cookies(socket_addr, sizes);
                }
            }
            Some(guard)
        } else {
            let _ = connected_tx.send(());
            None
        };

        // Then wait for either a successful remote connection, or a
        // transition to a "going down" state.
        let weak_clone = weak_socket.clone();
        let established = std::future::poll_fn(move |cx| {
            let Some(moto_socket) = weak_clone.upgrade() else {
                return Poll::Ready(None);
            };

            Self::with_tcp_netstack_socket(&moto_socket, |_socket_id, netstack_socket, _state| {
                match netstack_socket.state() {
                    moto_netstack::socket::tcp::State::Listen => {
                        // If a SynReceived socket gets RST, moto-netstack returns it to Listen.
                        log::debug!(
                            "tcp: listen: socket 0x{socket_id:x} was reset back to Listen; dropping"
                        );
                        Poll::Ready(Some(false))
                    }

                    moto_netstack::socket::tcp::State::SynSent => {
                        // This is totally unexpected.
                        log::error!(
                            "tcp: listen: socket 0x{socket_id:x}: bad state {:?}",
                            netstack_socket.state()
                        );
                        Poll::Ready(Some(false))
                    }

                    moto_netstack::socket::tcp::State::SynReceived => {
                        netstack_socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }

                    moto_netstack::socket::tcp::State::Established => Poll::Ready(Some(true)),

                    moto_netstack::socket::tcp::State::Closed
                    | moto_netstack::socket::tcp::State::FinWait1
                    | moto_netstack::socket::tcp::State::FinWait2
                    | moto_netstack::socket::tcp::State::CloseWait
                    | moto_netstack::socket::tcp::State::Closing
                    | moto_netstack::socket::tcp::State::LastAck
                    | moto_netstack::socket::tcp::State::TimeWait => Poll::Ready(Some(false)),
                }
            })
        })
        .await;
        drop(half_open);

        let Some(established) = established else {
            return;
        };
        if established {
            Self::on_incoming_connection(weak_socket).await;
        } else if let Some(moto_socket) = weak_socket.upgrade() {
            Self::drop_tcp_socket(moto_socket).await;
        }
    }

    /// Called when a listening socket becomes connected (state::Established).
    async fn on_incoming_connection(weak_socket: Weak<RefCell<Self>>) {
        let Some(moto_socket) = weak_socket.upgrade() else {
            return;
        };
        let remote_addr = {
            Self::with_tcp_netstack_socket(&moto_socket, |_socket_id, netstack_socket, _state| {
                assert_eq!(
                    netstack_socket.state(),
                    moto_netstack::socket::tcp::State::Established
                );

                // Same as on the connect side (on_socket_connected): without these,
                // remotely dropped sockets may hang around indefinitely.
                netstack_socket
                    .set_keep_alive(Some(moto_netstack::time::Duration::from_millis(20_000)));
                netstack_socket
                    .set_timeout(Some(moto_netstack::time::Duration::from_millis(300_000)));
                netstack_socket.set_nagle_enabled(false); // A good idea, generally.
                // Delayed ACKs (also set on the connect side; keep in sync).
                // Sub-MSS ACKs wait up to 10ms so a prompt reply carries the
                // ACK instead of a separate pure-ACK packet (halves egress
                // packets in request/response traffic). Bulk transfers are
                // unaffected: moto-netstack force-expires the timer once un-ACKed
                // data exceeds one MSS, and window-update ACKs bypass it.
                netstack_socket.set_ack_delay(Some(moto_netstack::time::Duration::from_millis(10)));

                let remote_endpoint = netstack_socket.remote_endpoint().unwrap();
                crate::runtime::net::config::socket_addr_from_endpoint(remote_endpoint)
            })
        };

        let tcp_listener = {
            let mut socket_ref = moto_socket.borrow_mut();
            let tcp_state = socket_ref.state.unwrap_tcp_mut();
            tcp_state.remote_addr = Some(remote_addr);

            // The listener can be mid-teardown while this handshake was
            // completing (its owner died, or it was closed under it), so the
            // reference is as fallible here as on the socket drop path.
            let Some(weak_listener) = tcp_state.tcp_listener.take() else {
                // Taken by the drop path: the socket is already being torn
                // down, and this task has nothing left to do.
                return;
            };
            weak_listener.upgrade()
        };
        let Some(tcp_listener) = tcp_listener else {
            // The listener is gone and nobody else knows this socket exists:
            // without an explicit drop it would leak, with the peer holding
            // a connection no one will ever serve.
            log::debug!(
                "on_incoming_connection: listener gone; dropping socket 0x{:x}.",
                moto_socket.borrow().socket_id()
            );
            Self::drop_tcp_socket(moto_socket).await;
            return;
        };

        let (accepted_tx, accepted_rx) = moto_async::oneshot();
        TcpListener::on_socket_connected(tcp_listener, moto_socket, accepted_tx).await;

        let _ = moto_async::LocalRuntime::spawn(async move {
            // We don't do I/O on the socket until it is accepted by the client.
            accepted_rx.await;
            Self::tcp_read_task(weak_socket).await
        });
    }

    async fn tcp_connect_task(weak_socket: Weak<RefCell<Self>>) {
        let socket_id = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };
            moto_socket.borrow().socket_id()
        };
        log::debug!("tcp_connect_task for socket 0x{socket_id:x}.");

        let weak_clone = weak_socket.clone();
        let terminal = std::future::poll_fn(move |cx| {
            let Some(moto_socket) = weak_clone.upgrade() else {
                return Poll::Ready(None);
            };

            Self::with_tcp_netstack_socket(&moto_socket, |_socket_id, netstack_socket, _state| {
                let state = netstack_socket.state();
                match connect_action(state) {
                    ConnectAction::Pending => {
                        netstack_socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }
                    action => Poll::Ready(Some((state, action))),
                }
            })
        })
        .await;

        let Some((state, action)) = terminal else {
            return;
        };
        log::debug!("TCP connect socket 0x{socket_id:x} reached {state:?}");

        match action {
            ConnectAction::Connected => Self::on_socket_connected(weak_socket).await,
            ConnectAction::Failed | ConnectAction::Pending => {
                Self::on_connect_failed(weak_socket).await
            }
        }
    }

    async fn on_connect_failed(weak_socket: Weak<RefCell<Self>>) {
        let Some(moto_socket) = weak_socket.upgrade() else {
            return;
        };

        Self::drop_tcp_socket(moto_socket.clone()).await;

        let (sender, msg) = {
            let mut socket_ref = moto_socket.borrow_mut();
            let socket_mut = &mut *socket_ref;
            let Self { base, state } = socket_mut;

            let tcp_state = state.unwrap_tcp_mut();
            let mut msg = tcp_state.connect_req.take().unwrap();
            msg.handle = base.socket_id;
            msg.status = match api_net::tcp_stream_connect_timeout(&msg) {
                Some(deadline) if deadline <= moto_rt::time::Instant::now() => moto_rt::E_TIMED_OUT,
                _ => moto_rt::E_NOT_CONNECTED,
            };

            (base.client_sender.clone(), msg)
        };

        let _ = sender.send(msg).await;
    }

    async fn on_socket_connected(weak_socket: Weak<RefCell<Self>>) {
        let Some(moto_socket) = weak_socket.upgrade() else {
            return;
        };

        Self::with_tcp_netstack_socket(&moto_socket, |socket_id, netstack_socket, _state| {
            log::debug!("Socket 0x{socket_id:x} connected.");
            // Without these, remotely dropped sockets may hang around indefinitely.
            netstack_socket
                .set_keep_alive(Some(moto_netstack::time::Duration::from_millis(20_000)));
            netstack_socket.set_timeout(Some(moto_netstack::time::Duration::from_millis(300_000)));
            netstack_socket.set_nagle_enabled(false); // A good idea, generally.
            // Delayed ACKs — see the comment on the accept side
            // (on_incoming_connection); keep the two in sync.
            netstack_socket.set_ack_delay(Some(moto_netstack::time::Duration::from_millis(10)));
        });

        let (sender, msg) = {
            let mut socket_ref = moto_socket.borrow_mut();
            let socket_mut = &mut *socket_ref;
            let Self { base, state } = socket_mut;

            let tcp_state = state.unwrap_tcp_mut();
            let mut msg = tcp_state.connect_req.take().unwrap();
            msg.handle = base.socket_id;
            api_net::put_socket_addr(&mut msg.payload, &base.local_addr);
            msg.status = moto_rt::E_OK;

            (base.client_sender.clone(), msg)
        };

        let _ = sender.send(msg).await;
        let _ =
            moto_async::LocalRuntime::spawn(async move { Self::tcp_read_task(weak_socket).await });
    }

    async fn tcp_read_task(weak_socket: Weak<RefCell<Self>>) {
        let weak_socket_cloned = weak_socket.clone();
        let _ = moto_async::LocalRuntime::spawn(async move {
            Self::tcp_write_task(weak_socket_cloned).await
        });

        let (socket_id, sender, subchannel_mask, rx_ready, stats, device_notify) = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };
            let socket_ref = moto_socket.borrow();
            (
                socket_ref.base.socket_id,
                socket_ref.base.sender().clone(),
                socket_ref.unwrap_tcp().subchannel_mask,
                socket_ref.unwrap_tcp().rx_ready.clone(),
                socket_ref.base.runtime.stats.clone(),
                socket_ref.base.device_notify(),
            )
        };
        rx_ready.notified().await;

        log::debug!(
            "TCP RX task for socket 0x{socket_id:x} conn 0x{:x}",
            sender.remote_handle().as_u64()
        );

        // Note: RX messages carry a single page each. Multi-page RX (the
        // mirror of the multi-page TX) was implemented and A/B-measured on
        // 2026-07-11: no throughput change — unlike the client->server
        // direction, where every message costs a task spawn etc., messages
        // in this direction are nearly free on both sides (the pump pushes
        // into the ring directly, the client io thread handles inline), so
        // there is nothing to amortize and the RX costs are per-page.
        loop {
            // Step 1: wait for the socket to become readable.
            let can_recv = std::future::poll_fn(|cx| {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    log::debug!("RX: socket 0x{socket_id:x} gone.");
                    return Poll::Ready(false);
                };

                Self::with_tcp_netstack_socket(
                    &moto_socket,
                    |_socket_id, netstack_socket, _state| {
                        if netstack_socket.can_recv() {
                            log::debug!("RX: socket 0x{socket_id:x} can_recv.");
                            return Poll::Ready(true);
                        }
                        if !netstack_socket.may_recv() {
                            log::debug!(
                                "RX: socket 0x{socket_id:x} !may_recv: {:?}.",
                                netstack_socket.state()
                            );
                            return Poll::Ready(false);
                        }

                        #[cfg(debug_assertions)]
                        {
                            let (state, can_recv) =
                                (netstack_socket.state(), netstack_socket.can_recv());
                            log::debug!(
                                "RX: socket 0x{_socket_id:x} can_recv: {can_recv} in {state:?}"
                            );
                        }

                        netstack_socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    },
                )
            })
            .await;

            if !can_recv {
                break;
            }

            // Step 3: allocate a page. This is where backpressure happens.
            if !sender.may_alloc_page(subchannel_mask) {
                stats
                    .tcp_rx_alloc_waits
                    .set(stats.tcp_rx_alloc_waits.get() + 1);
            }
            let Ok(page) = sender.alloc_page(subchannel_mask).await else {
                // The client's whole connection went away (the process exited
                // or panicked) while we awaited a free RX page under
                // backpressure. Stop delivering to a dead client rather than
                // unwrapping BadHandle and crashing sys-io.
                log::debug!("RX: socket 0x{socket_id:x} sender gone; stopping RX.");
                break;
            };

            // Step 4: read bytes from the socket. Note that we read at most one page,
            // because to read more, we need to check if the socket has more bytes to read,
            // which is done in step 1 above.
            let mut rx_buf = TcpRxBuf::new(page);
            {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    break;
                };

                Self::with_tcp_netstack_socket(&moto_socket, |_, netstack_socket, tcp_state| {
                    if !tcp_state.rx_closed {
                        match netstack_socket.recv_slice(rx_buf.bytes_mut()) {
                            Ok(len) => {
                                rx_buf.consume(len);
                                tcp_state.stat_rx_bytes += len as u64;
                                log::debug!("TCP socket 0x{socket_id:x} RX {len} bytes.");
                            }
                            Err(err) => {
                                if netstack_socket.may_recv() {
                                    log::warn!(
                                        "Unexpected error {err:?} reading bytes from socket 0x{socket_id:x}"
                                    );
                                }
                            }
                        }
                    }
                });
            }
            if rx_buf.consumed == 0 {
                break;
            }

            // Draining the buffer may reopen a closed receive window, but the
            // window update is only ever *transmitted* by an `iface.poll()`,
            // and the poll task may be asleep with a pre-drain `poll_delay()`.
            // Without this wake a zero-window stall recovers only via the
            // peer's persist probes (~32KB per probe; RX measured at
            // 0.78 MiB/s instead of 16+). moto-netstack's `window_to_update()`
            // gates the actual emission, so this cannot cause an ACK storm.
            device_notify.notify_one();

            // Step 5. Send bytes to the client.
            {
                let (io_page, sz) = (rx_buf.page, rx_buf.consumed);
                stats.tcp_rx_msgs.set(stats.tcp_rx_msgs.get() + 1);
                stats.tcp_rx_bytes.set(stats.tcp_rx_bytes.get() + sz as u64);
                let mut msg = moto_sys_io::api_net::tcp_stream_rx_msg(socket_id, io_page, sz, 0);
                msg.status = moto_rt::E_OK;
                let _ = sender.send(msg).await;
            }
        } // loop

        log::debug!("Socket 0x{socket_id:x}: RX task done.");

        // The RX task here waits on the socket, so any socket changes are detected.
        // But the TX task mostly waits on the user to send bytes, so socket changes
        // must be propagated.
        if let Some(moto_socket) = weak_socket.upgrade() {
            Self::with_tcp_netstack_socket(&moto_socket, |_, netstack_socket, tcp_state| {
                if !netstack_socket.may_send() {
                    tcp_state.tx_queue_notify.notify_one();
                }
            });
        }

        Self::tcp_state_change_notify(weak_socket, api_net::TcpState::WriteOnly).await;
    }

    async fn tcp_write_task(weak_socket: Weak<RefCell<Self>>) {
        let (tx_queue_notify, socket_id) = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };

            let socket_ref = moto_socket.borrow();
            let socket_id = socket_ref.base.socket_id;
            let tcp_state = socket_ref.unwrap_tcp();
            (tcp_state.tx_queue_notify.clone(), socket_id)
        };

        'outer: loop {
            let socket_state = std::future::poll_fn(|cx| {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    return Poll::Ready(None);
                };

                Self::with_tcp_netstack_socket(
                    &moto_socket,
                    |_socket_id, netstack_socket, _state| {
                        log::debug!(
                            "TX polling socket 0x{socket_id:x} in {:?}",
                            netstack_socket.state()
                        );
                        if netstack_socket.can_send() {
                            // Has space in the TX buffer.
                            Poll::Ready(Some(true))
                        } else if !(netstack_socket.may_send()) {
                            Poll::Ready(Some(false))
                        } else {
                            // Have to wait.
                            netstack_socket.register_send_waker(cx.waker());
                            Poll::Pending
                        }
                    },
                )
            })
            .await;

            let Some(true) = socket_state else {
                break; // The socket is no more.
            };

            // Step 2: wait for bytes to TX.
            log::debug!("TX task for socket 0x{socket_id:x}: waiting for bytes to send.");
            loop {
                {
                    let Some(moto_socket) = weak_socket.upgrade() else {
                        break 'outer;
                    };

                    {
                        let socket_ref = moto_socket.borrow();
                        let tcp_state = socket_ref.unwrap_tcp();

                        if tcp_state.tx_closed {
                            if tcp_state.tx_queue.is_empty() {
                                break 'outer;
                            } else {
                                break;
                            }
                        }

                        if !tcp_state.tx_queue.is_empty() {
                            break;
                        }
                    }

                    let may_send = Self::with_tcp_netstack_socket(
                        &moto_socket,
                        |_socket_id, netstack_socket, _state| netstack_socket.may_send(),
                    );

                    if !may_send {
                        break 'outer;
                    }
                }

                // We must wait inside the loop, otherwise the loop will busyloop.
                tx_queue_notify.notified().await;
            } // loop

            // Step 3: TX bytes out.
            log::debug!("TX task for socket 0x{socket_id:x}: maybe got bytes to send.");
            {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    break 'outer;
                };

                let tx_broken = Self::with_tcp_netstack_socket(
                    &moto_socket,
                    |socket_id, netstack_socket, tcp_state| {
                        while netstack_socket.can_send() {
                            let mut tx_buf = if let Some(x) = tcp_state.tx_queue.pop_front() {
                                x
                            } else {
                                break;
                            };

                            match netstack_socket.send_slice(tx_buf.bytes()) {
                                Ok(sz) => {
                                    tx_buf.consume(sz);
                                    log::debug!(
                                        "TCP TX: enqueued {sz} bytes into socket 0x{socket_id:x}."
                                    );
                                    if tx_buf.is_consumed() {
                                        // Client writes are completed in tcp_stream_write,
                                        // actual socket writes happen later/asynchronously.
                                        continue;
                                    } else {
                                        // moto_socket.
                                        tcp_state.tx_queue.push_front(tx_buf);
                                        continue;
                                    }
                                }
                                Err(err) => {
                                    // Unreachable today: can_send() above implies
                                    // may_send(), the only state send_slice rejects.
                                    // If it ever happens, the socket can no longer
                                    // transmit, so end this task the way a normal
                                    // TX close does instead of aborting sys-io.
                                    log::error!(
                                        "TCP TX: socket 0x{socket_id:x} rejected {} bytes: {err:?}.",
                                        tx_buf.bytes().len()
                                    );
                                    tcp_state.tx_queue.clear();
                                    return true;
                                }
                            }
                        }
                        false
                    },
                );

                moto_socket.borrow().base.device_notify.notify_one();
                if tx_broken {
                    break 'outer;
                }
            } // loop
        } // loop

        log::debug!("Socket 0x{socket_id:x} TX task done.");
        {
            if let Some(moto_socket) = weak_socket.upgrade() {
                let device_notify = Self::with_tcp_socket_set(
                    &moto_socket,
                    |_socket_id, sockets, handle, state| {
                        let may_send = sockets
                            .get::<moto_netstack::socket::tcp::Socket>(handle)
                            .may_send();
                        if may_send {
                            sockets.tcp_close(handle);
                        }
                        state.tx_closed = true;
                        state.tx_queue.clear();
                        if let Some(lingerer) = state.lingerer.take() {
                            lingerer.send(());
                        }

                        may_send
                    },
                );
                if device_notify {
                    moto_socket.borrow().base.device_notify.notify_one();
                }
            }
        }
        Self::tcp_state_change_notify(weak_socket, api_net::TcpState::ReadOnly).await;
    }

    async fn tcp_state_change_notify(
        weak_socket: Weak<RefCell<Self>>,
        new_state: api_net::TcpState,
    ) {
        let Some(moto_socket) = weak_socket.upgrade() else {
            return;
        };

        // The cause rides with the state so the client can report
        // ECONNRESET faithfully; every non-reset death leaves it zero.
        let cause_reset = Self::with_tcp_netstack_socket(&moto_socket, |_, netstack_socket, _| {
            netstack_socket.reset_received()
        });

        let (socket_id, sender) = {
            let socket_ref = moto_socket.borrow();
            if socket_ref.base.lingering {
                return;
            }
            (socket_ref.base.socket_id, socket_ref.base.sender().clone())
        };

        let mut msg = moto_ipc::io_channel::Msg::new();
        msg.command = api_net::NetCmd::EvtTcpStreamStateChanged as u16;
        msg.handle = socket_id;
        msg.payload.args_32_mut()[0] = new_state.into();
        if cause_reset {
            msg.payload.args_32_mut()[1] = api_net::TCP_STATE_CHANGE_CAUSE_RESET;
        }

        msg.status = moto_rt::E_OK;
        let _ = sender.send(msg).await;
    }

    pub(super) fn on_tcp_socket_drop(base: &mut super::SocketBase, state: &mut TcpState) {
        assert!(!base.lingering);
        assert!(state.tx_closed);
        assert!(state.rx_closed);
        assert!(state.tx_queue.is_empty());

        base.runtime
            .stats
            .tcp_sockets
            .set(base.runtime.stats.tcp_sockets.get() - 1);
    }

    // Drop the socket fully.
    pub async fn drop_tcp_socket(moto_socket: Rc<RefCell<Self>>) {
        // Abort all ops.
        let socket_id =
            Self::with_tcp_socket_set(&moto_socket, |socket_id, sockets, handle, state| {
                // Reset only what is still a connection. A socket that finished
                // its close handshake has nothing left to abort, and aborting it
                // would put an RST on the wire *after* a clean FIN exchange:
                // moto-netstack sends one for any CLOSED socket that still knows
                // its peer, which is what TIME-WAIT is.
                if sockets
                    .get::<moto_netstack::socket::tcp::Socket>(handle)
                    .is_open()
                {
                    sockets.tcp_abort(handle);
                }
                state.rx_closed = true;
                state.tx_closed = true;
                socket_id
            });
        log::debug!("Dropping TCP socket 0x{socket_id:x}.");
        moto_socket.borrow().base.device_notify().notify_one();

        // Let the device process the abort above (send RST out).
        moto_async::sleep(std::time::Duration::from_millis(1)).await;

        let runtime = moto_socket.borrow().base.runtime.clone();

        {
            let mut socket_ref = moto_socket.borrow_mut();
            let mut runtime_ref = socket_ref.base.runtime.inner.borrow_mut();

            // Sockets can linger long after their clients are gone.
            if let Some(client) = runtime_ref
                .clients
                .get_mut(&socket_ref.base.sender().remote_handle())
            {
                let _ = client.sockets.remove(&socket_ref.base.socket_id);
            }

            drop(runtime_ref);

            let tcp_listener = socket_ref.unwrap_tcp_mut().tcp_listener.take();
            log::debug!(
                "dropping socket 0x{socket_id:x}: tcp_listener: {}",
                tcp_listener.is_some()
            );

            if let Some(weak) = tcp_listener {
                if let Some(strong) = weak.upgrade() {
                    log::debug!("strong tcp_listener for socket 0x{socket_id:x}");
                    TcpListener::on_socket_dropped(strong, socket_id);
                } else {
                    log::debug!("weak tcp_listener for socket 0x{socket_id:x}");
                }
            } else {
                log::debug!("missing tcp_listener for socket 0x{socket_id:x}????");
            }
            // if let Some(tcp_listener) = tcp_listener.map(|weak| weak.upgrade()).flatten() {
            //     TcpListener::on_socket_dropped(tcp_listener, socket_id);
            // }
        }

        // Drop the socket.
        runtime.inner.borrow_mut().sockets.remove(&socket_id);
    }

    // The socket may become detached.
    pub async fn close_tcp_socket_inner(
        moto_socket: Rc<RefCell<MotoSocket>>,
        mut close_req: Option<moto_ipc::io_channel::Msg>,
    ) {
        let socket_id = moto_socket.borrow().socket_id();

        let action =
            Self::with_tcp_socket_set(&moto_socket, |_socket_id, sockets, handle, state| {
                let netstack_socket = sockets.get_mut::<moto_netstack::socket::tcp::Socket>(handle);
                // No reader ever again: data after our FIN earns an RST, and
                // the FIN-WAIT-2/TIME-WAIT rings release to the floor. On
                // the abort paths below this is moot (reset clears it).
                netstack_socket.set_rx_shutdown();

                // SO_LINGER(0) is the one way to ask for a reset.
                if Some(0) == state.linger_secs {
                    return CloseAction::Abort;
                }

                // Closing with data still unread resets instead, as it does on
                // Linux. The receive half stops draining right below, so a FIN
                // would leave the peer waiting on a window that never reopens;
                // and the peer needs to learn that what it sent was not read.
                if netstack_socket.recv_queue() > 0 {
                    return CloseAction::Abort;
                }

                // A connection that never carried a byte of ours resets too.
                // A reset cannot truncate a stream that sent nothing, so the
                // reason to close gracefully is absent, while the reasons not
                // to are concrete: the client is gone, so a peer that keeps
                // writing must learn at once that nobody will ever read it,
                // and until it does this socket holds its whole receive buffer
                // absorbing that data for the entire linger.
                if state.stat_tx_bytes == 0 {
                    return CloseAction::Abort;
                }

                if state.tx_queue.is_empty() {
                    // Nothing of ours is left to hand over, so the FIN goes out
                    // now; moto-netstack puts whatever is still in its own send
                    // buffer ahead of it. This also makes `may_send()` false,
                    // which is what stops the TX task from re-registering the
                    // send waker that `tcp_linger_task` takes over below.
                    sockets.tcp_close(handle);
                    CloseAction::Finish
                } else {
                    // The TX task still has client writes to hand over. It is
                    // the one that closes, once they are in the send buffer.
                    CloseAction::DrainThenFinish
                }
            });

        // A state change is not a packet: the FIN above only reaches the wire
        // when the device polls. (The TX task notifies for itself.)
        if action == CloseAction::Finish {
            moto_socket.borrow().base.device_notify().notify_one();
        }

        let (linger_secs, delayed_notify) = {
            let mut socket_ref = moto_socket.borrow_mut();
            let state = socket_ref.unwrap_tcp_mut();
            let linger_secs = state.linger_secs.take();

            state.tx_closed = true;
            state.rx_closed = true;
            state.tx_queue_notify.notify_one();

            if action == CloseAction::Abort {
                (0, false)
            } else if let Some(secs) = linger_secs {
                (secs, true)
            } else {
                (DEFAULT_LINGER_SECS, false)
            }
        };

        let socket_clone = moto_socket.clone();
        if linger_secs > 0 {
            let lingerer = {
                let mut socket_ref = moto_socket.borrow_mut();
                socket_ref.base.lingering = true;

                // Only a close that still has writes to hand over waits for the
                // TX task, because only then is the TX task the one that sends
                // the FIN. Waiting unconditionally would hang for the whole
                // linger on a socket whose TX task has already finished -- a
                // shutdown(WRITE) followed by a close, say -- since the signal
                // below is sent exactly once, when that task ends.
                let lingerer = if action == CloseAction::DrainThenFinish {
                    let (sender, receiver) = moto_async::oneshot();
                    socket_ref.unwrap_tcp_mut().lingerer = Some(sender);
                    Some(receiver)
                } else {
                    None
                };

                let mut runtime_ref = socket_ref.base.runtime.inner.borrow_mut();
                // Note: if initiated from the client-done handling in net.rs,
                // the socket won't be in the client hashmap anymore -- and the
                // client itself may already be gone when a graceful close
                // races the connection teardown, so tolerate a missing client.
                if let Some(client) = runtime_ref
                    .clients
                    .get_mut(&socket_ref.base.sender().remote_handle())
                {
                    client.sockets.remove(&socket_ref.base.socket_id);
                }

                lingerer
            };

            let close_req = if delayed_notify {
                close_req.take()
            } else {
                None
            };

            log::debug!("TCP socket 0x{socket_id:x}: lingering for {linger_secs} seconds.");
            let deadline =
                moto_async::Instant::now() + std::time::Duration::from_secs(linger_secs as u64);
            moto_async::LocalRuntime::spawn(async move {
                Self::tcp_linger_task(socket_clone, deadline, lingerer).await
            });
        } else {
            log::debug!("TCP socket 0x{socket_id:x}: not lingering.");
            Self::drop_tcp_socket(socket_clone).await;
        }

        if !delayed_notify && let Some(msg) = close_req.take() {
            let sender = moto_socket.borrow().base.sender().clone();
            let mut resp = msg;
            resp.status = moto_rt::E_OK;
            let _ = sender.send(resp).await;
        }
    }

    /// See a closing connection through: the FIN out, then the peer's answer to
    /// it, bounded by `deadline`. Whatever is left when that runs out is reset
    /// by [`Self::drop_tcp_socket`].
    async fn tcp_linger_task(
        moto_socket: Rc<RefCell<Self>>,
        deadline: moto_async::Instant,
        lingerer: Option<moto_async::oneshot::Receiver<()>>,
    ) {
        use futures::FutureExt;

        let socket_id = moto_socket.borrow().socket_id();

        // Step 1: the TX task hands the client's remaining writes to the
        // netstack and closes. Present only when there were any (see
        // `close_tcp_socket_inner`); the FIN is already queued otherwise.
        if let Some(lingerer) = lingerer {
            futures::select! {
            _ = lingerer.fuse() => {
                log::debug!("Lingering socket 0x{socket_id:x}: TX done.");
            },
            _ = moto_async::sleep_until(deadline.into()).fuse() => {
                log::debug!("Lingering socket 0x{socket_id:x}: TX timed out.");
            },
            }
        }

        // Step 2: the close handshake. `is_open()` is false in CLOSED and
        // TIME-WAIT, which are its two ends -- our FIN acknowledged and, if we
        // closed first, the peer's FIN in as well.
        //
        // This waits on the netstack's send waker, which every state change
        // wakes, rather than polling: a close that took a second to notice it
        // was done held a socket's whole 128 KiB of buffers for that second.
        // Taking that waker over is safe only because the TX task is finished
        // with it -- step 1 above, or `may_send()` already false.
        {
            let closed = std::future::poll_fn(|cx| {
                Self::with_tcp_netstack_socket(&moto_socket, |_, netstack_socket, _| {
                    if netstack_socket.is_open() {
                        netstack_socket.register_send_waker(cx.waker());
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
            });

            futures::select! {
            _ = closed.fuse() => {
                log::debug!("Lingering socket 0x{socket_id:x}: closed.");
            },
            _ = moto_async::sleep_until(deadline.into()).fuse() => {
                log::debug!("Lingering socket 0x{socket_id:x}: timed out.");
            },
            }
        }

        moto_socket.borrow_mut().base.lingering = false;
        Self::drop_tcp_socket(moto_socket).await;
    }

    /* ----------------------------------- API calls ------------------------------------ */
    pub async fn tcp_connect(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        runtime.pressure.admit()?;
        let remote_addr = api_net::get_socket_addr(&msg.payload);

        log::debug!(
            "sys-io: 0x{:x}: tcp connect to {:?}",
            sender.remote_handle().as_u64(),
            remote_addr
        );

        let Some((device_idx, local_ip_addr)) = runtime.find_route(&remote_addr.ip()) else {
            log::debug!(
                "sys-io: 0x{:x}: tcp connect to {:?}: route not found",
                sender.remote_handle().as_u64(),
                remote_addr
            );

            return Err(ErrorKind::NetworkUnreachable.into());
        };

        let local_port = runtime
            .get_ephemeral_tcp_port(device_idx, local_ip_addr)
            .ok_or_else(|| {
                log::warn!("Failed to allocate local port for {local_ip_addr:?}.");
                std::io::Error::from(ErrorKind::OutOfMemory)
            })?;

        let local_addr = SocketAddr::new(local_ip_addr, local_port.port);
        let subchannel_mask = api_net::io_subchannel_mask(msg.payload.args_8()[23]);

        // Create the socket.
        let weak_socket = {
            let moto_socket = Self::create_tcp_socket(
                runtime,
                device_idx,
                local_addr,
                sender.clone(),
                subchannel_mask,
                TcpBufferSizes::from_payload(&msg.payload),
                RingBuild::Configured,
            )?;

            // Set timeout, if needed.
            if let Some(timeout) = api_net::tcp_stream_connect_timeout(&msg) {
                Self::with_tcp_netstack_socket(
                    &moto_socket,
                    |socket_id, netstack_socket, _state| {
                        let now = moto_rt::time::Instant::now();
                        if timeout <= now {
                            // We check this upon receiving sqe; the thread got preempted or something.
                            // Just use an arbitrary small timeout.
                            netstack_socket
                                .set_timeout(Some(moto_netstack::time::Duration::from_micros(10)));
                        } else {
                            netstack_socket.set_timeout(Some(
                                moto_netstack::time::Duration::from_micros(
                                    timeout.duration_since(now).as_micros() as u64,
                                ),
                            ));
                        }
                    },
                );
            }

            // Issue the moto-netstack connect request.
            let connect_result = {
                let mut socket_ref = moto_socket.borrow_mut();
                let socket_mut = &mut *socket_ref;
                let Self { base, state } = socket_mut;
                let state = state.unwrap_tcp_mut();

                state.ephemeral_port = Some(local_port);
                state.connect_req = Some(msg);
                state.remote_addr = Some(remote_addr);

                log::debug!(
                    "TCP connect: socket 0x{:x} {local_addr:?} => {remote_addr:?}.",
                    base.socket_id
                );
                base.runtime.inner.borrow_mut().devices[base.device_idx].tcp_connect(
                    base.handle(),
                    local_addr,
                    remote_addr,
                )
            };
            if connect_result.is_err() {
                log::debug!("Discarding TCP socket after connect setup failed.");
                Self::drop_tcp_socket(moto_socket).await;
                return Err(ErrorKind::ConnectionRefused.into());
            }

            Rc::downgrade(&moto_socket)
        };

        // Spawn the socket task.

        moto_async::LocalRuntime::spawn(async move {
            Self::tcp_connect_task(weak_socket).await;
        });

        Ok(())
    }

    pub async fn tcp_tx(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        // Recover the page(s) first, before any validation, so that they are
        // freed on every return path. `flags` distinguishes the two request
        // formats: zero = classic single page (size in args_64[1]), nonzero =
        // multi-page (flags = total size, pages full except the last) — see
        // api_net::tcp_stream_tx_multi_msg.
        let mut pages: Vec<(moto_ipc::io_channel::IoPage, usize)> = if msg.flags == 0 {
            let page_idx = msg.payload.shared_pages()[0];
            let Ok(page) = sender.get_page(page_idx) else {
                return Err(ErrorKind::InvalidInput.into());
            };

            let sz = msg.payload.args_64()[1] as usize;
            if sz > moto_ipc::io_channel::PAGE_SIZE {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidInput.into());
            }
            vec![(page, sz)]
        } else {
            let Ok((pages, total_len)) = api_net::tcp_stream_tx_multi_decode(&msg, sender) else {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidInput.into());
            };
            let mut remaining = total_len as usize;
            pages
                .into_iter()
                .map(|page| {
                    let sz = remaining.min(moto_ipc::io_channel::PAGE_SIZE);
                    remaining -= sz;
                    (page, sz)
                })
                .collect()
        };

        let socket_id = msg.handle;
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let mut socket_ref = moto_socket.borrow_mut();
            if socket_ref.base.client_sender.remote_handle() != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }

            // Check that the socket is indeed tcp before unwrapping.
            if !matches!(socket_ref.state, SocketState::Tcp(_)) {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidInput.into());
            }

            let tcp_state = socket_ref.unwrap_tcp_mut();

            if tcp_state.tx_closed {
                log::debug!("TCP socket {socket_id:x}: TX with tx_closed.");
                return Err(ErrorKind::NotConnected.into());
            }

            let total_sz: usize = pages.iter().map(|(_, sz)| *sz).sum();
            tcp_state.stat_tx_bytes += total_sz as u64;
            runtime
                .stats
                .tcp_tx_msgs
                .set(runtime.stats.tcp_tx_msgs.get() + 1);
            runtime
                .stats
                .tcp_tx_bytes
                .set(runtime.stats.tcp_tx_bytes.get() + total_sz as u64);
            for (page, sz) in pages.drain(..) {
                tcp_state.tx_queue.push_back(TcpTxBuf {
                    page,
                    len: sz,
                    consumed: 0,
                });
            }

            tcp_state.tx_queue_notify.notify_one();
        }

        Ok(())
    }

    pub async fn tcp_rx_ack_received(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;
        runtime
            .stats
            .tcp_rx_acks
            .set(runtime.stats.tcp_rx_acks.get() + 1);
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let mut socket_ref = moto_socket.borrow_mut();
            if socket_ref.base.client_sender.remote_handle() != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }

            // Check that the socket is indeed tcp before unwrapping.
            if !matches!(socket_ref.state, SocketState::Tcp(_)) {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidInput.into());
            }

            let tcp_state = socket_ref.unwrap_tcp().rx_ready.notify_one();
        }

        Ok(())
    }

    pub async fn tcp_getsockopt(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let mut socket_ref = moto_socket.borrow_mut();
            if socket_ref.base.client_sender.remote_handle() != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }
            // Check that the socket is indeed tcp before unwrapping.
            if !matches!(socket_ref.state, SocketState::Tcp(_)) {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidData.into());
            }
        }

        let options = msg.payload.args_64()[0];
        if options == 0 {
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut resp = msg;
        match options {
            api_net::TCP_OPTION_NODELAY => {
                let nagle_enabled = Self::with_tcp_netstack_socket(
                    &moto_socket,
                    |_socket_id, netstack_socket, _state| netstack_socket.nagle_enabled(),
                );
                let nodelay = !nagle_enabled;
                resp.payload.args_64_mut()[0] = if nodelay { 1 } else { 0 };
            }
            api_net::TCP_OPTION_LINGER => {
                let linger = moto_socket.borrow().unwrap_tcp().linger_secs.clone();
                if let Some(secs) = linger {
                    resp.payload.args_32_mut()[2] = 1;
                    resp.payload.args_32_mut()[3] = secs;
                } else {
                    resp.payload.args_32_mut()[2] = 0;
                }
            }
            api_net::TCP_OPTION_TTL => {
                let hop_limit = Self::with_tcp_netstack_socket(
                    &moto_socket,
                    |_socket_id, netstack_socket, _state| netstack_socket.hop_limit(),
                );
                let ttl = if let Some(hop_limit) = hop_limit {
                    hop_limit as u32
                } else {
                    64 // This is what moto-netstack documentation implies.
                };
                resp.payload.args_32_mut()[0] = ttl;
            }
            api_net::TCP_OPTION_RCVBUF | api_net::TCP_OPTION_SNDBUF => {
                let effective = Self::with_tcp_netstack_socket(
                    &moto_socket,
                    |_socket_id, netstack_socket, _state| {
                        if options == api_net::TCP_OPTION_RCVBUF {
                            netstack_socket.effective_recv_capacity()
                        } else {
                            netstack_socket.effective_send_capacity()
                        }
                    },
                );
                resp.payload.args_64_mut()[1] = effective as u64;
            }
            _ => {
                log::debug!("Invalid option 0x{options}");
                return Err(ErrorKind::InvalidInput.into());
            }
        }

        resp.status = moto_rt::E_OK;
        let _ = sender.send(resp).await;

        Ok(())
    }

    pub async fn tcp_setsockopt(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let mut socket_ref = moto_socket.borrow_mut();
            if socket_ref.base.client_sender.remote_handle() != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }
            // Check that the socket is indeed tcp before unwrapping.
            if !matches!(socket_ref.state, SocketState::Tcp(_)) {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidData.into());
            }
        }

        let mut options = msg.payload.args_64()[0];
        if options == 0 {
            return Err(ErrorKind::InvalidInput.into());
        }

        log::debug!("TCP setsockopt 0x{options:x} for socket 0x{socket_id:x}.");

        if options == api_net::TCP_OPTION_NODELAY {
            let nodelay_u64 = msg.payload.args_64()[1];
            let nodelay = match nodelay_u64 {
                1 => true,
                0 => false,
                _ => {
                    return Err(ErrorKind::InvalidInput.into());
                }
            };

            log::debug!("TCP setsockopt NODELAY({nodelay}) for socket 0x{socket_id:x}.");
            Self::with_tcp_netstack_socket(&moto_socket, |_socket_id, netstack_socket, _state| {
                netstack_socket.set_nagle_enabled(!nodelay);
            });
        } else if options == api_net::TCP_OPTION_LINGER {
            let linger_secs = if msg.payload.args_32()[2] == 0 {
                None
            } else {
                Some(msg.payload.args_32()[3])
            };

            log::debug!("TCP setsockopt LINGER({linger_secs:?}) for socket 0x{socket_id:x}.");
            moto_socket.borrow_mut().unwrap_tcp_mut().linger_secs = linger_secs;
        } else if options == api_net::TCP_OPTION_TTL {
            let ttl = msg.payload.args_32()[2];
            if ttl == 0 || ttl > 255 {
                return Err(ErrorKind::InvalidInput.into());
            };

            Self::with_tcp_netstack_socket(&moto_socket, |_socket_id, netstack_socket, _state| {
                netstack_socket.set_hop_limit(Some(ttl as u8));
            });
        } else if options == api_net::TCP_OPTION_RCVBUF || options == api_net::TCP_OPTION_SNDBUF {
            let bytes = TcpBufferSizes::normalize(msg.payload.args_64()[1]);
            let effective = Self::with_tcp_netstack_socket(
                &moto_socket,
                |_socket_id, netstack_socket, _state| {
                    if options == api_net::TCP_OPTION_RCVBUF {
                        netstack_socket.grow_rx_capacity(bytes);
                        netstack_socket.effective_recv_capacity()
                    } else {
                        netstack_socket.grow_tx_capacity(bytes);
                        netstack_socket.effective_send_capacity()
                    }
                },
            );
            // The reply reports the effective size: a clamped request must
            // read back clamped, never as the number the caller asked for.
            let mut resp = msg;
            resp.payload.args_64_mut()[1] = effective as u64;
            resp.status = moto_rt::E_OK;
            let _ = sender.send(resp).await;
            return Ok(());
        } else {
            let shut_rd = options & api_net::TCP_OPTION_SHUT_RD != 0;
            if shut_rd {
                options ^= api_net::TCP_OPTION_SHUT_RD;
            }

            let shut_wr = options & api_net::TCP_OPTION_SHUT_WR != 0;
            if shut_wr {
                options ^= api_net::TCP_OPTION_SHUT_WR;
            }

            if options != 0 {
                log::debug!("Unknown TCP option 0x{options:x}.");
                return Err(ErrorKind::InvalidInput.into());
            }

            log::debug!(
                "TCP setsockopt SHUTDOWN(rd: {shut_rd}, wr: {shut_wr}) for socket 0x{socket_id:x}."
            );
            Self::with_tcp_netstack_socket(
                &moto_socket,
                |_socket_id, netstack_socket, state| -> () {
                    if shut_rd {
                        state.rx_closed = true;
                        // Data after our FIN now earns an RST (Linux
                        // RCV_SHUTDOWN semantics); before the FIN the
                        // netstack keeps absorbing, as Linux does.
                        netstack_socket.set_rx_shutdown();
                    }
                    if shut_wr {
                        // Close the write half gracefully, applying the same
                        // linger logic as a full socket close (see
                        // `close_tcp_socket_inner`): mark TX as closed and wake
                        // the TX task. Any bytes still queued to send are not
                        // dropped -- `tcp_write_task` flushes them out to the
                        // wire first and only then calls `netstack_socket.close()`
                        // (the FIN). Unlike a full close, the socket itself is
                        // kept alive (the read half stays open), so no linger
                        // task / deferred drop is needed here.
                        state.tx_closed = true;
                        state.tx_queue_notify.notify_one();
                    }
                },
            );
        }

        let mut resp = msg;
        resp.status = moto_rt::E_OK;
        let _ = sender.send(resp).await;
        Ok(())
    }

    pub async fn tcp_close(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        // We respond OK immediately (if the socket is found, etc.),
        // and do all the cleanup work later/asynchronously.
        let socket_id = msg.handle;
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let mut socket_ref = moto_socket.borrow_mut();
            if socket_ref.base.client_sender.remote_handle() != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }
            // Check that the socket is indeed tcp before unwrapping.
            if !matches!(socket_ref.state, SocketState::Tcp(_)) {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidData.into());
            }
        }

        Self::close_tcp_socket_inner(moto_socket, Some(msg)).await;
        Ok(())
    }
}

/// Refill the pool at `key` until its deficit is gone. Departures from the
/// Listen state spawn this; under memory pressure the refill parks instead,
/// and pressure's recovery task re-arms it here once availability returns.
pub(in crate::runtime::net) fn spawn_pool_replenish(
    runtime: NetRuntime,
    weak_listener: Weak<RefCell<TcpListener>>,
    device_idx: usize,
    socket_addr: SocketAddr,
    key: super::super::backlog::PoolKey,
) {
    moto_async::LocalRuntime::spawn(async move {
        // The whole deficit, which a burst that emptied the pool has just
        // deepened. Every departure replenishes, so re-reading it each time
        // is what keeps them from overshooting together; a torn-down
        // listener owes nothing, and this loop ends.
        while runtime.backlog.deficit(key) > 0 {
            if runtime
                .pressure
                .defer_replenish(key, &weak_listener, device_idx, socket_addr)
            {
                break;
            }
            if MotoSocket::create_tcp_listening_socket(
                weak_listener.clone(),
                device_idx,
                socket_addr,
            )
            .await
            .is_err()
            {
                break;
            }
        }
    });
}

/// Convert a socket address into the IPv6 (IPv4-mapped) octets + port form used
/// by [`moto_sys_io::stats::TcpSocketStatsV1`].
fn addr_to_octets(addr: &SocketAddr) -> ([u8; 16], u16) {
    match addr {
        SocketAddr::V4(v4) => (v4.ip().to_ipv6_mapped().octets(), v4.port()),
        SocketAddr::V6(v6) => (v6.ip().octets(), v6.port()),
    }
}

const fn tcp_protocol_state(state: NetstackTcpState) -> TcpProtocolState {
    match state {
        NetstackTcpState::Closed => TcpProtocolState::Closed,
        NetstackTcpState::Listen => TcpProtocolState::Listen,
        NetstackTcpState::SynSent => TcpProtocolState::SynSent,
        NetstackTcpState::SynReceived => TcpProtocolState::SynReceived,
        NetstackTcpState::Established => TcpProtocolState::Established,
        NetstackTcpState::FinWait1 => TcpProtocolState::FinWait1,
        NetstackTcpState::FinWait2 => TcpProtocolState::FinWait2,
        NetstackTcpState::CloseWait => TcpProtocolState::CloseWait,
        NetstackTcpState::Closing => TcpProtocolState::Closing,
        NetstackTcpState::LastAck => TcpProtocolState::LastAck,
        NetstackTcpState::TimeWait => TcpProtocolState::TimeWait,
    }
}

const _: () = {
    assert!(size_of::<TcpProtocolState>() == size_of::<NetstackTcpState>());
    assert!(align_of::<TcpProtocolState>() == align_of::<NetstackTcpState>());
    assert!(tcp_protocol_state(NetstackTcpState::Closed) as u32 == NetstackTcpState::Closed as u32);
    assert!(tcp_protocol_state(NetstackTcpState::Listen) as u32 == NetstackTcpState::Listen as u32);
    assert!(
        tcp_protocol_state(NetstackTcpState::SynSent) as u32 == NetstackTcpState::SynSent as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::SynReceived) as u32
            == NetstackTcpState::SynReceived as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::Established) as u32
            == NetstackTcpState::Established as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::FinWait1) as u32 == NetstackTcpState::FinWait1 as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::FinWait2) as u32 == NetstackTcpState::FinWait2 as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::CloseWait) as u32
            == NetstackTcpState::CloseWait as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::Closing) as u32 == NetstackTcpState::Closing as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::LastAck) as u32 == NetstackTcpState::LastAck as u32
    );
    assert!(
        tcp_protocol_state(NetstackTcpState::TimeWait) as u32 == NetstackTcpState::TimeWait as u32
    );
};

/// Best-effort mapping of a socket's netstack state (plus our shutdown flags) onto
/// the Motor OS-level [`api_net::TcpState`] reported in stats.
fn api_tcp_state(
    netstack_state: moto_netstack::socket::tcp::State,
    rx_closed: bool,
    tx_closed: bool,
    has_listener: bool,
) -> api_net::TcpState {
    use api_net::TcpState as T;
    use moto_netstack::socket::tcp::State as S;

    match netstack_state {
        S::Closed => T::Closed,
        S::Listen => T::Listening,
        S::SynSent => T::Connecting,
        S::SynReceived => {
            // Still owned by a listener => an incoming connection awaiting accept.
            if has_listener {
                T::PendingAccept
            } else {
                T::Connecting
            }
        }
        // Established: reflect which directions are still open.
        S::Established => match (rx_closed, tx_closed) {
            (false, false) => T::ReadWrite,
            (false, true) => T::ReadOnly,
            (true, false) => T::WriteOnly,
            (true, true) => T::Closed,
        },
        // Remote initiated the close; we may still have data to send.
        S::CloseWait | S::LastAck => {
            if tx_closed {
                T::Closed
            } else {
                T::WriteOnly
            }
        }
        // We initiated the close; we may still have data to receive.
        S::FinWait1 | S::FinWait2 | S::Closing | S::TimeWait => {
            if rx_closed {
                T::Closed
            } else {
                T::ReadOnly
            }
        }
    }
}

struct TcpRxBuf {
    page: moto_ipc::io_channel::IoPage,
    consumed: usize,
}

impl TcpRxBuf {
    fn new(page: moto_ipc::io_channel::IoPage) -> Self {
        Self { page, consumed: 0 }
    }

    fn consume(&mut self, sz: usize) {
        self.consumed += sz;
        assert!(self.consumed <= moto_ipc::io_channel::PAGE_SIZE);
    }

    fn bytes_mut(&self) -> &mut [u8] {
        &mut self.page.bytes_mut()[self.consumed..]
    }
}

struct TcpTxBuf {
    page: moto_ipc::io_channel::IoPage,
    len: usize,
    consumed: usize,
}

impl TcpTxBuf {
    fn bytes(&self) -> &[u8] {
        &self.page.bytes()[self.consumed..self.len]
    }

    fn consume(&mut self, sz: usize) {
        self.consumed += sz;
        assert!(self.consumed <= self.len);
    }

    fn is_consumed(&self) -> bool {
        self.consumed == self.len
    }
}

/// Debug-only tests of the code above, run inside a live sys-io. See
/// [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use crate::self_test::{SelfTest, st_assert_eq};
    use moto_netstack::socket::tcp::{CongestionControl, Socket, SocketBuffer};

    pub(crate) const TESTS: &[SelfTest] = &[(
        "net::socket::tcp::cubic_is_the_default_controller",
        cubic_is_the_default_controller,
    )];

    /// A fresh netstack socket must already be Cubic, before anyone sets it.
    ///
    /// `new_socket` names Cubic explicitly, which a dropped `socket-tcp-cubic`
    /// feature would break at compile time. The default is the other half:
    /// nothing would fail to compile if the build reverted to `None`, whose
    /// window is `usize::MAX`, and only this notices that.
    fn cubic_is_the_default_controller() -> Result<(), String> {
        let buffer = || SocketBuffer::new(vec![0; 64]);
        st_assert_eq!(
            Socket::new(buffer(), buffer()).congestion_control(),
            CongestionControl::Cubic
        );
        Ok(())
    }
}
