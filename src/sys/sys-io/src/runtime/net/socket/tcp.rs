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

use moto_sys::SysHandle;
use moto_sys_io::api_net;

use crate::runtime::net::tcp_listener::TcpListener;

use super::super::EphemeralTcpPort;
use super::super::NetRuntime;
use super::MotoSocket;
use super::SocketBase;
use super::SocketState;

/// For how long sockets linger upon close.
const DEFAULT_LINGER_SECS: u32 = 60;

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
    // The underlying smoltcp socket can't have its RX closed.
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
    // The underlying smoltcp socket may still have bytes to send.
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
        Self::with_tcp_smoltcp_socket(moto_socket, |_socket_id, smoltcp_socket, _state| {
            smoltcp_socket.set_hop_limit(Some(ttl));
        });
    }

    #[inline]
    pub(super) fn with_tcp_smoltcp_socket<F, T>(socket: &Rc<RefCell<Self>>, f: F) -> T
    where
        F: FnOnce(u64, &mut smoltcp::socket::tcp::Socket<'static>, &mut TcpState) -> T,
    {
        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, state } = socket_mut;

        let tcp_state = state.unwrap_tcp_mut();

        let mut inner = base.runtime.inner.borrow_mut();
        let device = &mut inner.devices[base.device_idx];
        let smoltcp_socket = device
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket<'static>>(base.smoltcp_handle);
        f(base.socket_id, smoltcp_socket, tcp_state)
    }

    /// Build a best-effort stats snapshot for this TCP socket, used by the
    /// `sys-io-stats-service` socket listing (see [`crate::runtime::net::stats`]).
    pub(crate) fn collect_tcp_stats(
        moto_socket: &Rc<RefCell<Self>>,
    ) -> moto_sys_io::stats::TcpSocketStatsV1 {
        use moto_sys_io::stats::TcpSocketStatsV1;

        // Read the smoltcp state first: with_tcp_smoltcp_socket() borrows both the
        // socket and the runtime inner, so we must not hold a borrow across it.
        let smoltcp_state =
            Self::with_tcp_smoltcp_socket(moto_socket, |_socket_id, smoltcp_socket, _state| {
                smoltcp_socket.state()
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
                smoltcp_state,
                tcp_state.rx_closed,
                tcp_state.tx_closed,
                tcp_state.tcp_listener.is_some(),
            ),
            smoltcp_state,
        }
    }

    fn create_tcp_socket(
        runtime: &NetRuntime,
        device_idx: usize,
        local_addr: SocketAddr,
        client_sender: moto_ipc::io_channel::Sender,
        subchannel_mask: u64,
    ) -> Rc<RefCell<MotoSocket>> {
        // 128KB buffers: the receive buffer caps the advertised TCP window and
        // the send buffer caps unacked bytes in flight; 32KB sat exactly at the
        // measured 321 MiB/s * ~100us BDP (see net-opportunities.md N1).
        const TCP_SOCKET_BUFFER_SIZE: usize = 128 * 1024;
        let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUFFER_SIZE]);
        let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; TCP_SOCKET_BUFFER_SIZE]);

        let mut smoltcp_socket = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);
        // smoltcp_socket.bind(socket_addr).unwrap();

        let (socket_id, smoltcp_handle) = {
            let mut inner = runtime.inner.borrow_mut();
            (
                inner.next_socket_id(),
                inner.devices[device_idx].sockets.add(smoltcp_socket),
            )
        };

        let base = SocketBase::new(
            socket_id,
            runtime.clone(),
            device_idx,
            smoltcp_handle,
            local_addr,
            client_sender,
        );

        base.runtime
            .stats
            .tcp_sockets
            .set(base.runtime.stats.tcp_sockets.get() + 1);
        base.runtime
            .stats
            .total_tcp_sockets
            .set(base.runtime.stats.total_tcp_sockets.get() + 1);

        MotoSocket::new(
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
        )
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
        let weak_socket = {
            let mut tcp_listener_mut = tcp_listener.borrow_mut();

            let moto_socket = Self::create_tcp_socket(
                tcp_listener_mut.runtime(),
                device_idx,
                socket_addr,
                tcp_listener_mut.client_sender().clone(),
                0,
            );

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

            Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket, _state| {
                // Smoltcp does not expire SynReceived sockets without a timeout.
                // Note: the numbers below are only for Listen/SynReceived sockets. They are
                // re-set to different numbers on established sockets.
                smoltcp_socket.set_timeout(Some(smoltcp::time::Duration::from_millis(5_000)));
                smoltcp_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(10_000)));
                smoltcp_socket.listen(socket_addr).unwrap();
                log::debug!(
                    "new TCP socket 0x{socket_id:x} listening on {socket_addr:?} for conn 0x{:x}",
                    tcp_listener_mut.client_sender().remote_handle().as_u64(),
                );
            });

            Rc::downgrade(&moto_socket)
        };

        // Spawn the listening task.
        moto_async::LocalRuntime::spawn(async move {
            let (connected_tx, connected_rx) = moto_async::oneshot();

            // Replenish the listening pool as soon as this socket leaves the Listen state.
            moto_async::LocalRuntime::spawn(async move {
                let _ = connected_rx.await;
                let _ =
                    Self::create_tcp_listening_socket(weak_listener, device_idx, socket_addr).await;
            });

            Self::tcp_listen_task(connected_tx, weak_socket).await;
        });

        Ok(())
    }

    async fn tcp_listen_task(
        connected_tx: moto_async::oneshot::Sender<()>,
        weak_socket: Weak<RefCell<Self>>, // Weak because called asynchronously.
    ) {
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

            Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket, _state| {
                match smoltcp_socket.state() {
                    smoltcp::socket::tcp::State::Listen => {
                        #[cfg(debug_assertions)]
                        log::debug!(
                            "Socket 0x{socket_id:x} in state Listen: task_id: {}",
                            moto_async::task_id(cx)
                        );
                        smoltcp_socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }
                    val => Poll::Ready(Some(val)),
                }
            })
        })
        .await;

        connected_tx.send(());
        runtime
            .stats
            .tcp_listening_sockets
            .set(runtime.stats.tcp_listening_sockets.get() - 1);

        let Some(socket_state) = socket_state else {
            log::debug!("tcp: listen: socket gone.");
            return;
        };

        log::debug!("tcp: listen: socket 0x{socket_id:x}: {socket_state:?}");

        if socket_state == smoltcp::socket::tcp::State::Established {
            Self::on_incoming_connection(weak_socket).await;
            return;
        }

        // Then wait for either a successful remote connection, or a
        // transition to a "going down" state.
        let weak_clone = weak_socket.clone();
        let established = std::future::poll_fn(move |cx| {
            let Some(moto_socket) = weak_clone.upgrade() else {
                return Poll::Ready(None);
            };

            Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                match smoltcp_socket.state() {
                    smoltcp::socket::tcp::State::Listen => {
                        // If SynReceived socket gets RST, smoltcp brings it back into Listen state.
                        log::debug!(
                            "tcp: listen: socket 0x{socket_id:x} was reset back to Listen; dropping"
                        );
                        Poll::Ready(Some(false))
                    }

                    smoltcp::socket::tcp::State::SynSent => {
                        // This is totally unexpected.
                        log::error!(
                            "tcp: listen: socket 0x{socket_id:x}: bad state {:?}",
                            smoltcp_socket.state()
                        );
                        Poll::Ready(Some(false))
                    }

                    smoltcp::socket::tcp::State::SynReceived => {
                        smoltcp_socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }

                    smoltcp::socket::tcp::State::Established => Poll::Ready(Some(true)),

                    smoltcp::socket::tcp::State::Closed
                    | smoltcp::socket::tcp::State::FinWait1
                    | smoltcp::socket::tcp::State::FinWait2
                    | smoltcp::socket::tcp::State::CloseWait
                    | smoltcp::socket::tcp::State::Closing
                    | smoltcp::socket::tcp::State::LastAck
                    | smoltcp::socket::tcp::State::TimeWait => Poll::Ready(Some(false)),
                }
            })
        })
        .await;

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
            Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                assert_eq!(
                    smoltcp_socket.state(),
                    smoltcp::socket::tcp::State::Established
                );

                // Same as on the connect side (on_socket_connected): without these,
                // remotely dropped sockets may hang around indefinitely.
                smoltcp_socket.set_timeout(Some(smoltcp::time::Duration::from_millis(120_000)));
                smoltcp_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(120_000)));
                smoltcp_socket.set_nagle_enabled(false); // A good idea, generally.
                // Delayed ACKs (also set on the connect side; keep in sync).
                // Sub-MSS ACKs wait up to 10ms so a prompt reply carries the
                // ACK instead of a separate pure-ACK packet (halves egress
                // packets in request/response traffic). Bulk transfers are
                // unaffected: smoltcp force-expires the timer once un-ACKed
                // data exceeds one MSS, and window-update ACKs bypass it.
                smoltcp_socket.set_ack_delay(Some(smoltcp::time::Duration::from_millis(10)));

                let remote_endpoint = smoltcp_socket.remote_endpoint().unwrap();
                crate::runtime::net::config::socket_addr_from_endpoint(remote_endpoint)
            })
        };

        let tcp_listener = {
            let mut socket_ref = moto_socket.borrow_mut();
            let socket_id = socket_ref.socket_id();

            let tcp_state = socket_ref.state.unwrap_tcp_mut();
            tcp_state.remote_addr = Some(remote_addr);

            let tcp_listener = tcp_state.tcp_listener.take().unwrap();
            tcp_listener.upgrade().unwrap()
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
        use smoltcp::socket::tcp::State;

        let socket_id = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };
            moto_socket.borrow().socket_id()
        };
        log::debug!("tcp_connect_task for socket 0x{socket_id:x}.");

        let mut prev_state = State::SynSent;
        loop {
            let weak_clone = weak_socket.clone();
            let new_state = std::future::poll_fn(move |cx| {
                let Some(moto_socket) = weak_clone.upgrade() else {
                    return Poll::Ready(None);
                };

                Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                    match smoltcp_socket.state() {
                        State::Closed => Poll::Ready(Some(State::Closed)),
                        State::Listen | State::SynReceived => {
                            panic!("Unexpected state {:?}", smoltcp_socket.state())
                        }

                        smoltcp::socket::tcp::State::SynSent => {
                            smoltcp_socket.register_recv_waker(cx.waker());
                            Poll::Pending
                        }

                        State::Established => Poll::Ready(Some(State::Established)),
                        State::FinWait1 => todo!(),
                        State::FinWait2 => todo!(),
                        State::CloseWait => todo!(),
                        State::Closing => todo!(),
                        State::LastAck => todo!(),
                        State::TimeWait => todo!(),
                    }
                })
            })
            .await;

            let Some(new_state) = new_state else {
                return;
            };

            if prev_state != new_state {
                log::debug!("TCP socket 0x{socket_id:x}: {prev_state:?} => {new_state:?}");

                match new_state {
                    State::Closed => {
                        Self::on_connect_failed(weak_socket).await;
                        return;
                    }
                    State::Listen => todo!(),
                    State::SynSent => todo!(),
                    State::SynReceived => todo!(),
                    State::Established => {
                        Self::on_socket_connected(weak_socket).await;
                        return;
                    }
                    State::FinWait1 => todo!(),
                    State::FinWait2 => todo!(),
                    State::CloseWait => todo!(),
                    State::Closing => todo!(),
                    State::LastAck => todo!(),
                    State::TimeWait => todo!(),
                }

                prev_state = new_state;
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
            msg.status = moto_rt::E_TIMED_OUT;

            (base.client_sender.clone(), msg)
        };

        let _ = sender.send(msg).await;
    }

    async fn on_socket_connected(weak_socket: Weak<RefCell<Self>>) {
        let Some(moto_socket) = weak_socket.upgrade() else {
            return;
        };

        Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket, _state| {
            log::debug!("Socket 0x{socket_id:x} connected.");
            // Without these, remotely dropped sockets may hang around indefinitely.
            smoltcp_socket.set_timeout(Some(smoltcp::time::Duration::from_millis(120_000)));
            smoltcp_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(120_000)));
            smoltcp_socket.set_nagle_enabled(false); // A good idea, generally.
            // Delayed ACKs — see the comment on the accept side
            // (on_incoming_connection); keep the two in sync.
            smoltcp_socket.set_ack_delay(Some(smoltcp::time::Duration::from_millis(10)));
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

                Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                    if smoltcp_socket.can_recv() {
                        log::debug!("RX: socket 0x{socket_id:x} can_recv.");
                        return Poll::Ready(true);
                    }
                    if !smoltcp_socket.may_recv() {
                        log::debug!(
                            "RX: socket 0x{socket_id:x} !may_recv: {:?}.",
                            smoltcp_socket.state()
                        );
                        return Poll::Ready(false);
                    }

                    #[cfg(debug_assertions)]
                    {
                        let (state, can_recv) = (smoltcp_socket.state(), smoltcp_socket.can_recv());
                        log::debug!(
                            "RX: socket 0x{_socket_id:x} can_recv: {can_recv} in {state:?}"
                        );
                    }

                    smoltcp_socket.register_recv_waker(cx.waker());
                    Poll::Pending
                })
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
            let page = sender.alloc_page(subchannel_mask).await.unwrap();

            // Step 4: read bytes from the socket. Note that we read at most one page,
            // because to read more, we need to check if the socket has more bytes to read,
            // which is done in step 1 above.
            let mut rx_buf = TcpRxBuf::new(page);
            {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    break;
                };

                Self::with_tcp_smoltcp_socket(&moto_socket, |_, smoltcp_socket, tcp_state| {
                    if !tcp_state.rx_closed {
                        match smoltcp_socket.recv_slice(rx_buf.bytes_mut()) {
                            Ok(len) => {
                                rx_buf.consume(len);
                                tcp_state.stat_rx_bytes += len as u64;
                                log::debug!("TCP socket 0x{socket_id:x} RX {len} bytes.");
                            }
                            Err(err) => {
                                if smoltcp_socket.may_recv() {
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
            // 0.78 MiB/s instead of 16+). smoltcp's `window_to_update()`
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
            Self::with_tcp_smoltcp_socket(&moto_socket, |_, smoltcp_socket, tcp_state| {
                if !smoltcp_socket.may_send() {
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

                Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                    log::debug!(
                        "TX polling socket 0x{socket_id:x} in {:?}",
                        smoltcp_socket.state()
                    );
                    if smoltcp_socket.can_send() {
                        // Has space in the TX buffer.
                        Poll::Ready(Some(true))
                    } else if !(smoltcp_socket.may_send()) {
                        Poll::Ready(Some(false))
                    } else {
                        // Have to wait.
                        smoltcp_socket.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                })
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

                    let may_send = Self::with_tcp_smoltcp_socket(
                        &moto_socket,
                        |_socket_id, smoltcp_socket, _state| smoltcp_socket.may_send(),
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

                Self::with_tcp_smoltcp_socket(
                    &moto_socket,
                    |socket_id, smoltcp_socket, tcp_state| {
                        while smoltcp_socket.can_send() {
                            let mut tx_buf = if let Some(x) = tcp_state.tx_queue.pop_front() {
                                x
                            } else {
                                break;
                            };

                            match smoltcp_socket.send_slice(tx_buf.bytes()) {
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
                                Err(_err) => todo!(),
                            }
                        }
                    },
                );

                moto_socket.borrow().base.device_notify.notify_one();
            } // loop
        } // loop

        log::debug!("Socket 0x{socket_id:x} TX task done.");
        {
            if let Some(moto_socket) = weak_socket.upgrade() {
                let device_notify = Self::with_tcp_smoltcp_socket(
                    &moto_socket,
                    |socket_id, smoltcp_socket, state| {
                        let device_notify = if smoltcp_socket.may_send() {
                            smoltcp_socket.close();
                            true
                        } else {
                            false
                        };
                        state.tx_closed = true;
                        state.tx_queue.clear();
                        if let Some(lingerer) = state.lingerer.take() {
                            lingerer.send(());
                        }

                        device_notify
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
            Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket, state| {
                smoltcp_socket.abort();
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

        // Need to determine when to abort and when to notify. The logic is convoluted.
        // Can it be made more clear?
        let abort =
            Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket, state| {
                let abort = if smoltcp_socket.may_send() {
                    if state.tx_queue.is_empty() && smoltcp_socket.send_queue() == 0 {
                        true
                    } else {
                        false
                    }
                } else {
                    true
                };

                if abort || Some(0) == state.linger_secs {
                    true
                } else {
                    false
                }
            });

        let (linger_secs, delayed_notify) = {
            let mut socket_ref = moto_socket.borrow_mut();
            let state = socket_ref.unwrap_tcp_mut();
            let linger_secs = state.linger_secs.take();

            state.tx_closed = true;
            state.rx_closed = true;
            state.tx_queue_notify.notify_one();

            if abort {
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
                let (sender, receiver) = moto_async::oneshot();
                socket_ref.unwrap_tcp_mut().lingerer = Some(sender);

                let mut runtime_ref = socket_ref.base.runtime.inner.borrow_mut();
                // Note: if initiated from the client done handling in net.rs,
                // the socket won't be with the client hashmap anymore.
                runtime_ref
                    .clients
                    .get_mut(&socket_ref.base.sender().remote_handle())
                    .unwrap()
                    .sockets
                    .remove(&socket_ref.base.socket_id);

                receiver
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

    async fn tcp_linger_task(
        moto_socket: Rc<RefCell<Self>>,
        deadline: moto_async::Instant,
        lingerer: moto_async::oneshot::Receiver<()>,
    ) {
        use futures::FutureExt;

        let socket_id = moto_socket.borrow().socket_id();

        futures::select! {
        _ = lingerer.fuse() => {
            log::debug!("Lingering socket 0x{socket_id:x}: TX done.");
        },
        _ = moto_async::sleep_until(deadline.into()).fuse() => {
            log::debug!("Lingering socket 0x{socket_id:x}: timed out.");
        },
        }

        while moto_async::Instant::now() < deadline {
            if Self::with_tcp_smoltcp_socket(&moto_socket, |_, smoltcp_socket, _| {
                smoltcp_socket.is_open()
            }) {
                log::debug!("Lingering socket 0x{socket_id:x}: lingering a bit more.");
                moto_async::sleep(std::time::Duration::from_secs(1)).await;
            } else {
                break;
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
            );

            // Set timeout, if needed.
            if let Some(timeout) = api_net::tcp_stream_connect_timeout(&msg) {
                Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket, _state| {
                    let now = moto_rt::time::Instant::now();
                    if timeout <= now {
                        // We check this upon receiving sqe; the thread got preempted or something.
                        // Just use an arbitrary small timeout.
                        smoltcp_socket.set_timeout(Some(smoltcp::time::Duration::from_micros(10)));
                    } else {
                        smoltcp_socket.set_timeout(Some(smoltcp::time::Duration::from_micros(
                            timeout.duration_since(now).as_micros() as u64,
                        )));
                    }
                });
            }

            // Issue smoltcp connect request.
            {
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
                base.runtime.inner.borrow_mut().devices[base.device_idx]
                    .tcp_connect(base.smoltcp_handle, local_addr, remote_addr)
                    .map_err(|err| {
                        log::error!("Unexpected smoltcp connect error: {err:?}.");

                        std::io::Error::from(ErrorKind::ConnectionRefused)
                    })?;
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
                let nagle_enabled = Self::with_tcp_smoltcp_socket(
                    &moto_socket,
                    |_socket_id, smoltcp_socket, _state| smoltcp_socket.nagle_enabled(),
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
                let hop_limit = Self::with_tcp_smoltcp_socket(
                    &moto_socket,
                    |_socket_id, smoltcp_socket, _state| smoltcp_socket.hop_limit(),
                );
                let ttl = if let Some(hop_limit) = hop_limit {
                    hop_limit as u32
                } else {
                    64 // This is what smoltcp documentation implies.
                };
                resp.payload.args_32_mut()[0] = ttl;
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
            Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                smoltcp_socket.set_nagle_enabled(!nodelay);
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

            Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                smoltcp_socket.set_hop_limit(Some(ttl as u8));
            });
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
            Self::with_tcp_smoltcp_socket(
                &moto_socket,
                |_socket_id, smoltcp_socket, state| -> () {
                    if shut_rd {
                        state.rx_closed = true;
                    }
                    if shut_wr {
                        // Close the write half gracefully, applying the same
                        // linger logic as a full socket close (see
                        // `close_tcp_socket_inner`): mark TX as closed and wake
                        // the TX task. Any bytes still queued to send are not
                        // dropped -- `tcp_write_task` flushes them out to the
                        // wire first and only then issues `smoltcp::close()`
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

/// Convert a socket address into the IPv6 (IPv4-mapped) octets + port form used
/// by [`moto_sys_io::stats::TcpSocketStatsV1`].
fn addr_to_octets(addr: &SocketAddr) -> ([u8; 16], u16) {
    match addr {
        SocketAddr::V4(v4) => (v4.ip().to_ipv6_mapped().octets(), v4.port()),
        SocketAddr::V6(v6) => (v6.ip().octets(), v6.port()),
    }
}

/// Best-effort mapping of a socket's smoltcp state (plus our shutdown flags) onto
/// the Motor OS-level [`api_net::TcpState`] reported in stats.
fn api_tcp_state(
    smoltcp_state: smoltcp::socket::tcp::State,
    rx_closed: bool,
    tx_closed: bool,
    has_listener: bool,
) -> api_net::TcpState {
    use api_net::TcpState as T;
    use smoltcp::socket::tcp::State as S;

    match smoltcp_state {
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
