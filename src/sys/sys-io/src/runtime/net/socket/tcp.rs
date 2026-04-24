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

    fn create_tcp_socket(
        runtime: &NetRuntime,
        device_idx: usize,
        local_addr: SocketAddr,
        client: SysHandle,
        subchannel_mask: u64,
    ) -> Rc<RefCell<MotoSocket>> {
        let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 16384 * 2]);
        let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 16384 * 2]);

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
            client,
        );

        let tcp_socket = Rc::new(RefCell::new(MotoSocket::new(
            base,
            SocketState::Tcp(TcpState {
                ephemeral_port: None,
                subchannel_mask,
                tcp_listener: None,
                connect_req: None,
                remote_addr: None,
                tx_queue: VecDeque::new(),
                tx_queue_notify: Rc::new(moto_async::LocalNotify::new()),
                stat_tx_bytes: 0,
                stat_rx_bytes: 0,
            }),
        )));

        let socket_id = tcp_socket.borrow().socket_id();
        {
            let mut inner = runtime.inner.borrow_mut();
            inner.sockets.insert(socket_id, tcp_socket.clone());
            inner
                .clients
                .get_mut(&client)
                .unwrap()
                .sockets
                .insert(socket_id);
        }

        tcp_socket
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
                tcp_listener_mut.client(),
                0,
            );

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
                smoltcp_socket.listen(socket_addr).unwrap();
                log::debug!(
                    "new TCP socket 0x{socket_id:x} listening on {socket_addr:?} for conn 0x{:x}",
                    tcp_listener_mut.client().as_u64(),
                );
            });

            Rc::downgrade(&moto_socket)
        };

        // Spawn the listening task.

        moto_async::LocalRuntime::spawn(async move {
            let (connected_tx, connected_rx) = moto_async::oneshot();
            Self::tcp_listen_task(connected_tx, weak_socket).await;

            // Spawn an extra one once the previous one is connected.
            let _ = connected_rx.await;
            Self::create_tcp_listening_socket(weak_listener, device_idx, socket_addr).await;
        });

        Ok(())
    }

    async fn tcp_listen_task(
        connected_tx: moto_async::oneshot::Sender<()>,
        weak_socket: Weak<RefCell<Self>>, // Weak because called asynchronously.
    ) {
        let socket_id = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };
            moto_socket.borrow().socket_id()
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
                        smoltcp_socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }
                    val => Poll::Ready(Some(val)),
                }
            })
        })
        .await;

        connected_tx.send(());

        let Some(socket_state) = socket_state else {
            log::debug!("tcp: listen: socket gone.");
            return;
        };

        log::debug!("tcp: listen: {socket_state:?}");

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
                    smoltcp::socket::tcp::State::Listen | smoltcp::socket::tcp::State::SynSent => {
                        panic!()
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
            return;
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

                smoltcp_socket.set_nagle_enabled(false); // A good idea, generally.
                smoltcp_socket.set_ack_delay(None);

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
                    State::Closed => todo!(),
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

    async fn on_socket_connected(weak_socket: Weak<RefCell<Self>>) {
        let Some(moto_socket) = weak_socket.upgrade() else {
            return;
        };

        Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket, _state| {
            log::debug!("Socket 0x{socket_id:x} connected.");
            // Without these, remotely dropped sockets may hang around indefinitely.
            smoltcp_socket.set_timeout(Some(smoltcp::time::Duration::from_millis(5_000)));
            smoltcp_socket.set_keep_alive(Some(smoltcp::time::Duration::from_millis(10_000)));
            smoltcp_socket.set_nagle_enabled(false); // A good idea, generally.
            smoltcp_socket.set_ack_delay(None);
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

            let Some(sender) = base.sender() else {
                log::debug!(
                    "No client for newly connected socket 0x{:x}",
                    base.socket_id
                );
                return;
            };

            log::debug!("Socket 0x{:x} connected.", base.socket_id);
            (sender, msg)
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

        let (socket_id, sender, subchannel_mask) = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };
            let socket_ref = moto_socket.borrow();
            (
                socket_ref.base.socket_id,
                socket_ref.base.sender().unwrap(),
                socket_ref.unwrap_tcp().subchannel_mask,
            )
        };
        log::debug!("TCP RX task for socket 0x{socket_id:x}");

        loop {
            // Step 1: wait for the socket to become readable.
            let socket_state = std::future::poll_fn(|cx| {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    return Poll::Ready(None);
                };

                Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                    let (state, can_recv) = (smoltcp_socket.state(), smoltcp_socket.can_recv());
                    log::debug!("RX: socket 0x{_socket_id:x} can_recv: {can_recv} in {state:?}");

                    if !can_recv {
                        match state {
                            // These states should happen before the receive task is spawned.
                            smoltcp::socket::tcp::State::Listen
                            | smoltcp::socket::tcp::State::SynSent
                            | smoltcp::socket::tcp::State::SynReceived => {
                                panic!("Unexpected socket state {state:?}.");
                            }

                            // These states may still receive data from the remote endpoint.
                            smoltcp::socket::tcp::State::Established
                            | smoltcp::socket::tcp::State::FinWait1
                            | smoltcp::socket::tcp::State::FinWait2 => {
                                smoltcp_socket.register_recv_waker(cx.waker());
                                Poll::Pending
                            }

                            // These states happen after we received FIN from the remote,
                            // and so we should not expect any data.
                            smoltcp::socket::tcp::State::CloseWait
                            | smoltcp::socket::tcp::State::Closing
                            | smoltcp::socket::tcp::State::LastAck
                            | smoltcp::socket::tcp::State::TimeWait
                            | smoltcp::socket::tcp::State::Closed => {
                                Poll::Ready(Some((state, can_recv)))
                            }
                        }
                    } else {
                        Poll::Ready(Some((state, can_recv)))
                    }
                })
            })
            .await;

            let Some((state, can_recv)) = socket_state else {
                log::debug!("Socket 0x{socket_id:x}: RX task done.");
                return; // The socket is no more.
            };

            if !can_recv {
                // The socket is no longer readable (we received FIN).
                log::debug!("Socket 0x{socket_id:x}: RX task done.");
                return;
            }

            // Step 3: allocate a page.
            let page = sender.alloc_page(subchannel_mask).await.unwrap();

            // Step 4: read bytes from the socket. Note that we read at most one page,
            // because to read more, we need to check if the socket has more bytes to read,
            // which is done in step 1 above.
            let mut rx_buf = TcpRxBuf::new(page);
            {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    return;
                };

                Self::with_tcp_smoltcp_socket(&moto_socket, |_, smoltcp_socket, tcp_state| {
                    match smoltcp_socket.recv_slice(rx_buf.bytes_mut()) {
                        Ok(len) => {
                            rx_buf.consume(len);
                            tcp_state.stat_rx_bytes += len as u64;
                            log::debug!("TCP socket 0x{socket_id:x} RX {len} bytes.");
                        }
                        Err(err) => {
                            log::warn!(
                                "Unexpected error {err:?} reading bytes from socket 0x{socket_id:x}"
                            );
                        }
                    }
                });
            }
            if rx_buf.consumed == 0 {
                continue; // An error occurred: stop processing?
            }

            // Step 5. Send bytes to the client.
            {
                let (io_page, sz) = (rx_buf.page, rx_buf.consumed);
                let mut msg = moto_sys_io::api_net::tcp_stream_rx_msg(socket_id, io_page, sz, 0);
                msg.status = moto_rt::E_OK;
                let _ = sender.send(msg).await;
            }
        } // loop
    }

    async fn tcp_write_task(weak_socket: Weak<RefCell<Self>>) {
        let tx_queue_notify = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };

            let socket_ref = moto_socket.borrow();
            let tcp_state = socket_ref.unwrap_tcp();
            tcp_state.tx_queue_notify.clone()
        };

        loop {
            let socket_state = std::future::poll_fn(|cx| {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    return Poll::Ready(None);
                };

                Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
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

            let Some(may_send) = socket_state else {
                return; // THe socket is no more.
            };

            // Step 2: wait for bytes to TX.
            loop {
                {
                    let Some(moto_socket) = weak_socket.upgrade() else {
                        return;
                    };

                    let socket_ref = moto_socket.borrow();
                    let tcp_state = socket_ref.unwrap_tcp();

                    if tcp_state.tx_queue.is_empty() {
                        if !may_send {
                            return; // We shut down TX pipe.
                        }
                    } else {
                        break;
                    }
                }

                // We must wait inside the loop, otherwise the loop will busyloop.
                tx_queue_notify.notified().await;
            } // loop

            // Step 3: TX bytes out.
            {
                let Some(moto_socket) = weak_socket.upgrade() else {
                    return;
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
                sender.remote_handle(),
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
        // Note: we need to get the page so that it is freed.
        let page_idx = msg.payload.shared_pages()[0];
        let page = if let Ok(page) = sender.get_page(page_idx) {
            page
        } else {
            return Err(ErrorKind::InvalidData.into());
        };

        let socket_id = msg.handle;
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let mut socket_ref = moto_socket.borrow_mut();
            if socket_ref.base.client != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }

            let sz = msg.payload.args_64()[1] as usize;
            if sz > moto_ipc::io_channel::PAGE_SIZE {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidData.into());
            }

            // Check that the socket is indeed tcp before unwrapping.
            if !matches!(socket_ref.state, SocketState::Tcp(_)) {
                // TODO: drop the connection?
                return Err(ErrorKind::InvalidData.into());
            }

            let tcp_state = socket_ref.unwrap_tcp_mut();
            tcp_state.stat_tx_bytes += sz as u64;
            tcp_state.tx_queue.push_back(TcpTxBuf {
                page,
                len: sz,
                consumed: 0,
            });

            tcp_state.tx_queue_notify.notify_one();
        }

        Ok(())
    }

    pub async fn tcp_rx_ack_received(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        log::debug!("TCP RX ACK: should we do anything here?");

        Ok(())
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
