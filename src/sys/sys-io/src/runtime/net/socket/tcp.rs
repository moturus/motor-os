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
}

impl MotoSocket {
    pub(super) fn with_tcp_smoltcp_socket<F, T>(socket: &Rc<RefCell<Self>>, f: F) -> T
    where
        F: FnOnce(u64, &mut smoltcp::socket::tcp::Socket<'static>) -> T,
    {
        let socket_ref = socket.borrow_mut();

        let mut inner = socket_ref.base.runtime.inner.borrow_mut();
        let device = &mut inner.devices[socket_ref.base.device_idx];
        let smoltcp_socket = device
            .sockets
            .get_mut::<smoltcp::socket::tcp::Socket<'static>>(socket_ref.base.smoltcp_handle);
        f(socket_ref.socket_id(), smoltcp_socket)
    }

    fn create_tcp_socket(
        runtime: &NetRuntime,
        device_idx: usize,
        socket_addr: SocketAddr,
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
            socket_addr,
            client,
        );

        let tcp_socket = Rc::new(RefCell::new(MotoSocket::new(
            base,
            SocketState::Tcp(TcpState {
                ephemeral_port: None,
                subchannel_mask,
                tcp_listener: None,
                connect_req: None,
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
                let SocketState::Tcp(state) = state else {
                    panic!()
                };

                tcp_listener_mut.add_listening_socket(base.socket_id());
                state.ephemeral_port = tcp_listener_mut.ephemeral_port();
                state.tcp_listener = Some(weak_listener.clone());
            }

            Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket| {
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
            Self::listen(connected_tx, weak_socket).await;

            // Spawn an extra one once the previous one is connected.
            let _ = connected_rx.await;
            Self::create_tcp_listening_socket(weak_listener, device_idx, socket_addr).await;
        });

        Ok(())
    }

    async fn listen(
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

            Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket| {
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
            Self::on_incoming_connection(weak_socket);
            return;
        }

        // Then wait for either a successful remote connection, or a
        // transition to a "going down" state.
        let weak_clone = weak_socket.clone();
        let established = std::future::poll_fn(move |cx| {
            let Some(moto_socket) = weak_clone.upgrade() else {
                return Poll::Ready(None);
            };

            Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket| {
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
            Self::on_incoming_connection(weak_socket);
            return;
        }
    }

    fn on_incoming_connection(weak_socket: Weak<RefCell<Self>>) {
        todo!()
    }

    async fn socket_task(weak_socket: Weak<RefCell<Self>>) {
        use smoltcp::socket::tcp::State;

        let socket_id = {
            let Some(moto_socket) = weak_socket.upgrade() else {
                return;
            };
            moto_socket.borrow().socket_id()
        };
        log::debug!("socket task for 0x{socket_id:x}");

        let mut prev_state = State::SynSent;
        loop {
            let weak_clone = weak_socket.clone();
            let new_state = std::future::poll_fn(move |cx| {
                let Some(moto_socket) = weak_clone.upgrade() else {
                    return Poll::Ready(None);
                };

                Self::with_tcp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket| {
                    match smoltcp_socket.state() {
                        State::Closed => Poll::Ready(Some(State::Closed)),
                        State::Listen => {
                            panic!()
                        }

                        smoltcp::socket::tcp::State::SynSent => {
                            smoltcp_socket.register_recv_waker(cx.waker());
                            Poll::Pending
                        }

                        State::SynReceived => todo!(),
                        State::Established => todo!(),
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
                log::debug!("TCP socket {prev_state:?} => {new_state:?}");
                prev_state = new_state;
            }
        }
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
                Self::with_tcp_smoltcp_socket(&moto_socket, |socket_id, smoltcp_socket| {
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
                let SocketState::Tcp(state) = state else {
                    panic!()
                };

                state.ephemeral_port = Some(local_port);
                state.connect_req = Some(msg);

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
            Self::socket_task(weak_socket).await;
        });

        Ok(())
    }
}
