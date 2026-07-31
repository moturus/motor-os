use std::io::ErrorKind;
use std::rc::Weak;
use std::{cell::RefCell, net::SocketAddr, rc::Rc, task::Poll};

use moto_io_internal::udp_queues::{UdpDefragmentingQueue, UdpFragmentingQueue};
use moto_sys::SysHandle;
use moto_sys_io::api_net;

use super::super::NetRuntime;
use super::MotoSocket;
use super::SocketBase;
use super::SocketState;

pub struct UdpState {
    ephemeral_port: Option<u16>,
    tx_queue: UdpDefragmentingQueue,
    rx_queue: Rc<RefCell<UdpFragmentingQueue>>,
}

impl MotoSocket {
    pub(super) fn with_udp_smoltcp_socket<F, T>(socket: &Rc<RefCell<Self>>, f: F) -> T
    where
        F: FnOnce(u64, &mut smoltcp::socket::udp::Socket<'static>, &mut UdpState) -> T,
    {
        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, state } = socket_mut;

        let udp_state = state.unwrap_udp();

        let mut inner = base.runtime.inner.borrow_mut();
        let device = &mut inner.devices[base.device_idx];
        let smoltcp_socket = device
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket<'static>>(base.smoltcp_handle);
        f(base.socket_id(), smoltcp_socket, udp_state)
    }

    pub fn create_udp_socket(
        runtime: &NetRuntime,
        device_idx: usize,
        socket_addr: SocketAddr,
        ephemeral_port: Option<u16>,
        client_sender: moto_ipc::io_channel::Sender,
        subchannel_mask: u64,
    ) -> std::io::Result<Rc<RefCell<MotoSocket>>> {
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
            vec![0; 65536],
        );
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
            vec![0; 65536],
        );

        let mut smoltcp_socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);
        smoltcp_socket
            .bind(socket_addr)
            .map_err(|_| ErrorKind::InvalidInput)?;
        let runtime = runtime.clone();

        let (socket_id, smoltcp_handle) = {
            let mut inner = runtime.inner.borrow_mut();
            (
                inner.next_socket_id(),
                inner.devices[device_idx].sockets.add(smoltcp_socket),
            )
        };

        let base = SocketBase::new(
            socket_id,
            runtime,
            device_idx,
            smoltcp_handle,
            socket_addr,
            client_sender,
        );
        MotoSocket::new(
            base,
            SocketState::Udp(UdpState {
                ephemeral_port,
                tx_queue: UdpDefragmentingQueue::new(),
                rx_queue: Rc::new(RefCell::new(UdpFragmentingQueue::new(
                    socket_id,
                    subchannel_mask,
                ))),
            }),
        )
    }

    async fn udp_rx(weak_socket: Weak<RefCell<MotoSocket>>) {
        let weak_clone = weak_socket.clone();

        // Poll for packet.
        let cont = std::future::poll_fn(move |cx| {
            let Some(socket) = weak_clone.upgrade() else {
                return Poll::Ready(false); // The socket is gone.
            };

            Self::with_udp_smoltcp_socket(&socket, |socket_id, smoltcp_socket, udp_state| {
                if smoltcp_socket.can_recv() {
                    let (buf, metadata) = smoltcp_socket.recv().unwrap();
                    let addr: SocketAddr =
                        crate::runtime::net::config::socket_addr_from_endpoint(metadata.endpoint);
                    log::debug!(
                        "UDP socket 0x{:x} got {} bytes from {:?}",
                        u64::from(socket_id),
                        buf.len(),
                        addr
                    );
                    udp_state.rx_queue.borrow_mut().push_back(buf, addr);
                    Poll::Ready(true)
                } else {
                    #[cfg(debug_assertions)]
                    log::debug!("rx empty/pending: task id: {}", moto_async::task_id(cx));

                    smoltcp_socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await;

        if !cont {
            return;
        }

        let Some(socket) = weak_socket.upgrade() else {
            return; // The socket is gone.
        };
        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, state } = socket_mut;
        let udp_state = state.unwrap_udp();

        let sender = base.client_sender.clone();
        let page_allocator = async |subchannel_mask| {
            sender
                .alloc_page(subchannel_mask)
                .await
                .map_err(|err| err as u16)
        };

        let rx_queue = udp_state.rx_queue.clone();
        let socket_id = base.socket_id();
        drop(socket_ref);
        // Not held across the sends below (see `udp_tx`). `rx_queue` and
        // `sender` are separately owned, so what is already queued still
        // reaches the client, as an orphan if it has closed the socket.
        drop(socket);

        // Note: rx_queue is only used in this fn, so we can safely keep the borrow.
        while let Some(mut msg) = rx_queue.borrow_mut().pop_front_async(page_allocator).await {
            msg.status = moto_rt::E_OK;

            log::debug!("RX msg for UDP socket 0x{socket_id:x}");
            let _ = sender.send(msg).await;
        }

        Self::spawn_udp_rx_task(weak_socket);
    }

    fn spawn_udp_rx_task(weak_socket: Weak<RefCell<MotoSocket>>) {
        // Note: because the socket has been created, there is no need to sync this
        // task, as no RX packets will be losts.
        let _ = moto_async::LocalRuntime::spawn(async move {
            Self::udp_rx(weak_socket).await;
        });
    }

    // TODO: this message was used before async channel was a thing. Maybe we don't need it now?
    async fn udp_tx_ack(sender: &moto_ipc::io_channel::Sender, socket_id: u64) {
        let mut msg = moto_ipc::io_channel::Msg::new();
        msg.command = api_net::NetCmd::UdpSocketTxRxAck.as_u16();
        msg.handle = socket_id;
        let _ = sender.send(msg).await;
    }

    pub(super) fn on_udp_socket_drop(base: &mut super::SocketBase, state: &mut UdpState) {
        // UDP sockets don't linger.
        let runtime = base.runtime.clone();
        let device_idx = base.device_idx;
        let socket_addr = base.local_addr;
        let smoltcp_handle = base.smoltcp_handle;
        let socket_id = base.socket_id;

        log::debug!("UDP socket 0x{socket_id:x} dropped.");

        runtime
            .stats
            .udp_sockets
            .set(runtime.stats.udp_sockets.get() - 1);

        {
            let mut inner = runtime.inner.borrow_mut();

            #[cfg(debug_assertions)]
            {
                let sockets = &mut inner.devices[device_idx].sockets;
                if sockets
                    .get_mut::<smoltcp::socket::udp::Socket>(smoltcp_handle)
                    .send_queue()
                    != 0
                {
                    // TODO: linger? UDP sockets don't linger, but we may?
                    log::debug!("Dropped UDP socket 0x{socket_id:x} with unsent bytes.");
                } else {
                    log::debug!("Dropped UDP socket 0x{socket_id:x}.");
                }
            }

            inner.devices[device_idx].remove_udp_addr_in_use(&socket_addr);
            if let Some(port) = state.ephemeral_port {
                inner.devices[device_idx].free_ephemeral_udp_port(port);
            }
        }
    }

    /* ----------------------------------- API calls ------------------------------------ */
    pub async fn udp_bind_for_remote(
        runtime: &NetRuntime,
        mut msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let remote_addr = api_net::get_socket_addr(&msg.payload);
        if remote_addr.ip().is_unspecified() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let Some((device_idx, local_ip_addr)) = runtime.find_route(&remote_addr.ip()) else {
            log::debug!(
                "sys-io: 0x{:x}: UDP route to {:?} not found",
                sender.remote_handle().as_u64(),
                remote_addr
            );
            return Err(ErrorKind::NetworkUnreachable.into());
        };

        let local_addr = SocketAddr::new(local_ip_addr, 0);
        api_net::put_socket_addr(&mut msg.payload, &local_addr);
        Self::udp_bind_on_device(runtime, msg, sender, local_addr, device_idx).await
    }

    pub async fn udp_bind(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_addr = api_net::get_socket_addr(&msg.payload);
        let ip_addr = socket_addr.ip();
        if ip_addr.is_unspecified() {
            // We don't allow binding to an unspecified addr (yet?).
            return Err(ErrorKind::InvalidInput.into());
        }

        let Some(device_idx) = runtime.inner.borrow().ip_addresses.get(&ip_addr).copied() else {
            #[cfg(debug_assertions)]
            log::debug!("IP addr {ip_addr:?} not found");
            return Err(ErrorKind::InvalidInput.into());
        };

        Self::udp_bind_on_device(runtime, msg, sender, socket_addr, device_idx).await
    }

    async fn udp_bind_on_device(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
        mut socket_addr: SocketAddr,
        device_idx: usize,
    ) -> std::io::Result<()> {
        let mut runtime_mut = runtime.inner.borrow_mut();
        let mut resp = msg;
        let ip_addr = socket_addr.ip();

        // Allocate/assign port, if needed.
        let mut allocated_port = None;
        if socket_addr.port() == 0 {
            let local_port = match runtime_mut.devices[device_idx].get_ephemeral_udp_port(&ip_addr)
            {
                Some(port) => port,
                None => {
                    log::warn!("get_ephemeral_udp_port({ip_addr:?}) failed");

                    return Err(ErrorKind::OutOfMemory.into());
                }
            };
            socket_addr.set_port(local_port);
            api_net::put_socket_addr(&mut resp.payload, &socket_addr);
            allocated_port = Some(local_port);
        }

        if let Err(err) = runtime_mut.devices[device_idx].add_udp_addr_in_use(socket_addr) {
            if let Some(port) = allocated_port {
                runtime_mut.devices[device_idx].free_ephemeral_udp_port(port);
            }
            return Err(err);
        }
        drop(runtime_mut);

        let subchannel_mask = api_net::io_subchannel_mask(msg.payload.args_8()[23]);

        let udp_socket = match Self::create_udp_socket(
            runtime,
            device_idx,
            socket_addr,
            allocated_port,
            sender.clone(),
            subchannel_mask,
        ) {
            Ok(socket) => socket,
            Err(err) => {
                let mut runtime_mut = runtime.inner.borrow_mut();
                runtime_mut.devices[device_idx].remove_udp_addr_in_use(&socket_addr);
                if let Some(port) = allocated_port {
                    runtime_mut.devices[device_idx].free_ephemeral_udp_port(port);
                }
                return Err(err);
            }
        };

        let socket_id = udp_socket.borrow().socket_id();
        let weak_socket = Rc::downgrade(&udp_socket);

        runtime
            .stats
            .udp_sockets
            .set(runtime.stats.udp_sockets.get() + 1);
        runtime
            .stats
            .total_udp_sockets
            .set(runtime.stats.total_udp_sockets.get() + 1);

        #[cfg(debug_assertions)]
        log::debug!(
            "new udp socket 0x{socket_id:x} on {:?}, conn: 0x{:x}",
            socket_addr,
            sender.remote_handle().as_u64()
        );

        resp.handle = socket_id;
        resp.status = moto_rt::E_OK;
        let _ = sender.send(resp).await;

        Self::spawn_udp_rx_task(weak_socket);

        Ok(())
    }

    /// Reclaim the io page of a TX request that cannot be delivered, and
    /// answer nothing.
    ///
    /// A UDP TX is fire-and-forget (`msg.id` is always zero), so the client
    /// has no waiter for it and the generic error reply in `on_msg` would
    /// echo the request back holding the page index reclaimed here: the
    /// client then frees the same page a second time through its orphan
    /// handler, or -- if it still has the socket -- mistakes the reply for an
    /// inbound datagram. An empty datagram carries no page at all, so the
    /// size field, not the page index, decides whether there is one.
    fn drop_undeliverable_udp_tx(
        runtime: &NetRuntime,
        msg: &moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) {
        if msg.payload.args_16()[10] != 0 {
            let _io_page = sender.get_page(msg.payload.shared_pages()[11]);
        }
        runtime
            .stats
            .udp_tx_dropped
            .set(runtime.stats.udp_tx_dropped.get() + 1);
    }

    pub async fn udp_tx(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;

        let Some(socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            log::debug!("UDP TX: no socket 0x{socket_id:x}");
            Self::drop_undeliverable_udp_tx(runtime, &msg, sender);
            return Ok(());
        };

        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, state } = socket_mut;

        if base.sender().remote_handle() != sender.remote_handle() {
            log::debug!("UDP TX: wrong client for socket");
            Self::drop_undeliverable_udp_tx(runtime, &msg, sender);
            return Ok(());
        }

        #[allow(irrefutable_let_patterns)]
        let SocketState::Udp(udp_state) = state else {
            log::debug!("UDP TX: bad socket kind");
            Self::drop_undeliverable_udp_tx(runtime, &msg, sender);
            return Ok(());
        };

        let fragment_id = msg.payload.args_16()[9];
        if udp_state
            .tx_queue
            .push_back(msg, |idx| sender.get_page(idx).map_err(|err| err.into()))
            .is_err()
        {
            if let Ok(pid) = moto_sys::SysObj::get_pid(sender.remote_handle()) {
                log::info!("Killing process 0x{:x} due to bad UDP fragment", pid);
            } else {
                log::warn!("UDP TX: can't determine client PID.");
            };
            let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
            return Ok(());
        }

        let mut need_udp_tx_ack = fragment_id != 0;

        let mut inner_ref = runtime.inner.borrow_mut();
        let mut inner = &mut *inner_ref;
        let smol_socket = inner.devices[base.device_idx]
            .sockets
            .get_mut::<smoltcp::socket::udp::Socket>(base.smoltcp_handle);

        loop {
            let Ok(datagram) = udp_state.tx_queue.next_datagram() else {
                if let Ok(pid) = moto_sys::SysObj::get_pid(sender.remote_handle()) {
                    log::info!("Killing process 0x{:x} due to bad UDP fragment", pid);
                } else {
                    log::warn!("UDP TX: can't determine client PID.");
                };
                let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
                return Ok(());
            };

            let Some(datagram) = datagram else {
                break;
            };

            if let Err(err) = smol_socket.send_slice(datagram.slice(), datagram.addr) {
                match err {
                    smoltcp::socket::udp::SendError::Unaddressable => {
                        log::debug!("Cannot send UDP packet to {:?}.", datagram.addr);
                        // TODO: do we need to notify the user?
                        continue;
                    }
                    smoltcp::socket::udp::SendError::BufferFull => {
                        // Can't send the packet: re-insert it into the pending queue.
                        udp_state.tx_queue.push_front(datagram);
                        log::debug!("reinserting UDP dgram");
                        break;
                    }
                }
            } else {
                need_udp_tx_ack = true;
                log::debug!(
                    "UDP: socket 0x{:x} sent {} bytes to {:?}",
                    u64::from(socket_id),
                    datagram.slice().len(),
                    datagram.addr
                );
                base.device_notify.notify_one();
            }
        }

        core::mem::drop(inner_ref);
        core::mem::drop(socket_ref);
        // The ack parks when the client's ring is full, and the close the
        // client sends next is then handled first. A reference held across
        // that await defers `MotoSocket::drop`, and with it the release of
        // the bound address, past the client's next bind of it.
        core::mem::drop(socket);

        if need_udp_tx_ack {
            // Notify the client that we've consumed the io page.
            Self::udp_tx_ack(sender, socket_id).await;
        }
        Ok(())
    }

    pub async fn udp_getsockopt(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let socket_ref = moto_socket.borrow();
            if socket_ref.base.sender().remote_handle() != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }
            if !matches!(socket_ref.state, SocketState::Udp(_)) {
                return Err(ErrorKind::InvalidData.into());
            }
        }

        if msg.payload.args_64()[0] != api_net::UDP_OPTION_TTL {
            return Err(ErrorKind::InvalidInput.into());
        }

        let ttl =
            Self::with_udp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
                smoltcp_socket.hop_limit().unwrap_or(64)
            });
        let mut resp = msg;
        resp.payload.args_32_mut()[0] = ttl as u32;
        resp.status = moto_rt::E_OK;
        core::mem::drop(moto_socket); // Not held across the await; see `udp_tx`.
        let _ = sender.send(resp).await;
        Ok(())
    }

    pub async fn udp_setsockopt(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;
        let Some(moto_socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        {
            let socket_ref = moto_socket.borrow();
            if socket_ref.base.sender().remote_handle() != sender.remote_handle() {
                return Err(ErrorKind::NotFound.into());
            }
            if !matches!(socket_ref.state, SocketState::Udp(_)) {
                return Err(ErrorKind::InvalidData.into());
            }
        }

        if msg.payload.args_64()[0] != api_net::UDP_OPTION_TTL {
            return Err(ErrorKind::InvalidInput.into());
        }
        let ttl = msg.payload.args_32()[2];
        if ttl == 0 || ttl > u8::MAX as u32 {
            return Err(ErrorKind::InvalidInput.into());
        }

        Self::with_udp_smoltcp_socket(&moto_socket, |_socket_id, smoltcp_socket, _state| {
            smoltcp_socket.set_hop_limit(Some(ttl as u8));
        });
        let mut resp = msg;
        resp.status = moto_rt::E_OK;
        core::mem::drop(moto_socket); // Not held across the await; see `udp_tx`.
        let _ = sender.send(resp).await;
        Ok(())
    }

    pub async fn udp_socket_drop(
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
            let socket_mut = &mut *socket_ref;
            let Self { base, state } = socket_mut;

            if base.sender().remote_handle() != sender.remote_handle() {
                log::debug!("UDP TX: wrong client for socket");
                return Err(ErrorKind::NotFound.into());
            }

            #[allow(irrefutable_let_patterns)]
            let SocketState::Udp(_) = state else {
                log::debug!("UDP Drop: bad socket kind");
                return Err(ErrorKind::InvalidInput.into());
            };
        }

        // UDP sockets are simple: just drop. TCP sockets may linger, which is a pain...
        {
            let mut runtime_ref = runtime.inner.borrow_mut();
            assert!(
                runtime_ref
                    .clients
                    .get_mut(&sender.remote_handle())
                    .unwrap()
                    .sockets
                    .remove(&socket_id)
            );

            runtime_ref.sockets.remove(&socket_id);
        }

        // `sockets` is the only lasting owner, so the removal above must leave
        // this clone the last one: the address is free once this message has
        // been handled only because `MotoSocket::drop` runs as it dies.
        #[cfg(debug_assertions)]
        assert_eq!(
            1,
            Rc::strong_count(&moto_socket),
            "udp socket 0x{socket_id:x}: a live reference defers its release"
        );

        Ok(())
    }
}
