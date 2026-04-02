use std::io::ErrorKind;
use std::rc::Weak;
use std::{cell::RefCell, net::SocketAddr, rc::Rc, task::Poll};

use moto_io_internal::udp_queues::{UdpDefragmentingQueue, UdpFragmentingQueue};
use moto_sys::SysHandle;
use moto_sys_io::api_net;

use super::super::NetRuntime;
use super::BaseSocket;
use super::MotoSocket;
use super::SocketKind;

pub struct UdpSocket {
    ephemeral_port: Option<u16>,
    tx_queue: UdpDefragmentingQueue,
    rx_queue: Rc<RefCell<UdpFragmentingQueue>>,
}

impl UdpSocket {
    pub(super) fn on_drop(&mut self, runtime: &NetRuntime, client: SysHandle) {
        /*
        if let Some(msg) = self.rx_queue.borrow_mut().take_msg() {
            panic!(); // We never push messages back to rx queue.
            /*
            // Need to free the stranded page.
            let sz = msg.payload.args_16()[10];
            if sz != 0 {
                let page_idx = msg.payload.shared_pages()[11];
                let mut inner = runtime.inner.borrow_mut();
                if let Some(client) = inner.clients.get(&client) {
                    let _page = client.sender.get_page(page_idx).unwrap();
                }
            }
            */
        }
        */
    }
}

impl MotoSocket {
    pub fn create_udp_socket(
        runtime: &NetRuntime,
        device_idx: usize,
        socket_addr: SocketAddr,
        client: SysHandle,
        subchannel_mask: u64,
    ) -> Rc<RefCell<MotoSocket>> {
        let rx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
            vec![0; 65536],
        );
        let tx_buffer = smoltcp::socket::udp::PacketBuffer::new(
            vec![smoltcp::socket::udp::PacketMetadata::EMPTY; 64],
            vec![0; 65536],
        );

        let mut smoltcp_socket = smoltcp::socket::udp::Socket::new(rx_buffer, tx_buffer);
        smoltcp_socket.bind(socket_addr).unwrap();
        let runtime = runtime.clone();

        let (socket_id, smoltcp_handle) = {
            let mut inner = runtime.inner.borrow_mut();
            (
                inner.next_socket_id(),
                inner.devices[device_idx].sockets.add(smoltcp_socket),
            )
        };

        let base = BaseSocket::new(
            socket_id,
            runtime,
            device_idx,
            smoltcp_handle,
            socket_addr,
            client,
        );
        Rc::new(RefCell::new(MotoSocket::new(
            base,
            SocketKind::Udp(UdpSocket {
                ephemeral_port: None,
                tx_queue: UdpDefragmentingQueue::new(),
                rx_queue: Rc::new(RefCell::new(UdpFragmentingQueue::new(
                    socket_id,
                    subchannel_mask,
                ))),
            }),
        )))
    }

    /*
    pub async fn udp_send_to(
        &self,
        buf: &[u8],
        endpoint: smoltcp::wire::IpEndpoint,
    ) -> std::io::Result<usize> {
        let Self { base, kind } = self;

        #[allow(irrefutable_let_patterns)]
        let SocketKind::Udp(udp_socket) = kind else {
            panic!();
        };
        std::future::poll_fn(|cx| {
            let notify = base.device_notify();

            base.with_smoltcp_socket::<_, smoltcp::socket::udp::Socket, _>(|smoltcp_socket| {
                if smoltcp_socket.can_send() {
                    let max_payload = smoltcp_socket.payload_send_capacity().min(buf.len());
                    smoltcp_socket
                        .send_slice(&buf[..max_payload], endpoint)
                        .unwrap();
                    notify.notify_one();
                    Poll::Ready(Ok(max_payload))
                } else {
                    smoltcp_socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await
    }

    pub async fn udp_recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, smoltcp::wire::IpEndpoint)> {
        let Self { base, kind } = self;

        #[allow(irrefutable_let_patterns)]
        let SocketKind::Udp(udp_socket) = kind else {
            panic!();
        };

        std::future::poll_fn(move |cx| {
            base.with_smoltcp_socket::<_, smoltcp::socket::udp::Socket, _>(|smoltcp_socket| {
                if smoltcp_socket.can_recv() {
                    let (len, metadata) = smoltcp_socket.recv_slice(buf).unwrap();
                    Poll::Ready(Ok((len, metadata.endpoint)))
                } else {
                    smoltcp_socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await
    }
    */

    async fn udp_rx(weak_socket: Weak<RefCell<MotoSocket>>) {
        let weak_clone = weak_socket.clone();

        // Poll for packet.
        let cont = std::future::poll_fn(move |cx| {
            let Some(socket) = weak_clone.upgrade() else {
                return Poll::Ready(false); // The socket is gone.
            };
            let mut socket_ref = socket.borrow_mut();
            let socket_mut = &mut *socket_ref;
            let Self { base, kind } = socket_mut;

            #[allow(irrefutable_let_patterns)]
            let SocketKind::Udp(udp_socket) = kind else {
                panic!();
            };

            let socket_id = base.socket_id();
            base.with_smoltcp_socket::<_, smoltcp::socket::udp::Socket, _>(|smoltcp_socket| {
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
                    udp_socket.rx_queue.borrow_mut().push_back(buf, addr);
                    Poll::Ready(true)
                } else {
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
        let Self { base, kind } = socket_mut;

        let sender = {
            if let Some(conn) = base.runtime.inner.borrow().clients.get(&base.client) {
                conn.sender.clone()
            } else {
                return;
            }
        };

        let page_allocator = async |subchannel_mask| {
            sender
                .alloc_page(subchannel_mask)
                .await
                .map_err(|err| err as u16)
        };

        #[allow(irrefutable_let_patterns)]
        let SocketKind::Udp(udp_socket) = kind else {
            panic!();
        };

        let rx_queue = udp_socket.rx_queue.clone();
        let socket_id = base.socket_id();
        drop(socket_ref);

        // Note: rx_queue is only used in this fn, so we can safely keep the borrow.
        while let Some(mut msg) = rx_queue.borrow_mut().pop_front_async(page_allocator).await {
            msg.status = moto_rt::E_OK;

            log::debug!("RX msg for UDP socket 0x{socket_id:x}");
            let _ = sender.send(msg).await;
        }

        Self::spawn_udp_rx_task(weak_socket);
    }

    fn spawn_udp_rx_task(weak_socket: Weak<RefCell<MotoSocket>>) {
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

    /* ----------------------------------- API calls ------------------------------------ */
    pub async fn udp_bind(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let mut socket_addr = moto_sys_io::api_net::get_socket_addr(&msg.payload);
        let mut inner = runtime.inner.borrow_mut();
        let mut resp = msg;

        // Verify that the IP is valid (if present) before the socket is created.
        let ip_addr = socket_addr.ip();

        if ip_addr.is_unspecified() {
            // We don't allow binding to an unspecified addr (yet?).
            return Err(ErrorKind::InvalidInput.into());
        }
        let device_idx = {
            match inner.ip_addresses.get(&ip_addr) {
                Some(idx) => *idx,
                None => {
                    #[cfg(debug_assertions)]
                    log::debug!("IP addr {ip_addr:?} not found");

                    return Err(ErrorKind::InvalidInput.into());
                }
            }
        };

        // Allocate/assign port, if needed.
        let mut allocated_port = None;
        if socket_addr.port() == 0 {
            let local_port = match inner.devices[device_idx].get_ephemeral_udp_port(&ip_addr) {
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

        inner.devices[device_idx].add_udp_addr_in_use(socket_addr)?;
        drop(inner);

        let subchannel_mask = api_net::io_subchannel_mask(msg.payload.args_8()[23]);

        let udp_socket = Self::create_udp_socket(
            runtime,
            device_idx,
            socket_addr,
            sender.remote_handle(),
            subchannel_mask,
        );

        let socket_id = udp_socket.borrow().socket_id();
        let weak_socket = Rc::downgrade(&udp_socket);
        {
            let mut inner = runtime.inner.borrow_mut();
            inner.sockets.insert(socket_id, udp_socket);
            inner
                .clients
                .get_mut(&sender.remote_handle())
                .unwrap()
                .sockets
                .insert(socket_id);
        }

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: new udp socket on {:?}, conn: 0x{:x}",
            socket_addr,
            sender.remote_handle().as_u64()
        );

        let mut resp = msg;
        resp.handle = socket_id;
        resp.status = moto_rt::E_OK;
        let _ = sender.send(resp).await;

        Self::spawn_udp_rx_task(weak_socket);

        Ok(())
    }

    pub async fn udp_tx(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;

        let Some(mut socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            let page_idx = msg.payload.shared_pages()[11];
            let _io_page = sender.get_page(page_idx); // Get the page out to deallocate.
            return Err(ErrorKind::NotFound.into());
        };

        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, kind } = socket_mut;

        if base.client() != sender.remote_handle() {
            log::debug!("UDP TX: wrong client for socket");
            let page_idx = msg.payload.shared_pages()[11];
            let _io_page = sender.get_page(page_idx); // Get the page out to deallocate.
            return Err(ErrorKind::NotFound.into());
        }

        #[allow(irrefutable_let_patterns)]
        let SocketKind::Udp(udp_socket) = kind else {
            log::debug!("UDP TX: bad socket kind");
            let page_idx = msg.payload.shared_pages()[11];
            let _io_page = sender.get_page(page_idx); // Get the page out to deallocate.
            return Err(ErrorKind::InvalidInput.into());
        };

        let fragment_id = msg.payload.args_16()[9];
        if udp_socket
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
            let Ok(datagram) = udp_socket.tx_queue.next_datagram() else {
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
                        udp_socket.tx_queue.push_front(datagram);
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

        if need_udp_tx_ack {
            // Notify the client that we've consumed the io page.
            Self::udp_tx_ack(sender, socket_id).await;
        }
        Ok(())
    }

    pub async fn udp_socket_drop(
        runtime: &NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let socket_id = msg.handle;

        let Some(mut socket) = runtime.inner.borrow().sockets.get(&socket_id).cloned() else {
            return Err(ErrorKind::NotFound.into());
        };

        let mut socket_ref = socket.borrow_mut();
        let socket_mut = &mut *socket_ref;
        let Self { base, kind } = socket_mut;

        if base.client() != sender.remote_handle() {
            log::debug!("UDP TX: wrong client for socket");
            return Err(ErrorKind::NotFound.into());
        }

        #[allow(irrefutable_let_patterns)]
        let SocketKind::Udp(udp_socket) = kind else {
            log::debug!("UDP Drop: bad socket kind");
            return Err(ErrorKind::InvalidInput.into());
        };

        drop(socket_ref);
        let socket = runtime
            .inner
            .borrow_mut()
            .sockets
            .remove(&socket_id)
            .unwrap();

        Self::on_drop(socket);

        Ok(())
    }
}
