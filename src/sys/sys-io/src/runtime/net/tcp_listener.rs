use super::socket::MotoSocket;
use moto_sys::SysHandle;
use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    io::ErrorKind,
    net::SocketAddr,
    rc::Rc,
};

const DEFAULT_NUM_LISTENING_SOCKETS: usize = 4;
const MAX_NUM_LISTENING_SOCKETS: usize = 32;

pub(super) struct TcpListener {
    listener_id: u64,
    runtime: super::NetRuntime,

    // What the user gave us, with one caveat:
    // - either a fully specified IPADDR:PORT,
    // - or 0.0.0.0:PORT.
    // - or, if the user gave us IPADDR:0, this will have IPADDR:EPHEMERAL_PORT.
    socket_addr: SocketAddr,
    client: SysHandle, // Denormalized for quick validation.

    // If listener::accept() is called first, it's sqe will be added
    // to pending_accepts.
    pending_accepts: VecDeque<(moto_ipc::io_channel::Msg, SysHandle)>,

    // Connected sockets that did not yet emit the accept QE.
    // When the socket is accepted, the oneshot should be fired.
    pending_sockets: VecDeque<(u64, SocketAddr, moto_async::oneshot::Sender<()>)>,

    // Pure listening sockets. We need to track them to drop when the listener is dropped.
    listening_sockets: HashSet<u64>,

    // Only present if the IP addr is specified. Which means that
    // in multi-device listeners this value is None.
    ephemeral_tcp_port: Option<Rc<super::EphemeralTcpPort>>,

    // All specific IPs this listener listens on, with their devices.
    listening_on: Vec<(SocketAddr, usize)>,

    // Will be applied to all new sockets.
    ttl: u8,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        assert!(
            self.pending_accepts.is_empty()
                && self.pending_sockets.is_empty()
                && self.listening_sockets.is_empty()
        );
    }
}

impl TcpListener {
    pub(super) fn runtime(&self) -> &super::NetRuntime {
        &self.runtime
    }

    pub(super) fn client(&self) -> SysHandle {
        self.client
    }

    pub(super) fn ephemeral_port(&self) -> Option<Rc<super::EphemeralTcpPort>> {
        self.ephemeral_tcp_port.clone()
    }

    // Called on conn drop.
    pub(super) fn hard_reset(&mut self) {
        self.pending_accepts.clear();
        self.pending_sockets.clear();
        self.listening_sockets.clear();
    }

    fn resolve_bind_addresses(
        runtime: &super::NetRuntime,
        socket_addr: &mut SocketAddr,
    ) -> std::io::Result<(
        Vec<(SocketAddr, usize)>,
        Option<Rc<super::EphemeralTcpPort>>,
    )> {
        let mut runtime_mut = runtime.inner.borrow_mut();
        let ip_addr = socket_addr.ip();

        let (l, p) = if ip_addr.is_unspecified() {
            if socket_addr.port() == 0 {
                // We don't allow listening on an unspecified port if the IP is also unspecified.
                return Err(ErrorKind::InvalidInput.into());
            }

            let mut listening_on = Vec::with_capacity(runtime_mut.ip_addresses.len());
            for (addr, device_idx) in &runtime_mut.ip_addresses {
                listening_on.push((SocketAddr::new(*addr, socket_addr.port()), *device_idx));
            }

            (listening_on, None)
        } else {
            let device_idx = match runtime_mut.ip_addresses.get(&ip_addr) {
                Some(idx) => *idx,
                None => {
                    #[cfg(debug_assertions)]
                    log::debug!("IP addr {ip_addr:?} not found");
                    return Err(ErrorKind::InvalidInput.into());
                }
            };
            if socket_addr.port() == 0 {
                let ephemeral_tcp_port = runtime_mut
                    .get_ephemeral_tcp_port(&runtime, device_idx, ip_addr)
                    .ok_or_else(|| {
                        log::info!("get_ephemeral_port({ip_addr:?}) failed");
                        std::io::Error::from(ErrorKind::OutOfMemory)
                    })?;
                socket_addr.set_port(ephemeral_tcp_port.port);

                (vec![(*socket_addr, device_idx)], Some(ephemeral_tcp_port))
            } else {
                (vec![(*socket_addr, device_idx)], None)
            }
        };

        Ok((l, p))
    }

    async fn spawn_listening_sockets(
        listener: Rc<RefCell<Self>>,
        num_listeners: usize,
    ) -> std::io::Result<()> {
        let (runtime, listening_on) = {
            let this = listener.borrow();
            (this.runtime.clone(), this.listening_on.clone())
        };

        for (addr, device_idx) in listening_on {
            for _ in 0..num_listeners {
                MotoSocket::create_tcp_listening_socket(Rc::downgrade(&listener), device_idx, addr)
                    .await?;
            }
        }

        Ok(())
    }

    pub(super) fn add_listening_socket(&mut self, socket_id: u64) {
        self.listening_sockets.insert(socket_id);
    }

    pub(super) async fn on_socket_connected(
        this: Rc<RefCell<Self>>,
        moto_socket: Rc<RefCell<MotoSocket>>,
        accepted_tx: moto_async::oneshot::Sender<()>,
    ) {
        let (socket_id, remote_addr) = {
            let socket_ref = moto_socket.borrow();
            (
                socket_ref.socket_id(),
                socket_ref.unwrap_tcp().remote_addr().unwrap(),
            )
        };

        log::debug!("TCP Listener: incoming conn {remote_addr:?} on socket 0x{socket_id:x}");

        let accepted = {
            let mut this_ref = this.borrow_mut();
            assert!(this_ref.listening_sockets.remove(&socket_id));
            MotoSocket::set_ttl(&moto_socket, this_ref.ttl);

            if let Some((msg, client)) = this_ref.pending_accepts.pop_front() {
                Some((msg, accepted_tx, client))
            } else {
                this_ref
                    .pending_sockets
                    .push_back((socket_id, remote_addr, accepted_tx));
                None
            }
        };

        if let Some((accept_req, accepted_tx, client)) = accepted {
            Self::process_matched_accept(
                this,
                socket_id,
                remote_addr,
                accepted_tx,
                accept_req,
                client,
            )
            .await
        }
    }

    async fn process_matched_accept(
        this: Rc<RefCell<Self>>,
        socket_id: u64,
        remote_addr: SocketAddr,
        accepted_tx: moto_async::oneshot::Sender<()>,
        accept_req: moto_ipc::io_channel::Msg,
        client: SysHandle,
    ) {
        let (sender, moto_socket) = {
            let mut this_ref = this.borrow_mut();
            let mut runtime_ref = this_ref.runtime.inner.borrow_mut();

            let sender = runtime_ref.clients.get(&client).unwrap().sender.clone();
            let moto_socket = runtime_ref.sockets.get(&socket_id).cloned();
            (sender, moto_socket)
        };

        let Some(moto_socket) = moto_socket else {
            this.borrow_mut()
                .pending_accepts
                .push_front((accept_req, client));
            return;
        };

        {
            let mut socket_ref = moto_socket.borrow_mut();
            socket_ref
                .unwrap_tcp_mut()
                .set_subchannel_mask(accept_req.payload.args_64()[0]);
            socket_ref.set_client(client);
        }

        log::debug!("Incoming TCP conn 0x{socket_id:x} <= {remote_addr:?} accepted.");

        let mut resp = accept_req;
        resp.handle = socket_id;
        moto_sys_io::api_net::put_socket_addr(&mut resp.payload, &remote_addr);
        resp.status = moto_rt::E_OK;

        let _ = sender.send(resp).await;
        accepted_tx.send(()).unwrap();
    }

    /* ----------------------------------- API calls ------------------------------------ */
    pub(super) async fn bind(
        runtime: &super::NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let mut resp = msg;
        let mut socket_addr = moto_sys_io::api_net::get_socket_addr(&msg.payload);

        {
            let mut runtime_mut = runtime.inner.borrow_mut();

            // Verify that we are not listening on that address yet.
            for listener in runtime_mut.tcp_listeners.values() {
                if listener.borrow().socket_addr == socket_addr {
                    return Err(ErrorKind::AddrInUse.into());
                }
            }
        }

        let (listening_on, ephemeral_tcp_port) =
            Self::resolve_bind_addresses(runtime, &mut socket_addr)?;

        if ephemeral_tcp_port.is_some() {
            moto_sys_io::api_net::put_socket_addr(&mut resp.payload, &socket_addr);
        }

        let num_listeners = if msg.flags == 0 {
            DEFAULT_NUM_LISTENING_SOCKETS
        } else {
            msg.flags as usize
        };
        if num_listeners > MAX_NUM_LISTENING_SOCKETS {
            return Err(ErrorKind::InvalidInput.into());
        }

        let mut runtime_mut = runtime.inner.borrow_mut();

        // Create TcpListener object.
        let listener_id = runtime_mut.next_socket_id();
        let mut listener = Rc::new(RefCell::new(TcpListener {
            listener_id,
            runtime: runtime.clone(),
            socket_addr,
            client: sender.remote_handle(),
            pending_accepts: Default::default(),
            pending_sockets: Default::default(),
            listening_sockets: Default::default(),
            ephemeral_tcp_port,
            listening_on,
            ttl: 64, // https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
        }));

        runtime_mut
            .tcp_listeners
            .insert(listener_id, listener.clone());
        assert!(
            runtime_mut
                .clients
                .get_mut(&sender.remote_handle())
                .unwrap()
                .tcp_listeners
                .insert(listener_id)
        );
        drop(runtime_mut);

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: new tcp listener on {:?}, conn: 0x{:x}",
            socket_addr,
            sender.remote_handle().as_u64()
        );

        // Start listening.
        Self::spawn_listening_sockets(listener, num_listeners).await;

        resp.handle = listener_id;
        resp.status = moto_rt::E_OK;
        let _ = sender.send(resp).await;

        Ok(())
    }

    pub(super) async fn accept(
        runtime: &super::NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &moto_ipc::io_channel::Sender,
    ) -> std::io::Result<()> {
        let listener_id = msg.handle;
        let tcp_listener = runtime
            .inner
            .borrow()
            .tcp_listeners
            .get(&listener_id)
            .cloned()
            .ok_or_else(|| {
                log::debug!("TCP listener 0x{listener_id:x} not found.");
                std::io::Error::from(ErrorKind::InvalidData)
            })?;

        if tcp_listener.borrow().client != sender.remote_handle() {
            // Validate that the listener and the connection belong to the same process.
            let pid1 = moto_sys::SysObj::get_pid(tcp_listener.borrow().client).unwrap();
            let pid2 = moto_sys::SysObj::get_pid(sender.remote_handle()).unwrap();
            if pid1 != pid2 {
                log::debug!(
                    "Accept: wrong process 0x{pid1:x} vs 0x{pid2:x} for Listener ID 0x{listener_id:x}"
                );
                return Err(ErrorKind::InvalidData.into());
            }
        }

        if let Some((socket_id, remote_addr, accepted_tx)) =
            { tcp_listener.borrow_mut().pending_sockets.pop_front() }
        {
            Self::process_matched_accept(
                tcp_listener,
                socket_id,
                remote_addr,
                accepted_tx,
                msg,
                sender.remote_handle(),
            )
            .await;
        } else {
            log::debug!("Pending accept request for TCP listener 0x{listener_id:x}.");
            tcp_listener
                .borrow_mut()
                .pending_accepts
                .push_back((msg, sender.remote_handle()));
        }

        Ok(())
    }
}
