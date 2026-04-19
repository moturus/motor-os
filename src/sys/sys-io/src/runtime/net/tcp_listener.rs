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
    pending_accepts: VecDeque<moto_ipc::io_channel::Msg>,

    // Connected sockets that did not yet emit the accept QE.
    // Note: connected_sockets below may contain dropped sockets.
    pending_sockets: VecDeque<(u64, SocketAddr)>,

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
    fn new(
        listener_id: u64,
        runtime: super::NetRuntime,
        client: SysHandle,
        socket_addr: SocketAddr,
    ) -> Self {
        Self {
            listener_id,
            runtime,
            client,
            socket_addr,
            pending_accepts: VecDeque::new(),
            pending_sockets: VecDeque::new(),
            listening_sockets: HashSet::new(),
            listening_on: Vec::new(),
            ephemeral_tcp_port: None,
            ttl: 64, // https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
        }
    }

    pub(super) fn runtime(&self) -> &super::NetRuntime {
        &self.runtime
    }

    pub(super) fn client(&self) -> SysHandle {
        self.client
    }

    pub(super) fn ephemeral_port(&self) -> Option<Rc<super::EphemeralTcpPort>> {
        self.ephemeral_tcp_port.clone()
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
        moto_async::sleep(std::time::Duration::from_millis(1000)).await;
        log::error!("TcpListener::accept(): not implemented");
        Err(ErrorKind::Unsupported.into())
    }
}
