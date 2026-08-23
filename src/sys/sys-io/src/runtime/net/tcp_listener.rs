use super::socket::MotoSocket;
use crate::runtime::channel_budget::ClientSender;
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
const MAX_PENDING_ACCEPTS: usize = 1024;

type PendingSocket = (u64, SocketAddr, moto_async::oneshot::Sender<()>);
type PendingAccept = (moto_ipc::io_channel::Msg, ClientSender);

pub(super) struct TcpListener {
    listener_id: u64,
    runtime: super::NetRuntime,

    // What the user gave us, with one caveat:
    // - either a fully specified IPADDR:PORT,
    // - or a family-specific unspecified address and fixed port.
    // - or, if the user gave us IPADDR:0, this will have IPADDR:EPHEMERAL_PORT.
    socket_addr: SocketAddr,
    client_sender: ClientSender,

    // If listener::accept() is called first, it's sqe will be added
    // to pending_accepts.
    pending_accepts: VecDeque<PendingAccept>,

    // Connected sockets that did not yet emit the accept QE.
    // When the socket is accepted, the oneshot should be fired.
    pending_sockets: VecDeque<PendingSocket>,

    // Pure listening sockets. We need to track them to drop when the listener is dropped.
    listening_sockets: HashSet<u64>,

    // Only present if the IP addr is specified. Which means that
    // in multi-device listeners this value is None.
    ephemeral_tcp_port: Option<Rc<super::EphemeralTcpPort>>,

    // All specific IPs this listener listens on, with their devices.
    listening_on: Vec<(SocketAddr, usize)>,

    // Will be applied to all new sockets.
    ttl: u8,

    // Buffer sizes for backlog sockets, read at their construction: a size
    // configured later applies to later accepts (2026-08-11 review ruling).
    buffer_sizes: super::socket::tcp::TcpBufferSizes,
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

    pub(super) fn listener_id(&self) -> u64 {
        self.listener_id
    }

    pub(super) fn client_sender(&self) -> &ClientSender {
        &self.client_sender
    }

    pub(super) fn buffer_sizes(&self) -> super::socket::tcp::TcpBufferSizes {
        self.buffer_sizes
    }

    pub(super) fn ephemeral_port(&self) -> Option<Rc<super::EphemeralTcpPort>> {
        self.ephemeral_tcp_port.clone()
    }

    pub(super) fn listens_on(&self, socket_addr: SocketAddr, device_idx: usize) -> bool {
        self.listening_on.contains(&(socket_addr, device_idx))
    }

    // Called on conn drop.
    pub(super) async fn hard_reset(this: Rc<RefCell<Self>>) {
        let pending_accepts = {
            let mut listener = this.borrow_mut();
            listener.close_pools();
            let pending_accepts = std::mem::take(&mut listener.pending_accepts);
            while listener.pop_pending_socket().is_some() {}
            listener.listening_sockets.clear();
            pending_accepts
        };
        drop(this);
        Self::cancel_pending_accepts(pending_accepts).await;
    }

    async fn cancel_pending_accepts(mut pending: VecDeque<PendingAccept>) {
        while let Some((mut msg, client)) = pending.pop_front() {
            msg.status = moto_rt::E_NOT_CONNECTED;
            let _ = client.send(msg).await;
        }
    }

    fn queue_pending_socket(
        &mut self,
        socket: PendingSocket,
        at_front: bool,
    ) -> Result<(), PendingSocket> {
        if !self.runtime.completed.try_admit(self.listener_id) {
            return Err(socket);
        }
        if at_front {
            self.pending_sockets.push_front(socket);
        } else {
            self.pending_sockets.push_back(socket);
        }
        Ok(())
    }

    fn pop_pending_socket(&mut self) -> Option<PendingSocket> {
        let socket = self.pending_sockets.pop_front()?;
        self.runtime.completed.release(self.listener_id);
        Some(socket)
    }

    // Hand back whatever demand-driven growth this listener's pools hold: they
    // are charged against a global bound, which would otherwise ratchet closed
    // as listeners come and go. Listen tasks may still be running, and find
    // their pool gone; that is a replenishment nobody wants any more.
    fn close_pools(&self) {
        for (addr, device_idx) in &self.listening_on {
            self.runtime.backlog.close((self.listener_id, *addr));
            // A dead listener must stop minting SYN cookies at once; without
            // this its endpoint would keep answering SYNs statelessly for as
            // long as the caps once held.
            self.runtime.inner.borrow_mut().devices[*device_idx].disengage_syn_cookies(*addr);
        }
    }

    /// Take `count` of `key`'s sockets out of `Listen`: growth its pool did not
    /// use in the last window (see [`super::backlog`]).
    ///
    /// Each one ends its listen task exactly as a socket that took a SYN and
    /// lost it does, so the gauge, the pool accounting, and the socket itself
    /// are torn down by the path that already owns them. A socket that has
    /// taken a SYN is a handshake in progress rather than slack, so it is left
    /// alone; the pool's target is already lowered, so what cannot be dropped
    /// here simply drains as connections arrive.
    pub(super) fn shrink_pool(
        runtime: &super::NetRuntime,
        key: super::backlog::PoolKey,
        count: usize,
    ) {
        let (listener_id, addr) = key;

        // Aborting borrows the runtime, so the candidates are collected first.
        let candidates: Vec<Rc<RefCell<MotoSocket>>> = {
            let inner = runtime.inner.borrow();
            let Some(listener) = inner.tcp_listeners.get(&listener_id) else {
                return;
            };
            let listener = listener.borrow();
            listener
                .listening_sockets
                .iter()
                .filter_map(|socket_id| inner.sockets.get(socket_id).cloned())
                .collect()
        };

        let mut dropped = 0;
        for moto_socket in candidates {
            if dropped == count {
                break;
            }
            if MotoSocket::abort_if_listening(&moto_socket, addr) {
                dropped += 1;
            }
        }
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
                if addr.is_ipv4() == ip_addr.is_ipv4() {
                    listening_on.push((SocketAddr::new(*addr, socket_addr.port()), *device_idx));
                }
            }
            if listening_on.is_empty() {
                return Err(ErrorKind::InvalidInput.into());
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

    fn spawn_listening_sockets(
        listener: Rc<RefCell<Self>>,
        num_listeners: usize,
    ) -> std::io::Result<()> {
        let (runtime, listening_on) = {
            let this = listener.borrow();
            (this.runtime.clone(), this.listening_on.clone())
        };

        for (addr, device_idx) in listening_on {
            for _ in 0..num_listeners {
                MotoSocket::create_tcp_listening_socket(
                    Rc::downgrade(&listener),
                    device_idx,
                    addr,
                )?;
            }
        }

        Ok(())
    }

    async fn unregister_and_drop(runtime: &super::NetRuntime, tcp_listener: Rc<RefCell<Self>>) {
        let (listener_id, remote_handle) = {
            let listener = tcp_listener.borrow();
            (listener.listener_id, listener.client_sender.remote_handle())
        };

        // Unregister the listener BEFORE dropping its sockets — same ordering
        // as on_connection_done(): a listening socket leaving the Listen state
        // respawns a replacement via its weak listener ref (socket/tcp.rs), so
        // the listener must be unreachable first (removed from the maps AND
        // this function's Rc dropped below), or the drained sets repopulate.
        {
            let mut inner = runtime.inner.borrow_mut();
            inner.tcp_listeners.remove(&listener_id);
            if let Some(client) = inner.clients.get_mut(&remote_handle) {
                client.tcp_listeners.remove(&listener_id);
            }
        }

        let (socket_ids, pending_accepts) = {
            let mut listener = tcp_listener.borrow_mut();

            listener.close_pools();
            let pending_accepts = std::mem::take(&mut listener.pending_accepts);
            let mut socket_ids = Vec::with_capacity(
                listener.pending_sockets.len() + listener.listening_sockets.len(),
            );

            while let Some(entry) = listener.pop_pending_socket() {
                socket_ids.push(entry.0);
            }
            socket_ids.extend(listener.listening_sockets.drain());
            (socket_ids, pending_accepts)
        };

        // Prevent replenish tasks from upgrading their weak listener refs.
        drop(tcp_listener);
        Self::cancel_pending_accepts(pending_accepts).await;

        for socket_id in socket_ids {
            // Socket teardown is asynchronous and can cascade-remove another
            // socket already listed here.
            let maybe_socket = runtime.inner.borrow().sockets.get(&socket_id).cloned();
            let Some(moto_socket) = maybe_socket else {
                continue;
            };
            MotoSocket::drop_tcp_socket(moto_socket).await;
        }
    }

    pub(super) fn add_listening_socket(&mut self, socket_id: u64) {
        self.listening_sockets.insert(socket_id);
    }

    // Called when a socket still owned by this listener is dropped without being
    // handed off to a client, e.g. a half-open handshake that timed out or was reset.
    pub(super) fn on_socket_dropped(this: Rc<RefCell<Self>>, socket_id: u64) {
        let mut this_ref = this.borrow_mut();
        this_ref.listening_sockets.remove(&socket_id);
        if let Some(position) = this_ref
            .pending_sockets
            .iter()
            .position(|(id, _, _)| *id == socket_id)
        {
            this_ref.pending_sockets.remove(position);
            this_ref.runtime.completed.release(this_ref.listener_id);
        }
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

        let (accepted, refused) = {
            let mut this_ref = this.borrow_mut();
            assert!(this_ref.listening_sockets.remove(&socket_id));
            MotoSocket::set_ttl(&moto_socket, this_ref.ttl);

            let pending_accept = loop {
                let Some((msg, client)) = this_ref.pending_accepts.pop_front() else {
                    break None;
                };
                if this_ref.runtime.client_is_active(client.remote_handle()) {
                    break Some((msg, client));
                }
                log::debug!(
                    "Discarding stale accept for closed connection 0x{:x}.",
                    client.remote_handle().as_u64()
                );
            };

            if let Some((msg, client)) = pending_accept {
                (Some((msg, accepted_tx, client)), None)
            } else {
                match this_ref.queue_pending_socket((socket_id, remote_addr, accepted_tx), false) {
                    Ok(()) => (None, None),
                    Err((_, _, accepted_tx)) => (None, Some(accepted_tx)),
                }
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
        } else if let Some(_accepted_tx) = refused {
            log::debug!("TCP accept backlog full; resetting socket 0x{socket_id:x}.");
            MotoSocket::drop_tcp_socket(moto_socket).await;
        }
    }

    async fn process_matched_accept(
        this: Rc<RefCell<Self>>,
        socket_id: u64,
        remote_addr: SocketAddr,
        accepted_tx: moto_async::oneshot::Sender<()>,
        accept_req: moto_ipc::io_channel::Msg,
        client_sender: ClientSender,
    ) {
        let moto_socket = this
            .borrow()
            .runtime
            .inner
            .borrow()
            .sockets
            .get(&socket_id)
            .cloned();

        let Some(moto_socket) = moto_socket else {
            this.borrow_mut()
                .pending_accepts
                .push_front((accept_req, client_sender));
            return;
        };

        let registered = {
            let mut socket_ref = moto_socket.borrow_mut();
            if socket_ref.set_client_sender(&client_sender) {
                socket_ref
                    .unwrap_tcp_mut()
                    .set_subchannel_mask(accept_req.payload.args_64()[0]);
                true
            } else {
                false
            }
        };
        if !registered {
            log::debug!(
                "Discarding accept for closed connection 0x{:x}.",
                client_sender.remote_handle().as_u64()
            );
            let queued = this
                .borrow_mut()
                .queue_pending_socket((socket_id, remote_addr, accepted_tx), true);
            if let Err((_, _, _accepted_tx)) = queued {
                MotoSocket::drop_tcp_socket(moto_socket).await;
            }
            return;
        }

        log::debug!("Incoming TCP conn 0x{socket_id:x} <= {remote_addr:?} accepted.");

        let mut resp = accept_req;
        resp.handle = socket_id;
        moto_sys_io::api_net::put_socket_addr(&mut resp.payload, &remote_addr);
        resp.status = moto_rt::E_OK;

        let _ = client_sender.send(resp).await;
        accepted_tx.send(()).unwrap();
    }

    /* ----------------------------------- API calls ------------------------------------ */
    pub(super) async fn bind(
        runtime: &super::NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        client_sender: &ClientSender,
    ) -> std::io::Result<()> {
        runtime.pressure.admit()?;
        let mut resp = msg;
        let mut socket_addr = moto_sys_io::api_net::get_socket_addr(&msg.payload);

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

        let overlaps_existing = listening_on.iter().any(|(addr, device_idx)| {
            runtime_mut
                .tcp_listeners
                .values()
                .any(|listener| listener.borrow().listens_on(*addr, *device_idx))
        });
        if overlaps_existing {
            return Err(ErrorKind::AddrInUse.into());
        }

        // Create TcpListener object.
        let listener_id = runtime_mut.next_socket_id();
        for (addr, _) in &listening_on {
            runtime.backlog.open((listener_id, *addr), num_listeners);
        }
        let listener = Rc::new(RefCell::new(TcpListener {
            listener_id,
            runtime: runtime.clone(),
            socket_addr,
            client_sender: client_sender.clone(),
            pending_accepts: Default::default(),
            pending_sockets: Default::default(),
            listening_sockets: Default::default(),
            ephemeral_tcp_port,
            listening_on,
            ttl: 64, // https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
            buffer_sizes: super::socket::tcp::TcpBufferSizes::from_payload(&msg.payload),
        }));

        runtime_mut
            .tcp_listeners
            .insert(listener_id, listener.clone());
        assert!(
            runtime_mut
                .clients
                .get_mut(&client_sender.remote_handle())
                .unwrap()
                .tcp_listeners
                .insert(listener_id)
        );
        drop(runtime_mut);

        #[cfg(debug_assertions)]
        log::debug!(
            "sys-io: new tcp listener on {:?}, conn: 0x{:x}",
            socket_addr,
            client_sender.remote_handle().as_u64()
        );

        // Start listening.
        if let Err(err) = Self::spawn_listening_sockets(listener.clone(), num_listeners) {
            Self::unregister_and_drop(runtime, listener).await;
            return Err(err);
        }

        resp.handle = listener_id;
        resp.status = moto_rt::E_OK;
        let _ = client_sender.send(resp).await;

        Ok(())
    }

    /// Refuse a request that arrives on a channel other than the one the
    /// listener was created on, unless both belong to the same process.
    ///
    /// A pid that cannot be read is refused rather than trusted, and that is
    /// the ordinary case here, not a corrupt one: `get_pid` answers
    /// `BadHandle` once a client's connection is torn down, which any request
    /// still queued in shared memory can race. Every accept takes this path,
    /// because each one is posted on a freshly reserved channel, so the two
    /// handles always differ.
    fn check_same_process(
        tcp_listener: &Rc<RefCell<Self>>,
        sender: &moto_ipc::io_channel::Sender,
        what: &str,
        listener_id: u64,
    ) -> std::io::Result<()> {
        let listener_handle = tcp_listener.borrow().client_sender.remote_handle();
        if listener_handle == sender.remote_handle() {
            return Ok(());
        }

        let pids = (
            moto_sys::SysObj::get_pid(listener_handle),
            moto_sys::SysObj::get_pid(sender.remote_handle()),
        );
        if let (Ok(pid1), Ok(pid2)) = pids
            && pid1 == pid2
        {
            return Ok(());
        }

        log::debug!(
            "{what}: refusing listener 0x{listener_id:x}: clients 0x{:x} ({:?}) vs 0x{:x} ({:?})",
            listener_handle.as_u64(),
            pids.0,
            sender.remote_handle().as_u64(),
            pids.1
        );
        Err(ErrorKind::InvalidData.into())
    }

    pub(super) async fn accept(
        runtime: &super::NetRuntime,
        msg: moto_ipc::io_channel::Msg,
        sender: &ClientSender,
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

        Self::check_same_process(&tcp_listener, sender, "Accept", listener_id)?;

        if let Some((socket_id, remote_addr, accepted_tx)) =
            { tcp_listener.borrow_mut().pop_pending_socket() }
        {
            Self::process_matched_accept(
                tcp_listener,
                socket_id,
                remote_addr,
                accepted_tx,
                msg,
                sender.clone(),
            )
            .await;
        } else {
            log::debug!("Pending accept request for TCP listener 0x{listener_id:x}.");
            let mut listener = tcp_listener.borrow_mut();
            if listener.pending_accepts.len() >= MAX_PENDING_ACCEPTS {
                return Err(ErrorKind::OutOfMemory.into());
            }
            listener.pending_accepts.push_back((msg, sender.clone()));
        }

        Ok(())
    }

    pub(super) async fn get_option(
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
                std::io::Error::from(ErrorKind::NotFound)
            })?;

        if tcp_listener.borrow().client_sender.remote_handle() != sender.remote_handle() {
            log::debug!("TCP listener 0x{listener_id:x} not found.");
            return Err(ErrorKind::NotFound.into());
        }

        let options = msg.payload.args_64()[0];
        let mut resp = msg;
        match options {
            moto_sys_io::api_net::TCP_OPTION_TTL => {
                resp.payload.args_8_mut()[23] = tcp_listener.borrow().ttl;
            }
            moto_sys_io::api_net::TCP_OPTION_RCVBUF => {
                resp.payload.args_64_mut()[1] = tcp_listener.borrow().buffer_sizes.rx as u64;
            }
            moto_sys_io::api_net::TCP_OPTION_SNDBUF => {
                resp.payload.args_64_mut()[1] = tcp_listener.borrow().buffer_sizes.tx as u64;
            }
            moto_sys_io::api_net::TCP_OPTION_ONLY_V6 => {
                if !tcp_listener.borrow().socket_addr.is_ipv6() {
                    return Err(ErrorKind::Unsupported.into());
                }
                resp.payload.args_8_mut()[23] = 1;
            }
            _ => return Err(ErrorKind::InvalidInput.into()),
        }
        resp.status = moto_rt::E_OK;

        let _ = sender.send(resp).await;
        Ok(())
    }

    pub(super) async fn set_option(
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
                std::io::Error::from(ErrorKind::NotFound)
            })?;

        if tcp_listener.borrow().client_sender.remote_handle() != sender.remote_handle() {
            log::debug!("TCP listener 0x{listener_id:x} not found.");
            return Err(ErrorKind::NotFound.into());
        }

        let options = msg.payload.args_64()[0];
        let mut resp = msg;
        match options {
            moto_sys_io::api_net::TCP_OPTION_TTL => {
                let ttl = msg.payload.args_8()[23];
                if ttl == 0 {
                    return Err(ErrorKind::InvalidInput.into());
                }
                tcp_listener.borrow_mut().ttl = ttl;
            }
            // Applies to accepts served by backlog sockets constructed after
            // this call (the 2026-08-11 review ruling); sockets already in
            // the pool keep the sizes and scale they were built with.
            moto_sys_io::api_net::TCP_OPTION_RCVBUF => {
                let bytes = super::socket::tcp::TcpBufferSizes::normalize(msg.payload.args_64()[1]);
                tcp_listener.borrow_mut().buffer_sizes.rx = bytes;
                resp.payload.args_64_mut()[1] = bytes as u64;
            }
            moto_sys_io::api_net::TCP_OPTION_SNDBUF => {
                let bytes = super::socket::tcp::TcpBufferSizes::normalize(msg.payload.args_64()[1]);
                tcp_listener.borrow_mut().buffer_sizes.tx = bytes;
                resp.payload.args_64_mut()[1] = bytes as u64;
            }
            moto_sys_io::api_net::TCP_OPTION_ONLY_V6 => {
                if msg.payload.args_8()[23] > 1 {
                    return Err(ErrorKind::InvalidInput.into());
                }
                if !tcp_listener.borrow().socket_addr.is_ipv6() || msg.payload.args_8()[23] == 0 {
                    return Err(ErrorKind::Unsupported.into());
                }
            }
            _ => return Err(ErrorKind::InvalidInput.into()),
        }
        resp.status = moto_rt::E_OK;

        let _ = sender.send(resp).await;
        Ok(())
    }

    pub(super) async fn drop_from_client(
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

        Self::check_same_process(&tcp_listener, sender, "Drop", listener_id)?;

        Self::unregister_and_drop(runtime, tcp_listener).await;

        Ok(())
    }
}
