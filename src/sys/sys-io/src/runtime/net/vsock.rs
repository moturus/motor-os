use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::rc::{Rc, Weak};
use std::task::Poll;
use std::time::Duration;

use futures::FutureExt;
use moto_ipc::io_channel;
use moto_sys::SysHandle;
use moto_sys_io::api_net::NetCmd;
use moto_sys_io::api_vsock;
use virtio_async::vsock::{
    DecodeError, Event, Operation, PacketHeader, RawHeader, SHUTDOWN_RECEIVE, SHUTDOWN_SEND,
    SocketType, VsockDevice,
};

use super::NetRuntime;
use super::socket::{MotoSocket, SocketBase};
use crate::runtime::channel_budget::ClientSender;
use crate::runtime::vsock::admission::{
    AdmissionError, ConnectionTuple, MAX_LISTENERS, TupleIndex, VsockAddr,
};
use crate::runtime::vsock::connection::{Connection, ReceiveOutcome, TerminalCause};
use crate::runtime::vsock::listener::ListenerState;

const MAX_PENDING_CONTROLS: usize = 64;
const MAX_PENDING_TX_PAGES: usize = 16;
const MAX_STREAMS: usize = 64;
const PUMP_QUANTUM: usize = 32;

pub(super) struct PendingAccept {
    client: SysHandle,
    ready: moto_async::oneshot::Sender<Result<u64, moto_rt::Error>>,
}

// Keep the discovered raw device inline: boxing it would allocate on the
// dormant boot path solely to shrink the lazily activated variants.
#[allow(clippy::large_enum_variant)]
enum DeviceState {
    Dormant(Option<virtio_async::VirtioDevice>),
    Ready(Rc<VsockDevice>),
    Failed {
        driver: Option<Rc<VsockDevice>>,
        error: moto_rt::Error,
    },
}

#[derive(Clone, Copy)]
enum PendingControl {
    Stream {
        socket_id: u64,
        operation: Operation,
        flags: u32,
    },
    Refusal(RawHeader),
}

pub(super) struct VsockRuntime {
    device: DeviceState,
    pub(super) tuples: TupleIndex,
    controls: VecDeque<PendingControl>,
    submit_notify: Option<Rc<moto_async::LocalNotify>>,
    control_space: Option<Rc<moto_async::LocalNotify>>,
    failure_notify: Option<Rc<moto_async::LocalNotify>>,
    next_tx_socket: u64,
    pumps_started: bool,
}

impl VsockRuntime {
    pub(super) fn new(device: Option<virtio_async::VirtioDevice>) -> Self {
        Self {
            device: DeviceState::Dormant(device),
            tuples: TupleIndex::new(),
            controls: VecDeque::new(),
            submit_notify: None,
            control_space: None,
            failure_notify: None,
            next_tx_socket: 0,
            pumps_started: false,
        }
    }

    pub(super) fn availability(&self) -> Result<(), moto_rt::Error> {
        match &self.device {
            DeviceState::Dormant(None) => Err(moto_rt::Error::NotFound),
            DeviceState::Failed { error, .. } => Err(*error),
            DeviceState::Dormant(Some(_)) | DeviceState::Ready(_) => Ok(()),
        }
    }

    fn ready_driver(&self) -> Result<Rc<VsockDevice>, moto_rt::Error> {
        match &self.device {
            DeviceState::Ready(driver) => Ok(driver.clone()),
            DeviceState::Failed { error, .. } => Err(*error),
            DeviceState::Dormant(None) => Err(moto_rt::Error::NotFound),
            DeviceState::Dormant(Some(_)) => Err(moto_rt::Error::NotReady),
        }
    }

    fn retained_driver(&self) -> Option<Rc<VsockDevice>> {
        match &self.device {
            DeviceState::Ready(driver) => Some(driver.clone()),
            DeviceState::Failed { driver, .. } => driver.clone(),
            DeviceState::Dormant(_) => None,
        }
    }

    fn accepts_protocol_effects(&self) -> bool {
        matches!(self.device, DeviceState::Ready(_))
    }

    fn has_control_space(&self) -> bool {
        self.controls.len() < MAX_PENDING_CONTROLS
    }

    fn submit_notify(&self) -> Rc<moto_async::LocalNotify> {
        self.submit_notify
            .as_ref()
            .expect("activated vsock has no submit notifier")
            .clone()
    }

    fn control_space(&self) -> Rc<moto_async::LocalNotify> {
        self.control_space
            .as_ref()
            .expect("activated vsock has no control-space notifier")
            .clone()
    }

    fn failure_notify(&mut self) -> Rc<moto_async::LocalNotify> {
        self.failure_notify
            .get_or_insert_with(|| Rc::new(moto_async::LocalNotify::new()))
            .clone()
    }

    fn failure_error(&self) -> Option<moto_rt::Error> {
        match &self.device {
            DeviceState::Failed { error, .. } => Some(*error),
            _ => None,
        }
    }

    fn notify_submit(&self) {
        self.submit_notify
            .as_ref()
            .expect("activated vsock has no submit notifier")
            .notify_one();
    }

    fn queue_control(&mut self, control: PendingControl) -> Result<(), moto_rt::Error> {
        if let PendingControl::Stream {
            socket_id,
            operation,
            flags,
        } = control
            && let Some(existing) = self.controls.iter_mut().find(|pending| {
                matches!(pending, PendingControl::Stream { socket_id: id, .. } if *id == socket_id)
            })
        {
            match existing {
                    PendingControl::Stream {
                        operation: old_operation,
                        flags: old_flags,
                        ..
                    } if operation == Operation::Reset => {
                        *old_operation = operation;
                        *old_flags = 0;
                        self.notify_submit();
                        return Ok(());
                    }
                    PendingControl::Stream {
                        operation: Operation::CreditUpdate,
                        ..
                    } if operation == Operation::Shutdown => {
                        *existing = control;
                        self.notify_submit();
                        return Ok(());
                    }
                    PendingControl::Stream {
                        operation: Operation::Shutdown,
                        flags: old_flags,
                        ..
                    } if operation == Operation::Shutdown => {
                        *old_flags |= flags;
                        self.notify_submit();
                        return Ok(());
                    }
                    PendingControl::Stream {
                        operation: Operation::CreditUpdate,
                        ..
                    } if operation == Operation::CreditRequest => {
                        *existing = control;
                        self.notify_submit();
                        return Ok(());
                    }
                    PendingControl::Stream {
                        operation: Operation::CreditRequest,
                        ..
                    } if operation == Operation::CreditUpdate => return Ok(()),
                    _ if matches!(operation, Operation::CreditUpdate | Operation::CreditRequest) => {
                        return Ok(());
                    }
                    _ => return Err(moto_rt::Error::InternalError),
            }
        }
        if !self.has_control_space() {
            return Err(moto_rt::Error::OutOfMemory);
        }
        self.controls.push_back(control);
        self.notify_submit();
        Ok(())
    }
}

struct TxPage {
    page: io_channel::IoPage,
    len: usize,
    consumed: usize,
}

pub(super) struct VsockSocketState {
    connection: Connection,
    tx_pages: VecDeque<TxPage>,
    subchannel_mask: u64,
    listener_id: Option<u64>,
    connect_notify: Rc<moto_async::LocalNotify>,
    rx_notify: Rc<moto_async::LocalNotify>,
    state_notify: Rc<moto_async::LocalNotify>,
    output_lock: Rc<moto_async::LocalMutex<()>>,
    connected_observed: bool,
    client_ready: bool,
    client_gone: bool,
    notified_flags: u32,
    pending_reset: bool,
    reset_queued: bool,
    credit_request_outstanding: bool,
}

impl VsockSocketState {
    fn new(connection: Connection, subchannel_mask: u64) -> Result<Self, moto_rt::Error> {
        Self::with_owner(connection, subchannel_mask, None)
    }

    fn new_unaccepted(connection: Connection, listener_id: u64) -> Result<Self, moto_rt::Error> {
        Self::with_owner(connection, 0, Some(listener_id))
    }

    fn with_owner(
        connection: Connection,
        subchannel_mask: u64,
        listener_id: Option<u64>,
    ) -> Result<Self, moto_rt::Error> {
        let mut tx_pages = VecDeque::new();
        tx_pages
            .try_reserve_exact(MAX_PENDING_TX_PAGES)
            .map_err(|_| moto_rt::Error::OutOfMemory)?;
        Ok(Self {
            connection,
            tx_pages,
            subchannel_mask,
            listener_id,
            connect_notify: Rc::new(moto_async::LocalNotify::new()),
            rx_notify: Rc::new(moto_async::LocalNotify::new()),
            state_notify: Rc::new(moto_async::LocalNotify::new()),
            output_lock: Rc::new(moto_async::LocalMutex::new(())),
            connected_observed: false,
            client_ready: false,
            client_gone: false,
            notified_flags: 0,
            pending_reset: false,
            reset_queued: false,
            credit_request_outstanding: false,
        })
    }

    fn accepted_tx_drained(&self) -> bool {
        self.tx_pages.is_empty()
    }

    fn state_change(&self) -> (u32, Option<moto_rt::Error>) {
        let mut flags = 0;
        if self.connection.local_read_closed() {
            flags |= api_vsock::STATE_READ_CLOSED;
        }
        if self.connection.local_write_closed() {
            flags |= api_vsock::STATE_WRITE_CLOSED;
        }
        let cause = match self.connection.terminal_cause() {
            None => None,
            Some(TerminalCause::OrderlyClosed) => {
                flags |= api_vsock::STATE_TERMINAL;
                None
            }
            Some(TerminalCause::InternalError) => {
                flags |= api_vsock::STATE_TERMINAL;
                Some(moto_rt::Error::InternalError)
            }
            Some(TerminalCause::ConnectionReset) => {
                flags |= api_vsock::STATE_TERMINAL;
                Some(moto_rt::Error::ConnectionReset)
            }
            Some(TerminalCause::Refused | TerminalCause::TimedOut) => None,
        };
        (flags, cause)
    }

    fn terminal_ready_to_drop(&self) -> bool {
        self.connection.terminal_cause().is_some()
            && (!self.connection.has_buffered_rx() || self.connection.local_receive_shutdown())
            && !self.pending_reset
    }
}

pub(super) fn on_socket_drop(base: &mut SocketBase, state: &mut VsockSocketState) {
    assert!(state.connection.terminal_cause().is_some());
    assert!(state.tx_pages.is_empty());
    let removed_again = base
        .runtime()
        .inner
        .borrow_mut()
        .vsock
        .tuples
        .remove_stream(base.socket_id());
    assert!(removed_again.is_none());
}

pub(super) fn on_listener_drop(base: &mut SocketBase, listener: &mut ListenerState<PendingAccept>) {
    assert!(
        base.runtime()
            .inner
            .borrow_mut()
            .vsock
            .tuples
            .remove_listener(base.socket_id())
            .is_some()
    );
    while listener.pop().is_some() {}
    // A matched child leaves the FIFO, but retains listener_id until its
    // accept response is published.
    let children = {
        let inner = base.runtime().inner.borrow();
        let mut children: [Option<u64>; MAX_STREAMS] = std::array::from_fn(|_| None);
        let mut next = 0;
        for socket_id in inner.vsock.tuples.stream_ids() {
            let socket = inner
                .sockets
                .get(&socket_id)
                .expect("vsock tuple index has no common socket");
            if socket.borrow().unwrap_vsock().listener_id == Some(base.socket_id()) {
                children[next] = Some(socket_id);
                next += 1;
            }
        }
        children
    };
    for socket_id in children.into_iter().flatten() {
        base.runtime().reset_unaccepted(socket_id);
    }
}

impl NetRuntime {
    fn check_vsock_capability(&self, client_handle: SysHandle) -> Result<(), moto_rt::Error> {
        let mut inner = self.inner.borrow_mut();
        let client = inner
            .clients
            .get_mut(&client_handle)
            .ok_or(moto_rt::Error::NotFound)?;
        let capabilities = *client
            .capabilities
            .get_or_insert_with(|| moto_sys::SysObj::get_capabilities(client_handle));
        let capabilities = capabilities.map_err(moto_rt::Error::from)?;
        if capabilities & moto_sys::caps::CAP_VSOCK == 0 {
            return Err(moto_rt::Error::NotAllowed);
        }
        Ok(())
    }

    fn fail_vsock_activation(&self) -> moto_rt::Error {
        let notify = {
            let mut inner = self.inner.borrow_mut();
            if let DeviceState::Failed { error, .. } = &inner.vsock.device {
                return *error;
            }
            inner.vsock.device = DeviceState::Failed {
                driver: None,
                error: moto_rt::Error::InternalError,
            };
            inner.vsock.failure_notify.clone()
        };
        if let Some(notify) = notify {
            notify.notify_all();
        }
        moto_rt::Error::InternalError
    }

    fn activate_vsock(&self) -> Result<Rc<VsockDevice>, moto_rt::Error> {
        {
            let inner = self.inner.borrow();
            match &inner.vsock.device {
                DeviceState::Ready(driver) => return Ok(driver.clone()),
                DeviceState::Failed { error, .. } => return Err(*error),
                DeviceState::Dormant(None) => return Err(moto_rt::Error::NotFound),
                DeviceState::Dormant(Some(_)) => {}
            }
        }

        let raw = {
            let mut inner = self.inner.borrow_mut();
            if inner
                .vsock
                .controls
                .try_reserve_exact(MAX_PENDING_CONTROLS)
                .is_err()
            {
                drop(inner);
                return Err(self.fail_vsock_activation());
            }
            inner.vsock.submit_notify = Some(Rc::new(moto_async::LocalNotify::new()));
            inner.vsock.control_space = Some(Rc::new(moto_async::LocalNotify::new()));
            let DeviceState::Dormant(raw) = &mut inner.vsock.device else {
                unreachable!()
            };
            raw.take().unwrap()
        };

        let driver = match VsockDevice::from(raw) {
            Ok(driver) => driver,
            Err(err) => {
                log::error!("Failed to activate virtio-vsock: {err}");
                return Err(self.fail_vsock_activation());
            }
        };
        {
            let mut inner = self.inner.borrow_mut();
            inner.vsock.device = DeviceState::Ready(driver.clone());
            assert!(!inner.vsock.pumps_started);
            inner.vsock.pumps_started = true;
        }
        self.spawn_vsock_pumps();
        Ok(driver)
    }

    pub(super) async fn on_vsock_msg(&self, msg: io_channel::Msg, sender: ClientSender) {
        let command = NetCmd::try_from(msg.command).unwrap();
        let result = match self.check_vsock_capability(sender.remote_handle()) {
            Ok(()) => match command {
                NetCmd::VsockLocalCid => self.vsock_local_cid(msg, &sender).await,
                NetCmd::VsockStreamConnect => self.vsock_connect(msg, &sender).await,
                NetCmd::VsockStreamTx => self.vsock_tx(msg, &sender),
                NetCmd::VsockStreamShutdown => self.vsock_shutdown(msg, &sender).await,
                NetCmd::VsockStreamClose => self.vsock_close(msg, &sender),
                NetCmd::VsockListenerBind => self.vsock_listener_bind(msg, &sender).await,
                NetCmd::VsockListenerAccept => self.vsock_listener_accept(msg, &sender).await,
                NetCmd::VsockListenerDrop => self.vsock_listener_drop(msg, &sender).await,
                _ => unreachable!(),
            },
            Err(err) => Err(err),
        };
        if let Err(error) = result {
            if command == NetCmd::VsockListenerDrop && msg.id == 0 {
                return;
            }
            let mut response = msg;
            response.status = error.into();
            let _ = sender.send(response).await;
        }
    }

    pub(super) async fn send_vsock_success(
        &self,
        mut response: io_channel::Msg,
        sender: &ClientSender,
    ) -> bool {
        let notify = self.inner.borrow_mut().vsock.failure_notify();
        loop {
            let mut failed = core::pin::pin!(notify.notified().fuse());
            let failure = { self.inner.borrow().vsock.failure_error() };
            if let Some(error) = failure {
                response.status = error.into();
                return sender.send(response).await.is_ok();
            }
            let mut send = core::pin::pin!(sender.send(response).fuse());
            let sent = futures::select_biased! {
                _ = failed => None,
                result = send => Some(result.is_ok()),
            };
            if let Some(sent) = sent {
                return sent;
            }
        }
    }

    async fn vsock_local_cid(
        &self,
        request: io_channel::Msg,
        sender: &ClientSender,
    ) -> Result<(), moto_rt::Error> {
        api_vsock::decode_local_cid_request(&request)?;
        let driver = self.activate_vsock()?;
        let response = api_vsock::encode_local_cid_response(&request, driver.guest_cid())?;
        let _ = self.send_vsock_success(response, sender).await;
        Ok(())
    }

    async fn vsock_listener_bind(
        &self,
        request: io_channel::Msg,
        sender: &ClientSender,
    ) -> Result<(), moto_rt::Error> {
        let requested_port = api_vsock::decode_listener_bind_request(&request)?;
        let driver = self.activate_vsock()?;
        let listener = ListenerState::<PendingAccept>::new().map_err(map_allocation_error)?;
        let local_cid = driver.guest_cid();
        let (socket_id, response) = {
            let mut inner = self.inner.borrow_mut();
            let socket_id = inner.next_socket_id();
            let port = inner
                .vsock
                .tuples
                .reserve_listener(socket_id, local_cid, requested_port)
                .map_err(map_admission_error)?;
            let local = api_vsock::VsockAddr {
                cid: local_cid,
                port,
            };
            let response =
                match api_vsock::encode_listener_bind_response(&request, socket_id, local) {
                    Ok(response) => response,
                    Err(err) => {
                        assert!(inner.vsock.tuples.remove_listener(socket_id).is_some());
                        return Err(err);
                    }
                };
            (socket_id, response)
        };

        let base = SocketBase::new_vsock_listener(socket_id, self.clone(), sender.clone());
        MotoSocket::new_vsock_listener(base, listener).map_err(map_allocation_error)?;
        if !self.send_vsock_success(response, sender).await {
            let _ = self.remove_vsock_listener(socket_id, sender.remote_handle());
        }
        Ok(())
    }

    async fn vsock_listener_accept(
        &self,
        request: io_channel::Msg,
        sender: &ClientSender,
    ) -> Result<(), moto_rt::Error> {
        let decoded = api_vsock::decode_listener_accept_request(&request)?;
        self.inner.borrow().vsock.availability()?;
        let listener = self
            .inner
            .borrow()
            .sockets
            .get(&request.handle)
            .cloned()
            .ok_or(moto_rt::Error::NotFound)?;
        {
            let listener = listener.borrow();
            if !listener.is_vsock_listener()
                || !same_process(listener.sender().remote_handle(), sender.remote_handle())
            {
                return Err(moto_rt::Error::NotFound);
            }
        }
        let socket_id = { listener.borrow_mut().unwrap_vsock_listener_mut().pop() };
        let wait = if socket_id.is_none() {
            let (ready, wait) = moto_async::oneshot();
            let enqueue_result = {
                let mut listener = listener.borrow_mut();
                listener
                    .unwrap_vsock_listener_mut()
                    .enqueue_accept(PendingAccept {
                        client: sender.remote_handle(),
                        ready,
                    })
            };
            enqueue_result.map_err(|()| moto_rt::Error::OutOfMemory)?;
            Some(wait)
        } else {
            None
        };
        drop(listener);
        let socket_id = match (socket_id, wait) {
            (Some(socket_id), None) => socket_id,
            (None, Some(wait)) => wait.await.map_err(|_| moto_rt::Error::NotConnected)??,
            _ => unreachable!(),
        };
        self.vsock_accept_task(socket_id, request, sender, decoded.subchannel_mask)
            .await
    }

    async fn vsock_listener_drop(
        &self,
        mut request: io_channel::Msg,
        sender: &ClientSender,
    ) -> Result<(), moto_rt::Error> {
        api_vsock::decode_listener_drop_request(&request)?;
        self.inner.borrow().vsock.availability()?;
        self.remove_vsock_listener(request.handle, sender.remote_handle())?;
        if request.id != 0 {
            request.status = moto_rt::E_OK;
            let _ = self.send_vsock_success(request, sender).await;
        }
        Ok(())
    }

    pub(super) fn remove_vsock_listener(
        &self,
        socket_id: u64,
        client_handle: SysHandle,
    ) -> Result<(), moto_rt::Error> {
        let (socket, mut accepts) = {
            let mut inner = self.inner.borrow_mut();
            let owned = inner.sockets.get(&socket_id).is_some_and(|socket| {
                let socket = socket.borrow();
                socket.is_vsock_listener() && socket.sender().remote_handle() == client_handle
            });
            if !owned {
                return Err(moto_rt::Error::NotFound);
            }
            let socket = inner.sockets.remove(&socket_id).unwrap();
            if let Some(client) = inner.clients.get_mut(&client_handle) {
                client.sockets.remove(&socket_id);
            }
            let accepts = socket
                .borrow_mut()
                .unwrap_vsock_listener_mut()
                .take_accepts();
            (socket, accepts)
        };
        drop(socket);
        while let Some(accept) = accepts.pop_front() {
            let _ = accept.ready.send(Err(moto_rt::Error::NotConnected));
        }
        Ok(())
    }

    pub(super) fn discard_vsock_accepts_from(&self, client: SysHandle) {
        let listeners = {
            let inner = self.inner.borrow();
            let mut listeners: [Option<Rc<RefCell<MotoSocket>>>; MAX_LISTENERS] =
                std::array::from_fn(|_| None);
            for (slot, listener) in listeners.iter_mut().zip(
                inner
                    .sockets
                    .values()
                    .filter(|socket| socket.borrow().is_vsock_listener()),
            ) {
                *slot = Some(listener.clone());
            }
            listeners
        };
        for listener in listeners.into_iter().flatten() {
            while let Some(accept) = listener
                .borrow_mut()
                .unwrap_vsock_listener_mut()
                .remove_accept(|accept| accept.client == client)
            {
                let _ = accept.ready.send(Err(moto_rt::Error::NotConnected));
            }
        }
    }

    async fn vsock_connect(
        &self,
        request: io_channel::Msg,
        sender: &ClientSender,
    ) -> Result<(), moto_rt::Error> {
        let decoded = api_vsock::decode_connect_request(&request)?;
        if decoded.peer.cid != 2 {
            return Err(moto_rt::Error::NotImplemented);
        }
        let driver = self.activate_vsock()?;
        let connection = Connection::new_outgoing().map_err(map_allocation_error)?;
        let state = VsockSocketState::new(connection, decoded.subchannel_mask)?;

        let (socket_id, tuple) = {
            let mut inner = self.inner.borrow_mut();
            if !inner.vsock.has_control_space() {
                return Err(moto_rt::Error::OutOfMemory);
            }
            let socket_id = inner.next_socket_id();
            let tuple = inner
                .vsock
                .tuples
                .reserve_outgoing(
                    socket_id,
                    driver.guest_cid(),
                    VsockAddr {
                        cid: decoded.peer.cid,
                        port: decoded.peer.port,
                    },
                )
                .map_err(map_admission_error)?;
            (socket_id, tuple)
        };
        let base = SocketBase::new_vsock(socket_id, self.clone(), tuple, sender.clone());
        let socket = match MotoSocket::new_vsock(base, state) {
            Ok(socket) => socket,
            Err(err) => return Err(map_allocation_error(err)),
        };
        let queued = self
            .inner
            .borrow_mut()
            .vsock
            .queue_control(PendingControl::Stream {
                socket_id,
                operation: Operation::Request,
                flags: 0,
            });
        if let Err(err) = queued {
            socket
                .borrow_mut()
                .unwrap_vsock_mut()
                .connection
                .device_failed();
            self.remove_vsock_socket(socket_id);
            return Err(err);
        }

        let runtime = self.clone();
        moto_async::LocalRuntime::spawn(async move {
            runtime
                .vsock_connect_task(Rc::downgrade(&socket), request)
                .await;
        });
        Ok(())
    }

    fn vsock_tx(&self, msg: io_channel::Msg, sender: &ClientSender) -> Result<(), moto_rt::Error> {
        let mut pages = if msg.flags == 0 {
            let page = sender.get_page(msg.payload.shared_pages()[0])?;
            let len = usize::try_from(msg.payload.args_64()[1])
                .map_err(|_| moto_rt::Error::InvalidArgument)?;
            if len == 0 || len > io_channel::PAGE_SIZE {
                return Err(moto_rt::Error::InvalidArgument);
            }
            VecDeque::from([TxPage {
                page,
                len,
                consumed: 0,
            }])
        } else {
            let (pages, total) = api_vsock::stream_tx_multi_decode(&msg, sender)?;
            let mut remaining = total as usize;
            pages
                .into_iter()
                .map(|page| {
                    let len = remaining.min(io_channel::PAGE_SIZE);
                    remaining -= len;
                    TxPage {
                        page,
                        len,
                        consumed: 0,
                    }
                })
                .collect()
        };

        let socket = self.owned_vsock_socket(msg.handle, sender.remote_handle())?;
        {
            let mut socket = socket.borrow_mut();
            let state = socket.unwrap_vsock_mut();
            if !state.connection.accepts_new_writes() {
                return Err(connection_write_error(&state.connection));
            }
            if state.tx_pages.len() + pages.len() > MAX_PENDING_TX_PAGES {
                return Err(moto_rt::Error::InvalidArgument);
            }
            state.tx_pages.append(&mut pages);
        }
        self.inner.borrow().vsock.notify_submit();
        Ok(())
    }

    async fn vsock_shutdown(
        &self,
        request: io_channel::Msg,
        sender: &ClientSender,
    ) -> Result<(), moto_rt::Error> {
        let flags = api_vsock::decode_shutdown_request(&request)?;
        let socket = self.owned_vsock_socket(request.handle, sender.remote_handle())?;
        let notify = {
            let mut socket = socket.borrow_mut();
            let state = socket.unwrap_vsock_mut();
            if state.connection.terminal_cause().is_some() {
                return Err(connection_write_error(&state.connection));
            }
            state.connection.request_shutdown(flags);
            state.state_notify.notify_one();
            state.connect_notify.clone()
        };
        self.inner.borrow().vsock.notify_submit();

        loop {
            let ready = {
                let socket = socket.borrow();
                let state = socket.unwrap_vsock();
                state.connection.terminal_cause().is_some()
                    || state.connection.shutdown_published(flags)
            };
            if ready {
                break;
            }
            notify.notified().await;
        }

        let output_lock = socket.borrow().unwrap_vsock().output_lock.clone();
        let _guard = output_lock.lock().await;
        loop {
            let mut changed = core::pin::pin!(notify.notified().fuse());
            let mut response = request;
            response.status = {
                let socket = socket.borrow();
                let state = socket.unwrap_vsock();
                match state.connection.terminal_cause() {
                    Some(TerminalCause::InternalError) => moto_rt::E_INTERNAL_ERROR,
                    _ if state.connection.shutdown_published(flags) => moto_rt::E_OK,
                    Some(_) => connection_write_error(&state.connection).into(),
                    None => unreachable!("shutdown response lost its completion state"),
                }
            };
            let mut send = core::pin::pin!(sender.send(response).fuse());
            let result = futures::select_biased! {
                _ = changed => None,
                result = send => Some(result),
            };
            if let Some(result) = result {
                return result;
            }
        }
    }

    fn vsock_close(
        &self,
        request: io_channel::Msg,
        sender: &ClientSender,
    ) -> Result<(), moto_rt::Error> {
        api_vsock::decode_close_request(&request)?;
        let socket = self.owned_vsock_socket(request.handle, sender.remote_handle())?;
        self.start_vsock_cleanup(&socket);
        Ok(())
    }

    fn owned_vsock_socket(
        &self,
        socket_id: u64,
        client: SysHandle,
    ) -> Result<Rc<RefCell<MotoSocket>>, moto_rt::Error> {
        self.inner.borrow().vsock.availability()?;
        let socket = self
            .inner
            .borrow()
            .sockets
            .get(&socket_id)
            .cloned()
            .ok_or(moto_rt::Error::NotFound)?;
        let socket_ref = socket.borrow();
        if !socket_ref.is_vsock() || socket_ref.sender().remote_handle() != client {
            return Err(moto_rt::Error::NotFound);
        }
        drop(socket_ref);
        Ok(socket)
    }
}

fn map_allocation_error(error: std::io::Error) -> moto_rt::Error {
    match error.kind() {
        ErrorKind::OutOfMemory => moto_rt::Error::OutOfMemory,
        _ => moto_rt::Error::InternalError,
    }
}

fn same_process(owner: SysHandle, requester: SysHandle) -> bool {
    if owner == requester {
        return true;
    }
    matches!(
        (moto_sys::SysObj::get_pid(owner), moto_sys::SysObj::get_pid(requester)),
        (Ok(owner), Ok(requester)) if owner == requester
    )
}

fn map_admission_error(error: AdmissionError) -> moto_rt::Error {
    match error {
        AdmissionError::InvalidPort => moto_rt::Error::InvalidArgument,
        AdmissionError::PortInUse | AdmissionError::TupleInUse => moto_rt::Error::AlreadyInUse,
        AdmissionError::StreamLimit
        | AdmissionError::ListenerLimit
        | AdmissionError::OutOfMemory => moto_rt::Error::OutOfMemory,
        AdmissionError::SocketIdInUse | AdmissionError::UnknownListener => {
            moto_rt::Error::InternalError
        }
    }
}

fn connection_write_error(connection: &Connection) -> moto_rt::Error {
    match connection.terminal_cause() {
        Some(TerminalCause::ConnectionReset) => moto_rt::Error::ConnectionReset,
        Some(TerminalCause::InternalError) => moto_rt::Error::InternalError,
        _ => moto_rt::Error::NotConnected,
    }
}

enum StreamWork {
    Data {
        socket: Rc<RefCell<MotoSocket>>,
        len: usize,
    },
    Control {
        socket_id: u64,
        operation: Operation,
        flags: u32,
    },
}

impl NetRuntime {
    fn spawn_vsock_pumps(&self) {
        let runtime = self.clone();
        moto_async::LocalRuntime::spawn(async move { runtime.vsock_rx_pump().await });
        let runtime = self.clone();
        moto_async::LocalRuntime::spawn(async move { runtime.vsock_tx_submit_pump().await });
        let runtime = self.clone();
        moto_async::LocalRuntime::spawn(async move { runtime.vsock_tx_reclaim_pump().await });
        let runtime = self.clone();
        moto_async::LocalRuntime::spawn(async move { runtime.vsock_event_pump().await });
    }

    async fn vsock_tx_submit_pump(&self) {
        loop {
            if matches!(self.inner.borrow().vsock.device, DeviceState::Failed { .. }) {
                return;
            }
            let notify = self.inner.borrow().vsock.submit_notify();
            let wake = notify.notified();
            let mut progressed = 0;
            while progressed < PUMP_QUANTUM && self.vsock_submit_one() {
                progressed += 1;
            }
            if progressed == PUMP_QUANTUM {
                moto_async::yield_to_io().await;
            } else {
                wake.await;
            }
        }
    }

    fn vsock_submit_one(&self) -> bool {
        let driver = match self.inner.borrow().vsock.ready_driver() {
            Ok(driver) => driver,
            Err(_) => return false,
        };

        let control = self.inner.borrow_mut().vsock.controls.pop_front();
        if let Some(control) = control {
            let packet = match control {
                PendingControl::Refusal(raw) => Some(raw),
                PendingControl::Stream {
                    socket_id,
                    operation,
                    flags,
                } => self
                    .inner
                    .borrow()
                    .sockets
                    .get(&socket_id)
                    .cloned()
                    .map(|socket| stream_header(&socket.borrow(), operation, flags, 0)),
            };
            let Some(packet) = packet else {
                self.vsock_control_released();
                return true;
            };
            match driver.try_send(packet, &[]) {
                Ok(()) => {
                    self.vsock_control_published(control);
                    self.vsock_control_released();
                    return true;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    self.inner.borrow_mut().vsock.controls.push_front(control);
                    return false;
                }
                Err(err) => {
                    log::error!("virtio-vsock control submission failed: {err}");
                    self.fail_vsock_device();
                    return false;
                }
            }
        }

        let Some(work) = self.next_vsock_stream_work() else {
            return false;
        };
        match work {
            StreamWork::Control {
                socket_id,
                operation,
                flags,
            } => {
                let queued = self
                    .inner
                    .borrow_mut()
                    .vsock
                    .queue_control(PendingControl::Stream {
                        socket_id,
                        operation,
                        flags,
                    });
                if queued.is_err() {
                    return false;
                }
                if let Some(socket) = self.inner.borrow().sockets.get(&socket_id).cloned() {
                    let mut socket = socket.borrow_mut();
                    let state = socket.unwrap_vsock_mut();
                    match operation {
                        Operation::Shutdown => state.connection.record_shutdown_queued(flags),
                        Operation::CreditRequest => state.credit_request_outstanding = true,
                        Operation::Reset => state.reset_queued = true,
                        _ => {}
                    }
                }
                true
            }
            StreamWork::Data { socket, len } => {
                let result = {
                    let socket = socket.borrow();
                    let state = socket.unwrap_vsock();
                    let page = state.tx_pages.front().unwrap();
                    driver.try_send(
                        stream_header(&socket, Operation::ReadWrite, 0, len as u32),
                        &page.page.bytes()[page.consumed..page.consumed + len],
                    )
                };
                match result {
                    Ok(()) => {
                        let mut socket = socket.borrow_mut();
                        let state = socket.unwrap_vsock_mut();
                        state
                            .connection
                            .charge_tx_after_publish(len as u32)
                            .expect("vsock TX credit changed during synchronous publication");
                        let page = state.tx_pages.front_mut().unwrap();
                        page.consumed += len;
                        if page.consumed == page.len {
                            state.tx_pages.pop_front();
                        }
                        state.connect_notify.notify_all();
                        true
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => false,
                    Err(err) => {
                        log::error!("virtio-vsock data submission failed: {err}");
                        self.fail_vsock_device();
                        false
                    }
                }
            }
        }
    }

    fn next_vsock_stream_work(&self) -> Option<StreamWork> {
        let mut inner = self.inner.borrow_mut();
        let cursor = inner.vsock.next_tx_socket;
        let mut after: Option<(u64, Rc<RefCell<MotoSocket>>)> = None;
        let mut wrapped: Option<(u64, Rc<RefCell<MotoSocket>>)> = None;
        for socket_id in inner.vsock.tuples.stream_ids() {
            let socket = inner
                .sockets
                .get(&socket_id)
                .expect("vsock tuple index has no common socket");
            let socket_ref = socket.borrow();
            let state = socket_ref.unwrap_vsock();
            let allowance = state.connection.credit().tx_allowance();
            let data_runnable = !state.tx_pages.is_empty()
                && state.connection.can_publish_accepted_tx()
                && (allowance != 0 || !state.credit_request_outstanding);
            let actionable = state.pending_reset && !state.reset_queued
                || state.connection.shutdown_ready(state.accepted_tx_drained()) != 0
                || data_runnable;
            if !actionable {
                continue;
            }
            let candidate = (socket_id, socket.clone());
            if socket_id > cursor
                && after
                    .as_ref()
                    .is_none_or(|(candidate_id, _)| socket_id < *candidate_id)
            {
                after = Some(candidate);
            } else if wrapped
                .as_ref()
                .is_none_or(|(candidate_id, _)| socket_id < *candidate_id)
            {
                wrapped = Some(candidate);
            }
        }
        let (socket_id, socket) = after.or(wrapped)?;
        inner.vsock.next_tx_socket = socket_id;
        let socket_ref = socket.borrow();
        let state = socket_ref.unwrap_vsock();
        if state.pending_reset && !state.reset_queued {
            return Some(StreamWork::Control {
                socket_id,
                operation: Operation::Reset,
                flags: 0,
            });
        }
        let shutdown = state.connection.shutdown_ready(state.accepted_tx_drained());
        if shutdown != 0 {
            return Some(StreamWork::Control {
                socket_id,
                operation: Operation::Shutdown,
                flags: shutdown,
            });
        }
        let allowance = state.connection.credit().tx_allowance() as usize;
        if allowance == 0 {
            if state.credit_request_outstanding {
                return None;
            }
            drop(socket_ref);
            return Some(StreamWork::Control {
                socket_id,
                operation: Operation::CreditRequest,
                flags: 0,
            });
        }
        let page = state.tx_pages.front().unwrap();
        let len = (page.len - page.consumed)
            .min(allowance)
            .min(moto_sys::sys_mem::PAGE_SIZE_SMALL as usize);
        drop(socket_ref);
        Some(StreamWork::Data { socket, len })
    }

    fn vsock_control_published(&self, control: PendingControl) {
        let PendingControl::Stream {
            socket_id,
            operation,
            flags,
        } = control
        else {
            return;
        };
        let Some(socket) = self.inner.borrow().sockets.get(&socket_id).cloned() else {
            return;
        };
        let mut socket = socket.borrow_mut();
        let state = socket.unwrap_vsock_mut();
        match operation {
            Operation::Shutdown => state.connection.record_shutdown_published(flags),
            Operation::Reset => {
                state.pending_reset = false;
                state.reset_queued = false;
            }
            _ => {}
        }
        state.connect_notify.notify_all();
        state.state_notify.notify_one();
        let remove_unaccepted = state.listener_id.is_some() && state.terminal_ready_to_drop();
        drop(socket);
        if remove_unaccepted {
            self.remove_vsock_socket(socket_id);
        }
    }

    fn vsock_control_released(&self) {
        let (space, submit) = {
            let inner = self.inner.borrow();
            (inner.vsock.control_space(), inner.vsock.submit_notify())
        };
        space.notify_all();
        submit.notify_one();
    }

    async fn vsock_tx_reclaim_pump(&self) {
        let mut progressed = 0;
        loop {
            let Some(driver) = self.inner.borrow().vsock.retained_driver() else {
                return;
            };
            let result = std::future::poll_fn(|cx| driver.poll_reclaim_tx(cx)).await;
            if let Err(err) = result {
                log::error!("virtio-vsock TX completion failed: {err}");
                self.fail_vsock_device();
            }
            if let Some(notify) = self.inner.borrow().vsock.submit_notify.as_ref() {
                notify.notify_one();
            }
            progressed += 1;
            if progressed == PUMP_QUANTUM {
                progressed = 0;
                moto_async::yield_to_io().await;
            }
        }
    }
}

fn stream_header(socket: &MotoSocket, operation: Operation, flags: u32, len: u32) -> RawHeader {
    let tuple = socket.vsock_tuple();
    let advertisement = socket
        .unwrap_vsock()
        .connection
        .credit()
        .local_advertisement();
    PacketHeader {
        src_cid: tuple.local.cid,
        dst_cid: tuple.peer.cid,
        src_port: tuple.local.port,
        dst_port: tuple.peer.port,
        len,
        socket_type: SocketType::Stream,
        operation,
        flags,
        buf_alloc: advertisement.buf_alloc,
        fwd_cnt: advertisement.fwd_cnt,
    }
    .into()
}

impl NetRuntime {
    async fn vsock_rx_pump(&self) {
        let mut progressed = 0;
        loop {
            let (driver, space) = {
                let inner = self.inner.borrow();
                let Some(driver) = inner.vsock.retained_driver() else {
                    return;
                };
                (driver, inner.vsock.control_space())
            };
            // A received packet can require one control response. Register the
            // capacity waiter before each poll, then do not consume the used
            // entry unless that response can be retained synchronously.
            let mut space_ready = core::pin::pin!(space.notified().fuse());
            let mut receive = core::pin::pin!(
                std::future::poll_fn(|cx| {
                    if !self.inner.borrow().vsock.has_control_space() {
                        return Poll::Pending;
                    }
                    driver.poll_receive(cx, |decoded, payload| {
                        self.handle_vsock_packet(driver.guest_cid(), decoded, payload)
                    })
                })
                .fuse()
            );
            let result = futures::select! {
                result = receive => result,
                _ = space_ready => continue,
            };
            if let Err(err) = result {
                log::debug!("discarding invalid virtio-vsock packet: {:?}", err.kind);
            }
            progressed += 1;
            if progressed == PUMP_QUANTUM {
                progressed = 0;
                moto_async::yield_to_io().await;
            }
        }
    }

    fn handle_vsock_packet(
        &self,
        local_cid: u32,
        decoded: Result<PacketHeader, DecodeError>,
        payload: &[u8],
    ) -> Result<(), DecodeError> {
        // A failed device remains retained so returned DMA owners can be
        // reclaimed, but it must not create new protocol work.
        if !self.inner.borrow().vsock.accepts_protocol_effects() {
            return Ok(());
        }
        let header = match decoded {
            Ok(header) => header,
            Err(err) => {
                if let Some(raw) = err.raw.and_then(|raw| RawHeader::refusal(local_cid, raw)) {
                    let _ = self
                        .inner
                        .borrow_mut()
                        .vsock
                        .queue_control(PendingControl::Refusal(raw));
                }
                return Err(err);
            }
        };
        let tuple = ConnectionTuple {
            local: VsockAddr {
                cid: header.dst_cid,
                port: header.dst_port,
            },
            peer: VsockAddr {
                cid: header.src_cid,
                port: header.src_port,
            },
        };
        let socket_id = (header.dst_cid == local_cid)
            .then(|| self.inner.borrow().vsock.tuples.stream_socket(tuple))
            .flatten();
        let Some(socket_id) = socket_id else {
            if header.dst_cid == local_cid
                && header.operation == Operation::Request
                && self.admit_vsock_request(&header)
            {
                self.inner.borrow().vsock.notify_submit();
                return Ok(());
            }
            if let Some(raw) = RawHeader::refusal(local_cid, header.into()) {
                let _ = self
                    .inner
                    .borrow_mut()
                    .vsock
                    .queue_control(PendingControl::Refusal(raw));
            }
            return Ok(());
        };
        let socket = self
            .inner
            .borrow()
            .sockets
            .get(&socket_id)
            .cloned()
            .expect("vsock tuple index has no common socket");

        let (outcome, orderly_reset) = {
            let mut socket = socket.borrow_mut();
            let state = socket.unwrap_vsock_mut();
            let outcome = state.connection.receive(&header, payload);
            if state.connection.credit().tx_allowance() != 0 {
                state.credit_request_outstanding = false;
            }
            if outcome == ReceiveOutcome::Connected {
                state.connected_observed = true;
            }
            if header.operation == Operation::ReadWrite
                && !payload.is_empty()
                && outcome != ReceiveOutcome::SendReset
            {
                state.rx_notify.notify_one();
            }
            let orderly_reset = state.connection.take_orderly_reset_if_ready();
            if !state.connection.can_publish_accepted_tx() {
                state.tx_pages.clear();
            }
            state.connect_notify.notify_all();
            state.rx_notify.notify_one();
            state.state_notify.notify_one();
            (outcome, orderly_reset)
        };

        match outcome {
            ReceiveOutcome::SendCreditUpdate => {
                let _ = self
                    .inner
                    .borrow_mut()
                    .vsock
                    .queue_control(PendingControl::Stream {
                        socket_id,
                        operation: Operation::CreditUpdate,
                        flags: 0,
                    });
            }
            ReceiveOutcome::SendReset => self.queue_vsock_reset(socket_id),
            ReceiveOutcome::None | ReceiveOutcome::Connected => {}
        }
        if orderly_reset {
            self.queue_vsock_reset(socket_id);
        }
        let remove_unaccepted = {
            let socket = socket.borrow();
            let state = socket.unwrap_vsock();
            state.listener_id.is_some() && state.terminal_ready_to_drop()
        };
        if remove_unaccepted {
            self.remove_vsock_socket(socket_id);
        }
        self.inner.borrow().vsock.notify_submit();
        Ok(())
    }

    fn admit_vsock_request(&self, header: &PacketHeader) -> bool {
        let local = VsockAddr {
            cid: header.dst_cid,
            port: header.dst_port,
        };
        let peer = VsockAddr {
            cid: header.src_cid,
            port: header.src_port,
        };
        let (listener_id, listener, sender) = {
            let inner = self.inner.borrow();
            let Some(listener_id) = inner.vsock.tuples.listener_socket(local) else {
                return false;
            };
            let listener = inner
                .sockets
                .get(&listener_id)
                .cloned()
                .expect("vsock listener index has no common socket");
            let listener_ref = listener.borrow();
            if !listener_ref.unwrap_vsock_listener().has_capacity() {
                return false;
            }
            let sender = listener_ref.sender().clone();
            drop(listener_ref);
            (listener_id, listener, sender)
        };
        let Ok(connection) = Connection::new_incoming(header) else {
            return false;
        };
        let Ok(state) = VsockSocketState::new_unaccepted(connection, listener_id) else {
            return false;
        };
        let (socket_id, tuple) = {
            let mut inner = self.inner.borrow_mut();
            let socket_id = inner.next_socket_id();
            let Ok(tuple) = inner
                .vsock
                .tuples
                .reserve_accepted(listener_id, socket_id, peer)
            else {
                return false;
            };
            (socket_id, tuple)
        };
        let base = SocketBase::new_vsock(socket_id, self.clone(), tuple, sender);
        if MotoSocket::new_vsock(base, state).is_err() {
            return false;
        }
        // The RX pump reserved one control slot before consuming REQUEST, and
        // admission has no await point at which another task could take it.
        self.inner
            .borrow_mut()
            .vsock
            .queue_control(PendingControl::Stream {
                socket_id,
                operation: Operation::Response,
                flags: 0,
            })
            .expect("RX control-space reservation was lost during REQUEST admission");
        self.match_vsock_accept(&listener, socket_id);
        true
    }

    fn match_vsock_accept(&self, listener: &Rc<RefCell<MotoSocket>>, socket_id: u64) {
        let accept = listener
            .borrow_mut()
            .unwrap_vsock_listener_mut()
            .push(socket_id);
        if let Some(waiter) = accept
            && let Err(Ok(returned_id)) = waiter.ready.send(Ok(socket_id))
        {
            assert_eq!(returned_id, socket_id);
            self.reset_unaccepted(socket_id);
        }
    }

    fn queue_vsock_reset(&self, socket_id: u64) {
        if let Some(socket) = self.inner.borrow().sockets.get(&socket_id).cloned() {
            let mut socket = socket.borrow_mut();
            let state = socket.unwrap_vsock_mut();
            if !state.pending_reset {
                state.pending_reset = true;
                state.reset_queued = false;
                state.tx_pages.clear();
                state.connect_notify.notify_all();
                state.rx_notify.notify_one();
                state.state_notify.notify_one();
            }
        }
        self.inner.borrow().vsock.notify_submit();
    }

    fn reset_unaccepted(&self, socket_id: u64) {
        let socket = self.inner.borrow().sockets.get(&socket_id).cloned();
        let Some(socket) = socket else {
            return;
        };
        let needs_reset = {
            let mut socket = socket.borrow_mut();
            let state = socket.unwrap_vsock_mut();
            assert!(state.listener_id.is_some());
            state.tx_pages.clear();
            let needs_reset = state.connection.abandon_unread_rx() || state.pending_reset;
            state.connect_notify.notify_all();
            state.rx_notify.notify_one();
            state.state_notify.notify_one();
            needs_reset
        };
        if matches!(self.inner.borrow().vsock.device, DeviceState::Ready(_)) && needs_reset {
            self.queue_vsock_reset(socket_id);
        } else {
            self.remove_vsock_socket(socket_id);
        }
    }

    async fn vsock_event_pump(&self) {
        let mut progressed = 0;
        loop {
            let Some(driver) = self.inner.borrow().vsock.retained_driver() else {
                return;
            };
            let event = std::future::poll_fn(|cx| {
                driver.poll_event(cx, |event| {
                    if event == Ok(Event::TransportReset) {
                        driver.stop_reposting();
                    }
                    event
                })
            })
            .await;
            if self.inner.borrow().vsock.accepts_protocol_effects() {
                match event {
                    Ok(Event::TransportReset) => self.fail_vsock_device(),
                    Err(err) => log::debug!("discarding invalid virtio-vsock event: {err:?}"),
                }
            }
            progressed += 1;
            if progressed == PUMP_QUANTUM {
                progressed = 0;
                moto_async::yield_to_io().await;
            }
        }
    }

    fn fail_vsock_device(&self) {
        let (sockets, listeners, failure_notify) = {
            let mut inner = self.inner.borrow_mut();
            if matches!(&inner.vsock.device, DeviceState::Failed { .. }) {
                return;
            }
            let driver = inner.vsock.retained_driver();
            if let Some(driver) = &driver {
                driver.stop_reposting();
            }
            inner.vsock.device = DeviceState::Failed {
                driver,
                error: moto_rt::Error::InternalError,
            };
            inner.vsock.controls.clear();
            let mut sockets: [Option<Rc<RefCell<MotoSocket>>>; MAX_STREAMS] =
                std::array::from_fn(|_| None);
            for (slot, socket_id) in sockets.iter_mut().zip(inner.vsock.tuples.stream_ids()) {
                *slot = inner.sockets.get(&socket_id).cloned();
            }
            let mut listeners: [Option<(u64, SysHandle)>; MAX_LISTENERS] =
                std::array::from_fn(|_| None);
            for (slot, socket_id) in listeners.iter_mut().zip(inner.vsock.tuples.listener_ids()) {
                let socket = inner
                    .sockets
                    .get(&socket_id)
                    .expect("vsock listener index has no common socket")
                    .borrow();
                *slot = Some((socket_id, socket.sender().remote_handle()));
            }
            (sockets, listeners, inner.vsock.failure_notify.clone())
        };
        for socket in sockets.into_iter().flatten() {
            let (socket_id, unaccepted) = {
                let mut socket = socket.borrow_mut();
                let socket_id = socket.socket_id();
                let state = socket.unwrap_vsock_mut();
                state.tx_pages.clear();
                state.pending_reset = false;
                state.reset_queued = false;
                state.connection.device_failed();
                state.notified_flags = 0;
                state.connect_notify.notify_all();
                state.rx_notify.notify_one();
                state.state_notify.notify_one();
                (socket_id, state.listener_id.is_some())
            };
            if unaccepted {
                self.remove_vsock_socket(socket_id);
            }
        }
        for (socket_id, client) in listeners.into_iter().flatten() {
            let listener = self
                .inner
                .borrow()
                .sockets
                .get(&socket_id)
                .cloned()
                .expect("indexed vsock listener disappeared during device failure");
            let mut accepts = listener
                .borrow_mut()
                .unwrap_vsock_listener_mut()
                .take_accepts();
            while let Some(accept) = accepts.pop_front() {
                let _ = accept.ready.send(Err(moto_rt::Error::InternalError));
            }
            self.remove_vsock_listener(socket_id, client)
                .expect("indexed vsock listener disappeared during device failure");
        }
        self.vsock_control_released();
        if let Some(notify) = failure_notify {
            notify.notify_all();
        }
    }

    async fn vsock_connect_task(&self, weak: Weak<RefCell<MotoSocket>>, request: io_channel::Msg) {
        let Some(socket) = weak.upgrade() else {
            return;
        };
        let notify = socket.borrow().unwrap_vsock().connect_notify.clone();
        let mut deadline = core::pin::pin!(moto_async::sleep(Duration::from_secs(2)).fuse());
        let was_connected = loop {
            let (connected, terminal) = {
                let socket = socket.borrow();
                let state = socket.unwrap_vsock();
                (
                    state.connected_observed,
                    state.connection.terminal_cause().is_some(),
                )
            };
            if connected {
                break true;
            }
            if terminal {
                break false;
            }
            let mut changed = core::pin::pin!(notify.notified().fuse());
            futures::select! {
                _ = changed => {},
                _ = deadline => {
                    let (socket_id, timed_out) = {
                        let mut socket = socket.borrow_mut();
                        let socket_id = socket.socket_id();
                        let timed_out = socket
                            .unwrap_vsock_mut()
                            .connection
                            .connect_timed_out();
                        (socket_id, timed_out)
                    };
                    if timed_out {
                        self.queue_vsock_reset(socket_id);
                    }
                }
            }
        };

        let (sender, output_lock, local) = {
            let socket = socket.borrow();
            let state = socket.unwrap_vsock();
            (
                socket.sender().clone(),
                state.output_lock.clone(),
                socket.vsock_tuple().local,
            )
        };
        let (sent, response_connected) = {
            let _guard = output_lock.lock().await;
            loop {
                let mut changed = core::pin::pin!(notify.notified().fuse());
                let error = match socket.borrow().unwrap_vsock().connection.terminal_cause() {
                    Some(TerminalCause::InternalError) => Some(moto_rt::Error::InternalError),
                    _ if was_connected => None,
                    None => None,
                    Some(TerminalCause::TimedOut) => Some(moto_rt::Error::TimedOut),
                    Some(TerminalCause::ConnectionReset) => Some(moto_rt::Error::ConnectionReset),
                    Some(TerminalCause::Refused | TerminalCause::OrderlyClosed) => {
                        Some(moto_rt::Error::NotConnected)
                    }
                };
                let response_connected = error.is_none();
                let response = if let Some(error) = error {
                    let mut response = request;
                    response.status = error.into();
                    response
                } else {
                    api_vsock::encode_connect_response(
                        &request,
                        socket.borrow().socket_id(),
                        api_vsock::VsockAddr {
                            cid: local.cid,
                            port: local.port,
                        },
                    )
                    .expect("reserved vsock tuple produced an invalid response")
                };
                let mut send = core::pin::pin!(sender.send(response).fuse());
                let send_result = futures::select_biased! {
                    _ = changed => None,
                    result = send => Some(result),
                };
                let Some(send_result) = send_result else {
                    continue;
                };
                let sent = send_result.is_ok();
                if sent && response_connected {
                    socket.borrow_mut().unwrap_vsock_mut().client_ready = true;
                }
                break (sent, response_connected);
            }
        };

        if response_connected && sent {
            self.start_vsock_client_tasks(&socket);
            return;
        }
        if was_connected {
            self.start_vsock_cleanup(&socket);
        }

        loop {
            let (socket_id, ready) = {
                let socket = socket.borrow();
                (
                    socket.socket_id(),
                    socket.unwrap_vsock().terminal_ready_to_drop(),
                )
            };
            if ready {
                self.remove_vsock_socket(socket_id);
                return;
            }
            notify.notified().await;
        }
    }

    async fn vsock_accept_task(
        &self,
        socket_id: u64,
        request: io_channel::Msg,
        sender: &ClientSender,
        subchannel_mask: u64,
    ) -> Result<(), moto_rt::Error> {
        let socket = self.inner.borrow().sockets.get(&socket_id).cloned();
        let Some(socket) = socket else {
            return Err(moto_rt::Error::NotConnected);
        };
        let (local, peer, output_lock, connect_notify) = {
            let socket = socket.borrow();
            let tuple = socket.vsock_tuple();
            (
                api_vsock::VsockAddr {
                    cid: tuple.local.cid,
                    port: tuple.local.port,
                },
                api_vsock::VsockAddr {
                    cid: tuple.peer.cid,
                    port: tuple.peer.port,
                },
                socket.unwrap_vsock().output_lock.clone(),
                socket.unwrap_vsock().connect_notify.clone(),
            )
        };
        let response = api_vsock::encode_listener_accept_response(&request, socket_id, local, peer)
            .expect("reserved vsock tuple produced an invalid accept response");
        let _guard = output_lock.lock().await;
        loop {
            let changed = connect_notify.notified().fuse();
            let (failure, client_active) = {
                let inner = self.inner.borrow();
                let socket_ref = socket.borrow();
                let state = socket_ref.unwrap_vsock();
                let terminal = state.connection.terminal_cause();
                let listener_retained = state
                    .listener_id
                    .is_some_and(|id| inner.sockets.contains_key(&id));
                let retained = inner
                    .sockets
                    .get(&socket_id)
                    .is_some_and(|retained| Rc::ptr_eq(retained, &socket));
                let failure = if matches!(terminal, Some(TerminalCause::InternalError)) {
                    Some(moto_rt::Error::InternalError)
                } else if !retained || !listener_retained {
                    Some(moto_rt::Error::NotConnected)
                } else {
                    inner.vsock.ready_driver().err()
                };
                let client_active = inner
                    .clients
                    .get(&sender.remote_handle())
                    .is_some_and(|client| !client.shutting_down);
                (failure, client_active)
            };
            if let Some(error) = failure {
                return Err(error);
            }
            if !client_active {
                self.reset_unaccepted(socket_id);
                return Ok(());
            }
            let send = sender.send(response).fuse();
            futures::pin_mut!(changed, send);
            futures::select_biased! {
                _ = changed => {}
                result = send => {
                    if result.is_err() {
                        self.reset_unaccepted(socket_id);
                        return Ok(());
                    }
                    break;
                }
            }
        }

        // No await after FIFO publication: install ownership and routing
        // before this runtime can dispatch another message for the stream.
        {
            let mut socket = socket.borrow_mut();
            assert!(socket.set_client_sender(sender));
            let state = socket.unwrap_vsock_mut();
            state.subchannel_mask = subchannel_mask;
            state.listener_id = None;
            state.client_ready = true;
        }
        drop(_guard);
        self.start_vsock_client_tasks(&socket);
        Ok(())
    }

    fn start_vsock_client_tasks(&self, socket: &Rc<RefCell<MotoSocket>>) {
        let runtime = self.clone();
        let weak = Rc::downgrade(socket);
        moto_async::LocalRuntime::spawn(async move { runtime.vsock_state_task(weak).await });
        let runtime = self.clone();
        let weak = Rc::downgrade(socket);
        moto_async::LocalRuntime::spawn(async move { runtime.vsock_client_rx_task(weak).await });
        let socket = socket.borrow();
        socket.unwrap_vsock().state_notify.notify_one();
        socket.unwrap_vsock().rx_notify.notify_one();
    }

    async fn vsock_state_task(&self, weak: Weak<RefCell<MotoSocket>>) {
        loop {
            let notify = {
                let Some(socket) = weak.upgrade() else {
                    return;
                };
                socket.borrow().unwrap_vsock().state_notify.clone()
            };
            notify.notified().await;
            let Some(socket) = weak.upgrade() else {
                return;
            };
            let output_lock = socket.borrow().unwrap_vsock().output_lock.clone();
            let _guard = output_lock.lock().await;
            if !socket.borrow().unwrap_vsock().client_ready {
                continue;
            }
            let sent = loop {
                // A terminal stream must leave the tables even when its
                // former client can no longer receive the final notification.
                if socket.borrow().unwrap_vsock().client_gone {
                    break true;
                }
                let mut changed = core::pin::pin!(notify.notified().fuse());
                let message = {
                    let socket = socket.borrow();
                    let socket_id = socket.socket_id();
                    let state = socket.unwrap_vsock();
                    let (flags, cause) = state.state_change();
                    (flags != state.notified_flags).then(|| {
                        (
                            api_vsock::state_changed(socket_id, flags, cause)
                                .expect("vsock state produced an invalid notification"),
                            flags,
                        )
                    })
                };
                let Some((message, flags)) = message else {
                    break true;
                };
                let sender = socket.borrow().sender().clone();
                let mut send = core::pin::pin!(sender.send(message).fuse());
                let result = futures::select_biased! {
                    _ = changed => None,
                    result = send => Some(result),
                };
                let Some(result) = result else {
                    continue;
                };
                if result.is_ok() {
                    socket.borrow_mut().unwrap_vsock_mut().notified_flags = flags;
                    break true;
                }
                break false;
            };
            drop(_guard);
            if !sent {
                self.disconnect_vsock_client(&socket);
            }
            let finish = socket.borrow().unwrap_vsock().terminal_ready_to_drop();
            let socket_id = socket.borrow().socket_id();
            if finish {
                self.remove_vsock_socket(socket_id);
                return;
            }
        }
    }

    async fn vsock_client_rx_task(&self, weak: Weak<RefCell<MotoSocket>>) {
        loop {
            let rx_notify = {
                let Some(socket) = weak.upgrade() else {
                    return;
                };
                socket.borrow().unwrap_vsock().rx_notify.clone()
            };
            rx_notify.notified().await;
            let Some(socket) = weak.upgrade() else {
                return;
            };
            let (sender, subchannel_mask, read_closed) = {
                let socket = socket.borrow();
                let state = socket.unwrap_vsock();
                (
                    socket.sender().clone(),
                    state.subchannel_mask,
                    state.connection.local_read_closed()
                        && (!state.connection.has_buffered_rx()
                            || state.connection.local_receive_shutdown()),
                )
            };
            if read_closed {
                return;
            }
            loop {
                let should_read = {
                    let socket = socket.borrow();
                    let state = socket.unwrap_vsock();
                    state.client_ready
                        && !state.connection.local_receive_shutdown()
                        && state.connection.has_buffered_rx()
                };
                if !should_read {
                    break;
                }

                let mut page = core::pin::pin!(sender.alloc_page(subchannel_mask).fuse());
                let mut changed = core::pin::pin!(rx_notify.notified().fuse());
                let page = futures::select! {
                    page = page => match page {
                        Ok(page) => page,
                        Err(_) => {
                            self.disconnect_vsock_client(&socket);
                            return;
                        }
                    },
                    _ = changed => continue,
                };

                let output_lock = socket.borrow().unwrap_vsock().output_lock.clone();
                let _guard = output_lock.lock().await;
                let (page, len, orderly_reset) = {
                    let mut socket = socket.borrow_mut();
                    let state = socket.unwrap_vsock_mut();
                    if state.connection.local_receive_shutdown()
                        || !state.connection.has_buffered_rx()
                    {
                        drop(page);
                        continue;
                    }
                    let mut page = page;
                    let outcome = state.connection.read_into_reserved(page.bytes_mut());
                    let crate::runtime::vsock::stream::ReadOutcome::Copied(len) = outcome else {
                        drop(page);
                        continue;
                    };
                    let orderly_reset = state.connection.take_orderly_reset_if_ready();
                    (page, len, orderly_reset)
                };
                let socket_id = socket.borrow().socket_id();
                // Encoding transfers the page into a Copy message. Keep this
                // publication serialized ahead of a later failure state; the
                // native side discards queued RX when it observes that state.
                let message = api_vsock::stream_rx_msg(socket_id, page, len, 0);
                let sent = sender.send(message).await.is_ok();
                drop(_guard);
                if !sent {
                    self.disconnect_vsock_client(&socket);
                    return;
                }
                if orderly_reset {
                    self.queue_vsock_reset(socket_id);
                }
                socket.borrow().unwrap_vsock().state_notify.notify_one();
                self.queue_vsock_credit_update(socket_id).await;
            }
            let read_closed = {
                let socket = socket.borrow();
                let state = socket.unwrap_vsock();
                state.connection.local_read_closed()
                    && (!state.connection.has_buffered_rx()
                        || state.connection.local_receive_shutdown())
            };
            if read_closed {
                return;
            }
        }
    }

    async fn queue_vsock_credit_update(&self, socket_id: u64) {
        loop {
            let space = {
                let inner = self.inner.borrow();
                if !matches!(inner.vsock.device, DeviceState::Ready(_)) {
                    return;
                }
                let Some(socket) = inner.sockets.get(&socket_id) else {
                    return;
                };
                if socket
                    .borrow()
                    .unwrap_vsock()
                    .connection
                    .terminal_cause()
                    .is_some()
                {
                    return;
                }
                inner.vsock.control_space()
            };
            let waiter = space.notified();
            let result = self
                .inner
                .borrow_mut()
                .vsock
                .queue_control(PendingControl::Stream {
                    socket_id,
                    operation: Operation::CreditUpdate,
                    flags: 0,
                });
            match result {
                Ok(()) => return,
                Err(moto_rt::Error::OutOfMemory) => waiter.await,
                Err(_) => return,
            }
        }
    }

    pub(super) fn disconnect_vsock_client(&self, socket: &Rc<RefCell<MotoSocket>>) {
        if std::mem::replace(
            &mut socket.borrow_mut().unwrap_vsock_mut().client_gone,
            true,
        ) {
            return;
        }
        self.start_vsock_cleanup(socket);
    }

    pub(super) fn start_vsock_cleanup(&self, socket: &Rc<RefCell<MotoSocket>>) {
        let start_timer = {
            let mut socket = socket.borrow_mut();
            let state = socket.unwrap_vsock_mut();
            state
                .connection
                .request_shutdown(SHUTDOWN_RECEIVE | SHUTDOWN_SEND);
            state.connect_notify.notify_all();
            state.rx_notify.notify_one();
            state.state_notify.notify_one();
            state.connection.begin_cleanup()
        };
        self.inner.borrow().vsock.notify_submit();
        if !start_timer {
            return;
        }
        let runtime = self.clone();
        let weak = Rc::downgrade(socket);
        let (socket_id, notify) = {
            let socket = socket.borrow();
            (
                socket.socket_id(),
                socket.unwrap_vsock().connect_notify.clone(),
            )
        };
        moto_async::LocalRuntime::spawn(async move {
            let mut deadline = core::pin::pin!(moto_async::sleep(Duration::from_secs(8)).fuse());
            loop {
                let Some(socket) = weak.upgrade() else {
                    return;
                };
                // Register before rechecking so terminalization or removal
                // cannot race with parking this cleanup task.
                let mut changed = core::pin::pin!(notify.notified().fuse());
                let finished = socket
                    .borrow()
                    .unwrap_vsock()
                    .connection
                    .terminal_cause()
                    .is_some()
                    || !runtime
                        .inner
                        .borrow()
                        .sockets
                        .get(&socket_id)
                        .is_some_and(|retained| Rc::ptr_eq(retained, &socket));
                drop(socket);
                if finished {
                    return;
                }
                futures::select! {
                    _ = changed => continue,
                    _ = deadline => break,
                }
            }

            let Some(socket) = weak.upgrade() else {
                return;
            };
            if !runtime
                .inner
                .borrow()
                .sockets
                .get(&socket_id)
                .is_some_and(|retained| Rc::ptr_eq(retained, &socket))
            {
                return;
            }
            let expired = {
                let mut socket = socket.borrow_mut();
                let state = socket.unwrap_vsock_mut();
                if state.connection.expire_cleanup() {
                    state.tx_pages.clear();
                    state.state_notify.notify_one();
                    true
                } else {
                    false
                }
            };
            if expired {
                runtime.queue_vsock_reset(socket_id);
            }
        });
    }

    fn remove_vsock_socket(&self, socket_id: u64) {
        let socket = {
            let mut inner = self.inner.borrow_mut();
            let Some(socket) = inner.sockets.remove(&socket_id) else {
                return;
            };
            assert!(inner.vsock.tuples.remove_stream(socket_id).is_some());
            let listener_id = socket.borrow().unwrap_vsock().listener_id;
            if let Some(listener) = listener_id.and_then(|id| inner.sockets.get(&id).cloned()) {
                listener
                    .borrow_mut()
                    .unwrap_vsock_listener_mut()
                    .remove(socket_id);
            }
            {
                let socket = socket.borrow();
                let state = socket.unwrap_vsock();
                state.connect_notify.notify_all();
                state.rx_notify.notify_one();
                state.state_notify.notify_one();
            }
            let client = socket.borrow().sender().remote_handle();
            if let Some(client) = inner.clients.get_mut(&client) {
                client.sockets.remove(&socket_id);
            }
            socket
        };
        drop(socket);
    }
}
