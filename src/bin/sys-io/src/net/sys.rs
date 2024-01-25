use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::runtime::{process::Process, PendingCompletion};
use crate::{moto_log, runtime::IoSubsystem};
use moto_ipc::io_channel;
use moto_runtime::rt_api;
use moto_sys::{ErrorCode, SysHandle};

use super::tcp::{TcpListener, TcpState, TcpStream};
use super::{config::NetConfig, netdev::NetEvent};
use super::{netdev::NetDev, IoBuf};

pub(super) struct NetSys {
    devices: Vec<Box<NetDev>>, // Never changes, as device_idx references inside here.
    handles: HashMap<SysHandle, usize>, // Handle -> idx in self.devices.
    ip_addresses: HashMap<IpAddr, usize>,
    next_id: u64,

    tcp_listeners: HashMap<u64, TcpListener>,
    tcp_streams: HashMap<u64, TcpStream>,

    pending_events: VecDeque<(usize, NetEvent)>, // (device idx, event)
    pending_completions: VecDeque<PendingCompletion>,

    // Process ID -> TCP listeners/streams.
    process_tcp_listeners_map: HashMap<SysHandle, HashSet<u64>>,
    process_tcp_streams_map: HashMap<SysHandle, HashSet<u64>>,

    config: NetConfig,
}

impl NetSys {
    pub fn new(net_config: super::config::NetConfig) -> Self {
        #[cfg(debug_assertions)]
        crate::moto_log!(
            "{}:{} TODO: tcp stream read does one buffer at a time. Enqueue more?.",
            file!(),
            line!()
        );

        let mut self_mut = Self {
            devices: Vec::new(),
            handles: HashMap::new(),
            ip_addresses: HashMap::new(),
            next_id: 1,
            tcp_listeners: HashMap::new(),
            tcp_streams: HashMap::new(),
            pending_events: VecDeque::new(),
            pending_completions: VecDeque::new(),
            process_tcp_listeners_map: HashMap::new(),
            process_tcp_streams_map: HashMap::new(),
            config: net_config,
        };

        self_mut.devices.push(super::netdev_loopback::init());
        self_mut
            .devices
            .append(&mut super::netdev_virtio::init(&self_mut.config));

        for idx in 0..self_mut.devices.len() {
            let device = &self_mut.devices[idx];
            for handle in device.wait_handles() {
                self_mut.handles.insert(handle, idx);
            }
            for addr in device.ip_addresses() {
                self_mut.ip_addresses.insert(addr.addr, idx);
            }

            #[cfg(debug_assertions)]
            moto_log!("sys-io: initialized net device {}", device.name());
        }
        self_mut
    }

    fn tcp_listener_bind(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> io_channel::QueueEntry {
        if self.devices.is_empty() {
            sqe.status = ErrorCode::NotFound.into();
            return sqe;
        }

        let socket_addr = match rt_api::net::get_socket_addr(&sqe.payload) {
            Ok(addr) => addr,
            Err(err) => {
                sqe.status = err.into();
                return sqe;
            }
        };

        let ip_addr = socket_addr.ip();
        let device_idx: Option<usize> = if ip_addr.is_unspecified() {
            None
        } else {
            match self.ip_addresses.get(&ip_addr) {
                Some(idx) => Some(*idx),
                None => {
                    sqe.status = ErrorCode::InvalidArgument.into();
                    return sqe;
                }
            }
        };

        let test_device_idx = match device_idx {
            Some(idx) => idx,
            None => 0_usize,
        };

        if self.devices[test_device_idx]
            .tcp_listener_find(&socket_addr)
            .is_some()
        {
            sqe.status = ErrorCode::AlreadyInUse.into();
            return sqe;
        }

        let new_id = self.next_id();
        self.tcp_listeners.insert(
            new_id,
            TcpListener::new(new_id, proc.handle(), device_idx, socket_addr),
        );
        let proc_listeners = match self.process_tcp_listeners_map.get_mut(&proc.handle()) {
            Some(val) => val,
            None => {
                self.process_tcp_listeners_map
                    .insert(proc.handle(), HashSet::new());
                self.process_tcp_listeners_map
                    .get_mut(&proc.handle())
                    .unwrap()
            }
        };
        assert!(proc_listeners.insert(new_id));

        #[cfg(debug_assertions)]
        moto_log!(
            "sys-io: new tcp listener on {:?}, conn: 0x{:x}",
            socket_addr,
            proc.handle().as_u64()
        );

        match device_idx {
            None => {
                for device in &mut self.devices {
                    device.tcp_listener_bind(self.tcp_listeners.get(&new_id).unwrap());
                }
            }
            Some(idx) => {
                self.devices[idx].tcp_listener_bind(self.tcp_listeners.get(&new_id).unwrap())
            }
        }

        sqe.handle = new_id;
        sqe.status = ErrorCode::Ok.into();
        sqe
    }

    fn tcp_listener_accept(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let listener = match self.tcp_listeners.get_mut(&sqe.handle) {
            Some(l) => l,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };

        if listener.process() != proc.handle() {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        match listener.get_pending_stream() {
            Some(stream_id) => {
                let stream = self.tcp_streams.get_mut(&stream_id).unwrap();
                stream.mark_accepted();
                sqe.handle = stream_id;
                rt_api::net::put_socket_addr(&mut sqe.payload, stream.remote_addr());
                sqe.status = ErrorCode::Ok.into();
                Some(sqe)
            }
            None => {
                listener.add_pending_accept(sqe);
                None
            }
        }
    }

    fn tcp_listener_drop(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let listener_id = sqe.handle;
        let proc_handle = proc.handle();
        let listener = match self.tcp_listeners.get_mut(&listener_id) {
            Some(val) => val,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };
        if listener.process() != proc_handle {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        let mut listener = self.tcp_listeners.remove(&listener_id).unwrap();
        assert!(self
            .process_tcp_listeners_map
            .get_mut(&proc_handle)
            .unwrap()
            .remove(&listener_id));

        let device_idx = listener.device_idx();
        let addr = *listener.socket_addr();

        // #[cfg(debug_assertions)]
        // moto_log!("sys-io: TCP listener {:?} dropped (locally).", addr);

        match device_idx {
            Some(idx) => self.devices[idx].tcp_listener_drop(addr),
            None => {
                for device in &mut self.devices {
                    device.tcp_listener_drop(addr);
                }
            }
        }

        // Clear pending accepts.
        while let Some(mut cqe) = listener.get_pending_accept() {
            cqe.status = ErrorCode::UnexpectedEof.into();
            self.pending_completions.push_back(PendingCompletion {
                cqe,
                endpoint_handle: proc_handle,
            });
        }

        // Clear pending incoming streams.
        while let Some(id) = listener.get_pending_stream() {
            let mut stream = self.tcp_streams.remove(&id).unwrap();
            assert!(self
                .process_tcp_streams_map
                .get_mut(&proc_handle)
                .unwrap()
                .remove(&id));

            stream.set_state(TcpState::Closed);

            let device_idx = stream.device();
            let local_addr = *stream.local_addr();
            let remote_addr = *stream.remote_addr();

            #[cfg(debug_assertions)]
            moto_log!(
                "sys-io: incoming TCP connection {:?} - {:?} dropped due to listener drop.",
                local_addr,
                remote_addr
            );

            self.devices[device_idx].tcp_stream_drop(&local_addr, &remote_addr);
        }

        sqe.status = ErrorCode::Ok.into();
        return Some(sqe);
    }

    fn new_tcp_stream(&mut self, stream: TcpStream) {
        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "sys-io: new tcp stream 0x{:x} {:?} -> {:?}",
        //     stream.id(),
        //     stream.local_addr(),
        //     stream.remote_addr()
        // );

        let id = stream.id();
        let proc = *stream.process();
        assert!(self.tcp_streams.insert(id, stream).is_none());
        let proc_streams = match self.process_tcp_streams_map.get_mut(&proc) {
            Some(val) => val,
            None => {
                self.process_tcp_streams_map.insert(proc, HashSet::new());
                self.process_tcp_streams_map.get_mut(&proc).unwrap()
            }
        };
        assert!(proc_streams.insert(id));
    }

    fn tcp_stream_connect(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let remote_addr = match rt_api::net::get_socket_addr(&sqe.payload) {
            Ok(addr) => addr,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };

        let timeout = match sqe.payload.args_64()[3] {
            u64::MAX => None,
            t => {
                let timo = moto_sys::time::Instant::from_u64(t);
                if timo <= moto_sys::time::Instant::now() {
                    sqe.status = ErrorCode::TimedOut.into();
                    return Some(sqe);
                }
                Some(timo)
            }
        };

        #[cfg(debug_assertions)]
        moto_log!(
            "sys-io: 0x{:x}: tcp connect to {:?}",
            proc.handle().as_u64(),
            remote_addr
        );

        let (device_idx, local_ip_addr) = if let Some(pair) = self.find_route(&remote_addr.ip()) {
            pair
        } else {
            #[cfg(debug_assertions)]
            moto_log!(
                "sys-io: 0x{:x}: tcp connect to {:?}: route not found",
                proc.handle().as_u64(),
                remote_addr
            );

            sqe.status = ErrorCode::NotFound.into();
            return Some(sqe);
        };

        let local_port =
            match self.devices[device_idx].get_ephemeral_port(&local_ip_addr, &remote_addr) {
                Some(port) => port,
                None => {
                    moto_log!("get_ephemeral_port({:?}) failed", local_ip_addr);
                    sqe.status = ErrorCode::OutOfMemory.into();
                    return Some(sqe);
                }
            };

        let new_id = self.next_id();
        self.new_tcp_stream(TcpStream::new_outgoing(
            new_id,
            proc.handle(),
            device_idx,
            SocketAddr::new(local_ip_addr, local_port),
            remote_addr,
            sqe,
        ));

        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "sys-io: 0x{:x}: new outgoing tcp stream {:?} -> {:?}",
        //     proc.handle().as_u64(),
        //     SocketAddr::new(local_ip_addr, local_port),
        //     remote_addr
        // );

        let stream = self.tcp_streams.get(&new_id).unwrap();
        self.devices[device_idx].tcp_stream_connect(stream, timeout);

        None
    }

    fn tcp_stream_write(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let tcp_id = sqe.handle;
        let io_buffer = sqe.payload.buffers()[0];
        let sz = sqe.payload.args_64()[1] as usize;
        let proc_handle = proc.handle();
        let bytes = match proc.conn().buffer_bytes(io_buffer) {
            Ok(val) => val,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };
        if sz > bytes.len() {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }
        let bytes = &bytes[0..sz];

        let stream = match self.tcp_streams.get(&tcp_id) {
            Some(val) => val,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };

        if *stream.process() != proc_handle {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if !stream.state().can_write() {
            sqe.status = ErrorCode::UnexpectedEof.into();
            return Some(sqe);
        }

        let device_idx = stream.device();
        let local_addr = *stream.local_addr();
        let remote_addr = *stream.remote_addr();

        self.devices[device_idx].tcp_stream_write(
            &local_addr,
            &remote_addr,
            IoBuf::new(sqe, bytes),
        );

        None
    }

    fn tcp_stream_read(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let tcp_id = sqe.handle;
        let io_buffer = sqe.payload.buffers()[0];
        let sz = sqe.payload.args_64()[1] as usize;
        let proc_handle = proc.handle();
        let bytes = match proc.conn().buffer_bytes(io_buffer) {
            Ok(val) => val,
            Err(err) => {
                sqe.status = err.into();
                return Some(sqe);
            }
        };
        if sz > bytes.len() {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }
        let bytes = &bytes[0..sz];

        let stream = match self.tcp_streams.get(&tcp_id) {
            Some(val) => val,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };

        if *stream.process() != proc_handle {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if !stream.state().can_read() {
            sqe.status = ErrorCode::UnexpectedEof.into();
            return Some(sqe);
        }

        let device_idx = stream.device();
        let local_addr = *stream.local_addr();
        let remote_addr = *stream.remote_addr();

        self.devices[device_idx].tcp_stream_read(&local_addr, &remote_addr, IoBuf::new(sqe, bytes));

        None
    }

    fn tcp_stream_set_option(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        let tcp_id = sqe.handle;
        let proc_handle = proc.handle();

        let stream = match self.tcp_streams.get_mut(&tcp_id) {
            Some(val) => val,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };

        if *stream.process() != proc_handle {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if stream.state() == TcpState::Connecting {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        let mut options = sqe.payload.args_64()[0];
        if options == 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if options == rt_api::net::TCP_OPTION_READ_TIMEOUT
            || options == rt_api::net::TCP_OPTION_WRITE_TIMEOUT
        {
            let device_idx = stream.device();
            let local_addr = *stream.local_addr();
            let remote_addr = *stream.remote_addr();

            let dur_nanos = sqe.payload.args_64()[1];
            let duration = if dur_nanos == u64::MAX {
                None
            } else {
                Some(std::time::Duration::from_nanos(dur_nanos))
            };

            let res = if options == rt_api::net::TCP_OPTION_READ_TIMEOUT {
                self.devices[device_idx].tcp_stream_set_read_timeout(
                    &local_addr,
                    &remote_addr,
                    duration,
                )
            } else {
                self.devices[device_idx].tcp_stream_set_write_timeout(
                    &local_addr,
                    &remote_addr,
                    duration,
                )
            };

            sqe.status = res.into();
            return Some(sqe);
        }

        if options == rt_api::net::TCP_OPTION_NODELAY {
            let nodelay_u64 = sqe.payload.args_64()[1];
            let nodelay = match nodelay_u64 {
                1 => true,
                0 => false,
                _ => {
                    sqe.status = ErrorCode::InvalidArgument.into();
                    return Some(sqe);
                }
            };
            let device_idx = stream.device();
            let local_addr = *stream.local_addr();
            let remote_addr = *stream.remote_addr();

            sqe.status = self.devices[device_idx]
                .tcp_stream_set_nodelay(&local_addr, &remote_addr, nodelay)
                .into();
            return Some(sqe);
        }

        let shut_rd = (options & rt_api::net::TCP_OPTION_SHUT_RD != 0) && stream.state().can_read();
        options ^= rt_api::net::TCP_OPTION_SHUT_RD;

        let shut_wr =
            (options & rt_api::net::TCP_OPTION_SHUT_WR != 0) && stream.state().can_write();
        options ^= rt_api::net::TCP_OPTION_SHUT_WR;

        if options != 0 {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        if !(shut_rd || shut_wr) {
            sqe.status = ErrorCode::Ok.into(); // Nothing to do.
            return Some(sqe);
        }

        if shut_rd && shut_wr {
            stream.set_state(TcpState::Closed);
        } else if shut_rd {
            if stream.state() == TcpState::ReadWrite {
                stream.set_state(TcpState::WriteOnly);
            } else {
                assert_eq!(stream.state(), TcpState::ReadOnly);
                stream.set_state(TcpState::Closed);
            }
        } else {
            assert!(shut_wr);
            if stream.state() == TcpState::ReadWrite {
                stream.set_state(TcpState::ReadOnly);
            } else {
                assert_eq!(stream.state(), TcpState::WriteOnly);
                stream.set_state(TcpState::Closed);
            }
        }

        let device_idx = stream.device();
        let local_addr = *stream.local_addr();
        let remote_addr = *stream.remote_addr();

        self.devices[device_idx].tcp_stream_shutdown(&local_addr, &remote_addr, shut_rd, shut_wr);

        sqe.status = ErrorCode::Ok.into();
        return Some(sqe);
    }

    fn tcp_stream_drop(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        // While there can still be outgoing writes that need completion,
        // we drop everything here: let the user-side worry about
        // not dropping connections before writes are complete.
        let tcp_id = sqe.handle;
        let proc_handle = proc.handle();
        let stream = match self.tcp_streams.get_mut(&tcp_id) {
            Some(val) => val,
            None => {
                sqe.status = ErrorCode::InvalidArgument.into();
                return Some(sqe);
            }
        };
        if *stream.process() != proc_handle {
            sqe.status = ErrorCode::InvalidArgument.into();
            return Some(sqe);
        }

        let mut stream = self.tcp_streams.remove(&tcp_id).unwrap();
        assert!(self
            .process_tcp_streams_map
            .get_mut(&proc_handle)
            .unwrap()
            .remove(&tcp_id));

        if stream.state() != TcpState::Closed {
            stream.set_state(TcpState::Closed);
        }

        let device_idx = stream.device();
        let local_addr = *stream.local_addr();
        let remote_addr = *stream.remote_addr();

        if device_idx != usize::MAX {
            self.devices[device_idx].tcp_stream_drop(&local_addr, &remote_addr);
        }

        sqe.status = ErrorCode::Ok.into();
        return Some(sqe);
    }

    fn next_id(&mut self) -> u64 {
        let res = self.next_id;
        self.next_id += 1;
        res
    }

    // Find the device to route through.
    fn find_route(&self, ip_addr: &IpAddr) -> Option<(usize, IpAddr)> {
        // First, look through local addresses.
        match self.ip_addresses.get(ip_addr) {
            Some(device_idx) => return Some((*device_idx, *ip_addr)),
            None => {}
        }

        // If not found, look through routes.
        for route in &self.config.routes {
            if route.is_reachable(ip_addr) {
                for idx in 0..self.devices.len() {
                    if self.devices[idx].name() == route.device_name {
                        return Some((idx, route.gateway.clone()));
                    }
                }
                panic!("route referencing an unknown device");
            }
        }

        None
    }

    fn process_event(&mut self, device_idx: usize, event: NetEvent) {
        // #[cfg(debug_assertions)]
        // moto_log!("NET event: {:?}", event);

        match event {
            NetEvent::IncomingTcpConnect((local, remote)) => {
                self.on_tcp_connect_incoming(device_idx, local, remote)
            }
            NetEvent::OutgoingTcpConnect((local, remote, result)) => {
                self.on_tcp_connect_outgoing_result(device_idx, local, remote, result)
            }
            NetEvent::TcpTx((local, remote, rx_buf)) => {
                self.on_tcp_x(device_idx, local, remote, rx_buf)
            }
            NetEvent::TcpRx((local, remote, rx_buf)) => {
                self.on_tcp_x(device_idx, local, remote, rx_buf)
            }
            NetEvent::TcpStreamClosed((local, remote)) => {
                self.on_tcp_closed(device_idx, local, remote)
            }
        }
    }

    fn on_tcp_x(
        &mut self,
        _device_idx: usize,
        _local_addr: SocketAddr,
        _remote_addr: SocketAddr,
        x_buf: IoBuf,
    ) {
        assert_ne!(x_buf.status, ErrorCode::NotReady);
        let mut cqe = x_buf.sqe;
        let proc_handle = self.tcp_streams.get(&cqe.handle).unwrap().process();
        cqe.payload.args_64_mut()[1] = x_buf.consumed as u64;
        cqe.status = x_buf.status.into();
        self.pending_completions.push_back(PendingCompletion {
            cqe,
            endpoint_handle: *proc_handle,
        });
    }

    fn on_tcp_connect_incoming(
        &mut self,
        device_idx: usize,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) {
        let dev = &self.devices[device_idx];
        let listener_id = if let Some(id) = dev.tcp_listener_find(&local_addr) {
            id
        } else {
            let socket_addr = match local_addr.ip() {
                IpAddr::V4(_) => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_addr.port())
                }
                IpAddr::V6(_) => {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), local_addr.port())
                }
            };
            // Unwrap below is justified, as devices are not allowed to surface
            // incoming connections without listeners.
            dev.tcp_listener_find(&socket_addr).expect(
                format!(
                    "{}:{} missing listener for {} {:?}",
                    file!(),
                    line!(),
                    device_idx,
                    socket_addr
                )
                .as_str(),
            )
        };

        let (proc_handle, maybe_cqe) = {
            let listener = self.tcp_listeners.get_mut(&listener_id).unwrap();
            (listener.process(), listener.get_pending_accept())
        };

        let new_id = self.next_id();
        self.new_tcp_stream(TcpStream::new_incoming(
            new_id,
            proc_handle,
            device_idx,
            local_addr,
            remote_addr,
        ));

        self.devices[device_idx].tcp_stream_new_incoming(local_addr, remote_addr, new_id);

        if let Some(mut cqe) = maybe_cqe {
            // The listener has a pending accept: this is a fully connected stream now.
            self.tcp_streams
                .get_mut(&new_id)
                .unwrap()
                .set_state(TcpState::ReadWrite);
            cqe.handle = new_id;
            rt_api::net::put_socket_addr(&mut cqe.payload, &remote_addr);
            cqe.status = ErrorCode::Ok.into();
            self.pending_completions.push_back(PendingCompletion {
                cqe,
                endpoint_handle: proc_handle,
            });
        } else {
            // The stream is "pending".
            self.tcp_listeners
                .get_mut(&listener_id)
                .unwrap()
                .add_pending_stream(new_id);
        }
    }

    fn on_tcp_connect_outgoing_result(
        &mut self,
        device_idx: usize,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        result: ErrorCode,
    ) {
        let dev = &self.devices[device_idx];

        if result.is_err() {
            let mut tcp_stream = self
                .tcp_streams
                .remove(&dev.tcp_stream_find(&local_addr, &remote_addr).unwrap())
                .unwrap();

            assert!(self
                .process_tcp_streams_map
                .get_mut(tcp_stream.process())
                .unwrap()
                .remove(&tcp_stream.id()));

            assert_eq!(tcp_stream.state(), TcpState::Connecting);
            tcp_stream.set_state(TcpState::Closed);

            let mut cqe = *tcp_stream.connect_sqe();
            cqe.status = result.into();

            self.pending_completions.push_back(PendingCompletion {
                cqe,
                endpoint_handle: *tcp_stream.process(),
            });

            return;
        }

        let id = dev.tcp_stream_find(&local_addr, &remote_addr).unwrap();
        let stream = self.tcp_streams.get_mut(&id).unwrap();
        assert_eq!(stream.state(), TcpState::Connecting);
        stream.set_state(TcpState::ReadWrite);

        let mut cqe = *stream.connect_sqe();
        cqe.handle = id;
        cqe.status = ErrorCode::Ok.into();
        self.pending_completions.push_back(PendingCompletion {
            cqe,
            endpoint_handle: *stream.process(),
        });
    }

    fn on_tcp_closed(
        &mut self,
        device_idx: usize,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) {
        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "sys-io: TCP connection {:?} - {:?} closed remotely.",
        //     local_addr,
        //     remote_addr
        // );

        let dev = &mut self.devices[device_idx];
        if let Some(id) = dev.tcp_stream_remote(&local_addr, &remote_addr) {
            let stream = self.tcp_streams.get_mut(&id).unwrap();
            stream.set_state(TcpState::Closed);
            stream.clear_device();
        }
    }
}

impl IoSubsystem for NetSys {
    fn wait_handles(&self) -> Vec<SysHandle> {
        let mut res = Vec::new();
        for handle in self.handles.keys() {
            res.push(*handle);
        }

        res
    }

    fn process_wakeup(&mut self, handle: moto_sys::SysHandle) {
        let idx = self.handles.get(&handle).unwrap();
        self.devices[*idx].process_wakeup(handle);
    }

    fn process_sqe(
        &mut self,
        proc: &mut Process,
        mut sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry> {
        debug_assert_eq!(sqe.status(), ErrorCode::NotReady);

        match sqe.command {
            rt_api::net::CMD_TCP_LISTENER_BIND => Some(self.tcp_listener_bind(proc, sqe)),
            rt_api::net::CMD_TCP_LISTENER_ACCEPT => self.tcp_listener_accept(proc, sqe),
            rt_api::net::CMD_TCP_LISTENER_DROP => self.tcp_listener_drop(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_CONNECT => self.tcp_stream_connect(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_WRITE => self.tcp_stream_write(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_READ => self.tcp_stream_read(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_SET_OPTION => self.tcp_stream_set_option(proc, sqe),
            rt_api::net::CMD_TCP_STREAM_DROP => self.tcp_stream_drop(proc, sqe),
            _ => {
                #[cfg(debug_assertions)]
                moto_log!(
                    "sys-io::net: unrecognized command {} from endpoint 0x{:x}",
                    sqe.command,
                    proc.handle().as_u64()
                );

                sqe.status = ErrorCode::InvalidArgument.into();
                Some(sqe)
            }
        }
    }

    fn on_process_drop(&mut self, proc: &mut Process) {
        if let Some(listeners) = self.process_tcp_listeners_map.remove(&proc.handle()) {
            for id in listeners {
                let mut listener = self.tcp_listeners.remove(&id).unwrap();
                let device_idx = listener.device_idx();
                match device_idx {
                    Some(idx) => {
                        self.devices[idx].hard_drop_tcp_listener(listener.socket_addr());
                    }
                    None => {
                        for device in &mut self.devices {
                            device.hard_drop_tcp_listener(listener.socket_addr());
                        }
                    }
                }
                listener.hard_drop();
            }
        }
        if let Some(streams) = self.process_tcp_streams_map.remove(&proc.handle()) {
            for id in streams {
                let mut stream = self.tcp_streams.remove(&id).unwrap();
                if stream.device() != usize::MAX {
                    self.devices[stream.device()]
                        .hard_drop_tcp_stream(stream.local_addr(), stream.remote_addr());
                }
                stream.hard_drop();
            }
        }

        // #[cfg(debug_assertions)]
        // moto_log!(
        //     "sys-io: process 0x{:x} dropped: {} listeners, {} streams left.",
        //     proc.handle().as_u64(),
        //     self.tcp_listeners.len(),
        //     self.tcp_streams.len()
        // );
    }

    fn poll(&mut self) -> Option<PendingCompletion> {
        if let Some(prev) = self.pending_completions.pop_front() {
            return Some(prev);
        }

        for device_idx in 0..self.devices.len() {
            let dev = self.devices.get_mut(device_idx).unwrap();
            while let Some(event) = dev.poll() {
                self.pending_events.push_back((device_idx, event));
            }
        }

        while let Some((device_idx, event)) = self.pending_events.pop_front() {
            self.process_event(device_idx, event);
        }

        self.pending_completions.pop_front()
    }

    fn wait_timeout(&mut self) -> Option<core::time::Duration> {
        let mut timeout = None;
        for device_idx in 0..self.devices.len() {
            let dev = self.devices.get_mut(device_idx).unwrap();
            if let Some(timo) = dev.wait_timeout() {
                match timeout {
                    Some(prev) => {
                        if prev > timo {
                            timeout = Some(timo);
                        }
                    }
                    None => timeout = Some(timo),
                }
            }
        }

        timeout
    }
}
