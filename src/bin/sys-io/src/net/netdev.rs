use std::net::SocketAddr;
use std::{collections::HashMap, net::IpAddr};

use moto_sys::{ErrorCode, SysHandle};

use super::tcp::TcpListener;
use super::tcp::TcpStream;
use super::IoBuf;

#[derive(Debug)]
pub(super) enum NetEvent {
    IncomingTcpConnect((SocketAddr, SocketAddr)), // (local,remote)
    OutgoingTcpConnect((SocketAddr, SocketAddr, ErrorCode)),
    TcpTx((SocketAddr, SocketAddr, IoBuf)),
    TcpRx((SocketAddr, SocketAddr, IoBuf)),
    TcpStreamClosed((SocketAddr, SocketAddr)),
}

pub(super) trait NetInterface {
    fn wait_handles(&self) -> Vec<SysHandle>;
    fn poll(&mut self) -> Option<NetEvent>;
    fn process_wakeup(&mut self, handle: SysHandle);

    fn tcp_listener_bind(&mut self, addr: &SocketAddr);
    fn tcp_listener_drop(&mut self, addr: &SocketAddr);

    fn tcp_stream_connect(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        timeout: Option<moto_sys::time::Instant>,
    );
    fn tcp_stream_write(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        write_buf: IoBuf,
    );
    fn tcp_stream_read(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        read_buf: IoBuf,
    );

    fn tcp_stream_set_read_timeout(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        timeout: Option<std::time::Duration>,
    ) -> ErrorCode;

    fn tcp_stream_set_write_timeout(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        timeout: Option<std::time::Duration>,
    ) -> ErrorCode;

    fn tcp_stream_set_nodelay(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        nodelay: bool,
    ) -> ErrorCode;

    fn tcp_stream_shutdown(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        shut_rd: bool,
        shut_wr: bool,
    );
    fn tcp_stream_drop(&mut self, local_addr: &SocketAddr, remote_addr: &SocketAddr);

    fn hard_drop_tcp_listener(&mut self, addr: &SocketAddr);
    fn hard_drop_tcp_stream(&mut self, local_addr: &SocketAddr, remote_addr: &SocketAddr);
    fn wait_timeout(&mut self) -> Option<core::time::Duration>;
}

pub(super) struct NetDev {
    cidrs: Vec<super::config::IpCidr>,
    tcp_listeners: HashMap<SocketAddr, u64>, // local -> ID.
    tcp_streams: HashMap<(SocketAddr, SocketAddr), u64>, // (local,remote) -> ID.
    iface: Box<dyn NetInterface>,
    name: String,
}

impl NetDev {
    // NetInterface forwarders.
    pub fn wait_handles(&self) -> Vec<SysHandle> {
        self.iface.wait_handles()
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn process_wakeup(&mut self, handle: SysHandle) {
        self.iface.process_wakeup(handle)
    }

    pub fn new(
        cidrs: Vec<super::config::IpCidr>,
        iface: Box<dyn NetInterface>,
        name: String,
    ) -> Self {
        Self {
            cidrs,
            tcp_listeners: HashMap::new(),
            tcp_streams: HashMap::new(),
            iface,
            name,
        }
    }

    pub fn wait_timeout(&mut self) -> Option<core::time::Duration> {
        self.iface.wait_timeout()
    }

    pub fn ip_addresses(&self) -> &Vec<super::config::IpCidr> {
        &self.cidrs
    }

    pub fn tcp_listener_find(&self, addr: &SocketAddr) -> Option<u64> {
        self.tcp_listeners.get(addr).copied()
    }

    pub fn tcp_listener_bind(&mut self, listener: &TcpListener) {
        self.tcp_listeners
            .insert(*listener.socket_addr(), listener.id());
        self.iface.tcp_listener_bind(&listener.socket_addr());
    }

    pub fn tcp_listener_drop(&mut self, addr: SocketAddr) {
        assert!(self.tcp_listeners.remove(&(addr)).is_some());
        self.iface.tcp_listener_drop(&addr);
    }

    pub fn tcp_stream_connect(
        &mut self,
        stream: &TcpStream,
        timeout: Option<moto_sys::time::Instant>,
    ) {
        assert!(self
            .tcp_streams
            .insert((*stream.local_addr(), *stream.remote_addr()), stream.id())
            .is_none());
        self.iface
            .tcp_stream_connect(stream.local_addr(), stream.remote_addr(), timeout);
    }

    pub fn tcp_stream_new_incoming(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        id: u64,
    ) {
        assert!(self
            .tcp_streams
            .insert((local_addr, remote_addr), id)
            .is_none());
    }

    pub fn tcp_stream_write(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        write_buf: IoBuf,
    ) {
        self.iface
            .tcp_stream_write(local_addr, remote_addr, write_buf)
    }

    pub fn tcp_stream_read(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        read_buf: IoBuf,
    ) {
        self.iface
            .tcp_stream_read(local_addr, remote_addr, read_buf)
    }

    pub fn tcp_stream_set_read_timeout(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        timeout: Option<std::time::Duration>,
    ) -> ErrorCode {
        self.iface
            .tcp_stream_set_read_timeout(local_addr, remote_addr, timeout)
    }

    pub fn tcp_stream_set_write_timeout(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        timeout: Option<std::time::Duration>,
    ) -> ErrorCode {
        self.iface
            .tcp_stream_set_write_timeout(local_addr, remote_addr, timeout)
    }

    pub fn tcp_stream_set_nodelay(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        nodelay: bool,
    ) -> ErrorCode {
        self.iface
            .tcp_stream_set_nodelay(local_addr, remote_addr, nodelay)
    }

    pub fn tcp_stream_shutdown(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        shut_rd: bool,
        shut_wr: bool,
    ) {
        self.iface
            .tcp_stream_shutdown(local_addr, remote_addr, shut_rd, shut_wr)
    }

    pub fn tcp_stream_drop(&mut self, local_addr: &SocketAddr, remote_addr: &SocketAddr) {
        assert!(self
            .tcp_streams
            .remove(&(*local_addr, *remote_addr))
            .is_some());
        self.iface.tcp_stream_drop(local_addr, remote_addr);
    }

    pub fn tcp_stream_find(
        &self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> Option<u64> {
        self.tcp_streams.get(&(*local_addr, *remote_addr)).copied()
    }

    pub fn tcp_stream_remote(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
    ) -> Option<u64> {
        self.tcp_streams.remove(&(*local_addr, *remote_addr))
    }

    pub fn hard_drop_tcp_listener(&mut self, addr: &SocketAddr) {
        self.tcp_listeners.remove(addr).expect("missing listener");
        self.iface.hard_drop_tcp_listener(addr);
        crate::moto_log!("{}:{} drop listener {:?}", file!(), line!(), addr);
    }

    pub fn hard_drop_tcp_stream(&mut self, addr1: &SocketAddr, addr2: &SocketAddr) {
        self.tcp_streams.remove(&(*addr1, *addr2));
        self.iface.hard_drop_tcp_stream(addr1, addr2);
    }

    pub fn get_ephemeral_port(
        &mut self,
        local_ip_addr: &IpAddr,
        remote_addr: &SocketAddr,
    ) -> Option<u16> {
        // See https://en.wikipedia.org/wiki/Ephemeral_port.
        const EPHEMERAL_PORT_MIN: u16 = 49152;
        const EPHEMERAL_PORT_MAX: u16 = 65535;

        // TODO: do better than a linear search.
        for port in EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX {
            let local_addr = SocketAddr::new(*local_ip_addr, port);
            if self.tcp_listeners.contains_key(&local_addr) {
                continue;
            }

            if self.tcp_streams.contains_key(&(local_addr, *remote_addr)) {
                continue;
            }

            return Some(port);
        }

        None
    }

    pub fn poll(&mut self) -> Option<NetEvent> {
        self.iface.poll()
    }
}
