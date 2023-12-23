// Loopback network interface/device.

use std::cell::UnsafeCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use moto_sys::{ErrorCode, SysHandle};

use super::netdev::{NetDev, NetEvent, NetInterface};
use super::IoBuf;

struct LoopbackTcpStream {
    tx_queue: Option<VecDeque<IoBuf>>,
    rx_queue: Option<VecDeque<IoBuf>>,
}

impl LoopbackTcpStream {
    fn new() -> Self {
        Self {
            tx_queue: Some(VecDeque::new()),
            rx_queue: Some(VecDeque::new()),
        }
    }
}

struct Loopback {
    listeners: HashSet<SocketAddr>,
    events: VecDeque<NetEvent>,
    tcp_streams: HashMap<(SocketAddr, SocketAddr), UnsafeCell<LoopbackTcpStream>>,
}

impl Loopback {
    fn new() -> Self {
        Self {
            listeners: HashSet::new(),
            events: VecDeque::new(),
            tcp_streams: HashMap::new(),
        }
    }

    fn read_write(
        reader: &UnsafeCell<LoopbackTcpStream>,
        writer: &UnsafeCell<LoopbackTcpStream>,
        reader_addr: &SocketAddr,
        writer_addr: &SocketAddr,
    ) -> Option<NetEvent> {
        unsafe {
            let reader = reader.get().as_mut().unwrap_unchecked();
            let writer = writer.get().as_mut().unwrap_unchecked();

            let mut tx_buf = match writer.tx_queue.as_mut().unwrap().pop_front() {
                Some(val) => val,
                None => return None, // Nothing to write.
            };

            if tx_buf.consumed == tx_buf.buf_len {
                // On the previous call to read_write(), TcpRx event was generated.
                tx_buf.status = ErrorCode::Ok;
                return Some(NetEvent::TcpTx((*writer_addr, *reader_addr, tx_buf)));
            }

            let mut rx_buf = match reader.rx_queue.as_mut().unwrap().pop_front() {
                Some(val) => val,
                None => {
                    writer.tx_queue.as_mut().unwrap().push_front(tx_buf);
                    return None; // Nowhere to read to.
                }
            };

            assert_eq!(rx_buf.consumed, 0); // We always pop rx.
            assert!(tx_buf.consumed < tx_buf.buf_len);
            let len = rx_buf.buf_len.min(tx_buf.buf_len - tx_buf.consumed);

            core::ptr::copy_nonoverlapping(
                (tx_buf.buf_ptr + tx_buf.consumed) as *const u8,
                rx_buf.buf_ptr as *mut u8,
                len,
            );

            // Re-insert tx_buf.
            tx_buf.consumed += len;
            writer.tx_queue.as_mut().unwrap().push_front(tx_buf);

            // Generate RX event.
            rx_buf.consumed = len;
            rx_buf.status = ErrorCode::Ok;
            Some(NetEvent::TcpRx((*reader_addr, *writer_addr, rx_buf)))
        }
    }

    fn drop_stream(&mut self, addr1: SocketAddr, addr2: SocketAddr) {
        let stream = self.tcp_streams.remove(&(addr1, addr2));
        if stream.is_none() {
            return;
        }

        let stream = stream.unwrap().into_inner();
        if let Some(tx_queue) = stream.tx_queue {
            for mut tx in tx_queue {
                tx.status = ErrorCode::UnexpectedEof;
                self.events.push_back(NetEvent::TcpTx((addr1, addr2, tx)));
            }
        }
        if let Some(rx_queue) = stream.rx_queue {
            for mut rx in rx_queue {
                rx.status = ErrorCode::UnexpectedEof;
                self.events.push_back(NetEvent::TcpRx((addr1, addr2, rx)));
            }
        }
    }

    fn shut_stream(&mut self, addr1: SocketAddr, addr2: SocketAddr, shut_rd: bool, shut_wr: bool) {
        if let Some(stream) = self.tcp_streams.get(&(addr1, addr2)) {
            let maybe_rx = unsafe { &mut stream.get().as_mut().unwrap().rx_queue };
            if shut_rd {
                if let Some(rx_queue) = maybe_rx.take() {
                    for mut rx in rx_queue {
                        rx.status = ErrorCode::UnexpectedEof;
                        self.events.push_back(NetEvent::TcpRx((addr1, addr2, rx)));
                    }
                }
            }

            let maybe_tx = unsafe { &mut stream.get().as_mut().unwrap().tx_queue };
            if shut_wr {
                if let Some(tx_queue) = maybe_tx.take() {
                    for mut tx in tx_queue {
                        tx.status = ErrorCode::UnexpectedEof;
                        self.events.push_back(NetEvent::TcpTx((addr1, addr2, tx)));
                    }
                }
            }

            if maybe_rx.is_none() && maybe_tx.is_none() {
                self.tcp_streams.remove(&(addr1, addr2));
            }

            self.events
                .push_back(NetEvent::TcpStreamClosed((addr1, addr2)));
        }
    }
}

impl NetInterface for Loopback {
    fn wait_handles(&self) -> Vec<SysHandle> {
        Vec::new()
    }

    fn poll(&mut self) -> Option<NetEvent> {
        self.events.pop_front()
    }

    fn process_wakeup(&mut self, _: SysHandle) {
        panic!() // No wakeups for loopback.
    }

    fn tcp_stream_connect(&mut self, local_addr: &SocketAddr, remote_addr: &SocketAddr) {
        if self.listeners.contains(remote_addr) {
            self.tcp_streams.insert(
                (*local_addr, *remote_addr),
                UnsafeCell::new(LoopbackTcpStream::new()),
            );
            self.tcp_streams.insert(
                (*remote_addr, *local_addr),
                UnsafeCell::new(LoopbackTcpStream::new()),
            );

            self.events
                .push_back(NetEvent::IncomingTcpConnect((*remote_addr, *local_addr)));
            self.events.push_back(NetEvent::OutgoingTcpConnect((
                *local_addr,
                *remote_addr,
                ErrorCode::Ok,
            )));
        } else {
            self.events.push_back(NetEvent::OutgoingTcpConnect((
                *local_addr,
                *remote_addr,
                ErrorCode::NotFound,
            )));
        }
    }

    fn tcp_stream_write(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        mut write_buf: IoBuf,
    ) {
        let writer = self.tcp_streams.get(&(*local_addr, *remote_addr)).unwrap();
        unsafe {
            if let Some(tx_queue) = &mut writer.get().as_mut().unwrap_unchecked().tx_queue {
                tx_queue.push_back(write_buf);
            } else {
                write_buf.status = ErrorCode::UnexpectedEof;
                self.events
                    .push_back(NetEvent::TcpTx((*local_addr, *remote_addr, write_buf)));
                return;
            }
        }

        let reader = self.tcp_streams.get(&(*remote_addr, *local_addr)).unwrap();

        while let Some(event) = Self::read_write(reader, writer, remote_addr, local_addr) {
            self.events.push_back(event)
        }
    }

    fn tcp_stream_read(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        mut read_buf: IoBuf,
    ) {
        let reader = match self.tcp_streams.get(&(*local_addr, *remote_addr)) {
            Some(val) => val,
            None => {
                // The connection was dropped/removed.
                read_buf.status = ErrorCode::UnexpectedEof;
                self.events
                    .push_back(NetEvent::TcpRx((*local_addr, *remote_addr, read_buf)));
                return;
            }
        };
        unsafe {
            if let Some(rx_queue) = &mut reader.get().as_mut().unwrap_unchecked().rx_queue {
                rx_queue.push_back(read_buf);
            } else {
                read_buf.status = ErrorCode::UnexpectedEof;
                self.events
                    .push_back(NetEvent::TcpRx((*local_addr, *remote_addr, read_buf)));
                return;
            }
        }

        let writer = self.tcp_streams.get(&(*remote_addr, *local_addr)).unwrap();

        while let Some(event) = Self::read_write(reader, writer, local_addr, remote_addr) {
            self.events.push_back(event)
        }
    }

    fn tcp_listener_bind(&mut self, addr: &SocketAddr) {
        assert!(self.listeners.insert(*addr));
    }

    fn tcp_stream_drop(&mut self, local_addr: &SocketAddr, remote_addr: &SocketAddr) {
        self.drop_stream(*local_addr, *remote_addr);
        self.drop_stream(*remote_addr, *local_addr);

        // Notify that the peer dropped.
        self.events
            .push_back(NetEvent::TcpStreamClosed((*remote_addr, *local_addr)));
    }

    fn tcp_stream_shutdown(
        &mut self,
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr,
        shut_rd: bool,
        shut_wr: bool,
    ) {
        self.shut_stream(*local_addr, *remote_addr, shut_rd, shut_wr);
        self.shut_stream(*remote_addr, *local_addr, shut_wr, shut_rd);
    }

    fn tcp_listener_drop(&mut self, addr: &SocketAddr) {
        assert!(self.listeners.remove(addr));
    }

    fn hard_drop_tcp_listener(&mut self, addr: &SocketAddr) {
        self.listeners.remove(addr);
    }

    fn hard_drop_tcp_stream(&mut self, local_addr: &SocketAddr, remote_addr: &SocketAddr) {
        self.tcp_streams.remove(&(*local_addr, *remote_addr));
    }

    fn tcp_stream_set_read_timeout(
        &mut self,
        _local_addr: &SocketAddr,
        _remote_addr: &SocketAddr,
        _timeout: Option<std::time::Duration>,
    ) -> ErrorCode {
        ErrorCode::Ok // TODO: do it properly
    }

    fn tcp_stream_set_write_timeout(
        &mut self,
        _local_addr: &SocketAddr,
        _remote_addr: &SocketAddr,
        _timeout: Option<std::time::Duration>,
    ) -> ErrorCode {
        ErrorCode::Ok // TODO: do it properly
    }

    fn tcp_stream_set_nodelay(
        &mut self,
        _local_addr: &SocketAddr,
        _remote_addr: &SocketAddr,
        _nodelay: bool,
    ) -> ErrorCode {
        ErrorCode::Ok // We don't delay
    }

    fn wait_timeout(&mut self) -> Option<core::time::Duration> {
        None
    }
}

pub(super) fn init() -> Box<NetDev> {
    let mut ips = Vec::new();
    ips.push(super::config::IpCidr {
        addr: std::net::Ipv4Addr::new(127, 0, 0, 1).into(),
        prefix: 24,
    });
    Box::new(NetDev::new(
        ips,
        Box::new(Loopback::new()),
        "loopback".to_owned(),
    ))
}
