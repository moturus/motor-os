use super::rt_net::{ChannelReservation, NetChannel};
use crate::{posix::PosixFile, runtime::WaitObject};
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::sync::atomic::*;
use moto_io_internal::udp_queues::{PageAllocator, UdpDefragmentingQueue, UdpFragmentingQueue};
use moto_ipc::io_channel;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::{mutex::Mutex, ErrorCode};
use moto_rt::{E_NOT_READY, E_TIMED_OUT};
use moto_sys_io::api_net;
use moto_sys_io::api_net::IO_SUBCHANNELS;

pub struct UdpSocket {
    channel_reservation: ChannelReservation,
    local_addr: SocketAddr,
    handle: u64,
    wait_object: WaitObject,
    nonblocking: AtomicBool,
    subchannel_mask: u64, // Never changes.

    tx_queue: Mutex<UdpFragmentingQueue>,
    rx_queue: Mutex<UdpDefragmentingQueue>,

    peer_addr: Mutex<Option<SocketAddr>>,

    rx_timeout_ns: AtomicU64,
    tx_timeout_ns: AtomicU64,

    me: Weak<UdpSocket>,
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        // Clear TX queue.
        let msg = self.tx_queue.lock().take_msg();
        if let Some(msg) = msg {
            assert_eq!(msg.command, api_net::NetCmd::UdpSocketTxRx as u16);
            let sz_read = msg.payload.args_64()[1];
            if sz_read > 0 {
                let _ = self.channel().get_page(msg.payload.shared_pages()[11]);
            }
        }

        let mut req = io_channel::Msg::new();
        req.command = api_net::NetCmd::UdpSocketDrop as u16;
        req.handle = self.handle();

        // TODO: is this unwrap OK?
        self.channel().post_msg(req).unwrap();
    }
}

impl UdpSocket {
    pub fn handle(&self) -> u64 {
        self.handle
    }

    pub fn weak(&self) -> Weak<Self> {
        self.me.clone()
    }

    fn channel(&self) -> &NetChannel {
        self.channel_reservation.channel()
    }

    pub fn local_addr(&self) -> &SocketAddr {
        &self.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        *self.peer_addr.lock()
    }

    pub fn bind(socket_addr: &SocketAddr) -> Result<Arc<UdpSocket>, ErrorCode> {
        let mut socket_addr = *socket_addr;
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            // crate::moto_log!("we don't currently allow binding to 0.0.0.0:0");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut channel_reservation = super::rt_net::reserve_channel();
        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();
        let req =
            api_net::bind_udp_socket_request(&socket_addr, channel_reservation.subchannel_idx());
        let resp = channel_reservation.channel().send_receive(req);
        if resp.status() != moto_rt::E_OK {
            return Err(resp.status());
        }

        if socket_addr.port() == 0 {
            let actual_addr = api_net::get_socket_addr(&resp.payload);
            assert_eq!(socket_addr.ip(), actual_addr.ip());
            assert_ne!(0, actual_addr.port());
            socket_addr.set_port(actual_addr.port());
        }

        let udp_socket = Arc::new_cyclic(|me| UdpSocket {
            local_addr: socket_addr,
            channel_reservation,
            handle: resp.handle,
            nonblocking: AtomicBool::new(false),
            wait_object: WaitObject::new(moto_rt::poll::POLL_READABLE),
            subchannel_mask,
            tx_queue: Mutex::new(UdpFragmentingQueue::new(resp.handle, subchannel_mask)),
            peer_addr: Mutex::new(None),
            rx_queue: Mutex::new(UdpDefragmentingQueue::new()),
            rx_timeout_ns: AtomicU64::new(u64::MAX),
            tx_timeout_ns: AtomicU64::new(u64::MAX),
            me: me.clone(),
        });
        udp_socket.channel().udp_socket_created(&udp_socket);
        crate::net::rt_net::stats_udp_socket_created();

        #[cfg(debug_assertions)]
        crate::moto_log!(
            "{}:{} new UdpSocket {:?}",
            file!(),
            line!(),
            udp_socket.local_addr
        );

        Ok(udp_socket)
    }

    pub fn connect(&self, addr: &SocketAddr) {
        *self.peer_addr.lock() = Some(*addr);
    }

    pub fn recv_or_peek_from(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, SocketAddr), ErrorCode> {
        if self.nonblocking.load(Ordering::Acquire) {
            return self.recv_or_peek_from_nonblocking(buf, peek);
        }

        let deadline = {
            let timo = self.tx_timeout_ns.load(Ordering::Relaxed);
            if timo == u64::MAX {
                None
            } else {
                Some(moto_rt::time::Instant::now() + core::time::Duration::from_nanos(timo))
            }
        };

        loop {
            match self.recv_or_peek_from_nonblocking(buf, peek) {
                Ok(res) => return Ok(res),
                Err(err) => {
                    if err != E_NOT_READY {
                        return Err(err);
                    }
                }
            }

            if let Some(deadline) = deadline {
                if deadline <= moto_rt::time::Instant::now() {
                    return Err(E_TIMED_OUT);
                }
            }

            self.wait_object
                .wait(moto_rt::poll::POLL_READABLE, deadline);
        }
    }

    fn recv_or_peek_from_nonblocking(
        &self,
        buf: &mut [u8],
        peek: bool,
    ) -> Result<(usize, SocketAddr), ErrorCode> {
        if peek {
            self.peek_from_nonblocking(buf)
        } else {
            self.recv_from_nonblocking(buf)
        }
    }

    fn recv_from_nonblocking(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        let datagram = loop {
            let Some(datagram) = self.rx_queue.lock().next_datagram().unwrap() else {
                return Err(E_NOT_READY);
            };

            if let Some(peer_addr) = self.peer_addr() {
                if peer_addr != datagram.addr {
                    continue;
                }
            }

            break datagram;
        };

        let bytes = datagram.slice();
        let sz = bytes.len().min(buf.len());
        buf[0..sz].clone_from_slice(&bytes[0..sz]);

        Ok((sz, datagram.addr))
    }

    fn peek_from_nonblocking(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        let mut rx_queue = self.rx_queue.lock();
        let datagram = loop {
            let Some(datagram) = rx_queue.peek_datagram().unwrap() else {
                return Err(E_NOT_READY);
            };

            if let Some(peer_addr) = self.peer_addr() {
                if peer_addr != datagram.addr {
                    // Need to remove the datagram from the queue.
                    let _ = rx_queue.next_datagram();
                    continue;
                }
            }

            break datagram;
        };

        let bytes = datagram.slice();
        let sz = bytes.len().min(buf.len());
        buf[0..sz].clone_from_slice(&bytes[0..sz]);

        Ok((sz, datagram.addr))
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        if buf.len() > moto_rt::net::MAX_UDP_PAYLOAD {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        if self.nonblocking.load(Ordering::Acquire) {
            return self.send_to_nonblocking(buf, addr);
        }

        let deadline = {
            let timo = self.tx_timeout_ns.load(Ordering::Relaxed);
            if timo == u64::MAX {
                None
            } else {
                Some(moto_rt::time::Instant::now() + core::time::Duration::from_nanos(timo))
            }
        };

        loop {
            match self.send_to_nonblocking(buf, addr) {
                Ok(sz) => return Ok(sz),
                Err(err) => {
                    if err != E_NOT_READY {
                        return Err(err);
                    }
                }
            }

            if let Some(deadline) = deadline {
                if deadline <= moto_rt::time::Instant::now() {
                    return Err(E_TIMED_OUT);
                }
            }

            self.wait_object
                .wait(moto_rt::poll::POLL_WRITABLE, deadline);
        }
    }

    fn send_to_nonblocking(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        if !self.tx_queue.lock().is_empty() {
            self.try_tx();
        }

        let mut tx_queue = self.tx_queue.lock();
        if tx_queue.is_full() {
            return Err(E_NOT_READY);
        }

        tx_queue.push_back(buf, *addr);
        drop(tx_queue);

        self.try_tx();

        Ok(buf.len())
    }

    fn try_tx(&self) {
        let mut tx_lock = self.tx_queue.lock();
        let page_allocator = |subchannel_mask: u64| self.channel().alloc_page(subchannel_mask);
        loop {
            let Some(msg) = tx_lock.pop_front(page_allocator) else {
                return;
            };

            let sz = msg.payload.args_16()[10] as usize;
            if let Err(msg) = self.try_tx_msg(msg, sz) {
                tx_lock.push_front(msg);
                return;
            }
        }
    }

    fn try_tx_msg(&self, msg: io_channel::Msg, write_sz: usize) -> Result<(), io_channel::Msg> {
        self.channel().post_msg(msg)
    }

    // Note: this is called from the I/O thread so should not block.
    pub fn process_incoming_msg(&self, msg: io_channel::Msg) {
        let cmd = api_net::NetCmd::try_from(msg.command).unwrap();
        match cmd {
            api_net::NetCmd::UdpSocketTxRx => {
                let fragment_id = msg.payload.args_16()[9];
                let notify = {
                    let mut rx_queue = self.rx_queue.lock();
                    rx_queue
                        .push_back(msg, |idx| self.channel().get_page(idx))
                        .unwrap();

                    rx_queue.have_datagram().unwrap()
                };
                if notify {
                    self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
                }
            }
            api_net::NetCmd::UdpSocketTxRxAck => {
                self.wait_object.on_event(moto_rt::poll::POLL_WRITABLE);
                self.try_tx();
            }
            _ => panic!("Unexpected UDP cmd: {:?}", cmd),
        }
    }

    pub fn peek(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.recv_or_peek_from(buf, true).map(|(sz, _)| sz)
    }

    fn set_nonblocking(&self, val: bool) {
        self.nonblocking.store(val, Ordering::Release);
    }

    pub unsafe fn setsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_NONBLOCKING => {
                assert_eq!(len, 1);
                let nonblocking = *(ptr as *const u8);
                if nonblocking > 1 {
                    return moto_rt::E_INVALID_ARGUMENT;
                }
                self.set_nonblocking(nonblocking == 1);
                moto_rt::E_OK
            }
            moto_rt::net::SO_RCVTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = *(ptr as *const u64);
                self.set_read_timeout(timeout);
                moto_rt::E_OK
            }
            moto_rt::net::SO_SNDTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = *(ptr as *const u64);
                self.set_write_timeout(timeout);
                moto_rt::E_OK
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                let _ttl = *(ptr as *const u32);
                // self.set_ttl(ttl)
                panic!("UDP: set_ttl() not implemented")
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    pub unsafe fn getsockopt(&self, option: u64, ptr: usize, len: usize) -> ErrorCode {
        match option {
            moto_rt::net::SO_RCVTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = self.read_timeout();
                *(ptr as *mut u64) = timeout;
                moto_rt::E_OK
            }
            moto_rt::net::SO_SNDTIMEO => {
                assert_eq!(len, core::mem::size_of::<u64>());
                let timeout = self.write_timeout();
                *(ptr as *mut u64) = timeout;
                moto_rt::E_OK
            }
            moto_rt::net::SO_TTL => {
                assert_eq!(len, 4);
                panic!("UDP: ttl() not implemented")
                // match self.ttl() {
                //     Ok(ttl) => {
                //         *(ptr as *mut u32) = ttl;
                //         moto_rt::E_OK
                //     }
                //     Err(err) => err,
                // }
            }
            moto_rt::net::SO_ERROR => {
                assert_eq!(len, 2);
                // let err = self.take_error();
                // *(ptr as *mut u16) = err;
                *(ptr as *mut u16) = moto_rt::E_OK;
                moto_rt::E_OK
            }
            _ => panic!("unrecognized option {option}"),
        }
    }

    fn set_read_timeout(&self, timeout_ns: u64) {
        self.rx_timeout_ns.store(timeout_ns, Ordering::Relaxed);
    }

    fn set_write_timeout(&self, timeout_ns: u64) {
        self.tx_timeout_ns.store(timeout_ns, Ordering::Relaxed);
    }

    fn read_timeout(&self) -> u64 {
        self.rx_timeout_ns.load(Ordering::Relaxed)
    }

    fn write_timeout(&self) -> u64 {
        self.tx_timeout_ns.load(Ordering::Relaxed)
    }

    fn maybe_raise_events(&self, interests: Interests) {
        let mut events = 0;

        if (interests & moto_rt::poll::POLL_WRITABLE != 0) && !self.tx_queue.lock().is_full() {
            events |= moto_rt::poll::POLL_WRITABLE;
        }

        if (interests & moto_rt::poll::POLL_READABLE) != 0 {
            let mut buf = [0_u8; 4];
            if self.peek_from_nonblocking(&mut buf).is_ok() {
                events |= moto_rt::poll::POLL_READABLE;
            }
        }

        if events != 0 {
            self.wait_object.on_event(events);
        }
    }
}

impl PosixFile for UdpSocket {
    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let Some(addr) = self.peer_addr() else {
            return Err(moto_rt::E_NOT_CONNECTED);
        };

        self.send_to(buf, &addr)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.recv_or_peek_from(buf, false).map(|(sz, _)| sz)
    }

    fn poll_add(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        self.wait_object.add_interests(r_id, token, interests)?;
        self.maybe_raise_events(interests);
        Ok(())
    }

    fn poll_set(&self, r_id: u64, token: Token, interests: Interests) -> Result<(), ErrorCode> {
        self.wait_object.set_interests(r_id, token, interests)?;
        self.maybe_raise_events(interests);
        Ok(())
    }

    fn poll_del(&self, r_id: u64) -> Result<(), ErrorCode> {
        self.wait_object.del_interests(r_id)
    }
}
