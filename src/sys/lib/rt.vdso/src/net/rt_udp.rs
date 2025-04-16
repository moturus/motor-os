use super::rt_net::{ChannelReservation, NetChannel};
use crate::{posix::PosixFile, runtime::WaitObject};
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::sync::atomic::*;
use moto_ipc::io_channel;
use moto_rt::{mutex::Mutex, ErrorCode};
use moto_rt::{E_NOT_READY, E_TIMED_OUT};
use moto_sys_io::api_net;
use moto_sys_io::api_net::IO_SUBCHANNELS;

/*
pub fn udp_recv_from(rt_fd: RtFd, buf: &mut [u8]) -> Result<(usize, netc::sockaddr), ErrorCode> {
    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };

    let vdso_udp_recv_from: extern "C" fn(i32, *mut u8, usize, *mut netc::sockaddr) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_recv_from
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let res = vdso_udp_recv_from(rt_fd, buf.as_mut_ptr(), buf.len(), &mut addr as *mut _);
    if res < 0 {
        Err((-res) as ErrorCode)
    } else {
        Ok(((res as usize), addr))
    }
}

pub fn udp_peek_from(rt_fd: RtFd, buf: &mut [u8]) -> Result<(usize, netc::sockaddr), ErrorCode> {
    let mut addr: netc::sockaddr = unsafe { core::mem::zeroed() };

    let vdso_udp_peek_from: extern "C" fn(i32, *mut u8, usize, *mut netc::sockaddr) -> i64 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get()
                .net_udp_peek_from
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let res = vdso_udp_peek_from(rt_fd, buf.as_mut_ptr(), buf.len(), &mut addr as *mut _);
    if res < 0 {
        Err((-res) as ErrorCode)
    } else {
        Ok(((res as usize), addr))
    }
}
*/

struct PendingTx {
    bytes: Vec<u8>,
    consumed: usize,
    addr: Option<SocketAddr>,
    msg: Option<(io_channel::Msg, usize)>,
}

impl PendingTx {
    fn new(buf: &[u8], addr: &SocketAddr) -> Self {
        Self {
            bytes: Vec::from(buf),
            consumed: 0,
            addr: Some(*addr),
            msg: None,
        }
    }

    fn new_from_msg(msg: io_channel::Msg, sz: usize) -> Self {
        Self {
            bytes: Vec::new(),
            consumed: 0,
            addr: None,
            msg: Some((msg, sz)),
        }
    }
}

pub struct UdpSocket {
    channel_reservation: ChannelReservation,
    local_addr: SocketAddr,
    handle: u64,
    wait_object: WaitObject,
    nonblocking: AtomicBool,
    subchannel_mask: u64, // Never changes.

    // We can send only up to 4096 bytes at once to sys-io, but UDP
    // packets can be larger, up to 65507 bytes, so packets
    // larger than 4096 are "queued".
    pending_tx: Mutex<Option<PendingTx>>,

    rx_queue: Mutex<VecDeque<io_channel::Msg>>,

    rx_timeout_ns: AtomicU64,
    tx_timeout_ns: AtomicU64,

    me: Weak<UdpSocket>,
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        // Clear TX queue (of length 0 or 1).
        let pending_tx = self.pending_tx.lock().take();
        if let Some(pending_tx) = pending_tx {
            if let Some((msg, _)) = pending_tx.msg {
                assert_eq!(msg.command, api_net::NetCmd::UdpSocketTx as u16);
                let sz_read = msg.payload.args_64()[1];
                if sz_read > 0 {
                    let _ = self.channel().get_page(msg.payload.shared_pages()[11]);
                }
            }
        }
    }
}

impl UdpSocket {
    // This number comes from Linux/Unix.
    const MAX_UDP_PAYLOAD_SZ: usize = 65507;

    pub fn handle(&self) -> u64 {
        self.handle
    }

    pub fn weak(&self) -> Weak<Self> {
        self.me.clone()
    }

    fn channel(&self) -> &NetChannel {
        self.channel_reservation.channel()
    }

    pub fn bind(socket_addr: &SocketAddr) -> Result<Arc<UdpSocket>, ErrorCode> {
        let mut socket_addr = *socket_addr;
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            crate::moto_log!("we don't currently allow binding to 0.0.0.0:0");
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
            pending_tx: Mutex::new(None),
            rx_queue: Mutex::new(VecDeque::new()),
            rx_timeout_ns: AtomicU64::new(0),
            tx_timeout_ns: AtomicU64::new(0),
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
            if timo == 0 {
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
        let mut rx_queue = self.rx_queue.lock();
        if rx_queue.is_empty() {
            return Err(E_NOT_READY);
        }

        let msg = rx_queue.front().unwrap();
        if msg.payload.args_16()[9] == 0 {
            let addr = api_net::get_socket_addr(&msg.payload);
            let sz = msg.payload.args_16()[10] as usize;
            assert!(sz <= moto_ipc::io_channel::PAGE_SIZE);
            assert_ne!(0, sz);
            let io_page = self
                .channel()
                .get_page(msg.payload.shared_pages()[11])
                .unwrap();

            let sz = sz.min(buf.len());
            buf[0..sz].clone_from_slice(&io_page.bytes()[0..sz]);

            Ok((sz, addr))
        } else {
            todo!()
        }
    }

    pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        if self.nonblocking.load(Ordering::Acquire) {
            return self.send_to_nonblocking(buf, addr);
        }

        let deadline = {
            let timo = self.tx_timeout_ns.load(Ordering::Relaxed);
            if timo == 0 {
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
        if self.pending_tx.lock().is_some() {
            self.try_tx();
        }

        if buf.len() > 4096 {
            return self.try_add_tx_packet(buf, addr);
        }

        self.try_tx_small_packet(buf, addr)
    }

    fn try_add_tx_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        let mut tx_packet = self.pending_tx.lock();
        if tx_packet.is_some() {
            return Err(E_NOT_READY);
        }

        *tx_packet = Some(PendingTx::new(buf, addr));
        Ok(buf.len())
    }

    fn try_tx_small_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize, ErrorCode> {
        let mut tx_lock = self.pending_tx.lock();
        if tx_lock.is_some() {
            drop(tx_lock);
            return self.try_add_tx_packet(buf, addr);
        }
        let Ok(io_page) = self.channel().alloc_page(self.subchannel_mask) else {
            return self.try_add_tx_packet(buf, addr);
        };

        let write_sz = buf.len();
        assert!(write_sz <= io_page.bytes_mut().len());
        io_page.bytes_mut()[0..write_sz].copy_from_slice(buf);

        let msg = api_net::udp_socket_tx_msg(self.handle(), io_page, 0, write_sz as u16, addr);
        if let Err(msg) = self.try_tx_msg(msg, write_sz) {
            *tx_lock = Some(PendingTx::new_from_msg(msg, write_sz));
        }

        Ok(write_sz)
    }

    fn try_tx(&self) {
        todo!()
    }

    fn try_tx_msg(&self, msg: io_channel::Msg, write_sz: usize) -> Result<(), io_channel::Msg> {
        self.channel().post_msg(msg)?;
        Ok(())
    }

    // Note: this is called from the I/O thread so should not block.
    pub fn process_incoming_msg(&self, msg: io_channel::Msg) {
        let cmd = api_net::NetCmd::try_from(msg.command).unwrap();
        match cmd {
            api_net::NetCmd::UdpSocketRx => {
                self.rx_queue.lock().push_back(msg);
                self.wait_object.on_event(moto_rt::poll::POLL_READABLE);
            }
            _ => panic!("Unexpected UDP cmd: {:?}", cmd),
        }
    }
}

impl PosixFile for UdpSocket {}
