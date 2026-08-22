//! The largest buffer a Motor OS process can send to sys-io (the IO driver)
//! is 4K, but UDP datagrams can be much larger, so they must be
//! fragmented and then reassembled.
//!
//! In addition, the fragmenting queue will drop datagrams if it
//! reaches its max length, to avoid DDOSing the OS if the app
//! is slower to process incoming UDP datagrams than they are
//! received.
use alloc::{collections::vec_deque::VecDeque, vec::Vec};
use core::net::SocketAddr;
use moto_ipc::io_channel;
use moto_rt::ErrorCode;

pub const UDP_TX_QUEUE_MAX_DATAGRAMS: usize = 16;
pub const UDP_TX_QUEUE_MAX_BYTES: usize = 64 * io_channel::PAGE_SIZE;

pub struct UdpFragmentingQueue {
    socket_id: u64,
    subchannel_mask: u64,
    queue: VecDeque<UdpDatagram>,
    msg: Option<io_channel::Msg>,
    queued_bytes: usize,
    byte_limit: Option<usize>,
}

impl Drop for UdpFragmentingQueue {
    fn drop(&mut self) {
        assert!(self.msg.is_none())
    }
}

pub trait AsyncPageAllocator = async FnOnce(u64) -> Result<io_channel::IoPage, ErrorCode>;
pub trait PageAllocator = FnOnce(u64) -> Result<io_channel::IoPage, ErrorCode>;
pub trait PageGetter = FnOnce(u16) -> Result<io_channel::IoPage, ErrorCode>;

impl UdpFragmentingQueue {
    pub fn new(socket_id: u64, subchannel_mask: u64) -> Self {
        Self::new_inner(socket_id, subchannel_mask, None)
    }

    pub fn new_tx(socket_id: u64, subchannel_mask: u64) -> Self {
        Self::new_inner(socket_id, subchannel_mask, Some(UDP_TX_QUEUE_MAX_BYTES))
    }

    fn new_inner(socket_id: u64, subchannel_mask: u64, byte_limit: Option<usize>) -> Self {
        Self {
            socket_id,
            subchannel_mask,
            queue: VecDeque::new(),
            msg: None,
            queued_bytes: 0,
            byte_limit,
        }
    }

    pub fn take_msg(&mut self) -> Option<io_channel::Msg> {
        self.msg.take()
    }

    /// Discard the datagrams still waiting to be fragmented. They hold no io
    /// pages -- only the staged message does, and [`Self::take_msg`] owns it.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.queued_bytes = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.msg.is_none()
    }

    pub fn is_full(&self) -> bool {
        self.queue.len() >= UDP_TX_QUEUE_MAX_DATAGRAMS
            || self
                .byte_limit
                .is_some_and(|limit| self.queued_bytes >= limit)
    }

    pub fn push_back(&mut self, bytes: &[u8], addr: SocketAddr) -> bool {
        if self.queue.len() >= UDP_TX_QUEUE_MAX_DATAGRAMS
            || self
                .byte_limit
                .is_some_and(|limit| bytes.len() > limit - self.queued_bytes)
        {
            return false;
        }

        self.queued_bytes += bytes.len();
        self.queue.push_back(UdpDatagram::new(bytes, addr));
        true
    }

    pub fn push_front(&mut self, msg: io_channel::Msg) {
        assert!(self.msg.replace(msg).is_none())
    }

    pub fn pop_front<F>(&mut self, page_allocator: F) -> Option<io_channel::Msg>
    where
        F: PageAllocator,
    {
        if let Some(msg) = self.msg.take() {
            return Some(msg);
        }

        let udp_datagram = self.queue.front_mut()?;
        let msg = udp_datagram.next_msg(self.socket_id, self.subchannel_mask, page_allocator)?;

        if udp_datagram.is_done() {
            let datagram = self.queue.pop_front().unwrap();
            self.queued_bytes -= datagram.bytes.len();
        }

        Some(msg)
    }

    pub async fn pop_front_async<F>(&mut self, page_allocator: F) -> Option<io_channel::Msg>
    where
        F: AsyncPageAllocator,
    {
        if let Some(msg) = self.msg.take() {
            return Some(msg);
        }

        let udp_datagram = self.queue.front_mut()?;
        let msg = udp_datagram
            .next_msg_async(self.socket_id, self.subchannel_mask, page_allocator)
            .await?;

        if udp_datagram.is_done() {
            let datagram = self.queue.pop_front().unwrap();
            self.queued_bytes -= datagram.bytes.len();
        }

        Some(msg)
    }
}

const MAX_UDP_FRAGMENTS: usize = moto_rt::net::MAX_UDP_PAYLOAD.div_ceil(io_channel::PAGE_SIZE);

#[derive(Clone, Copy)]
struct FragmentSequence {
    addr: SocketAddr,
    next_id: u16,
    fragments: usize,
    bytes: usize,
}

impl FragmentSequence {
    fn after_fragment(
        pending: Option<Self>,
        fragment_id: u16,
        sz: u16,
        addr: SocketAddr,
    ) -> Result<Option<Self>, ErrorCode> {
        let sz = sz as usize;
        if sz > io_channel::PAGE_SIZE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        if fragment_id == 0 {
            return if pending.is_none() {
                Ok(None)
            } else {
                Err(moto_rt::E_INVALID_ARGUMENT)
            };
        }

        if fragment_id == u16::MAX {
            let Some(sequence) = pending else {
                return Err(moto_rt::E_INVALID_ARGUMENT);
            };
            if sz == 0 || sequence.addr != addr {
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            if sequence.fragments + 1 > MAX_UDP_FRAGMENTS
                || sequence.bytes + sz > moto_rt::net::MAX_UDP_PAYLOAD
            {
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            return Ok(None);
        }

        if sz != io_channel::PAGE_SIZE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let sequence = match pending {
            None if fragment_id == 1 => Self {
                addr,
                next_id: 2,
                fragments: 1,
                bytes: sz,
            },
            Some(sequence) if sequence.next_id == fragment_id && sequence.addr == addr => Self {
                next_id: fragment_id + 1,
                fragments: sequence.fragments + 1,
                bytes: sequence.bytes + sz,
                ..sequence
            },
            _ => return Err(moto_rt::E_INVALID_ARGUMENT),
        };

        if sequence.fragments >= MAX_UDP_FRAGMENTS
            || sequence.bytes >= moto_rt::net::MAX_UDP_PAYLOAD
        {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Ok(Some(sequence))
    }
}

#[allow(clippy::new_without_default)]
pub struct UdpDefragmentingQueue {
    queue: VecDeque<UdpFragment>,
    datagram: Option<UdpDatagram>,
    fragment_sequence: Option<FragmentSequence>,
    dropping_fragment_sequence: bool,
    tx_limits: bool,
    queued_datagrams: usize,
    queued_bytes: usize,
}

impl UdpDefragmentingQueue {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::new_inner(false)
    }

    pub fn new_tx() -> Self {
        Self::new_inner(true)
    }

    fn new_inner(tx_limits: bool) -> Self {
        Self {
            queue: VecDeque::new(),
            datagram: None,
            fragment_sequence: None,
            dropping_fragment_sequence: false,
            tx_limits,
            queued_datagrams: 0,
            queued_bytes: 0,
        }
    }

    /// Drop every partial or complete datagram, releasing its I/O pages.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.datagram = None;
        self.fragment_sequence = None;
        self.dropping_fragment_sequence = false;
        self.queued_datagrams = 0;
        self.queued_bytes = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.datagram.is_none() && self.queue.is_empty()
    }

    /// Returns `true` exactly once when admission drops a whole datagram.
    pub fn push_back<F>(&mut self, msg: io_channel::Msg, page_getter: F) -> Result<bool, ErrorCode>
    where
        F: PageGetter,
    {
        let addr = moto_sys_io::api_net::get_socket_addr(&msg.payload);
        let sz = msg.payload.args_16()[10];
        let fragment_id = msg.payload.args_16()[9];

        let next_sequence =
            match FragmentSequence::after_fragment(self.fragment_sequence, fragment_id, sz, addr) {
                Ok(sequence) => sequence,
                Err(err) => {
                    if sz != 0 {
                        let page_idx = msg.payload.shared_pages()[11];
                        let _ = page_getter(page_idx);
                    }
                    return Err(err);
                }
            };

        if self.dropping_fragment_sequence {
            debug_assert!(self.fragment_sequence.is_some());
            if sz != 0 {
                let page_idx = msg.payload.shared_pages()[11];
                let _ = page_getter(page_idx)?;
            }
            self.fragment_sequence = next_sequence;
            self.dropping_fragment_sequence = self.fragment_sequence.is_some();
            return Ok(false);
        }

        let starts_datagram = fragment_id == 0 || fragment_id == 1;
        let exceeds_limits = self.tx_limits
            && ((starts_datagram && self.queued_datagrams >= UDP_TX_QUEUE_MAX_DATAGRAMS)
                || sz as usize > UDP_TX_QUEUE_MAX_BYTES - self.queued_bytes);
        if exceeds_limits {
            if sz != 0 {
                let page_idx = msg.payload.shared_pages()[11];
                let _ = page_getter(page_idx)?;
            }
            self.drop_partial_datagram();
            self.fragment_sequence = next_sequence;
            self.dropping_fragment_sequence = self.fragment_sequence.is_some();
            return Ok(true);
        }

        let fragment = if sz == 0 {
            UdpFragment::empty(addr)
        } else {
            let page_idx = msg.payload.shared_pages()[11];
            let page = page_getter(page_idx)?;
            UdpFragment::from(page, fragment_id, sz, addr)
        };

        self.queue.push_back(fragment);
        self.fragment_sequence = next_sequence;
        if self.tx_limits {
            self.queued_bytes += sz as usize;
            if starts_datagram {
                self.queued_datagrams += 1;
            }
        }
        Ok(false)
    }

    fn drop_partial_datagram(&mut self) {
        let Some(sequence) = self.fragment_sequence else {
            return;
        };
        for _ in 0..sequence.fragments {
            let fragment = self.queue.pop_back().unwrap();
            self.queued_bytes -= fragment.sz as usize;
        }
        self.queued_datagrams -= 1;
    }

    pub fn push_front(&mut self, datagram: UdpDatagram) {
        if self.tx_limits {
            self.queued_datagrams += 1;
            self.queued_bytes += datagram.slice().len();
            debug_assert!(self.queued_datagrams <= UDP_TX_QUEUE_MAX_DATAGRAMS);
            debug_assert!(self.queued_bytes <= UDP_TX_QUEUE_MAX_BYTES);
        }
        assert!(self.datagram.replace(datagram).is_none());
    }

    #[allow(clippy::result_unit_err)]
    pub fn next_datagram(&mut self) -> Result<Option<UdpDatagram>, ()> {
        if let Some(datagram) = self.datagram.take() {
            self.remove_datagram(&datagram);
            return Ok(Some(datagram));
        }

        let Some(fragment) = self.queue.front() else {
            return Ok(None);
        };

        if fragment.fragment_id == 0 {
            let UdpFragment {
                page,
                bytes,
                fragment_id: _,
                sz,
                addr,
            } = self.queue.pop_front().unwrap();

            let datagram = UdpDatagram {
                page: page.map(|page| (page, sz as usize)),
                bytes,
                addr,
                consumed: 0,
            };
            self.remove_datagram(&datagram);
            Ok(Some(datagram))
        } else {
            if fragment.fragment_id != 1 {
                // this is a bug: fragments start at 1.
                return Err(());
            }

            // Determine if we have all fragments.
            let mut last_fragment_idx = 0;
            for idx in 1..self.queue.len() {
                let fragment_id = self.queue[idx].fragment_id;
                if fragment_id == u16::MAX {
                    last_fragment_idx = idx;
                    break;
                } else if (idx + 1) != (fragment_id as usize) {
                    return Err(());
                }
            }

            if last_fragment_idx == 0 {
                // Not all fragments are present.
                return Ok(None);
            }

            let addr = self.queue[0].addr;
            let total_bytes = io_channel::PAGE_SIZE * last_fragment_idx
                + (self.queue[last_fragment_idx].sz as usize);
            let mut bytes = Vec::with_capacity(total_bytes);
            for _ in 0..=last_fragment_idx {
                let tx_buf = self.queue.pop_front().unwrap();
                if tx_buf.addr != addr {
                    return Err(());
                }
                if (tx_buf.sz as usize) > io_channel::PAGE_SIZE {
                    return Err(());
                }
                bytes.extend_from_slice(tx_buf.slice());
            }

            if bytes.len() != total_bytes {
                return Err(());
            }

            let datagram = UdpDatagram {
                page: None,
                bytes,
                addr,
                consumed: 0,
            };
            self.remove_datagram(&datagram);
            Ok(Some(datagram))
        }
    }

    fn remove_datagram(&mut self, datagram: &UdpDatagram) {
        if self.tx_limits {
            self.queued_datagrams -= 1;
            self.queued_bytes -= datagram.slice().len();
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn have_datagram(&mut self) -> Result<bool, ()> {
        if self.datagram.is_some() {
            return Ok(true);
        }

        let Some(datagram) = self.next_datagram()? else {
            return Ok(false);
        };
        self.push_front(datagram);
        Ok(true)
    }

    #[allow(clippy::result_unit_err)]
    pub fn peek_datagram(&mut self) -> Result<Option<&UdpDatagram>, ()> {
        if !self.have_datagram()? {
            return Ok(None);
        }

        Ok(self.datagram.as_ref())
    }
}

pub struct UdpDatagram {
    page: Option<(io_channel::IoPage, usize)>,
    bytes: Vec<u8>,
    consumed: usize,
    pub addr: SocketAddr,
}

impl UdpDatagram {
    fn is_done(&self) -> bool {
        self.consumed >= self.bytes.len()
    }

    fn new(buf: &[u8], addr: SocketAddr) -> Self {
        Self {
            page: None,
            bytes: Vec::from(buf),
            consumed: 0,
            addr,
        }
    }

    fn next_msg<F>(
        &mut self,
        socket_id: u64,
        subchannel_mask: u64,
        page_allocator: F,
    ) -> Option<io_channel::Msg>
    where
        F: PageAllocator,
    {
        if self.bytes.is_empty() {
            return Some(moto_sys_io::api_net::udp_socket_tx_rx_empty_msg(
                socket_id, &self.addr,
            ));
        }

        assert!(self.consumed < self.bytes.len());
        debug_assert_eq!(0, self.consumed & (io_channel::PAGE_SIZE - 1));
        let remains = self.bytes.len() - self.consumed;
        let next_sz = io_channel::PAGE_SIZE.min(remains);

        let fragment_id = if self.bytes.len() <= io_channel::PAGE_SIZE {
            0
        } else if next_sz == remains {
            // The last fragment.
            u16::MAX
        } else {
            (1 + (self.consumed / io_channel::PAGE_SIZE)) as u16
        };

        let Ok(io_page) = page_allocator(subchannel_mask) else {
            return None;
        };

        io_page.bytes_mut()[0..next_sz]
            .copy_from_slice(&self.bytes[self.consumed..(self.consumed + next_sz)]);
        let msg = moto_sys_io::api_net::udp_socket_tx_rx_msg(
            socket_id,
            io_page,
            fragment_id,
            next_sz as u16,
            &self.addr,
        );

        self.consumed += next_sz;

        Some(msg)
    }

    async fn next_msg_async<F>(
        &mut self,
        socket_id: u64,
        subchannel_mask: u64,
        page_allocator: F,
    ) -> Option<io_channel::Msg>
    where
        F: AsyncPageAllocator,
    {
        if self.bytes.is_empty() {
            return Some(moto_sys_io::api_net::udp_socket_tx_rx_empty_msg(
                socket_id, &self.addr,
            ));
        }

        assert!(self.consumed < self.bytes.len());
        debug_assert_eq!(0, self.consumed & (io_channel::PAGE_SIZE - 1));
        let remains = self.bytes.len() - self.consumed;
        let next_sz = io_channel::PAGE_SIZE.min(remains);

        let fragment_id = if self.bytes.len() <= io_channel::PAGE_SIZE {
            0
        } else if next_sz == remains {
            // The last fragment.
            u16::MAX
        } else {
            (1 + (self.consumed / io_channel::PAGE_SIZE)) as u16
        };

        let Ok(io_page) = page_allocator(subchannel_mask).await else {
            return None;
        };

        io_page.bytes_mut()[0..next_sz]
            .copy_from_slice(&self.bytes[self.consumed..(self.consumed + next_sz)]);
        let msg = moto_sys_io::api_net::udp_socket_tx_rx_msg(
            socket_id,
            io_page,
            fragment_id,
            next_sz as u16,
            &self.addr,
        );

        self.consumed += next_sz;

        Some(msg)
    }

    pub fn slice(&self) -> &[u8] {
        if let Some((page, sz)) = self.page.as_ref() {
            assert!(self.bytes.is_empty());
            &page.bytes()[0..(*sz)]
        } else {
            &self.bytes
        }
    }
}

struct UdpFragment {
    page: Option<io_channel::IoPage>,
    bytes: Vec<u8>,
    fragment_id: u16,
    sz: u16,
    addr: SocketAddr,
}

impl UdpFragment {
    fn empty(addr: SocketAddr) -> Self {
        Self {
            page: None,
            bytes: Vec::new(),
            fragment_id: 0,
            sz: 0,
            addr,
        }
    }

    fn from(page: io_channel::IoPage, fragment_id: u16, sz: u16, addr: SocketAddr) -> Self {
        if fragment_id == 0 {
            Self {
                page: Some(page),
                bytes: Vec::new(),
                fragment_id,
                sz,
                addr,
            }
        } else {
            // Need to free the page.
            let mut bytes = Vec::with_capacity(sz as usize);
            bytes.extend_from_slice(&page.bytes()[0..(sz as usize)]);
            Self {
                page: None,
                bytes,
                fragment_id,
                sz,
                addr,
            }
        }
    }

    fn slice(&self) -> &[u8] {
        if let Some(page) = self.page.as_ref() {
            assert!(self.bytes.is_empty());
            &page.bytes()[0..(self.sz as usize)]
        } else {
            &self.bytes
        }
    }
}
