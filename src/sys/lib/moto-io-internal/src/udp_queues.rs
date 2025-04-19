//! The largest buffer a Motor OS process can send to sys-io (the IO driver)
//! is 4K, but UDP datagrams can be much larger, so they must be
//! fragmented and then reassembled.
use alloc::{collections::vec_deque::VecDeque, vec::Vec};
use core::net::SocketAddr;
use moto_ipc::io_channel;
use moto_rt::ErrorCode;

pub struct UdpFragmentingQueue {
    socket_id: u64,
    subchannel_mask: u64,
    queue: VecDeque<UdpDatagram>,
    msg: Option<io_channel::Msg>,
}

impl Drop for UdpFragmentingQueue {
    fn drop(&mut self) {
        assert!(self.msg.is_none())
    }
}

pub trait PageAllocator = FnOnce(u64) -> Result<io_channel::IoPage, ErrorCode>;
pub trait PageGetter = FnOnce(u16) -> Result<io_channel::IoPage, ErrorCode>;

impl UdpFragmentingQueue {
    const MAX_LEN: usize = 8;

    pub fn new(socket_id: u64, subchannel_mask: u64) -> Self {
        Self {
            socket_id,
            subchannel_mask,
            queue: VecDeque::new(),
            msg: None,
        }
    }

    pub fn take_msg(&mut self) -> Option<io_channel::Msg> {
        self.msg.take()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.msg.is_none()
    }

    pub fn is_full(&self) -> bool {
        self.queue.len() >= Self::MAX_LEN
    }

    pub fn push_back(&mut self, bytes: &[u8], addr: SocketAddr) {
        self.queue.push_back(UdpDatagram::new(bytes, addr))
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
            self.queue.pop_front().unwrap();
        }

        Some(msg)
    }
}

#[allow(clippy::new_without_default)]
pub struct UdpDefragmentingQueue {
    queue: VecDeque<UdpFragment>,
    datagram: Option<UdpDatagram>,
}

impl UdpDefragmentingQueue {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            datagram: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.datagram.is_none() && self.queue.is_empty()
    }

    pub fn push_back<F>(&mut self, msg: io_channel::Msg, page_getter: F) -> Result<(), ErrorCode>
    where
        F: PageGetter,
    {
        let page_idx = msg.payload.shared_pages()[11];
        let page = page_getter(page_idx)?;

        let addr = moto_sys_io::api_net::get_socket_addr(&msg.payload);
        let fragment_id = msg.payload.args_16()[9];
        let sz = msg.payload.args_16()[10];
        if (sz as usize) > io_channel::PAGE_SIZE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        self.queue
            .push_back(UdpFragment::from(page, fragment_id, sz, addr));

        Ok(())
    }

    pub fn push_front(&mut self, datagram: UdpDatagram) {
        assert!(self.datagram.replace(datagram).is_none());
    }

    #[allow(clippy::result_unit_err)]
    pub fn next_datagram(&mut self) -> Result<Option<UdpDatagram>, ()> {
        if let Some(datagram) = self.datagram.take() {
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

            Ok(Some(UdpDatagram {
                page: page.map(|page| (page, sz as usize)),
                bytes,
                addr,
                consumed: 0,
            }))
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

            Ok(Some(UdpDatagram {
                page: None,
                bytes,
                addr,
                consumed: 0,
            }))
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
        assert!(self.datagram.replace(datagram).is_none());
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
