/// A helper TCP RX stream.
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use moto_ipc::io_channel;
use moto_rt::mutex::Mutex;

struct RxBuf {
    page: io_channel::IoPage, // Will release the page on drop.
    len: usize,
    consumed: usize,
}

impl RxBuf {
    fn bytes(&self) -> &[u8] {
        &self.page.bytes()[self.consumed..self.len]
    }

    fn consume(&mut self, sz: usize) {
        self.consumed += sz;
        assert!(self.consumed <= self.len);
    }

    fn is_consumed(&self) -> bool {
        self.consumed == self.len
    }

    fn available(&self) -> usize {
        self.len - self.consumed
    }
}

pub struct InnerRxStream {
    recv_queue: VecDeque<io_channel::Msg>,
    rx_buf: Option<RxBuf>,
}

impl InnerRxStream {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            recv_queue: VecDeque::new(),
            rx_buf: None,
        }))
    }

    pub fn is_empty(&self) -> bool {
        self.recv_queue.is_empty() && self.rx_buf.is_none()
    }

    pub fn push_back(&mut self, msg: io_channel::Msg) {
        self.recv_queue.push_back(msg);
    }

    pub fn push_front(&mut self, msg: io_channel::Msg) {
        self.recv_queue.push_front(msg);
    }

    pub fn pop_front(&mut self) -> Option<io_channel::Msg> {
        self.recv_queue.pop_front()
    }

    pub fn loose_bytes(&self) -> Option<&[u8]> {
        self.rx_buf.as_ref().map(|buf| buf.bytes())
    }

    pub fn consume_bytes(&mut self, sz: usize) {
        let buf = self.rx_buf.as_mut().unwrap();
        buf.consume(sz);
        if buf.is_consumed() {
            self.rx_buf = None;
        }
    }

    pub fn push_bytes(
        &mut self,
        page: io_channel::IoPage, // Will release the page on drop.
        len: usize,
    ) {
        assert!(self.rx_buf.is_none());
        self.rx_buf = Some(RxBuf {
            page,
            len,
            consumed: 0,
        })
    }
}

impl Drop for InnerRxStream {
    fn drop(&mut self) {
        assert!(self.is_empty())
    }
}
