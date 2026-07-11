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
}

pub struct InnerRxStream {
    recv_queue: VecDeque<io_channel::Msg>,

    // Pages claimed out of TcpStreamRx messages but not yet consumed by the
    // application, in stream order. Each page is freed back to the channel
    // when dropped.
    rx_bufs: VecDeque<RxBuf>,
}

impl InnerRxStream {
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            recv_queue: VecDeque::new(),
            rx_bufs: VecDeque::new(),
        }))
    }

    pub fn is_empty(&self) -> bool {
        self.recv_queue.is_empty() && self.rx_bufs.is_empty()
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

    pub fn front(&self) -> Option<&io_channel::Msg> {
        self.recv_queue.front()
    }

    pub fn have_loose_bytes(&self) -> bool {
        !self.rx_bufs.is_empty()
    }

    pub fn push_bytes(
        &mut self,
        page: io_channel::IoPage, // Will release the page on drop.
        len: usize,
    ) {
        self.rx_bufs.push_back(RxBuf {
            page,
            len,
            consumed: 0,
        })
    }

    /// Drop (and thus free) all claimed pages.
    pub fn clear_rx_bufs(&mut self) {
        self.rx_bufs.clear();
    }

    /// Copy claimed bytes into `dst`, crossing page boundaries, until either
    /// side runs out. When `peek`, nothing is consumed.
    pub fn copy_out(&mut self, dst: &mut [&mut [u8]], peek: bool) -> usize {
        let mut copied = 0;
        // src_idx/src_off track the read position when peeking; when
        // consuming, the position is always the front buffer's start.
        let mut src_idx = 0;
        let mut src_off = 0;
        let mut dst_idx = 0;
        let mut dst_off = 0;
        while dst_idx < dst.len() {
            let Some(src) = self.rx_bufs.get_mut(src_idx) else {
                break;
            };
            let src_bytes = &src.bytes()[src_off..];
            let dst_buf = &mut dst[dst_idx][dst_off..];
            let sz = src_bytes.len().min(dst_buf.len());
            dst_buf[..sz].copy_from_slice(&src_bytes[..sz]);
            copied += sz;

            dst_off += sz;
            if dst_off == dst[dst_idx].len() {
                dst_idx += 1;
                dst_off = 0;
            }

            if peek {
                src_off += sz;
                if src_off == src.bytes().len() {
                    src_idx += 1;
                    src_off = 0;
                }
            } else {
                src.consume(sz);
                if src.is_consumed() {
                    self.rx_bufs.pop_front(); // Frees the page.
                }
            }
        }

        copied
    }
}

impl Drop for InnerRxStream {
    fn drop(&mut self) {
        assert!(self.is_empty())
    }
}
