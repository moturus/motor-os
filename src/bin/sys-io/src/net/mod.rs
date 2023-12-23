use moto_ipc::io_channel;
use moto_sys::ErrorCode;

mod config;
mod netdev;
mod netdev_loopback;
mod netdev_virtio;
mod smoltcp_helpers;
mod sys;
mod tcp;
mod util;

pub fn init() -> Box<dyn crate::runtime::IoSubsystem> {
    let config = config::load().ok();
    if config.is_none() {
        panic!("sys-net.cfg not available.");
    }
    Box::new(sys::NetSys::new(config.unwrap()))
}

#[derive(Clone, Copy)]
struct IoBuf {
    sqe: io_channel::QueueEntry,
    buf_ptr: usize,
    buf_len: usize,
    consumed: usize,
    status: ErrorCode,
}

impl std::fmt::Debug for IoBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IoBuf")
            .field("sqe", &self.sqe.id)
            .field("len", &self.consumed)
            .finish()
    }
}

impl IoBuf {
    fn new(sqe: io_channel::QueueEntry, buf: &[u8]) -> Self {
        Self {
            sqe,
            buf_ptr: buf.as_ptr() as usize,
            buf_len: buf.len(),
            consumed: 0,
            status: ErrorCode::NotReady,
        }
    }

    fn bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self.buf_ptr + self.consumed) as *const u8,
                self.buf_len - self.consumed,
            )
        }
    }

    fn consume(&mut self, sz: usize) {
        self.consumed += sz;
        assert!(self.consumed <= self.buf_len);
    }

    fn is_consumed(&self) -> bool {
        self.consumed == self.buf_len
    }
}
