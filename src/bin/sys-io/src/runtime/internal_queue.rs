//! Internal queue to let threads inside sys-io communicate.
use moto_runtime::util::ArrayQueue;
use moto_runtime::util::SpinLock;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::{any::Any, sync::Arc};

pub type Payload = Arc<dyn Any + Send + Sync>;

pub struct Msg {
    pub cmd: u16,
    futex_waiter: Arc<AtomicU32>,
    pub payload: Payload,
}

impl Drop for Msg {
    fn drop(&mut self) {
        assert_eq!(Msg::READY, self.futex_waiter.load(Ordering::Relaxed));
    }
}

impl Msg {
    pub const NOT_READY: u32 = 0;
    pub const READY: u32 = 1;

    pub fn mark_done(self) {
        self.futex_waiter.store(Self::READY, Ordering::Release);
        moto_runtime::futex_wake(&self.futex_waiter);
    }
}

static QUEUE: SpinLock<Option<ArrayQueue<Msg>>> = SpinLock::new(None);
const QUEUE_SIZE: usize = 64;

pub fn init() {
    *QUEUE.lock(line!()) = Some(ArrayQueue::new(QUEUE_SIZE));
}

pub fn call(cmd: u16, payload: Payload) {
    let futex_waiter = Arc::new(AtomicU32::new(Msg::NOT_READY));
    let mut msg = Msg {
        cmd,
        futex_waiter: futex_waiter.clone(),
        payload,
    };
    loop {
        match QUEUE.lock(line!()).as_ref().unwrap().push(msg) {
            Ok(_) => break,
            Err(m) => msg = m,
        }
    }
    moto_sys::SysCpu::wake(
        super::io_thread::IO_THREAD_HANDLE
            .load(Ordering::Relaxed)
            .into(),
    )
    .unwrap();

    moto_runtime::futex_wait(&futex_waiter, Msg::NOT_READY, None);
    assert_eq!(Msg::READY, futex_waiter.load(Ordering::Relaxed));
}

pub fn pop_msg() -> Option<Msg> {
    QUEUE.lock(line!()).as_ref().unwrap().pop()
}
