use std::cell::{Cell, RefCell};
use std::io::Result;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

pub struct Submission {
    pub operation: u8,
    pub sector: u64,
    pub pages: Vec<u64>,
    pub done: Option<moto_async::oneshot::Sender<Result<()>>>,
}

pub struct BlockDevice {
    pub submissions: RefCell<Vec<Submission>>,
    pub submitted: moto_async::LocalNotify,
    live: Rc<Cell<usize>>,
    capacity: usize,
    seg_max: usize,
}

impl BlockDevice {
    pub fn new(capacity: usize, seg_max: usize) -> Self {
        Self {
            submissions: RefCell::new(Vec::new()),
            submitted: moto_async::LocalNotify::new(),
            live: Rc::new(Cell::new(0)),
            capacity,
            seg_max,
        }
    }
    pub fn seg_max(&self) -> usize {
        self.seg_max
    }
    // The common fake API also supports variants using only interrupt wakeups.
    #[allow(dead_code)]
    pub fn reclaim_completed(&self) {}
    pub fn live(&self) -> usize {
        self.live.get()
    }
    fn submit(&self, operation: u8, sector: u64, pages: &[u64]) -> Option<RawCompletion> {
        assert!(pages.len() <= self.seg_max);
        if self.live.get() == self.capacity {
            return None;
        }
        self.live.set(self.live.get() + 1);
        let (sender, receiver) = moto_async::oneshot();
        self.submissions.borrow_mut().push(Submission {
            operation,
            sector,
            pages: pages.to_vec(),
            done: Some(sender),
        });
        self.submitted.notify_one();
        Some(RawCompletion {
            live: self.live.clone(),
            receiver,
            completed: false,
        })
    }
    pub unsafe fn try_read(&self, sector: u64, pages: &[u64]) -> Option<RawCompletion> {
        self.submit(0, sector, pages)
    }
    pub unsafe fn try_write(&self, sector: u64, pages: &[u64]) -> Option<RawCompletion> {
        self.submit(1, sector, pages)
    }
    pub fn try_flush(&self) -> Option<RawCompletion> {
        self.submit(2, 0, &[])
    }
}

pub struct RawCompletion {
    live: Rc<Cell<usize>>,
    receiver: moto_async::oneshot::Receiver<Result<()>>,
    completed: bool,
}

impl Future for RawCompletion {
    type Output = ((), Result<()>);
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = std::task::ready!(Pin::new(&mut self.receiver).poll(cx)).unwrap();
        self.completed = true;
        Poll::Ready(((), result))
    }
}

impl Drop for RawCompletion {
    fn drop(&mut self) {
        assert!(
            self.completed,
            "model completion discarded before completion"
        );
        self.live.set(self.live.get() - 1);
    }
}
