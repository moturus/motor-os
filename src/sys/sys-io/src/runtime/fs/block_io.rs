//! One submitter owns every filesystem request on a block device's queue.
use super::stats;
use futures::{StreamExt, stream::FuturesUnordered};
use moto_async::{channel, oneshot};
use std::cell::RefCell;
use std::future::poll_fn;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use virtio_async::{BlockDevice, RawCompletion};

pub(super) enum Message {
    Read {
        first_sector: u64,
        pages: Vec<u64>,
        reply: oneshot::Sender<Result<()>>,
    },
    Write {
        first_sector: u64,
        pages: Vec<u64>,
        reply: oneshot::Sender<Result<()>>,
    },
    Flush {
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Owns the caller's buffers from inbox admission through the final reply.
/// Dropping before polling the reply to completion is forbidden, even if
/// the task has already sent the result.
pub(super) struct Reply<T> {
    data: Option<T>,
    receiver: oneshot::Receiver<Result<()>>,
    armed: bool,
}

pub(super) async fn send<T>(
    inbox: &channel::Sender<Message>,
    data: T,
    message: impl FnOnce(oneshot::Sender<Result<()>>) -> Message,
) -> std::result::Result<Reply<T>, (T, Error)> {
    let (reply, receiver) = oneshot::oneshot();
    if inbox.send(message(reply)).await.is_err() {
        return Err((data, ErrorKind::NotConnected.into()));
    }
    // No await after admission: an accepted request always has an armed owner.
    Ok(Reply {
        data: Some(data),
        receiver,
        armed: true,
    })
}

impl<T: Unpin> Future for Reply<T> {
    type Output = (T, Result<()>);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = std::task::ready!(Pin::new(&mut self.receiver).poll(cx))
            .unwrap_or_else(|_| Err(ErrorKind::NotConnected.into()));
        self.armed = false;
        Poll::Ready((self.data.take().unwrap(), result))
    }
}

impl<T> Drop for Reply<T> {
    fn drop(&mut self) {
        assert!(!self.armed, "block I/O reply dropped before resolving");
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Read,
    Write,
    Flush,
}

struct Response {
    reply: Option<oneshot::Sender<Result<()>>>,
    // Includes chunks not submitted yet, so a partial run cannot reply early.
    remaining: usize,
    error: Option<(usize, Error)>,
    read_started: Option<u64>,
}

struct Request {
    operation: Operation,
    first_sector: u64,
    pages: Vec<u64>,
    next_page: usize,
    response: Rc<RefCell<Response>>,
}

impl Request {
    fn new(message: Message, seg_max: usize) -> Option<Self> {
        let (operation, first_sector, pages, reply) = match message {
            Message::Read {
                first_sector,
                pages,
                reply,
            } => (Operation::Read, first_sector, pages, reply),
            Message::Write {
                first_sector,
                pages,
                reply,
            } => (Operation::Write, first_sector, pages, reply),
            Message::Flush { reply } => (Operation::Flush, 0, Vec::new(), reply),
        };
        if pages.is_empty() && !matches!(operation, Operation::Flush) {
            let _ = reply.send(Ok(()));
            return None;
        }
        let response = Rc::new(RefCell::new(Response {
            reply: Some(reply),
            remaining: pages.len().div_ceil(seg_max).max(1),
            error: None,
            read_started: matches!(operation, Operation::Read).then(stats::now_ticks),
        }));
        Some(Self {
            operation,
            first_sector,
            pages,
            next_page: 0,
            response,
        })
    }

    fn try_submit(&self, device: &BlockDevice, fs_stats: &stats::FsStats) -> Option<RawCompletion> {
        let end = (self.next_page + device.seg_max()).min(self.pages.len());
        let pages = &self.pages[self.next_page..end];
        let sector = self.first_sector + self.next_page as u64 * 8;
        // SAFETY: only the adapter sends these addresses. Its admitted reply
        // owns the page buffers and panics on early drop, until every chunk
        // has completed and the response below is delivered.
        let completion = match self.operation {
            Operation::Read => unsafe { device.try_read(sector, pages) },
            Operation::Write => unsafe { device.try_write(sector, pages) },
            Operation::Flush => device.try_flush(),
        }?;
        match self.operation {
            Operation::Read => {
                fs_stats.device_reads.set(fs_stats.device_reads.get() + 1);
                fs_stats
                    .device_read_blocks
                    .set(fs_stats.device_read_blocks.get() + pages.len() as u64);
            }
            Operation::Write => {
                fs_stats.device_writes.set(fs_stats.device_writes.get() + 1);
                fs_stats
                    .device_write_blocks
                    .set(fs_stats.device_write_blocks.get() + pages.len() as u64);
            }
            Operation::Flush => {}
        }
        Some(completion)
    }
}

type Done = (Rc<RefCell<Response>>, usize, Result<()>);

async fn complete(
    completion: RawCompletion,
    response: Rc<RefCell<Response>>,
    chunk: usize,
) -> Done {
    // Consuming the completion releases its descriptors before delivery.
    let ((), result) = completion.await;
    (response, chunk, result)
}

fn deliver((response, chunk, result): Done, fs_stats: &stats::FsStats) {
    let mut response = response.borrow_mut();
    // Match the old request-order error even when chunks finish out of order.
    if let Err(error) = result
        && response
            .error
            .as_ref()
            .is_none_or(|(first, _)| chunk < *first)
    {
        response.error = Some((chunk, error));
    }
    response.remaining -= 1;
    if response.remaining == 0 {
        if stats::TIMINGS
            && let Some(started) = response.read_started
        {
            let elapsed = stats::now_ticks().wrapping_sub(started);
            fs_stats
                .device_read_ticks
                .set(fs_stats.device_read_ticks.get() + elapsed);
        }
        let result = response
            .error
            .take()
            .map_or(Ok(()), |(_, error)| Err(error));
        let _ = response.reply.take().unwrap().send(result);
    }
}

enum Event {
    Done(Done),
    Message(Option<Message>),
}

pub(super) async fn run(
    device: Rc<BlockDevice>,
    mut inbox: channel::Receiver<Message>,
    fs_stats: Rc<stats::FsStats>,
) {
    let mut pending: Option<Request> = None;
    let mut inflight = FuturesUnordered::new();
    let mut inbox_open = true;
    loop {
        let event = poll_fn(|cx| {
            if !inflight.is_empty()
                && let Poll::Ready(Some(done)) = inflight.poll_next_unpin(cx)
            {
                return Poll::Ready(Event::Done(done));
            }
            if pending.is_none() && inbox_open {
                // recv() may dequeue at construction; always poll it here.
                let mut recv = inbox.recv();
                if let Poll::Ready(message) = Pin::new(&mut recv).poll(cx) {
                    return Poll::Ready(Event::Message(message));
                }
            }
            if inflight.is_empty() && (pending.is_some() || !inbox_open) {
                unreachable!("a pending block request must fit an empty queue");
            }
            Poll::Pending
        })
        .await;
        match event {
            Event::Message(Some(message)) => pending = Request::new(message, device.seg_max()),
            Event::Message(None) => inbox_open = false,
            Event::Done(done) => deliver(done, &fs_stats),
        }
        while let Some(request) = pending.as_mut() {
            let Some(completion) = request.try_submit(&device, &fs_stats) else {
                break;
            };
            let chunk = request.next_page / device.seg_max();
            inflight.push(complete(completion, request.response.clone(), chunk));
            request.next_page = (request.next_page + device.seg_max()).min(request.pages.len());
            if request.next_page == request.pages.len() {
                pending = None;
            }
        }
        if !inbox_open && inflight.is_empty() && pending.is_none() {
            return;
        }
    }
}
