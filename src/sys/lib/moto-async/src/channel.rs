//! MPSC async channel.
//!
//! It was somewhat difficult to make it work well with
//! more than one sender. Having queues as VecDeque under
//! a spinlock resulted in 5-10 usec/message in Release build,
//! and 150ns (yes, nanos) in Debug build.
//!
//! By using concurrent queues (mpmc or SegQueue) with busy
//! looping, this implementation reaches about 2 messages/usec
//! in a test with two senders.
//!
//! There still ways to make it faster, as at the moment
//! there are several places where busy-looping happen
//! in a "nested" way.
extern crate alloc;

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use core::task::{Context, Poll, Waker};

const WAITING: u8 = 0;
const WOKEN: u8 = 1;
const DONE: u8 = 2;

struct SharedChannelData {
    // Need to track the number of senders to notify the receiver on the last drop.
    sender_count: AtomicUsize,

    senders_waiting: crossbeam::queue::SegQueue<(Waker, Arc<AtomicU8>)>,

    // A single-element queue for the single receiver in wait.
    receiver_rx: moto_mpmc::Receiver<Waker>,
    receiver_tx: moto_mpmc::Sender<Waker>,
}

impl SharedChannelData {
    fn wake_one_sender(&self) {
        while let Some((waker, state)) = self.senders_waiting.pop() {
            if state
                .compare_exchange(WAITING, WOKEN, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                waker.wake();
                break;
            }
        }
    }
}

pub struct Sender<T> {
    inner: Arc<moto_mpmc::Sender<T>>,
    shared: Arc<SharedChannelData>,
}

pub struct Receiver<T> {
    inner: Arc<moto_mpmc::Receiver<T>>,
    shared: Arc<SharedChannelData>,
}

pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = moto_mpmc::bounded(capacity);
    let (receiver_tx, receiver_rx) = moto_mpmc::bounded(1);

    let shared = Arc::new(SharedChannelData {
        sender_count: AtomicUsize::new(1),
        senders_waiting: Default::default(),
        receiver_rx,
        receiver_tx,
    });

    (
        Sender {
            inner: Arc::new(sender),
            shared: shared.clone(),
        },
        Receiver {
            inner: Arc::new(receiver),
            shared,
        },
    )
}

impl<T> Sender<T> {
    pub fn send(&self, value: T) -> SendFuture<T> {
        match self.inner.try_send(value) {
            Ok(()) => {
                // Wake receiver if it was waiting.
                if let Ok(waker) = self.shared.receiver_rx.try_recv() {
                    waker.wake();
                }
                SendFuture(SendFutureInner::Ready(None))
            }
            Err(moto_mpmc::TrySendError::Full(val)) => {
                SendFuture(SendFutureInner::Pending(SendPending {
                    sender: self.clone(),
                    value: Some(val),
                    wake_marker: None,
                }))
            }
            Err(moto_mpmc::TrySendError::Disconnected(val)) => {
                SendFuture(SendFutureInner::Ready(Some(val)))
            }
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.shared.sender_count.fetch_add(1, Ordering::AcqRel);
        Sender {
            inner: Arc::new(self.inner.as_ref().clone()),
            shared: self.shared.clone(),
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let senders = self.shared.sender_count.fetch_sub(1, Ordering::AcqRel) - 1;
        if senders == 0 {
            // Notify receiver that no more data is coming.
            if let Ok(waker) = self.shared.receiver_rx.try_recv() {
                waker.wake();
            }
        }
    }
}

struct SendPending<T> {
    sender: Sender<T>,
    value: Option<T>, // Value to send.
    wake_marker: Option<Arc<AtomicU8>>,
}

impl<T> Drop for SendPending<T> {
    fn drop(&mut self) {
        if let Some(node) = &self.wake_marker {
            let prev = node.swap(DONE, Ordering::AcqRel);
            if prev == WOKEN {
                self.sender.shared.wake_one_sender();
            }
        }
    }
}

// Has to be "inner" as the future is public, and we can't have a public enum
// with private variants.
enum SendFutureInner<T> {
    Ready(Option<T>), // Value to return on error.
    Pending(SendPending<T>),
}

pub struct SendFuture<T>(SendFutureInner<T>);

impl<T> Future for SendFuture<T> {
    type Output = Result<(), T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Safety: We need mutable access to `self.value`.
        // We are not moving `self` (the Future), nor are we creating a Pin to `value`.
        // We are just treating `value` as ordinary data.
        let this_outer = unsafe { self.get_unchecked_mut() };

        match &mut this_outer.0 {
            SendFutureInner::Ready(result) => Poll::Ready(match result.take() {
                Some(val) => Err(val),
                None => Ok(()),
            }),
            SendFutureInner::Pending(this) => {
                // "Disable" the wake marker, if present, as the future will either
                // complete below or queue a new one.
                if let Some(node) = &this.wake_marker {
                    let _ = node.swap(DONE, Ordering::AcqRel);
                }

                const BUSY_LOOP_ITERS: u32 = 12;
                let mut busy_loop_iter = 0;

                loop {
                    let value = unsafe { this.value.take().unwrap_unchecked() };
                    match this.sender.inner.try_send(value) {
                        Ok(()) => {
                            // Wake receiver if it was waiting.
                            if let Ok(waker) = this.sender.shared.receiver_rx.try_recv() {
                                waker.wake();
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Err(moto_mpmc::TrySendError::Full(val)) => {
                            this.value = Some(val);
                            busy_loop_iter += 1;
                            if busy_loop_iter >= BUSY_LOOP_ITERS {
                                break;
                            }
                            core::hint::spin_loop();
                        }
                        Err(moto_mpmc::TrySendError::Disconnected(val)) => {
                            return Poll::Ready(Err(val));
                        }
                    }
                }

                let node = Arc::new(AtomicU8::new(WAITING));
                this.wake_marker = Some(node.clone());
                let waker = cx.waker().clone();
                this.sender.shared.senders_waiting.push((waker, node));

                // Check one more time to avoid a race condition where the receiver
                // freed a slot before we queued our waker, but after our last try_send.
                let value = unsafe { this.value.take().unwrap_unchecked() };
                match this.sender.inner.try_send(value) {
                    Ok(()) => {
                        if let Some(node) = &this.wake_marker {
                            let prev = node.swap(DONE, Ordering::AcqRel);
                            if prev == WOKEN {
                                this.sender.shared.wake_one_sender();
                            }
                        }
                        // Wake receiver if it was waiting.
                        if let Ok(waker) = this.sender.shared.receiver_rx.try_recv() {
                            waker.wake();
                        }
                        Poll::Ready(Ok(()))
                    }
                    Err(moto_mpmc::TrySendError::Full(val)) => {
                        this.value = Some(val);
                        Poll::Pending
                    }
                    Err(moto_mpmc::TrySendError::Disconnected(val)) => {
                        if let Some(node) = &this.wake_marker {
                            let prev = node.swap(DONE, Ordering::AcqRel);
                            if prev == WOKEN {
                                this.sender.shared.wake_one_sender();
                            }
                        }
                        Poll::Ready(Err(val))
                    }
                }
            }
        }
    }
}

impl<T> Receiver<T> {
    pub fn recv<'a>(&'a mut self) -> RecvFuture<'a, T> {
        match self.inner.try_recv() {
            Ok(val) => {
                self.shared.wake_one_sender();
                RecvFuture(RecvFutureInner::Ready(Some(val)))
            }
            Err(moto_mpmc::TryRecvError::Empty) => RecvFuture(RecvFutureInner::Pending(self)),
            Err(moto_mpmc::TryRecvError::Disconnected) => RecvFuture(RecvFutureInner::Ready(None)),
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        while let Some((waker, state)) = self.shared.senders_waiting.pop() {
            if state
                .compare_exchange(WAITING, WOKEN, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                waker.wake();
            }
        }
    }
}

// Has to be "inner" as the future is public, and we can't have a public enum
// with private variants.
enum RecvFutureInner<'a, T> {
    Ready(Option<T>),
    Pending(&'a mut Receiver<T>),
}

// RecvFuture must borrow the Receiver, otherwise two RecvFutures could be
// constructed, which could be polled concurrently.
pub struct RecvFuture<'a, T>(RecvFutureInner<'a, T>);

#[allow(clippy::extra_unused_lifetimes)]
impl<'a, T> Future for RecvFuture<'_, T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Safety: We need mutable access to `self.value`.
        // We are not moving `self` (the Future), nor are we creating a Pin to `value`.
        // We are just treating `value` as ordinary data.
        let this = unsafe { self.get_unchecked_mut() };
        match &mut this.0 {
            RecvFutureInner::Ready(val) => Poll::Ready(val.take()),
            RecvFutureInner::Pending(receiver) => {
                let _ = receiver.shared.receiver_rx.try_recv(); // Clear the waiter.

                const BUSY_LOOP_ITERS: u32 = 12;
                let mut busy_loop_iter = 0;

                loop {
                    match receiver.inner.try_recv() {
                        Ok(val) => {
                            receiver.shared.wake_one_sender();
                            return Poll::Ready(Some(val));
                        }
                        Err(moto_mpmc::TryRecvError::Disconnected) => return Poll::Ready(None),
                        Err(moto_mpmc::TryRecvError::Empty) => {
                            busy_loop_iter += 1;
                            if busy_loop_iter >= BUSY_LOOP_ITERS {
                                break;
                            }
                            core::hint::spin_loop();
                        }
                    }
                }

                receiver
                    .shared
                    .receiver_tx
                    .try_send(cx.waker().clone())
                    .unwrap();

                // Check one more time, now with the waker set.
                match receiver.inner.try_recv() {
                    Ok(val) => {
                        let _ = receiver.shared.receiver_rx.try_recv(); // Clear the waiter.
                        receiver.shared.wake_one_sender();
                        Poll::Ready(Some(val))
                    }
                    Err(moto_mpmc::TryRecvError::Disconnected) => Poll::Ready(None),
                    Err(moto_mpmc::TryRecvError::Empty) => Poll::Pending,
                }
            }
        }
    }
}
