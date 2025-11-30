//! MPSC async channel.
extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use moto_rt::spinlock::SpinLock;

#[repr(C)]
struct SharedChannelData {
    sender_count: AtomicUsize,
    _padding_1: [u64; 7],

    senders_waiting_count: AtomicUsize,
    _padding_2: [u64; 7],
    senders_waiting: SpinLock<VecDeque<Waker>>,
    _padding_3: [u64; 7],

    receiver_waiting: AtomicBool,
    _padding_4: [u64; 7],
    receiver: SpinLock<Option<Waker>>,
}

impl SharedChannelData {
    fn pop_next_send_waiter(&self) -> Option<Waker> {
        if self.senders_waiting_count.load(Ordering::Acquire) > 0 {
            let mut guard = self.senders_waiting.lock();
            if let Some(waker) = guard.pop_front() {
                self.senders_waiting_count.fetch_sub(1, Ordering::Relaxed);
                return Some(waker);
            }
        }

        None
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

    let shared = Arc::new(SharedChannelData {
        sender_count: AtomicUsize::new(1),
        senders_waiting_count: AtomicUsize::new(0),
        senders_waiting: SpinLock::new(VecDeque::new()),
        receiver_waiting: AtomicBool::new(false),
        receiver: SpinLock::new(None),
        _padding_1: [0; 7],
        _padding_2: [0; 7],
        _padding_3: [0; 7],
        _padding_4: [0; 7],
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
                if self.shared.receiver_waiting.swap(false, Ordering::Acquire)
                    && let Some(waker) = self.shared.receiver.lock().take()
                {
                    waker.wake();
                }
                SendFuture(SendFutureInner::Ready(None))
            }
            Err(moto_mpmc::TrySendError::Full(val)) => {
                SendFuture(SendFutureInner::Pending(SendPending {
                    inner: self.inner.clone(),
                    shared: self.shared.clone(),
                    value: Some(val),
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
            if let Some(waker) = self.shared.receiver.lock().take() {
                waker.wake();
            }
        }
    }
}

struct SendPending<T> {
    inner: Arc<moto_mpmc::Sender<T>>,
    shared: Arc<SharedChannelData>,
    value: Option<T>,
}

enum SendFutureInner<T> {
    Ready(Option<T>),
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
                const BUSY_LOOP_ITERS: u32 = 32;
                let mut busy_loop_iter = 0;

                loop {
                    let value = unsafe { this.value.take().unwrap_unchecked() };
                    match this.inner.try_send(value) {
                        Ok(()) => {
                            // Wake receiver if it was waiting.
                            if this.shared.receiver_waiting.swap(false, Ordering::AcqRel)
                                && let Some(waker) = this.shared.receiver.lock().take()
                            {
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

                let waker = cx.waker().clone();
                this.shared
                    .senders_waiting_count
                    .fetch_add(1, Ordering::Relaxed);
                let mut guard = this.shared.senders_waiting.lock();

                let value = unsafe { this.value.take().unwrap_unchecked() };
                match this.inner.try_send(value) {
                    Ok(()) => {
                        this.shared
                            .senders_waiting_count
                            .fetch_sub(1, Ordering::Relaxed);
                        core::mem::drop(guard);
                        // Wake receiver if it was waiting.
                        if this.shared.receiver_waiting.swap(false, Ordering::AcqRel)
                            && let Some(waker) = this.shared.receiver.lock().take()
                        {
                            waker.wake();
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Err(moto_mpmc::TrySendError::Full(val)) => {
                        this.value = Some(val);
                    }
                    Err(moto_mpmc::TrySendError::Disconnected(val)) => {
                        return Poll::Ready(Err(val));
                    }
                }
                guard.push_back(waker);
                Poll::Pending
            }
        }
    }
}

impl<T> Receiver<T> {
    pub fn recv(&mut self) -> RecvFuture<T> {
        match self.inner.try_recv() {
            Ok(val) => {
                if let Some(waker) = self.shared.pop_next_send_waiter() {
                    waker.wake();
                }
                RecvFuture(RecvFutureInner::Ready(Some(val)))
            }
            Err(moto_mpmc::TryRecvError::Empty) => {
                RecvFuture(RecvFutureInner::Pending(RecvPending {
                    inner: self.inner.clone(),
                    shared: self.shared.clone(),
                }))
            }
            Err(moto_mpmc::TryRecvError::Disconnected) => RecvFuture(RecvFutureInner::Ready(None)),
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        while let Some(waker) = self.shared.pop_next_send_waiter() {
            waker.wake();
        }
    }
}

struct RecvPending<T> {
    inner: Arc<moto_mpmc::Receiver<T>>,
    shared: Arc<SharedChannelData>,
}

enum RecvFutureInner<T> {
    Ready(Option<T>),
    Pending(RecvPending<T>),
}

pub struct RecvFuture<T>(RecvFutureInner<T>);

impl<T> Future for RecvFuture<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Safety: We need mutable access to `self.value`.
        // We are not moving `self` (the Future), nor are we creating a Pin to `value`.
        // We are just treating `value` as ordinary data.
        let this = unsafe { self.get_unchecked_mut() };
        match &mut this.0 {
            RecvFutureInner::Ready(val) => Poll::Ready(val.take()),
            RecvFutureInner::Pending(slow) => {
                const BUSY_LOOP_ITERS: u32 = 32;
                let mut busy_loop_iter = 0;

                *slow.shared.receiver.lock() = Some(cx.waker().clone());
                slow.shared.receiver_waiting.store(true, Ordering::Release);

                loop {
                    match slow.inner.try_recv() {
                        Ok(val) => {
                            *slow.shared.receiver.lock() = None;
                            slow.shared.receiver_waiting.store(false, Ordering::Release);

                            if let Some(waker) = slow.shared.pop_next_send_waiter() {
                                waker.wake();
                            }
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

                Poll::Pending
            }
        }
    }
}
