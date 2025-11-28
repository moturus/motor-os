//! Async one-shot channel. Created with input from Gemini 3.
extern crate alloc;

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};

const CHANNEL_EMPTY: u8 = 0;
const CHANNEL_FULL: u8 = 1;
const CHANNEL_CLOSED: u8 = 2;

struct Channel<T> {
    state: AtomicU8,
    data: UnsafeCell<MaybeUninit<T>>,
    waker: UnsafeCell<Option<Waker>>,
    // Spinlock to protect Waker registration/notification
    waker_lock: AtomicBool,
}

// Safety: We manage synchronization manually via `state` and `waker_lock`.
unsafe impl<T: Send> Sync for Channel<T> {}
unsafe impl<T: Send> Send for Channel<T> {}

pub struct Sender<T> {
    channel: Arc<Channel<T>>,
}

pub struct Receiver<T> {
    channel: Arc<Channel<T>>,
}

/// Creates a new one-shot channel.
pub fn oneshot<T>() -> (Sender<T>, Receiver<T>) {
    let channel = Arc::new(Channel {
        state: AtomicU8::new(CHANNEL_EMPTY),
        data: UnsafeCell::new(MaybeUninit::uninit()),
        waker: UnsafeCell::new(None),
        waker_lock: AtomicBool::new(false),
    });

    (
        Sender {
            channel: channel.clone(),
        },
        Receiver { channel },
    )
}

impl<T> Sender<T> {
    pub fn send(self, value: T) -> Result<(), T> {
        if self.channel.state.load(Ordering::Acquire) == CHANNEL_CLOSED {
            return Err(value);
        }

        // Safety: receiver reads only when the channel is FULL, and
        // the channel becomes full only here in send(), which consumes
        // self (i.e. it is truly one-shot).
        unsafe {
            (*self.channel.data.get()).write(value);
        }

        self.channel.state.store(CHANNEL_FULL, Ordering::Release);
        self.wake_receiver();
        Ok(())
    }

    fn wake_receiver(&self) {
        // Acquire the lock.
        while self
            .channel
            .waker_lock
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }

        // Take the waker so we don't wake it twice or leak it.
        let waker = unsafe { (*self.channel.waker.get()).take() };

        // Release the lock.
        self.channel.waker_lock.store(false, Ordering::Release);

        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        // If we haven't sent anything, mark CLOSED so Receiver wakes up and sees error.
        let result = self.channel.state.compare_exchange(
            CHANNEL_EMPTY,
            CHANNEL_CLOSED,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );

        // If the transition succeeded, we are responsible for waking the receiver.
        if result.is_ok() {
            self.wake_receiver();
        }
    }
}

impl<T> Future for Receiver<T> {
    type Output = Result<T, moto_rt::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.channel.state.load(Ordering::Acquire);

        if state == CHANNEL_FULL {
            // Safety: state is FULL, data is initialized and memory valid via Acquire.
            let val = unsafe { self.channel.data.get().read().assume_init() };
            return Poll::Ready(Ok(val));
        }

        if state == CHANNEL_CLOSED {
            return Poll::Ready(Err(moto_rt::Error::NotConnected));
        }

        // Register the waker.
        // -- Acquire the waker lock.
        while self
            .channel
            .waker_lock
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }

        // Safety: we acquired the log above.
        unsafe {
            *self.channel.waker.get() = Some(cx.waker().clone());
        }

        self.channel.waker_lock.store(false, Ordering::Release);

        // Re-check the state in case the sender raced here.
        state = self.channel.state.load(Ordering::Acquire);

        match state {
            CHANNEL_FULL => {
                // Safety: safe because state FULL acts as a sync edge.
                let val = unsafe { self.channel.data.get().read().assume_init() };
                Poll::Ready(Ok(val))
            }
            CHANNEL_CLOSED => Poll::Ready(Err(moto_rt::Error::NotConnected)),
            _ => Poll::Pending,
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        // Mark state CLOSED so Sender fails fast.
        let _ = self.channel.state.compare_exchange(
            CHANNEL_EMPTY,
            CHANNEL_CLOSED,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
}
