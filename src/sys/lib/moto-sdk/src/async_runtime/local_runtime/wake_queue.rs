//! Intrusive ready queues. Every linked node owns one Arc<MotoWaker> reference.

extern crate alloc;

use super::MotoWaker;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use crossbeam::utils::CachePadded;

pub(super) struct Link {
    next: AtomicPtr<Link>,
}

impl Link {
    pub(super) const fn new() -> Self {
        Self {
            next: AtomicPtr::new(ptr::null_mut()),
        }
    }
}

// MotoWaker is repr(C), with Link first. The stub is only a Link and must
// never be converted to a MotoWaker or an Arc.
fn into_link(waker: Arc<MotoWaker>) -> *mut Link {
    Arc::into_raw(waker).cast_mut().cast()
}

unsafe fn from_link(link: *mut Link) -> Arc<MotoWaker> {
    unsafe { Arc::from_raw(link.cast()) }
}

// Padding keeps the producers' head swaps off the lines holding the Arc
// counts (every upgrade and drop), the stub, and the consumer's tail.
pub(super) struct WakeQueue {
    head: CachePadded<AtomicPtr<Link>>,
    stub: CachePadded<Link>,
    tail: UnsafeCell<*mut Link>,
}

// Producers access only atomics. The executor is the sole consumer; its
// Arc keeps Drop from accessing tail until that consumer has finished.
unsafe impl Send for WakeQueue {}
unsafe impl Sync for WakeQueue {}

impl WakeQueue {
    pub(super) fn try_new() -> moto_rt::Result<Arc<Self>> {
        let queue = Arc::try_new(Self {
            head: CachePadded::new(AtomicPtr::new(ptr::null_mut())),
            stub: CachePadded::new(Link::new()),
            tail: UnsafeCell::new(ptr::null_mut()),
        })
        .map_err(|_| moto_rt::Error::OutOfMemory)?;
        // Initialize self-pointers at the final address, before publication.
        queue.head.store(queue.stub(), Ordering::Relaxed);
        unsafe { *queue.tail.get() = queue.stub() };
        Ok(queue)
    }

    fn stub(&self) -> *mut Link {
        ptr::from_ref(&*self.stub).cast_mut()
    }

    /// The caller must exclusively own the node's link. Holding this Arc
    /// through publication prevents destruction while a producer is linking.
    pub(super) unsafe fn push(self: &Arc<Self>, waker: Arc<MotoWaker>) {
        unsafe { self.push_link(into_link(waker)) };
    }

    unsafe fn push_link(&self, link: *mut Link) {
        unsafe {
            (*link).next.store(ptr::null_mut(), Ordering::Relaxed);
            let previous = self.head.swap(link, Ordering::AcqRel);
            (*previous).next.store(link, Ordering::Release);
        }
    }

    /// Only the executor may consume, and calls must not overlap. None also
    /// covers an unfinished producer publication: the producer must notify
    /// the executor after linking, so its normal park handshake can wait.
    pub(super) unsafe fn pop(&self) -> Option<Arc<MotoWaker>> {
        unsafe {
            let mut tail = *self.tail.get();
            let mut next = (*tail).next.load(Ordering::Acquire);
            if tail == self.stub() {
                if next.is_null() {
                    return None;
                }
                *self.tail.get() = next;
                tail = next;
                next = (*tail).next.load(Ordering::Acquire);
            }

            if next.is_null() {
                if self.head.load(Ordering::Acquire) != tail {
                    return None;
                }
                // A following node is needed before tail can be freed or
                // reused: a producer may still need to write tail.next.
                self.push_link(self.stub());
                next = (*tail).next.load(Ordering::Acquire);
                if next.is_null() {
                    return None;
                }
            }

            *self.tail.get() = next;
            Some(from_link(tail))
        }
    }
}

impl Drop for WakeQueue {
    fn drop(&mut self) {
        // Arc::try_new drops its input if allocation fails, before the
        // self-pointers can be initialized at their final address.
        if self.tail.get_mut().is_null() {
            return;
        }
        // Headers hold Weak references to us. With the last strong reference
        // gone, no producer or executor can still access this queue.
        while let Some(waker) = unsafe { self.pop() } {
            drop(waker);
        }
        let stub = self.stub();
        debug_assert_eq!(*self.tail.get_mut(), stub);
        debug_assert_eq!(*self.head.get_mut(), stub);
    }
}

pub(super) struct LocalQueue {
    head: *mut Link,
    tail: *mut Link,
}

impl Default for LocalQueue {
    fn default() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }
}

impl LocalQueue {
    pub(super) fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// The caller must exclusively own the node's link, either after
    /// claiming its queued state or after fully removing it from WakeQueue.
    pub(super) unsafe fn push(&mut self, waker: Arc<MotoWaker>) {
        let link = into_link(waker);
        unsafe {
            (*link).next.store(ptr::null_mut(), Ordering::Relaxed);
            if self.tail.is_null() {
                self.head = link;
            } else {
                (*self.tail).next.store(link, Ordering::Relaxed);
            }
        }
        self.tail = link;
    }

    pub(super) fn pop(&mut self) -> Option<Arc<MotoWaker>> {
        if self.head.is_null() {
            return None;
        }
        let head = self.head;
        // Only this queue's owner can access these links until dequeue
        // clears the node's queued state.
        unsafe {
            self.head = (*head).next.load(Ordering::Relaxed);
            if self.head.is_null() {
                self.tail = ptr::null_mut();
            }
            Some(from_link(head))
        }
    }
}

impl Drop for LocalQueue {
    fn drop(&mut self) {
        while let Some(waker) = self.pop() {
            drop(waker);
        }
    }
}
