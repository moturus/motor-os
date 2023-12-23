use std::task::{RawWaker, RawWakerVTable};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

use smoltcp::iface::SocketHandle;

// TCP sockets in smoltcp wake wakers to indicate status changes.
#[derive(Clone)]
pub struct SocketWaker {
    socket_handle: SocketHandle,
    wakers: Rc<RefCell<VecDeque<SocketHandle>>>,
}

impl SocketWaker {
    pub fn new(socket_handle: SocketHandle, wakers: Rc<RefCell<VecDeque<SocketHandle>>>) -> Self {
        Self {
            socket_handle,
            wakers,
        }
    }

    pub fn into_raw_waker(self) -> RawWaker {
        let waker = Box::new(self);
        let ptr = Box::into_raw(waker) as *const ();

        RawWaker::new(ptr, &SOCKET_WAKER_VTABLE)
    }

    fn wake(&self) {
        self.wakers.borrow_mut().push_back(self.socket_handle)
    }
}

static SOCKET_WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(clone_waker, wake_waker, wake_by_ref_waker, drop_waker);

unsafe fn clone_waker(ptr: *const ()) -> RawWaker {
    let waker = &*(ptr as *const SocketWaker);
    waker.clone().into_raw_waker()
}

unsafe fn wake_waker(ptr: *const ()) {
    let waker = &*(ptr as *const SocketWaker);
    waker.wake();
    drop(Box::from_raw(ptr as *mut SocketWaker));
}

unsafe fn wake_by_ref_waker(ptr: *const ()) {
    let waker = &*(ptr as *const SocketWaker);
    waker.wake();
}

unsafe fn drop_waker(ptr: *const ()) {
    drop(Box::from_raw(ptr as *mut SocketWaker));
}
