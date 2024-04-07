use alloc::boxed::Box;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::*;
use core::task::{Context, Poll};
use moto_ipc::io_channel::*;
use moto_sys::syscalls::SysCpu;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;

#[cfg(debug_assertions)]
use crate::util::moturus_log;

use crate::util::ArrayQueue;
pub use moto_ipc::io_channel;

// From pin-utils, which can't be used in rust-dep-of-std.
#[macro_export]
macro_rules! pin_mut {
    ($($x:ident),* $(,)?) => { $(
        // Move the value to ensure that it is owned
        let mut $x = $x;
        // Shadow the original binding so that it can't be directly accessed
        // ever again.
        #[allow(unused_mut)]
        let mut $x = unsafe {
            core::pin::Pin::new_unchecked(&mut $x)
        };
    )* }
}

// We cast usize to u64 a lot here.
static _USIZE_8_BYTES: () = assert!(core::mem::size_of::<usize>() == 8);

pub struct IoPageWaiter {
    io_executor: &'static IoExecutor,
}

impl Future for IoPageWaiter {
    type Output = IoPage;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Ok(page) = self.io_executor.io_client().alloc_page() {
            core::task::Poll::Ready(page)
        } else {
            let wake_handle = cx.waker().as_raw().data() as usize as u64;
            self.io_executor.add_waiter(wake_handle);
            core::task::Poll::Pending
        }
    }
}

pub struct IoSender {
    msg: Msg,
    io_executor: &'static IoExecutor,
}

impl Future for IoSender {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.io_executor.io_client().send(self.msg) {
            Ok(_) => {
                let _ =
                    moto_sys::syscalls::SysCpu::wake(self.io_executor.io_client().server_handle());
                Poll::Ready(())
            }
            Err(err) => {
                debug_assert_eq!(err, ErrorCode::NotReady);
                let _ =
                    moto_sys::syscalls::SysCpu::wake(self.io_executor.io_client().server_handle());
                #[cfg(debug_assertions)]
                crate::util::moturus_log!("{}:{} IoSubmission::poll() pending", file!(), line!());

                let wake_handle = cx.waker().as_raw().data() as usize as u64;
                self.io_executor.add_waiter(wake_handle);
                Poll::Pending
            }
        }
    }
}

struct TrackingEntry {
    msg: Msg,
    done: AtomicBool,
}

pub struct IoSubmission {
    pmsg: *const UnsafeCell<TrackingEntry>, // From Arc::into_raw
    io_executor: &'static IoExecutor,
}

impl Drop for IoSubmission {
    fn drop(&mut self) {
        if !self.pmsg.is_null() {
            unsafe {
                // We either hold an additional reference, or none at all.
                Arc::decrement_strong_count(self.pmsg);
                let arc = Arc::from_raw(self.pmsg);
                debug_assert_eq!(1, Arc::strong_count(&arc));
                self.io_executor.cache_sqe(arc);
            }
        }
    }
}

impl IoSubmission {
    fn qe(&self) -> &mut TrackingEntry {
        debug_assert!(!self.pmsg.is_null());
        let p_sqe = self.pmsg as usize as *mut UnsafeCell<TrackingEntry>;
        unsafe { (*p_sqe).get_mut() }
    }

    fn new(
        io_executor: &'static IoExecutor,
        msg: Msg,
        cached: Option<Arc<UnsafeCell<TrackingEntry>>>,
    ) -> Self {
        let self_ = if let Some(cached) = cached {
            debug_assert_eq!(1, Arc::strong_count(&cached));
            let self_ = Self {
                pmsg: Arc::into_raw(cached),
                io_executor,
            };
            self_.qe().msg = msg;
            self_.qe().done.store(false, Ordering::Relaxed);
            self_
        } else {
            let sqe = Arc::new(UnsafeCell::new(TrackingEntry {
                msg,
                done: AtomicBool::new(false),
            }));
            Self {
                pmsg: Arc::into_raw(sqe),
                io_executor,
            }
        };

        // We need two refs: one is transferred to the server during submission,
        // one is transferred to IoCompletion.
        unsafe {
            Arc::increment_strong_count(self_.pmsg);
        }
        self_.qe().msg.id = self_.pmsg as usize as u64;
        self_
    }
}

impl Future for IoSubmission {
    type Output = IoCompletion;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoCompletion> {
        if self.pmsg.is_null() {
            #[cfg(debug_assertions)]
            crate::util::moturus_log!("{}:{} empty IoSubmission::poll()", file!(), line!());
            Poll::Ready(IoCompletion::new(self.pmsg, self.io_executor))
        } else {
            let wake_handle = cx.waker().as_raw().data() as usize as u64;
            self.qe().msg.wake_handle = wake_handle;
            match self.io_executor.io_client().send(self.qe().msg) {
                Ok(_) => {
                    // Note that IoCompletion will wake the server.
                    let out = IoCompletion::new(self.pmsg, self.io_executor);
                    self.pmsg = core::ptr::null();
                    Poll::Ready(out)
                }
                Err(err) => {
                    debug_assert_eq!(err, ErrorCode::NotReady);
                    #[cfg(debug_assertions)]
                    crate::util::moturus_log!(
                        "{}:{} IoSubmission::poll() pending",
                        file!(),
                        line!()
                    );
                    self.io_executor.add_waiter(wake_handle);
                    Poll::Pending
                }
            }
        }
    }
}

// NOTE: IoCompletions must be polled from the same thread as IoSubmissions,
//       as the server will wake the thread indicated by the wake_handle in sqe.
pub struct IoCompletion {
    cqe: *const UnsafeCell<TrackingEntry>, // From Arc::into_raw
    io_executor: &'static IoExecutor,
}

impl Drop for IoCompletion {
    fn drop(&mut self) {
        if self.cqe.is_null() {
            return;
        }
        unsafe {
            let arc = Arc::from_raw(self.cqe);
            self.io_executor.cache_sqe(arc);
        }
    }
}

impl IoCompletion {
    fn new(cqe: *const UnsafeCell<TrackingEntry>, io_executor: &'static IoExecutor) -> Self {
        Self { cqe, io_executor }
    }

    fn qe(&self) -> &mut TrackingEntry {
        debug_assert!(!self.cqe.is_null());
        let p_cqe = self.cqe as usize as *mut UnsafeCell<TrackingEntry>;
        unsafe { (*p_cqe).get_mut() }
    }

    fn done(&self) -> bool {
        self.qe().done.load(Ordering::Acquire)
    }
}

impl Future for IoCompletion {
    type Output = Msg;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Msg> {
        if self.cqe.is_null() {
            #[cfg(debug_assertions)]
            crate::util::moturus_log!("{}:{} empty IoSubmission::poll()", file!(), line!());
            return Poll::Ready(Msg::new());
        }

        let qe = self.qe();

        if self.done() {
            let res = qe.msg;

            let arc = unsafe { Arc::from_raw(self.cqe) };
            self.cqe = core::ptr::null();
            self.io_executor.cache_sqe(arc);

            Poll::Ready(res)
        } else {
            self.io_executor.poll_completions();
            if self.done() {
                let res = qe.msg;

                let arc = unsafe { Arc::from_raw(self.cqe) };
                self.cqe = core::ptr::null();
                self.io_executor.cache_sqe(arc);

                Poll::Ready(res)
            } else {
                let wake_handle = cx.waker().as_raw().data() as usize as u64;
                self.io_executor.add_waiter(wake_handle);
                // Note: the server (sys-io) will wake this thread.
                Poll::Pending
            }
        }
    }
}

// This IoExecutor is shared between threads and so is only &self.
struct IoExecutor {
    pmsg_cache: ArrayQueue<Arc<UnsafeCell<TrackingEntry>>>,
    io_client: Option<io_channel::ClientConnection>,
    waiters: crate::mutex::Mutex<(BTreeSet<u64>, VecDeque<u64>)>,
}

impl IoExecutor {
    fn new_zeroed() -> Self {
        Self {
            pmsg_cache: ArrayQueue::new(io_channel::QUEUE_SIZE as usize),
            io_client: None,
            waiters: crate::mutex::Mutex::new((BTreeSet::new(), VecDeque::new())),
        }
    }

    fn io_client(&self) -> &io_channel::ClientConnection {
        // Safe because we never expose Self without io_client: see inst() below.
        unsafe { self.io_client.as_ref().unwrap_unchecked() }
    }

    fn alloc_page(&'static self) -> IoPageWaiter {
        IoPageWaiter { io_executor: self }
    }

    pub fn get_page(&'static self, page_idx: u16) -> IoPage {
        self.io_client().get_page(page_idx)
    }

    fn io_submission(&'static self, sqe: Msg) -> IoSubmission {
        IoSubmission::new(self, sqe, self.pmsg_cache.pop())
    }

    fn cache_sqe(&self, sqe: Arc<UnsafeCell<TrackingEntry>>) {
        if Arc::strong_count(&sqe) == 1 {
            let _ = self.pmsg_cache.push(sqe);
        }
    }

    fn add_waiter(&self, wait_handle: u64) {
        if wait_handle == SysHandle::NONE.as_u64() {
            return;
        }
        let (set, queue) = &mut *self.waiters.lock();
        if set.insert(wait_handle) {
            queue.push_back(wait_handle);
        }
    }

    fn inst() -> &'static IoExecutor {
        static INST: AtomicPtr<IoExecutor> = AtomicPtr::new(core::ptr::null_mut());

        let inst = INST.load(Ordering::Relaxed);
        if inst.is_null() {
            let new: *mut Self = Box::into_raw(Box::new(Self::new_zeroed()));
            match INST.compare_exchange(inst, new, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => unsafe {
                    let io_client = match io_channel::ClientConnection::connect("sys-io") {
                        Ok(client) => client,
                        Err(err) => {
                            panic!("Failed to connect to sys-io: {:?}", err);
                        }
                    };
                    (*new).io_client = Some(io_client);

                    moto_sys::syscalls::SysCpu::spawn(
                        SysHandle::SELF,
                        4096 * 4,
                        Self::io_thread as u64,
                        0,
                    )
                    .unwrap();

                    new.as_ref().unwrap_unchecked()
                },
                Err(inst) => unsafe {
                    let to_drop = Box::from_raw(new);
                    core::mem::drop(to_drop);
                    inst.as_ref().unwrap_unchecked()
                },
            }
        } else {
            unsafe { inst.as_ref().unwrap_unchecked() }
        }
    }

    fn kick_waiters(&self) {
        // let _ = moto_sys::syscalls::SysCpu::wake(self.io_client().server_handle());

        // We want to loop one-by-one rather than take all waiters at once, as waking them
        // is a syscall, so it is better to keep existing waiters in the queue.
        loop {
            // Use a separate statement to pop a waiter, as otherwise the lock will
            // unlock much later.
            let waiter = {
                let (set, queue) = &mut *self.waiters.lock();
                if let Some(waiter) = queue.pop_front() {
                    set.remove(&waiter);
                    waiter
                } else {
                    return;
                }
            };
            let _ = moto_sys::syscalls::SysCpu::wake(waiter.into());
        }
    }

    fn poll_completions(&self) {
        loop {
            match self.io_client().recv() {
                Ok(cqe) => unsafe {
                    let pmsg = cqe.id as usize as *mut UnsafeCell<TrackingEntry>;
                    (*pmsg).get_mut().msg = cqe;
                    (*pmsg).get_mut().done.store(true, Ordering::Release);

                    let _ = moto_sys::syscalls::SysCpu::wake(cqe.wake_handle.into());
                    let _ = Arc::from_raw(pmsg); // To decrement ref count.

                    if cqe.wake_handle != SysHandle::NONE.into() {
                        if cqe.wake_handle != this_thread_handle() {
                            // TODO: be more efficient here.
                            let _ = moto_sys::syscalls::SysCpu::wake(cqe.wake_handle.into());
                        }
                    }
                },
                Err(err) => {
                    debug_assert_eq!(err, ErrorCode::NotReady);
                    break;
                }
            }
        }

        // TODO: can we wake the server not every time?
        let _ = moto_sys::syscalls::SysCpu::wake(self.io_client().server_handle());
    }

    fn io_thread(_: u64) -> ! {
        let self_ = Self::inst();
        let server_handle = self_.io_client().server_handle();

        loop {
            let _ = SysCpu::wait(
                &mut [server_handle],
                SysHandle::NONE,
                SysHandle::NONE,
                Some(moto_sys::time::Instant::now() + core::time::Duration::from_secs(10)),
            );
            self_.kick_waiters();
        }
    }
}

fn this_thread_handle() -> u64 {
    moto_sys::UserThreadControlBlock::get().self_handle
}

struct ThreadWaker;

impl ThreadWaker {
    fn new_waker() -> core::task::Waker {
        let handle = this_thread_handle();
        let raw_waker = core::task::RawWaker::new(handle as usize as *const (), &RAW_WAKER_VTABLE);
        unsafe { core::task::Waker::from_raw(raw_waker) }
    }
}

unsafe fn raw_waker_clone(ptr: *const ()) -> core::task::RawWaker {
    core::task::RawWaker::new(ptr, &RAW_WAKER_VTABLE)
}
unsafe fn raw_waker_wake(ptr: *const ()) {
    SysCpu::wake(moto_sys::SysHandle::from_u64(ptr as usize as u64))
        .expect("io_thread: wake raw waker")
}
unsafe fn raw_waker_wake_by_ref(ptr: *const ()) {
    SysCpu::wake(moto_sys::SysHandle::from_u64(ptr as usize as u64))
        .expect("io_thread: wake raw waker")
}
unsafe fn raw_waker_drop(_ptr: *const ()) {}

static RAW_WAKER_VTABLE: core::task::RawWakerVTable = core::task::RawWakerVTable::new(
    raw_waker_clone,
    raw_waker_wake,
    raw_waker_wake_by_ref,
    raw_waker_drop,
);

pub fn alloc_page() -> IoPageWaiter {
    IoExecutor::inst().alloc_page()
}

pub fn shared_page(idx: u16) -> IoPage {
    IoExecutor::inst().get_page(idx)
}

pub fn submit(sqe: Msg) -> IoSubmission {
    IoExecutor::inst().io_submission(sqe)
}

// We use IoSender (a future) instead of trying to send inline and queing into a local
// queue and completing so that the order of sent messages is preserved (important
// for things like TcpStream writes).
pub fn send(msg: Msg) -> IoSender {
    IoSender {
        msg,
        io_executor: &IoExecutor::inst(),
    }
}

/*
block_on() below is more or less a standard one-shot executor, like this:

        fn block_on<F: Future>(mut future: F) -> F::Output {
            fn create_raw_waker(thread: Thread) -> RawWaker {
                RawWaker::new(
                    Box::into_raw(Box::new(thread)) as *const _,
                    &RawWakerVTable::new(
                        |ptr| unsafe {
                            create_raw_waker((&*(ptr as *const Thread)).clone())
                        },
                        |ptr| unsafe {
                            Box::from_raw(ptr as *mut Thread).unpark();
                        },
                        |ptr| unsafe {
                            (&*(ptr as *const Thread)).unpark();
                        },
                        |ptr| unsafe {
                            Box::from_raw(ptr as *mut Thread);
                        },
                    ),
                )
            }

            let waker = unsafe {
                Waker::from_raw(create_raw_waker(thread::current()))
            };
            let mut context = Context::from_waker(&waker);
            let mut future = unsafe {
                Pin::new_unchecked(&mut future)
            };

            loop {
                match future.as_mut().poll(&mut context) {
                    Poll::Ready(output) => return output,
                    Poll::Pending => thread::park(),
                }
            }
        }

It just uses custom wait/wake logic because rust-dep-of-std does not have access to e.g. Thread::park().
*/
pub fn block_on<F: Future>(f: F) -> F::Output {
    let waker = ThreadWaker::new_waker();
    let mut context = core::task::Context::from_waker(&waker);
    pin_mut!(f);

    let mut busy_polling_iter = 0_u32;
    loop {
        match f.as_mut().poll(&mut context) {
            core::task::Poll::Ready(result) => break result,
            core::task::Poll::Pending => {
                busy_polling_iter += 1;
                if busy_polling_iter < 16 {
                    continue;
                }

                busy_polling_iter = 0;
                // #[cfg(debug_assertions)]
                // crate::util::moturus_log!("Executor::block_on(): going to sleep");

                let result = SysCpu::wait(
                    &mut [],
                    SysHandle::NONE,
                    SysHandle::NONE,
                    Some(moto_sys::time::Instant::now() + core::time::Duration::from_secs(4)),
                );
                if let Err(err) = result {
                    assert_eq!(err, ErrorCode::TimedOut);
                    #[cfg(debug_assertions)]
                    moturus_log!("\n\nio_executor: block_on timed out\n");
                }
            }
        }
    }
}
