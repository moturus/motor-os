use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::*;
use core::task::{Context, Poll};
use moto_ipc::io_channel::*;
use moto_sys::syscalls::SysCpu;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;

use crate::rt_api;

#[allow(unused)]
use crate::util::moturus_log;

use crate::util::ArrayQueue;
use crate::util::CachePadded;
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

const CMD_GET_IO_PAGE: u16 = CMD_RESERVED_MIN_LOCAL;
const CMD_WRITE_IO_PAGE: u16 = CMD_GET_IO_PAGE + 1;
const CMD_CONSUME_IO_PAGE: u16 = CMD_WRITE_IO_PAGE + 1;
pub const CMD_LOCAL_NOOP_OK: u16 = CMD_CONSUME_IO_PAGE + 1;

// We use our own "pointer" because AtomicPtr<> is not Copy, and because
// we want to implement Future.
#[derive(Clone, Copy)]
struct QueueEntryPointer {
    pqe: usize, // *mut QueueEntry; not atomic because the pointer never changes.
}

// We cast usize to u64 a lot here.
static _USIZE_8_BYTES: () = assert!(core::mem::size_of::<usize>() == 8);

impl QueueEntryPointer {
    fn qe<'a>(&'a self) -> &'a mut QueueEntry {
        debug_assert!(self.pqe != 0);
        unsafe { (self.pqe as *mut QueueEntry).as_mut().unwrap_unchecked() }
    }

    fn new() -> Self {
        let pqe = Box::into_raw(Box::new(QueueEntry::new())) as usize;
        Self { pqe }
    }

    fn free(self) {
        unsafe {
            let _: Box<QueueEntry> = Box::from_raw(self.pqe as *mut QueueEntry);
        }
    }

    fn set_id(&mut self) {
        self.qe().id = self.pqe as u64;
    }

    fn from_id(id: u64) -> Self {
        Self { pqe: id as usize }
    }
}

impl Future for QueueEntryPointer {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.qe().wake_handle = cx.waker().as_raw().data() as usize as u64;
        compiler_fence(Ordering::Release);
        fence(Ordering::Release);

        self.qe().poll()
    }
}

struct QueueSubmitter {
    entry: QueueEntryPointer,
}

impl Future for QueueSubmitter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let executor = IoExecutor::inst();
        match executor.queue.push(self.entry) {
            Ok(()) => {
                self.entry.qe().wake_handle = cx.waker().as_raw().data() as usize as u64;
                compiler_fence(Ordering::Release);
                fence(Ordering::Release);

                SysCpu::wake(executor.io_thread_handle()).expect("io_thread");
                core::task::Poll::Ready(())
            }
            Err(_) => {
                SysCpu::wake(executor.io_thread_handle()).expect("io_thread");
                core::task::Poll::Pending
            }
        }
    }
}

// The queue size here is double that of io_channel, to ensure that
// we can fill the io_channel (some queue entries here don't translate)
// into queue entries there.
const QUEUE_SIZE: usize = 128;

// This IoExecutor is shared between threads and so is only &self.
struct IoExecutor {
    queue: ArrayQueue<QueueEntryPointer>,
    free_list: ArrayQueue<QueueEntryPointer>,
    io_thread_handle: AtomicU64,
    has_work: CachePadded<AtomicBool>,
    sleeping: CachePadded<AtomicBool>,
}

// This IoExecutorThread is used only within the io_thread, and so is &mut.
struct IoExecutorThread {
    executor: &'static IoExecutor,
    io_client: io_channel::Client,
    wake_server: bool,
    _cached_wakee: u64,

    // We always drain the executor's queue and put stuff in here, to help move
    // remote submissions, which eventually free IO buffers.
    io_buffer_queue: VecDeque<QueueEntryPointer>,
    io_buffers_available: bool,

    submission_queue: VecDeque<QueueEntryPointer>,
}

impl IoExecutorThread {
    fn io_thread_start(_: usize) -> ! {
        let executor = IoExecutor::inst();

        executor.io_thread_handle.store(
            moto_sys::UserThreadControlBlock::get().self_handle,
            Ordering::Release,
        );

        let io_client = match io_channel::Client::connect("sys-io") {
            Ok(client) => client,
            Err(err) => {
                panic!("Failed to connect to sys-io: {:?}", err);
            }
        };

        let mut self_mut = IoExecutorThread {
            executor,
            io_client,
            wake_server: false,
            _cached_wakee: SysHandle::NONE.as_u64(),
            io_buffer_queue: VecDeque::new(),
            submission_queue: VecDeque::new(),
            io_buffers_available: true,
        };

        self_mut.io_thread();
    }

    fn cache_wakee(&mut self, wakee: u64) {
        let handle = SysHandle::from_u64(wakee);
        if core::intrinsics::likely(!handle.is_none()) {
            let _ = SysCpu::wake(handle);
        }
        /*
        if self.cached_wakee != wakee {
            let handle = SysHandle::from_u64(wakee);
            if core::intrinsics::likely(!handle.is_none()) {
                let _ = SysCpu::wake(handle);
            }

            self.cached_wakee = wakee;
        }
        */
    }

    // If pqe has been processed, returns None; otherwise returns it back.
    fn process_pqe(
        &mut self,
        pqe: QueueEntryPointer,
        debug_log: bool,
    ) -> Option<QueueEntryPointer> {
        let qe = pqe.qe();
        debug_assert_eq!(qe.status, ErrorCode::NotReady.into());

        match qe.command {
            CMD_GET_IO_PAGE => {
                if debug_log {
                    moturus_log!("io_thread: CMD_GET_IO_BUFFER");
                }
                match self.io_client.alloc_page() {
                    Ok(idx) => {
                        qe.payload.client_buffers_mut()[0] = idx;
                        compiler_fence(Ordering::Release);
                        fence(Ordering::Release);
                        qe.status = ErrorCode::Ok.into();
                        compiler_fence(Ordering::Release);
                        fence(Ordering::Release);
                        if debug_log {
                            moturus_log!("io_thread: will wake waiter");
                        }
                        self.cache_wakee(qe.wake_handle);
                        None
                    }
                    Err(err) => {
                        assert_eq!(err, ErrorCode::NotReady);
                        if debug_log {
                            moturus_log!("io_thread: NotReady");
                        }
                        Some(pqe)
                    }
                }
            }
            CMD_WRITE_IO_PAGE => {
                if debug_log {
                    moturus_log!("io_thread: CMD_WRITE_IO_BUFFER");
                }
                let buf_ptr = qe.payload.args_64()[0] as usize as *const u8;
                let buf_len = qe.payload.args_64()[1] as usize;
                if buf_len == 0 {
                    pqe.qe().status = ErrorCode::InvalidArgument.into();
                    return Some(pqe);
                }

                match self.io_client.alloc_page() {
                    Ok(page_idx) => {
                        let slice = self.io_client.buffer_bytes(page_idx).unwrap();
                        let to_write: usize = buf_len.min(io_channel::PAGE_SIZE);
                        unsafe {
                            core::ptr::copy_nonoverlapping(buf_ptr, slice.as_mut_ptr(), to_write);
                        }
                        qe.payload.client_buffers_mut()[0] = page_idx;
                        qe.payload.args_64_mut()[1] = to_write as u64;
                        compiler_fence(Ordering::Release);
                        fence(Ordering::Release);
                        qe.status = ErrorCode::Ok.into();
                        compiler_fence(Ordering::Release);
                        fence(Ordering::Release);
                        self.cache_wakee(qe.wake_handle);
                        None
                    }
                    Err(err) => {
                        assert_eq!(err, ErrorCode::NotReady);
                        if debug_log {
                            moturus_log!("io_thread: NotReady");
                        }
                        Some(pqe)
                    }
                }
            }
            moto_ipc::io_channel::CMD_NOOP_OK => match self.io_client.submit_sqe(*qe) {
                Ok(()) => {
                    self.wake_server = true;
                    None
                }
                Err(err) => {
                    assert_eq!(err, ErrorCode::NotReady);
                    Some(pqe)
                }
            },
            rt_api::net::CMD_MIN..=rt_api::net::CMD_MAX => {
                if debug_log {
                    moturus_log!("io_thread: got cmd {} (net) id: 0x{:x}", qe.command, qe.id);
                }
                match self.io_client.submit_sqe(*qe) {
                    Ok(()) => {
                        self.wake_server = true;
                        None
                    }
                    Err(err) => {
                        #[cfg(debug_assertions)]
                        moturus_log!("io_thread: submt_sqe: not ready");
                        assert_eq!(err, ErrorCode::NotReady);
                        if debug_log {
                            moturus_log!("io_thread: NotReady");
                        }
                        Some(pqe)
                    }
                }
            }
            _ => {
                if debug_log {
                    moturus_log!("io_thread: unknown command {}", qe.command);
                }
                qe.status = ErrorCode::InvalidArgument.into();
                compiler_fence(Ordering::Release);
                fence(Ordering::Release);
                self.cache_wakee(qe.wake_handle);
                None
            }
        }
    }

    fn consume_io_page(&mut self, pqe: QueueEntryPointer) {
        let qe = pqe.qe();
        let io_page_idx = qe.payload.client_buffers()[0];
        let buf_len = qe.payload.args_64()[2] as usize;

        if buf_len != 0 {
            let buf_ptr = qe.payload.args_64()[1] as usize as *mut u8;
            let slice = self.io_client.buffer_bytes(io_page_idx).unwrap();
            assert!(buf_len <= slice.len());
            unsafe {
                core::ptr::copy_nonoverlapping(slice.as_ptr(), buf_ptr, buf_len);
            }
        }
        self.io_client.free_client_page(io_page_idx).unwrap();
        self.io_buffers_available = true;
        qe.status = ErrorCode::Ok.into();
        compiler_fence(Ordering::Release);
        fence(Ordering::Release);
        self.cache_wakee(qe.wake_handle);
    }

    fn process_completions(&mut self) -> bool {
        let mut did_work = false;

        loop {
            match self.io_client.get_cqe() {
                Ok(cqe) => {
                    did_work = true;
                    #[cfg(debug_assertions)]
                    moturus_log!(
                        "got cqe! id: 0x{:x} status: {} {:?}",
                        cqe.id,
                        cqe.status,
                        cqe.status()
                    );
                    assert_ne!(cqe.status(), ErrorCode::NotReady);
                    let pqe = QueueEntryPointer::from_id(cqe.id);
                    *pqe.qe() = cqe;
                    compiler_fence(Ordering::Release);
                    fence(Ordering::Release);
                    self.cache_wakee(cqe.wake_handle);
                }
                Err(err) => {
                    assert_eq!(err, ErrorCode::NotReady);
                    break;
                }
            }
        }

        did_work
    }

    fn process_buffer_requests(&mut self) -> bool {
        let mut did_work = false;

        if self.io_buffers_available {
            while let Some(pqe) = self.io_buffer_queue.pop_front() {
                if let Some(pqe) = self.process_pqe(pqe, false) {
                    self.io_buffer_queue.push_front(pqe);
                    self.io_buffers_available = false;
                    break;
                }
                did_work = true;
            }
        }

        did_work
    }

    fn process_pending_submissions(&mut self) -> bool {
        let mut did_work = false;

        while let Some(pqe) = self.submission_queue.pop_front() {
            if let Some(pqe) = self.process_pqe(pqe, false) {
                self.submission_queue.push_front(pqe);
                break;
            }
            did_work = true;
        }

        did_work
    }

    fn process_incoming_queue(&mut self) -> bool {
        let mut did_work = false;
        while let Some(pqe) = self.executor.queue.pop() {
            did_work = true;
            let qe = pqe.qe();
            debug_assert_eq!(qe.status, ErrorCode::NotReady.into());

            match qe.command {
                CMD_GET_IO_PAGE | CMD_WRITE_IO_PAGE => {
                    if self.io_buffer_queue.is_empty() && self.io_buffers_available {
                        if let Some(pqe) = self.process_pqe(pqe, false) {
                            self.io_buffer_queue.push_back(pqe);
                            self.io_buffers_available = false;
                        }
                    } else {
                        self.io_buffer_queue.push_back(pqe);
                    }
                }
                CMD_CONSUME_IO_PAGE => self.consume_io_page(pqe),
                moto_ipc::io_channel::CMD_NOOP_OK => {
                    if self.submission_queue.is_empty() {
                        if let Some(pqe) = self.process_pqe(pqe, false) {
                            self.submission_queue.push_back(pqe);
                        }
                    } else {
                        self.submission_queue.push_back(pqe);
                    }
                }
                rt_api::net::CMD_MIN..=rt_api::net::CMD_MAX => {
                    if self.submission_queue.is_empty() {
                        if let Some(pqe) = self.process_pqe(pqe, false) {
                            self.submission_queue.push_back(pqe);
                        }
                    } else {
                        self.submission_queue.push_back(pqe);
                    }
                }
                CMD_LOCAL_NOOP_OK => {
                    if qe.flags == FLAG_CMD_NOOP_OK_TIMESTAMP {
                        qe.payload.args_64_mut()[2] = moto_sys::time::Instant::now().as_u64();
                        fence(Ordering::Release);
                    }
                    qe.status = ErrorCode::Ok.into();
                    compiler_fence(Ordering::Release);
                    fence(Ordering::Release);
                    self.cache_wakee(qe.wake_handle);
                }
                _ => {
                    qe.status = ErrorCode::InvalidArgument.into();
                    compiler_fence(Ordering::Release);
                    fence(Ordering::Release);
                    self.cache_wakee(qe.wake_handle);
                }
            }
        }

        did_work
    }

    fn io_thread(&mut self) -> ! {
        moto_sys::syscalls::SysCpu::affine_to_cpu(Some(1)).unwrap();
        let mut debug_timed_out = false;
        let mut busy_polling_iter = 0_u32;
        loop {
            let mut did_work: bool = self.process_completions();
            if did_work && debug_timed_out {
                moturus_log!("io_thread: lost wakeup #1");
                debug_timed_out = false;
            }
            if did_work {
                self.cache_wakee(SysHandle::NONE.as_u64());
            }

            did_work |= self.process_buffer_requests();
            if did_work && debug_timed_out {
                moturus_log!("io_thread: lost wakeup #2");
                debug_timed_out = false;
            }
            if did_work {
                self.cache_wakee(SysHandle::NONE.as_u64());
            }

            did_work |= self.process_pending_submissions();
            if did_work && debug_timed_out {
                moturus_log!("io_thread: lost wakeup #3");
                debug_timed_out = false;
            }
            if did_work {
                self.cache_wakee(SysHandle::NONE.as_u64());
            }

            did_work |= self.process_incoming_queue();
            if did_work && debug_timed_out {
                moturus_log!("io_thread: lost wakeup #4");
                debug_timed_out = false;
            }
            if did_work {
                self.cache_wakee(SysHandle::NONE.as_u64());
                busy_polling_iter = 0;
                continue;
            }

            busy_polling_iter += 1;
            if busy_polling_iter < 16 {
                continue;
            }

            // Nothing to do: go to sleep.
            // moturus_log!("io_thread: sleeping");
            // TODO: do we need Ordering::SeqCst below?
            self.executor.sleeping.store(true, Ordering::SeqCst);
            if self.executor.has_work.swap(false, Ordering::SeqCst) {
                self.executor.sleeping.store(false, Ordering::Release);
                // moturus_log!("io_thread: woke");
                continue;
            }

            let wake_target = if self.wake_server {
                self.wake_server = false;
                self.io_client.server_handle()
            } else {
                SysHandle::NONE
            };
            debug_timed_out = false;
            let result = SysCpu::wait(
                &mut [self.io_client.server_handle()],
                SysHandle::NONE,
                wake_target,
                Some(moto_sys::time::Instant::now() + core::time::Duration::from_secs(1)),
            );
            if result.is_err() {
                assert_eq!(result, Err(ErrorCode::TimedOut));
                debug_timed_out = true;
            }

            self.executor.sleeping.store(false, Ordering::Release);
            // moturus_log!("io_thread: woke");
        }
    }
}

impl IoExecutor {
    fn new_zeroed() -> Self {
        Self {
            queue: ArrayQueue::new(QUEUE_SIZE),
            free_list: ArrayQueue::new(QUEUE_SIZE * 4),
            io_thread_handle: AtomicU64::new(0),
            has_work: CachePadded::new(AtomicBool::new(false)),
            sleeping: CachePadded::new(AtomicBool::new(false)),
        }
    }

    fn get_free_pqe(&self) -> QueueEntryPointer {
        match self.free_list.pop() {
            Some(ptr) => ptr,
            None => QueueEntryPointer::new(),
        }
    }

    fn free_pqe(&self, pqe: QueueEntryPointer) {
        match self.free_list.push(pqe) {
            Ok(()) => {}
            Err(pqe) => pqe.free(),
        }
    }

    fn init_qe(&self, qe: &mut QueueEntry) {
        qe.clear();
        // qe.wake_handle = self.io_thread_handle().as_u64();
        qe.wake_handle = moto_sys::UserThreadControlBlock::get().self_handle;
    }

    async fn add_to_queue(&'static self, mut pqe: QueueEntryPointer) {
        pqe.set_id();
        QueueSubmitter { entry: pqe }.await
    }

    fn inst() -> &'static IoExecutor {
        static INST: AtomicPtr<IoExecutor> = AtomicPtr::new(core::ptr::null_mut());

        let inst = INST.load(Ordering::Relaxed);
        if inst.is_null() {
            let new: *mut Self = Box::into_raw(Box::new(Self::new_zeroed()));
            match INST.compare_exchange(inst, new, Ordering::Release, Ordering::Relaxed) {
                Ok(_) => unsafe {
                    moto_sys::syscalls::SysCpu::spawn(
                        SysHandle::SELF,
                        4096 * 4,
                        IoExecutorThread::io_thread_start as u64,
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

    #[cold]
    fn wait_for_handle(&self) {
        loop {
            let handle = self.io_thread_handle.load(Ordering::Relaxed);
            if handle != 0 {
                return;
            }
            core::hint::spin_loop();
        }
    }

    #[inline]
    fn io_thread_handle(&self) -> SysHandle {
        loop {
            let handle = self.io_thread_handle.load(Ordering::Relaxed);
            if handle != 0 {
                return SysHandle::from_u64(handle);
            } else {
                self.wait_for_handle();
            }
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

fn prepare_to_submit(mut sqe: QueueEntry) -> Result<QueueEntry, QueueEntry> {
    if sqe.status() != ErrorCode::NotReady || sqe.command == 0 {
        #[cfg(debug_assertions)]
        moturus_log!("prepare_to_submit: invalid argument");
        sqe.wake_handle = this_thread_handle();
        sqe.status = ErrorCode::InvalidArgument.into();
        return Err(sqe);
    }

    Ok(sqe)
}

pub async fn get_io_page() -> u16 {
    let ex = IoExecutor::inst();
    let pqe = ex.get_free_pqe();

    let qe: &mut QueueEntry = pqe.qe();
    ex.init_qe(qe);
    qe.command = CMD_GET_IO_PAGE;
    ex.add_to_queue(pqe).await;
    pqe.await;

    debug_assert!(qe.status().is_ok());
    let buf = qe.payload.client_buffers()[0];
    ex.free_pqe(pqe);
    buf
}

// Gets an IoBuffer and writes buf into it. Returns the IoBuffer and the number of
// bytes written.
pub async fn produce_io_page(buf: &[u8]) -> (u16, usize) {
    let ex = IoExecutor::inst();
    let pqe = ex.get_free_pqe();

    let qe: &mut QueueEntry = pqe.qe();
    ex.init_qe(qe);
    qe.command = CMD_WRITE_IO_PAGE;
    qe.payload.args_64_mut()[0] = buf.as_ptr() as usize as u64;
    qe.payload.args_64_mut()[1] = buf.len() as u64;
    ex.add_to_queue(pqe).await;
    pqe.await;

    debug_assert!(qe.status().is_ok());
    let buf = qe.payload.client_buffers()[0];
    let written = qe.payload.args_64()[1] as usize;
    ex.free_pqe(pqe);
    (buf, written)
}

pub async fn consume_io_page(io_page_idx: u16, buf: &mut [u8]) {
    let ex = IoExecutor::inst();
    let pqe = ex.get_free_pqe();

    let qe: &mut QueueEntry = pqe.qe();
    ex.init_qe(qe);
    qe.command = CMD_CONSUME_IO_PAGE;
    qe.payload.client_buffers_mut()[0] = io_page_idx;
    qe.payload.args_64_mut()[1] = buf.as_ptr() as usize as u64;
    qe.payload.args_64_mut()[2] = buf.len() as u64;
    ex.add_to_queue(pqe).await;
    pqe.await;

    debug_assert!(qe.status().is_ok());
    ex.free_pqe(pqe);
}

pub async fn put_io_page(io_page_idx: u16) {
    let ex = IoExecutor::inst();
    let pqe = ex.get_free_pqe();

    let qe: &mut QueueEntry = pqe.qe();
    ex.init_qe(qe);
    qe.command = CMD_CONSUME_IO_PAGE;
    qe.payload.client_buffers_mut()[0] = io_page_idx;
    qe.payload.args_64_mut()[1] = 0;
    qe.payload.args_64_mut()[2] = 0;
    ex.add_to_queue(pqe).await;
    pqe.await;

    debug_assert!(qe.status().is_ok());
    ex.free_pqe(pqe);
}

pub async fn submit(sqe: QueueEntry) -> QueueEntry {
    match prepare_to_submit(sqe) {
        Ok(mut sqe) => {
            let ex = IoExecutor::inst();
            let pqe = ex.get_free_pqe();
            let qe: &mut QueueEntry = pqe.qe();
            *qe = sqe;

            ex.add_to_queue(pqe).await;
            #[cfg(debug_assertions)]
            moturus_log!("add_to_queue done");
            pqe.await;
            #[cfg(debug_assertions)]
            moturus_log!("pqe.await done");

            sqe = *qe;
            ex.free_pqe(pqe);
            sqe
        }
        Err(sqe) => sqe,
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
                #[cfg(debug_assertions)]
                crate::util::moturus_log!("Executor::block_on(): going to sleep");

                let result = SysCpu::wait(
                    &mut [],
                    SysHandle::NONE,
                    SysHandle::NONE,
                    Some(moto_sys::time::Instant::now() + core::time::Duration::from_secs(1)),
                );
                if let Err(err) = result {
                    assert_eq!(err, ErrorCode::TimedOut);
                    #[cfg(debug_assertions)]
                    moturus_log!("io_executor: block_on timed out");
                }
            }
        }
    }
}
