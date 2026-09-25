use super::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::AtomicUsize;

static MEASURED_THREAD: AtomicU64 = AtomicU64::new(0);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

impl CountingAllocator {
    fn record(counter: &AtomicUsize) {
        let thread = MEASURED_THREAD.load(Ordering::Relaxed);
        if thread != 0 && thread == moto_sys::current_thread().as_u64() {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::record(&ALLOCATIONS);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::record(&ALLOCATIONS);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        Self::record(&ALLOCATIONS);
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        Self::record(&DEALLOCATIONS);
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

// Count only this thread's calls into the allocator, including requests that
// would fit in an existing slab. VDSO background threads are not measured.
struct Measurement;

impl Measurement {
    fn start() -> Self {
        assert_eq!(MEASURED_THREAD.load(Ordering::Relaxed), 0);
        ALLOCATIONS.store(0, Ordering::Relaxed);
        DEALLOCATIONS.store(0, Ordering::Relaxed);
        MEASURED_THREAD.store(moto_sys::current_thread().as_u64(), Ordering::Relaxed);
        Self
    }

    fn finish(self) -> (usize, usize) {
        drop(self);
        (
            ALLOCATIONS.load(Ordering::Relaxed),
            DEALLOCATIONS.load(Ordering::Relaxed),
        )
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        MEASURED_THREAD.store(0, Ordering::Relaxed);
    }
}

fn pair() -> (
    moto_sys::syscalls::RaiiHandle,
    moto_sys::syscalls::RaiiHandle,
) {
    let (wake, wait) =
        moto_sys::SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();
    (
        moto_sys::syscalls::RaiiHandle::from(wake),
        moto_sys::syscalls::RaiiHandle::from(wait),
    )
}

async fn prime(signals: &[moto_async::SysHandleFuture]) {
    std::future::poll_fn(|cx| {
        for signal in signals {
            assert_eq!(signal.do_poll(cx), Poll::Pending);
        }
        Poll::Ready(())
    })
    .await;
}

async fn consume(signals: &[moto_async::SysHandleFuture], result: moto_rt::Result<()>) {
    std::future::poll_fn(|cx| {
        for signal in signals {
            assert_eq!(signal.do_poll(cx), Poll::Ready(result));
        }
        Poll::Ready(())
    })
    .await;
}

pub(super) fn run() {
    let (wake, wait) = pair();
    let (other_wake, other_wait) = pair();
    let (cold, batch, delayed) = moto_async::LocalRuntime::new().block_on(async {
        let mut signal = wait.syshandle().as_future();
        prime(std::slice::from_ref(&signal)).await;
        let measured = Measurement::start();
        SysCpu::wake(wake.syshandle()).unwrap();
        moto_async::yield_to_io().await;
        let cold = measured.finish().0;
        consume(std::slice::from_ref(&signal), Ok(())).await;

        // Grow beyond the first completion's minimum buffer capacity, with
        // several futures per handle as well as more than one handle.
        let signals: [_; 9] = std::array::from_fn(|_| wait.syshandle().as_future());
        let mut other = other_wait.syshandle().as_future();
        prime(&signals).await;
        prime(std::slice::from_ref(&other)).await;
        let measured = Measurement::start();
        SysCpu::wake(wake.syshandle()).unwrap();
        SysCpu::wake(other_wake.syshandle()).unwrap();
        moto_async::yield_to_io().await;
        let batch = measured.finish().0;
        consume(&signals, Ok(())).await;
        consume(std::slice::from_ref(&other), Ok(())).await;

        // Model a relay that waited for room on its other pipe before
        // returning to the first handle. Its original future is still live.
        let mut delayed = 0;
        for wait_on_other in [false, true] {
            if wait_on_other {
                other.rearm();
                prime(std::slice::from_ref(&other)).await;
            }
            moto_async::yield_to_io().await;
            let measured = Measurement::start();
            signal.rearm();
            prime(std::slice::from_ref(&signal)).await;
            SysCpu::wake(wake.syshandle()).unwrap();
            moto_async::yield_to_io().await;
            delayed += measured.finish().0;
            consume(std::slice::from_ref(&signal), Ok(())).await;
        }
        (cold, batch, delayed)
    });
    assert_eq!(
        (cold, batch, delayed),
        (0, 0, 0),
        "cold, batch, delayed rearm"
    );
    bad_handles_and_cleanup();
    registration_from_waker();
    println!("----- moto_async::allocations PASS");
}

fn bad_handles_and_cleanup() {
    let (peer, wait) = pair();
    moto_async::LocalRuntime::new().block_on(async {
        let mut signal = wait.syshandle().as_future();
        let held = wait.syshandle().as_future();
        prime(std::slice::from_ref(&signal)).await;
        SysCpu::wake(peer.syshandle()).unwrap();
        moto_async::yield_to_io().await;
        consume(std::slice::from_ref(&signal), Ok(())).await;
        drop(peer);

        for _ in 0..3 {
            let measured = Measurement::start();
            signal.rearm();
            prime(std::slice::from_ref(&signal)).await;
            moto_async::yield_to_io().await;
            assert_eq!(measured.finish().0, 0, "rearming a bad handle allocated");
            consume(
                std::slice::from_ref(&signal),
                Err(moto_rt::Error::BadHandle),
            )
            .await;
        }
        // Reports for the re-armed future must not overwrite an inactive
        // future's original success, even though the handle has since died.
        consume(std::slice::from_ref(&held), Ok(())).await;
    });

    let (wake, wait) = pair();
    moto_async::LocalRuntime::new().block_on(async {
        let mut anchor = wait.syshandle().as_future();
        // The anchor keeps the map entry and its queue allocation alive.
        // Each dropped sibling must release precisely its inner Rc object.
        for drop_before_report in [true, false] {
            let mut sibling = Some(wait.syshandle().as_future());
            anchor.rearm();
            prime(std::slice::from_ref(&anchor)).await;
            if drop_before_report {
                drop(sibling.take());
            }
            let measured = Measurement::start();
            SysCpu::wake(wake.syshandle()).unwrap();
            moto_async::yield_to_io().await;
            drop(sibling);
            moto_async::yield_to_io().await;
            assert_eq!(
                measured.finish(),
                (0, 1),
                "dropped registration was not reclaimed"
            );
            consume(std::slice::from_ref(&anchor), Ok(())).await;
        }
    });
}

fn registration_from_waker() {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::task::{ContextBuilder, LocalWake, LocalWaker};

    struct Register {
        handle: SysHandle,
        signals: RefCell<Vec<moto_async::SysHandleFuture>>,
    }
    impl LocalWake for Register {
        fn wake(self: Rc<Self>) {
            self.signals
                .borrow_mut()
                .extend((0..9).map(|_| self.handle.as_future()));
        }
    }

    let (wake, wait) = pair();
    moto_async::LocalRuntime::new().block_on(async {
        let signal = wait.syshandle().as_future();
        let register = Rc::new(Register {
            handle: wait.syshandle(),
            signals: RefCell::new(Vec::new()),
        });
        let waker = LocalWaker::from(register.clone());
        std::future::poll_fn(|cx| {
            let mut cx = ContextBuilder::from_waker(cx.waker())
                .local_waker(&waker)
                .build();
            assert_eq!(signal.do_poll(&mut cx), Poll::Pending);
            Poll::Ready(())
        })
        .await;
        SysCpu::wake(wake.syshandle()).unwrap();
        moto_async::yield_to_io().await;

        // Capacity reserved by a registration inside wake() must survive
        // completion delivery, and no runtime collection may stay borrowed.
        let signals = register.signals.take();
        assert_eq!(signals.len(), 9);
        prime(&signals).await;
        let measured = Measurement::start();
        SysCpu::wake(wake.syshandle()).unwrap();
        moto_async::yield_to_io().await;
        assert_eq!(measured.finish().0, 0, "callback reservation was lost");
        consume(&signals, Ok(())).await;
        consume(std::slice::from_ref(&signal), Ok(())).await;
    });
}
