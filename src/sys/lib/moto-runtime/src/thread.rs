use alloc::boxed::Box;
use core::sync::atomic::*;
use moto_sys::ErrorCode;
use moto_sys::*;

pub fn sleep(dur: core::time::Duration) {
    // The current thread may have pending wakeups, and so the wait will immediately
    // return. Thus we have to track time and wait again.
    let stop = moto_rt::time::Instant::now() + dur;
    loop {
        match SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, Some(stop)) {
            Ok(()) => continue,
            Err(ErrorCode::TimedOut) => {
                debug_assert!(moto_rt::time::Instant::now() >= stop);
                return;
            }
            Err(err) => {
                panic!("Unrecognized error code: {:?}", err);
            }
        }
    }
}

pub struct Parker {
    handle: AtomicU64,
}

impl Parker {
    pub fn new() -> Self {
        Self {
            handle: AtomicU64::new(SysHandle::NONE.as_u64()),
        }
    }

    pub fn park(&self, dur: Option<core::time::Duration>) {
        let tcb = moto_sys::UserThreadControlBlock::get();
        let self_handle = tcb.self_handle;
        assert_eq!(
            SysHandle::NONE.as_u64(),
            self.handle.swap(self_handle, Ordering::AcqRel)
        );

        let stop = match dur {
            None => None,
            Some(dur) => Some(moto_rt::time::Instant::now() + dur),
        };

        let _ = SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, stop);
        self.handle
            .store(SysHandle::NONE.as_u64(), Ordering::Release);
    }

    pub fn unpark(&self) {
        let self_handle = self.handle.load(Ordering::Acquire);
        if self_handle != SysHandle::NONE.as_u64() {
            let _ = SysCpu::wake(SysHandle::from_u64(self_handle));
        }
    }
}

pub struct Thread {
    handle: SysHandle,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

impl Thread {
    pub unsafe fn new(stack: usize, p: Box<dyn FnOnce()>) -> Result<Thread, ErrorCode> {
        let thread_arg = Box::into_raw(Box::new(p)) as *mut _;
        moto_sys::SysCpu::spawn(
            SysHandle::SELF,
            stack as u64,
            __moto_runtime_thread_fn as usize as u64,
            thread_arg as usize as u64,
        )
        .map(|handle| Thread { handle })
    }

    pub fn join(self) {
        // wait() below will properly succeed if it is called while the joinee is still running
        // and will fail if the joinee has exited. We need to be careful here:
        // stdlib will panic if this join() returns while the joinee is still running,
        // but in moturus OS any thread can be woken unconditionally via SysCpu::wake(),
        // so we must make sure this thread is woken because the joinee has exited,
        // not otherwise.
        loop {
            let mut handles = [self.handle];
            match SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None) {
                Ok(_) => {
                    if handles[0] == self.handle {
                        break;
                    } // else => spurious wakeup.
                }
                Err(_) => {
                    assert_eq!(handles[0], self.handle);
                    break;
                }
            }
        }
    }
}

extern "C" fn __moto_runtime_thread_fn(thread_arg: usize) {
    unsafe {
        Box::from_raw(
            core::ptr::with_exposed_provenance::<Box<dyn FnOnce()>>(thread_arg).cast_mut(),
        )();
    }
    super::tls::destroy_tls();
    let _ = SysObj::put(SysHandle::SELF);
    unreachable!()
}
