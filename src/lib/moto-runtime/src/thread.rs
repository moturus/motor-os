use core::sync::atomic::*;
use moto_sys::syscalls::*;
use moto_sys::ErrorCode;

pub fn spawn(
    stack_size: usize,
    thread_fn: usize,
    thread_arg: usize,
) -> Result<SysHandle, ErrorCode> {
    SysCpu::spawn(
        SysHandle::SELF,
        stack_size as u64,
        thread_fn as u64,
        thread_arg as u64,
    )
}

pub fn exit_self() -> ! {
    let _ = SysCtl::put(SysHandle::SELF);
    unreachable!()
}

pub fn join(handle: SysHandle) {
    // wait() below will properly succeed if it is called while the joinee is still running
    // and will fail if the joinee has exited. We need to be careful here:
    // stdlib will panic if this join() returns while the joinee is still running,
    // but in moturus OS any thread can be woken unconditionally via SysCpu::wake(),
    // so we must make sure this thread is woken because the joinee has exited,
    // not otherwise.
    loop {
        let mut handles = [handle];
        match SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None) {
            Ok(_) => {
                if handles[0] == handle {
                    break;
                } // else => spurious wakeup.
            }
            Err(_) => {
                assert_eq!(handles[0], handle);
                break;
            }
        }
    }
}

pub fn sleep(dur: core::time::Duration) {
    // The current thread may have pending wakeups, and so the wait will immediately
    // return. Thus we have to track time and wait again.
    let stop = moto_sys::time::Instant::now() + dur;
    loop {
        match SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, Some(stop)) {
            Ok(()) => continue,
            Err(ErrorCode::TimedOut) => {
                debug_assert!(moto_sys::time::Instant::now() >= stop);
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
            Some(dur) => Some(moto_sys::time::Instant::now() + dur),
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
