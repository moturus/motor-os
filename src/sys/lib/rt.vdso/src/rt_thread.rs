use core::str;

use moto_rt::ErrorCode;
use moto_sys::SysHandle;

pub extern "C" fn spawn(
    thread_fn: extern "C" fn(thread_arg: u64),
    stack_size: usize,
    thread_arg: u64,
) -> u64 {
    struct RtThreadArgs {
        thread_fn: extern "C" fn(thread_arg: u64),
        thread_arg: u64,
    }

    extern "C" fn __rt_thread_fn(thread_arg: u64) {
        unsafe {
            let rt_args = alloc::boxed::Box::from_raw(thread_arg as usize as *mut RtThreadArgs);
            let thread_fn = rt_args.thread_fn;
            thread_fn(rt_args.thread_arg);
            super::rt_tls::on_thread_exiting();
            core::mem::drop(rt_args);
        }
        let _ = moto_sys::SysObj::put(SysHandle::SELF);
        unreachable!()
    }

    let rt_args = alloc::boxed::Box::new(RtThreadArgs {
        thread_fn,
        thread_arg,
    });
    let rt_args = alloc::boxed::Box::into_raw(rt_args);

    match moto_sys::SysCpu::spawn(
        SysHandle::SELF,
        stack_size as u64,
        __rt_thread_fn as usize as u64,
        rt_args as *const _ as usize as u64,
    ) {
        Ok(sys_handle) => {
            assert!(u64::from(sys_handle) > (moto_rt::E_MAX as u64));
            sys_handle.as_u64()
        }
        Err(err) => err as u64,
    }
}

pub extern "C" fn yield_now() {
    moto_sys::SysCpu::sched_yield()
}

pub extern "C" fn sleep(deadline: u64) {
    // The current thread may have pending wakeups, and so the wait will immediately
    // return. Thus we have to track time and wait again.
    let deadline = moto_rt::time::Instant::from_u64(deadline);
    loop {
        match moto_sys::SysCpu::wait(&mut [], SysHandle::NONE, SysHandle::NONE, Some(deadline)) {
            Ok(()) => continue,
            Err(moto_rt::E_TIMED_OUT) => {
                debug_assert!(moto_rt::time::Instant::now() >= deadline);
                return;
            }
            Err(err) => {
                panic!("Unrecognized error code: {:?}", err);
            }
        }
    }
}

pub extern "C" fn set_name(name_ptr: *const u8, name_len: usize) -> ErrorCode {
    let name_bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let name = if let Ok(s) = str::from_utf8(name_bytes) {
        s
    } else {
        return moto_rt::E_INVALID_ARGUMENT;
    };
    match moto_sys::set_current_thread_name(name) {
        Ok(_) => moto_rt::E_OK,
        Err(err) => err,
    }
}

pub extern "C" fn join(handle: u64) -> ErrorCode {
    // wait() below will properly succeed if it is called while the joinee is still running
    // and will fail if the joinee has exited. We need to be careful here:
    // stdlib will panic if this join() returns while the joinee is still running,
    // but in Motor OS any thread can be woken unconditionally via SysCpu::wake(),
    // so we must make sure this thread is woken because the joinee has exited,
    // not otherwise.
    let handle = SysHandle::from_u64(handle);
    loop {
        let mut handles = [handle];
        match moto_sys::SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None) {
            Ok(_) => {
                if handles[0] == handle {
                    break;
                } // else => spurious wakeup.
            }
            Err(_err) => {
                // TODO: figure out a way to report bad handle (e.g. not a thread handle)
                assert_eq!(handles[0], handle);
                break;
            }
        }
    }
    moto_rt::E_OK
}
