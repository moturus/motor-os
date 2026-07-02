//! C++ `thread_local` destructors: `__cxa_thread_atexit` (clang emits calls to it
//! under emulated TLS too).
//!
//! A per-thread LIFO dtor list lives under a VDSO TLS key; the key's destructor
//! runs the list at thread exit. A dtor registering another dtor creates a fresh
//! list, which the VDSO's exit loop (rt.vdso/src/rt_tls.rs) picks up on its next
//! iteration.
//!
//! Known limitation (see docs/porting-libc-appendix-b.md, B.3): dtors run on
//! *thread* exit; `main` returning ends the process via proc_exit without
//! draining the main thread's keys. Revisit when mlibc's exit() lands (M2).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

type CxaDtor = unsafe extern "C" fn(*mut u8);
type DtorList = Vec<(CxaDtor, usize)>;

static CXA_KEY: AtomicUsize = AtomicUsize::new(0); // 0 = key not created yet

unsafe extern "C" fn run_dtors(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let mut list = unsafe { Box::from_raw(p as *mut DtorList) };
    while let Some((dtor, obj)) = list.pop() {
        unsafe { dtor(obj as *mut u8) };
    }
}

fn cxa_key() -> usize {
    let key = CXA_KEY.load(Ordering::Acquire);
    if key != 0 {
        return key;
    }
    let new_key = moto_rt::tls::create(Some(run_dtors));
    match CXA_KEY.compare_exchange(0, new_key, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => new_key,
        Err(winner) => {
            unsafe { moto_rt::tls::destroy(new_key) };
            winner
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_thread_atexit(
    dtor: CxaDtor,
    obj: *mut u8,
    _dso_symbol: *mut u8,
) -> i32 {
    let key = cxa_key();
    let mut list_ptr = unsafe { moto_rt::tls::get(key) } as *mut DtorList;
    if list_ptr.is_null() {
        list_ptr = Box::into_raw(Box::new(DtorList::new()));
        unsafe { moto_rt::tls::set(key, list_ptr as *mut u8) };
    }
    unsafe { &mut *list_ptr }.push((dtor, obj as usize));
    0
}
