use core::sync::atomic::Ordering;

use crate::RtVdsoVtable;

pub type Key = usize;

#[inline]
pub fn create(dtor: Option<unsafe extern "C" fn(*mut u8)>) -> Key {
    let vdso_create: extern "C" fn(u64) -> Key = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().tls_create.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_create(match dtor {
        Some(func) => func as *const () as usize as u64,
        None => 0,
    })
}

/// # Safety
///
/// It is kinda safe, but stdlib wraps it in 'unsafe' and fails to compile if we dont' mark it safe.
#[inline]
pub unsafe fn set(key: Key, value: *mut u8) {
    let vdso_set: extern "C" fn(Key, *mut u8) = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().tls_set.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    vdso_set(key, value)
}

/// # Safety
///
/// It is kinda safe, but stdlib wraps it in 'unsafe' and fails to compile if we dont' mark it safe.
#[inline]
pub unsafe fn get(key: Key) -> *mut u8 {
    let vdso_get: extern "C" fn(Key) -> *mut u8 = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().tls_get.load(Ordering::Relaxed) as usize as *const ()
        )
    };

    vdso_get(key)
}

/// # Safety
///
/// It is kinda safe, but stdlib wraps it in 'unsafe' and fails to compile if we dont' mark it safe.
#[inline]
pub unsafe fn destroy(key: Key) {
    let vdso_destroy: extern "C" fn(Key) = unsafe {
        core::mem::transmute(
            RtVdsoVtable::get().tls_destroy.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_destroy(key)
}
