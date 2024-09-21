//! Per-process data such as command line arguments and environment variables.

#[cfg(feature = "rustc-dep-of-std")]
use alloc;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

use crate::RtVdsoVtableV1;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// An arbitrarily defined maximum lenth of an environment variable key.
pub const MAX_ENV_KEY_LEN: usize = 256;
/// An arbitrarily defined maximum lenth of an environment variable value.
pub const MAX_ENV_VAL_LEN: usize = 4092;

/// Get all environment variables for the current process.
pub fn env() -> alloc::vec::Vec<(String, String)> {
    let vdso_get_full_env: extern "C" fn() -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get()
                .proc_get_full_env
                .load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let env_addr = vdso_get_full_env();
    if env_addr == 0 {
        return alloc::vec::Vec::new();
    }
    let raw_vec = unsafe { deserialize_vec(env_addr) };
    assert_eq!(0, raw_vec.len() & 1);

    let mut result = Vec::new();
    for idx in 0..(raw_vec.len() >> 1) {
        let key = raw_vec[2 * idx].to_vec();
        let val = raw_vec[2 * idx + 1].to_vec();
        result.push(unsafe {
            (
                String::from_utf8_unchecked(key),
                String::from_utf8_unchecked(val),
            )
        });
    }

    crate::alloc::raw_dealloc(env_addr);
    result
}

/// Get a specific environment variable, if set.
pub fn getenv(key: &str) -> Option<String> {
    let vdso_get: extern "C" fn(*const u8, usize) -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_getenv.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let key = key.as_bytes();
    assert!(key.len() <= MAX_ENV_KEY_LEN); // Better to panic than silently do something different.

    let val_addr = vdso_get(key.as_ptr(), key.len());
    if val_addr == u64::MAX {
        return None;
    }
    if val_addr == 0 {
        return Some(String::new());
    }

    let val_len: *const u32 = val_addr as usize as *const u32;
    let val_bytes: *const u8 = (val_addr + 4) as usize as *const u8;

    let val: &[u8] = unsafe { core::slice::from_raw_parts(val_bytes, (*val_len) as usize) };
    let result = Some(alloc::string::ToString::to_string(
        core::str::from_utf8(val).unwrap(),
    ));

    crate::alloc::raw_dealloc(val_addr);
    result
}

/// Set an environment variable.
pub fn setenv(key: &str, val: &str) {
    let vdso_set: extern "C" fn(*const u8, usize, usize, usize) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_setenv.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let key = key.as_bytes();
    assert!(key.len() <= MAX_ENV_KEY_LEN); // Better to panic than silently do something different.
    let val = val.as_bytes();
    assert!(val.len() <= MAX_ENV_VAL_LEN); // Better to panic than silently do something different.
    vdso_set(key.as_ptr(), key.len(), val.as_ptr() as usize, val.len());
}

/// Unset an environment variable.
pub fn unsetenv(key: &str) {
    let vdso_set: extern "C" fn(*const u8, usize, usize, usize) = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_setenv.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let key = key.as_bytes();
    assert!(key.len() <= MAX_ENV_KEY_LEN); // Better to panic than silently do something different.
    vdso_set(key.as_ptr(), key.len(), 0, usize::MAX);
}

unsafe fn deserialize_vec(addr: u64) -> Vec<&'static [u8]> {
    assert_ne!(addr, 0);
    // first four bytes: the number of arguments;
    // then arguments, aligned at four bytes: size (four bytes), bytes.

    let mut pos = addr as usize;
    assert_eq!(pos & 3, 0);

    let num_args = *((pos as *const u32).as_ref().unwrap());
    pos += 4;

    let mut result = Vec::new();
    for _i in 0..num_args {
        let len = *((pos as *const u32).as_ref().unwrap());
        pos += 4;
        let bytes: &[u8] = core::slice::from_raw_parts(pos as *const u8, len as usize);
        result.push(bytes);
        pos += len as usize;
        pos = (pos + 3) & !3; // Align up to 4 bytes.
    }

    result
}
