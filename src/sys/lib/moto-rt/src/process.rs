//! Per-process data such as command line arguments and environment variables.

#[cfg(feature = "rustc-dep-of-std")]
use alloc;

#[cfg(not(feature = "rustc-dep-of-std"))]
extern crate alloc;

use crate::RtFd;
use crate::RtVdsoVtableV1;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

/// An arbitrarily defined maximum lenth of an environment variable key.
pub const MAX_ENV_KEY_LEN: usize = 256;
/// An arbitrarily defined maximum lenth of an environment variable value.
pub const MAX_ENV_VAL_LEN: usize = 4092;

pub const STDIO_INHERIT: RtFd = -((crate::error::E_MAX as RtFd) + 1);
pub const STDIO_NULL: RtFd = -((crate::error::E_MAX as RtFd) + 2);
pub const STDIO_MAKE_PIPE: RtFd = -((crate::error::E_MAX as RtFd) + 3);

/// Get all commandline args for the current process.
pub fn args() -> alloc::vec::Vec<String> {
    let vdso_args: extern "C" fn() -> u64 = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_args.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let args_addr = vdso_args();
    if args_addr == 0 {
        return alloc::vec::Vec::new();
    }
    let raw_vec = unsafe { deserialize_vec(args_addr) };

    let mut result = Vec::new();
    for idx in 0..raw_vec.len() {
        let arg = raw_vec[idx].to_vec();
        result.push(unsafe { String::from_utf8_unchecked(arg) });
    }

    crate::alloc::raw_dealloc(args_addr);
    result
}

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
    let num_keys = raw_vec.len() >> 1;
    for idx in 0..num_keys {
        let key = raw_vec[idx].to_vec();
        let val = raw_vec[idx + num_keys].to_vec();
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

#[allow(unused)]
#[derive(Default)]
pub struct SpawnArgs {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub stdin: RtFd,
    pub stdout: RtFd,
    pub stderr: RtFd,
}

#[repr(C)]
pub struct SpawnArgsRt {
    pub prog_name_addr: u64,
    pub prog_name_size: u64,
    pub args: u64, // Encoded.
    pub env: u64,  // Encoded.
    pub stdin: RtFd,
    pub stdout: RtFd,
    pub stderr: RtFd,
    pub _reserved: i32,
}

#[derive(Default)]
#[repr(C)]
pub struct SpawnResult {
    pub handle: u64,
    pub stdin: RtFd,
    pub stdout: RtFd,
    pub stderr: RtFd,
    pub _reserved: i32,
}

pub fn spawn(args: SpawnArgs) -> Result<(u64, RtFd, RtFd, RtFd), crate::ErrorCode> {
    use alloc::borrow::ToOwned;
    let vdso_spawn: extern "C" fn(*const SpawnArgsRt, *mut SpawnResult) -> crate::ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_spawn.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut keys = alloc::vec![];
    let mut vals = alloc::vec![];

    for (k, v) in &args.env {
        if k == "PWD" {
            // Ignore the env var.
            continue;
        }
        keys.push(k.clone());
        vals.push(v.clone());
    }

    // Set $PWD.
    let pwd = match args.cwd.as_ref() {
        Some(cwd) => cwd.clone(),
        None => {
            if let Ok(cwd) = super::fs::getcwd() {
                cwd.clone()
            } else {
                "".to_owned()
            }
        }
    };
    keys.push("PWD".to_owned());
    vals.push(pwd);

    let (rt_args, args_layout) = encode_args(&args.args);
    let (env, env_layout) = encode_env(keys, vals);

    let args_rt = SpawnArgsRt {
        prog_name_addr: args.program.as_str().as_ptr() as usize as u64,
        prog_name_size: args.program.as_str().len() as u64,
        args: rt_args,
        env,
        stdin: args.stdin,
        stdout: args.stdout,
        stderr: args.stderr,
        _reserved: 0,
    };

    let mut result_rt = SpawnResult::default();
    let res = vdso_spawn(&args_rt, &mut result_rt);
    if let Some(layout) = args_layout {
        unsafe { crate::alloc::dealloc(args_rt.args as usize as *mut u8, layout) };
    }
    if let Some(layout) = env_layout {
        unsafe { crate::alloc::dealloc(args_rt.env as usize as *mut u8, layout) };
    }

    if res != crate::E_OK {
        Err(res)
    } else {
        Ok((
            result_rt.handle,
            result_rt.stdin,
            result_rt.stdout,
            result_rt.stderr,
        ))
    }
}

pub fn kill(handle: u64) -> crate::ErrorCode {
    let vdso_kill: extern "C" fn(u64) -> crate::ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_kill.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    vdso_kill(handle)
}

pub fn wait(handle: u64) -> Result<i32, crate::ErrorCode> {
    let vdso_wait: extern "C" fn(u64) -> crate::ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_wait.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let result = vdso_wait(handle);
    if result != crate::E_OK {
        Err(result)
    } else {
        try_wait(handle)
    }
}
fn convert_exit_status(exit_status: u64) -> i32 {
    if exit_status & 0xffff_ffff_0000_0000 == 0 {
        // Map u64 to i32.
        let status_u32: u32 = exit_status as u32;
        unsafe { core::mem::transmute::<u32, i32>(status_u32) }
    } else {
        // The process exited not via Rust's std::process::exit, but
        // via a lower-level syscall. Don't try to second-guess what
        // it wanted to say, just return a -1.
        -1
    }
}

pub fn try_wait(handle: u64) -> Result<i32, crate::ErrorCode> {
    let vdso_status: extern "C" fn(u64, *mut u64) -> crate::ErrorCode = unsafe {
        core::mem::transmute(
            RtVdsoVtableV1::get().proc_status.load(Ordering::Relaxed) as usize as *const (),
        )
    };

    let mut status = 0_u64;
    let result = vdso_status(handle, &mut status);
    if result == crate::E_OK {
        Ok(convert_exit_status(status))
    } else {
        Err(result)
    }
}

fn encode_env(keys: Vec<String>, vals: Vec<String>) -> (u64, Option<core::alloc::Layout>) {
    assert_eq!(keys.len(), vals.len());

    let mut needed_len: u32 = 4; // Total num strings.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &str| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in &keys {
        calc_lengths(arg.as_str());
    }

    for arg in &vals {
        calc_lengths(arg.as_str());
    }

    if num_args == 0 {
        return (0, None);
    }

    let layout = core::alloc::Layout::from_size_align(needed_len as usize, 8).unwrap();
    let result_addr = unsafe { crate::alloc::alloc(layout) } as usize;
    assert_ne!(result_addr, 0);

    unsafe {
        let mut pos = result_addr as usize;
        *((pos as *mut u32).as_mut().unwrap()) = num_args;
        pos += 4;

        let mut write_arg = |arg: &str| {
            *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
            pos += 4;

            let bytes = arg.as_bytes();
            core::intrinsics::copy_nonoverlapping(bytes.as_ptr(), pos as *mut u8, bytes.len());
            pos += (bytes.len() + 3) & !3_usize;
        };

        for arg in keys {
            write_arg(arg.as_str());
        }

        for arg in vals {
            write_arg(arg.as_str());
        }
    }

    (result_addr as u64, Some(layout))
}

fn encode_args(args: &Vec<String>) -> (u64, Option<core::alloc::Layout>) {
    let mut needed_len: u32 = 4; // Args num.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &str| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in args {
        if arg.len() == 0 {
            continue;
        }
        calc_lengths(arg.as_str());
    }

    if num_args == 0 {
        return (0, None);
    }

    let layout = core::alloc::Layout::from_size_align(needed_len as usize, 8).unwrap();
    let result_addr = unsafe { crate::alloc::alloc(layout) } as usize;
    assert_ne!(result_addr, 0);

    unsafe {
        let mut pos = result_addr;
        *((pos as *mut u32).as_mut().unwrap()) = num_args;
        pos += 4;

        let mut write_arg = |arg: &str| {
            *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
            pos += 4;

            let bytes = arg.as_bytes();
            core::intrinsics::copy_nonoverlapping(bytes.as_ptr(), pos as *mut u8, bytes.len());
            pos += (bytes.len() + 3) & !3_usize;
        };

        for arg in args {
            if arg.len() == 0 {
                continue;
            }
            write_arg(arg.as_str());
        }
    }

    (result_addr as u64, Some(layout))
}
