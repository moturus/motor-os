#![allow(clippy::needless_late_init)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::ptr_offset_with_cast)]

// Libc dependencies go deep in Rust, and without exports in this module
// many things fail to link.

pub const STDIN_FILENO: crate::RtFd = crate::FD_STDIN;
pub const STDOUT_FILENO: crate::RtFd = crate::FD_STDOUT;
pub const STDERR_FILENO: crate::RtFd = crate::FD_STDERR;

// We need unsafe because stdlib wraps the call in unsafe block.
#[allow(unused_unsafe)]
pub unsafe fn close(fd: crate::RtFd) -> Result<(), crate::ErrorCode> {
    crate::fs::close(fd)
}

// mem* functions below have been copied from rust compiler_builtins/mem.rs.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.offset(i as isize) = *src.offset(i as isize);
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if src < dest as *const u8 {
        // copy from end
        let mut i = n;
        while i != 0 {
            i -= 1;
            *dest.offset(i as isize) = *src.offset(i as isize);
        }
    } else {
        // copy from beginning
        let mut i = 0;
        while i < n {
            *dest.offset(i as isize) = *src.offset(i as isize);
            i += 1;
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *s.offset(i as isize) = c as u8;
        i += 1;
    }
    s
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.offset(i as isize);
        let b = *s2.offset(i as isize);
        if a != b {
            return a as i32 - b as i32;
        }
        i += 1;
    }
    0
}

#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    panic!("__stack_chk_fail")
}

#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn __assert_fail() -> ! {
    // void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
    panic!("__assert_fail")
}
