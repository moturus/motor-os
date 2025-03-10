// Libc dependencies go deep in Rust, and without exports in this module
// many things fail to link.

mod fmod;
mod log;
mod log2;

pub const STDIN_FILENO: crate::RtFd = crate::FD_STDIN;
pub const STDOUT_FILENO: crate::RtFd = crate::FD_STDOUT;
pub const STDERR_FILENO: crate::RtFd = crate::FD_STDERR;

// We need unsafe because stdlib wraps the call in unsafe block.
#[allow(unused_unsafe)]
pub unsafe fn close(fd: crate::RtFd) -> Result<(), crate::ErrorCode> {
    crate::fs::close(fd)
}

// mem* functions below have been copied from rust compiler_builtins/mem.rs.
// #[linkage = "extern_weak"]
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.offset(i as isize) = *src.offset(i as isize);
        i += 1;
    }
    dest
}

// #[linkage = "extern_weak"]
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

// #[linkage = "extern_weak"]
#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *s.offset(i as isize) = c as u8;
        i += 1;
    }
    s
}

// #[linkage = "extern_weak"]
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

// Copied from libm.
macro_rules! force_eval {
    ($e:expr) => {
        unsafe { ::core::ptr::read_volatile(&$e) }
    };
}

#[no_mangle]
pub unsafe extern "C" fn trunc(x: f64) -> f64 {
    // Copied from libm.
    let x1p120 = f64::from_bits(0x4770000000000000); // 0x1p120f === 2 ^ 120

    let mut i: u64 = x.to_bits();
    let mut e: i64 = (i >> 52 & 0x7ff) as i64 - 0x3ff + 12;
    let m: u64;

    if e >= 52 + 12 {
        return x;
    }
    if e < 12 {
        e = 1;
    }
    m = -1i64 as u64 >> e;
    if (i & m) == 0 {
        return x;
    }
    force_eval!(x + x1p120);
    i &= !m;
    f64::from_bits(i)
}

#[no_mangle]
pub unsafe extern "C" fn ceil(x: f64) -> f64 {
    const TOINT: f64 = 1. / f64::EPSILON;

    let u: u64 = x.to_bits();
    let e: i64 = (u >> 52 & 0x7ff) as i64;
    let y: f64;

    if e >= 0x3ff + 52 || x == 0. {
        return x;
    }
    // y = int(x) - x, where int(x) is an integer neighbor of x
    y = if (u >> 63) != 0 {
        x - TOINT + TOINT - x
    } else {
        x + TOINT - TOINT - x
    };
    // special case because of non-nearest rounding modes
    if e < 0x3ff {
        force_eval!(y);
        return if (u >> 63) != 0 { -0. } else { 1. };
    }
    if y < 0. {
        x + y + 1.
    } else {
        x + y
    }
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
