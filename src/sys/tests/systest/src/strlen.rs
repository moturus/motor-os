//! Rust's optimizer and CStr require the runtime strlen symbol.

unsafe extern "C" {
    fn strlen(start: *const std::ffi::c_char) -> usize;
}

#[inline(never)]
unsafe fn loop_length(start: *const std::ffi::c_char) -> usize {
    let mut end = start;
    unsafe {
        while *end != 0 {
            end = end.add(1);
        }
        end.offset_from(start) as usize
    }
}

pub fn run_all_tests() {
    for (bytes, expected) in [
        (b"\0".as_slice(), 0),
        (b"Motor OS\0".as_slice(), 8),
        (b"first\0ignored\0".as_slice(), 5),
        (b"\xff\x80\0".as_slice(), 2),
    ] {
        let pointer = std::hint::black_box(bytes.as_ptr().cast());
        unsafe {
            assert_eq!(strlen(pointer), expected);
            assert_eq!(loop_length(pointer), expected);
            assert_eq!(std::ffi::CStr::from_ptr(pointer).to_bytes().len(), expected);
        }
    }
    let mut terminated = vec![b'x'; 8193];
    terminated[8192] = 0;
    let pointer = std::hint::black_box(terminated.as_ptr().cast());
    unsafe {
        assert_eq!(strlen(pointer), 8192);
        assert_eq!(loop_length(pointer), 8192);
        assert_eq!(std::ffi::CStr::from_ptr(pointer).to_bytes().len(), 8192);
        assert_eq!(strlen(pointer.add(4093)), 4099);
    }
    println!("strlen tests PASS");
}
