#![feature(start, libc)]
#![no_std]

extern crate libc;
extern crate x86;

#[start]
fn start(_argc: isize, _argv: *const *const u8) -> isize {
    0
}
