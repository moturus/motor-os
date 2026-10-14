//! Append mode: every write through an append handle lands at the current
//! end of the file, even after the file shrinks or grows through any handle.

use std::io::{IoSlice, Write};

pub fn run_tests() {
    let path = crate::temp_path("file-append-direct");
    std::fs::write(&path, b"xy").unwrap();
    let mut append = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(&path)
        .unwrap();
    append.write_all(b"a\n").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"xya\n");

    append.set_len(1).unwrap();
    append.write_all(b"b\n").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"xb\n");

    let mut other = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    other.write_all(b"0123").unwrap();
    append.write_all(b"c").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"0123c");
    other.set_len(2).unwrap();
    let written = append
        .write_vectored(&[IoSlice::new(b"d"), IoSlice::new(b"e")])
        .unwrap();
    assert_eq!(written, 2);
    assert_eq!(std::fs::read(&path).unwrap(), b"01de");
    std::fs::remove_file(&path).unwrap();
    println!("file_append tests PASS");
}
