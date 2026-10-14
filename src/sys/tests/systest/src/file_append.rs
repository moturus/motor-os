//! POSIX append mode: every write lands at the current end of the file, even
//! after the file shrinks or grows through another handle, and child
//! processes keep that behavior for an inherited stdout.

use std::io::{IoSlice, Write};

const PREFIX: &str = "file-append-";

fn spawn(
    args: &[&str],
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
) -> moto_rt::process::SpawnResult {
    moto_rt::process::spawn(moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        env: std::env::vars().collect(),
        cwd: None,
        stdin: moto_rt::process::STDIO_NULL,
        stdout,
        stderr,
    })
    .unwrap()
}

fn write_all(fd: moto_rt::RtFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        bytes = &bytes[moto_rt::fs::write(fd, bytes).unwrap()..];
    }
}

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg.starts_with(PREFIX))
}

pub fn run_child(args: &[String]) -> ! {
    match args[1].as_str() {
        "file-append-writer" => write_all(moto_rt::FD_STDOUT, b"+child"),
        "file-append-relay-parent" => relay_parent(&args[2]),
        "file-append-relay-writer" => {
            let attr = moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT).unwrap();
            assert_eq!(attr.file_type, moto_rt::fs::FILETYPE_FIFO);
            write_all(moto_rt::FD_STDOUT, b"out");
            write_all(moto_rt::FD_STDERR, b"err");
        }
        _ => panic!("unknown file-append child: {}", args[1]),
    }
    std::process::exit(0)
}

/// Shrink the file under this process's inherited stdout, then let a
/// grandchild write through relays on stdout and stderr.
fn relay_parent(path: &str) {
    write_all(moto_rt::FD_STDOUT, b"stale");
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(0)
        .unwrap();
    let child = spawn(
        &["file-append-relay-writer"],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_INHERIT,
    );
    assert_eq!(crate::wait_child(child.handle).unwrap(), 0);
}

fn direct_writes_follow_the_end() {
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
}

fn children_inherit_append() {
    let path = crate::temp_path("file-append-child");
    let path_str = path.to_str().unwrap();
    std::fs::write(&path, b"seed").unwrap();
    let append = moto_rt::fs::open(path_str, moto_rt::fs::O_APPEND).unwrap();
    // Shrink the file after the open so that only the append mode, not the
    // inherited offset, puts the child's write at the end.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(2)
        .unwrap();
    let child = spawn(
        &["file-append-writer"],
        append,
        moto_rt::process::STDIO_NULL,
    );
    assert_eq!(crate::wait_child(child.handle).unwrap(), 0);
    assert_eq!(std::fs::read(&path).unwrap(), b"se+child");

    let child = spawn(&["file-append-relay-parent", path_str], append, append);
    assert_eq!(crate::wait_child(child.handle).unwrap(), 0);
    moto_rt::fs::close(append).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        bytes == b"outerr" || bytes == b"errout",
        "relayed appends overlapped or left a gap: {bytes:?}"
    );
    std::fs::remove_file(&path).unwrap();
}

pub fn run_tests() {
    direct_writes_follow_the_end();
    children_inherit_append();
    println!("file_append tests PASS");
}
