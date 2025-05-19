use moto_ipc::stdio_pipe::StdioPipe;

fn test_stdio_pipe_basic() {
    use moto_sys::syscalls::*;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };

    let reader_thread = std::thread::spawn(move || {
        let mut step = 1_usize;
        loop {
            let mut buf: Vec<u8> = vec![0; step % 8176 + 17];

            let read = reader.read(buf.as_mut_slice()).unwrap();
            assert!(read > 0);
            if buf[read - 1] == 0 {
                break;
            }

            step += 1;
        }

        reader.total_read()
    });

    let writer_thread = std::thread::spawn(move || {
        for step in 1_usize..8000_usize {
            let mut buf = vec![];

            for _idx in 0..step {
                buf.push(7_u8);
            }
            assert_eq!(writer.write(buf.as_slice()).unwrap(), step);
        }

        assert_eq!(1, writer.write(&[0_u8; 1]).unwrap());
        writer.total_written()
    });

    let read = reader_thread.join().unwrap();
    let written = writer_thread.join().unwrap();

    assert_eq!(read, written);

    println!("test_stdio_pipe_basic PASS");
}

fn test_stdio_pipe_fd() {
    use std::io::Read;
    use std::io::Write;

    let mut child = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .env("some_key", "some_val")
        .env("none_key", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    let mut buf = [0; 64];

    // Test normal read/write.
    let msg1 = b"echo1 foo bar baz\n";
    child_stdin.write_all(msg1).unwrap();
    child_stdout.read_exact(&mut buf[0..msg1.len()]).unwrap();
    assert_eq!(msg1, &buf[0..msg1.len()]);

    let msg2 = b"echo2 blah blah blah\n";
    child_stdin.write_all(msg2).unwrap();
    child_stderr.read_exact(&mut buf[0..msg2.len()]).unwrap();
    assert_eq!(msg2, &buf[0..msg2.len()]);

    // Test read/write through fd.
    use std::os::fd::{FromRawFd, IntoRawFd};

    let raw_fd = child_stdin.into_raw_fd();
    let mut child_stdin = unsafe { std::fs::File::from_raw_fd(raw_fd) };

    let raw_fd = child_stdout.into_raw_fd();
    let mut child_stdout = unsafe { std::fs::File::from_raw_fd(raw_fd) };

    let raw_fd = child_stderr.into_raw_fd();
    let mut child_stderr = unsafe { std::fs::File::from_raw_fd(raw_fd) };

    let msg1 = b"echo1 foo bar baz\n";
    child_stdin.write_all(msg1).unwrap();
    child_stdout.read_exact(&mut buf[0..msg1.len()]).unwrap();
    assert_eq!(msg1, &buf[0..msg1.len()]);

    let msg2 = b"echo2 blah blah blah\n";
    child_stdin.write_all(msg2).unwrap();
    child_stderr.read_exact(&mut buf[0..msg2.len()]).unwrap();
    assert_eq!(msg2, &buf[0..msg2.len()]);

    // Test that close() works.
    drop(child_stderr); // This closes the FD.
    let mut child_stderr = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    assert!(child_stderr.read(&mut buf).is_err());

    child_stdin.write_all(b"exit 0\n").unwrap();
    child_stdin.flush().unwrap();
    child.wait().unwrap();

    println!("test_stdio_pipe_fd PASS");
}

fn test_stdio_pipe_async_fd() {
    use std::io::Read;
    use std::io::Write;

    let mut child = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .env("some_key", "some_val")
        .env("none_key", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let child_stderr = child.stderr.take().unwrap();

    let mut buf = [0; 64];

    // Test read/write through fd.
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

    let raw_fd = child_stdin.into_raw_fd();
    let mut child_stdin = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    moto_rt::net::set_nonblocking(child_stdin.as_raw_fd(), true).unwrap();

    let raw_fd = child_stdout.into_raw_fd();
    let mut child_stdout = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    moto_rt::net::set_nonblocking(child_stdout.as_raw_fd(), true).unwrap();

    let raw_fd = child_stderr.into_raw_fd();
    let mut child_stderr = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    moto_rt::net::set_nonblocking(child_stderr.as_raw_fd(), true).unwrap();

    const STDIN: u64 = 20;
    const STDOUT: u64 = 21;
    const STDERR: u64 = 22;

    const READABLE: u64 = moto_rt::poll::POLL_READABLE;
    const WRITABLE: u64 = moto_rt::poll::POLL_WRITABLE;

    let registry = moto_rt::poll::new().unwrap();

    let mut events = [moto_rt::poll::Event::default(); 3];

    moto_rt::poll::add(registry, child_stdout.as_raw_fd(), STDOUT, READABLE).unwrap();
    assert!(moto_rt::poll::add(registry, child_stdout.as_raw_fd(), STDOUT, WRITABLE).is_err());

    moto_rt::poll::add(registry, child_stderr.as_raw_fd(), STDERR, READABLE).unwrap();
    assert!(moto_rt::poll::add(registry, child_stderr.as_raw_fd(), STDERR, WRITABLE).is_err());

    // Nothing to read.
    assert_eq!(
        0,
        moto_rt::poll::wait(
            registry,
            (&mut events) as *mut _,
            3,
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_millis(1))
        )
        .unwrap()
    );

    assert_eq!(
        std::io::ErrorKind::WouldBlock,
        child_stdout.read(&mut buf).err().unwrap().kind()
    );

    assert_eq!(
        std::io::ErrorKind::WouldBlock,
        child_stderr.read(&mut buf).err().unwrap().kind()
    );

    // But we can write.
    moto_rt::poll::add(registry, child_stdin.as_raw_fd(), STDIN, WRITABLE).unwrap();
    assert!(moto_rt::poll::add(registry, child_stdin.as_raw_fd(), STDIN, READABLE).is_err());
    assert_eq!(
        1,
        moto_rt::poll::wait(registry, (&mut events) as *mut _, 3, None).unwrap()
    );

    assert_eq!(events[0].token, STDIN);
    assert_eq!(events[0].events, WRITABLE);

    let msg1 = b"echo1 foo bar baz\n";
    child_stdin.write_all(msg1).unwrap();

    // Stop polling stdin.
    moto_rt::poll::del(registry, child_stdin.as_raw_fd()).unwrap();

    // Check that we have one reatable event on stdout.
    assert_eq!(
        1,
        moto_rt::poll::wait(registry, (&mut events) as *mut _, 3, None).unwrap()
    );
    assert_eq!(events[0].token, STDOUT);
    assert_eq!(events[0].events, READABLE);

    let mut sz = 0;
    while sz < msg1.len() {
        sz += child_stdout.read(&mut buf[sz..msg1.len()]).unwrap_or(0);
    }
    assert_eq!(msg1, &buf[0..msg1.len()]);
    assert_eq!(
        std::io::ErrorKind::WouldBlock,
        child_stdout.read(&mut buf).err().unwrap().kind()
    );

    let msg2 = b"echo2 blah blah blah\n";
    child_stdin.write_all(msg2).unwrap();

    // Check that we have one reatable event on stderr.
    assert_eq!(
        1,
        moto_rt::poll::wait(registry, (&mut events) as *mut _, 3, None).unwrap()
    );
    assert_eq!(events[0].token, STDERR);
    assert_eq!(events[0].events, READABLE);

    let mut sz = 0;
    while sz < msg2.len() {
        sz += child_stderr.read(&mut buf[sz..msg2.len()]).unwrap_or(0);
    }
    assert_eq!(msg2, &buf[0..msg2.len()]);
    assert_eq!(
        std::io::ErrorKind::WouldBlock,
        child_stderr.read(&mut buf).err().unwrap().kind()
    );

    // Test that close() works.
    // Put some bytes into child_stderr.
    child_stdin.write_all(msg2).unwrap();
    drop(child_stderr); // This closes the FD.
    let mut child_stderr = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    assert!(child_stderr.read(&mut buf).is_err());

    // Nothing to read.
    assert_eq!(
        0,
        moto_rt::poll::wait(
            registry,
            (&mut events) as *mut _,
            3,
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_millis(1))
        )
        .unwrap()
    );

    child_stdin.write_all(b"exit 0\n").unwrap();
    while child_stdin.flush().is_err() {}
    child.wait().unwrap();

    moto_rt::fs::close(registry).unwrap();

    println!("test_stdio_pipe_async_fd PASS");
}

fn test_stdio_pipe_flush() {
    use moto_sys::syscalls::*;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };

    let (sender, receiver) = std::sync::mpsc::channel();

    let writer_thread = std::thread::spawn(move || {
        let buf = b"foobar";
        assert_eq!(writer.write(buf).unwrap(), buf.len());
        assert_eq!(
            writer.flush_nonblocking().err().unwrap(),
            moto_rt::E_NOT_READY
        );
        sender.send(()).unwrap();
        writer.flush().unwrap();
        assert!(writer.flush_nonblocking().is_ok());
    });

    // Wait a bit.
    receiver.recv().unwrap();
    let mut buf = [0; 64];
    let _ = reader.read(&mut buf).unwrap();
    writer_thread.join().unwrap();

    println!("test_stdio_pipe_flush PASS");
}

fn test_stdio_is_terminal() {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        println!("test_stdio_is_terminal: SKIPPED");
        return;
    }

    // This spawns a piped ChildStdio, and by default it is not a terminal.
    let mut child = crate::subcommand::spawn();
    assert!(!child.is_terminal());

    println!("test_stdio_is_terminal PASS");
}

fn test_stdio_reader_wake_on_writer_drop() {
    use moto_sys::SysHandle;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };

    let reader_thread = std::thread::spawn(move || loop {
        let mut buf = [0; 64];

        let Ok(read) = reader.read(&mut buf) else {
            break;
        };
        if read == 0 {
            break;
        }
    });

    let buf = [0; 64];
    let _ = writer.write(&buf).unwrap();

    // Sleep a bit to let the reader go into wait().
    std::thread::sleep(std::time::Duration::from_millis(20));
    core::mem::drop(writer);

    reader_thread.join().unwrap();

    println!("test_stdio_reader_wake_on_writer_drop PASS");
}

fn test_stdio_writer_wake_on_reader_drop() {
    use moto_sys::SysHandle;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };

    let writer_thread = std::thread::spawn(move || loop {
        let buf = [0; 64];

        let Ok(written) = writer.write(&buf) else {
            break;
        };
        if written == 0 {
            break;
        }
    });

    let mut buf = [0; 64];
    let _ = reader.read(&mut buf).unwrap();

    // Sleep a bit to let the writer go into wait().
    std::thread::sleep(std::time::Duration::from_millis(20));
    core::mem::drop(reader);

    writer_thread.join().unwrap();

    println!("test_stdio_writer_wake_on_reader_drop PASS");
}

pub fn run_all_tests() {
    test_stdio_pipe_basic();
    test_stdio_pipe_fd();
    test_stdio_pipe_async_fd();
    test_stdio_pipe_flush();
    test_stdio_is_terminal();
    test_stdio_reader_wake_on_writer_drop();
    test_stdio_writer_wake_on_reader_drop();
}
