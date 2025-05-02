use moto_ipc::stdio_pipe::StdioPipe;

fn test_stdio_pipe_basic() {
    use moto_sys::syscalls::*;
    std::thread::sleep(std::time::Duration::from_millis(1000));

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

pub fn run_all_tests() {
    test_stdio_pipe_basic();
    test_stdio_pipe_fd();
}
