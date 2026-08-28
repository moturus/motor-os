use moto_ipc::stdio_pipe::StdioPipe;

const INHERITED_RELAY_MIDDLE: &str = "stdio-inherited-relay-middle";
const INHERITED_RELAY_WRITER: &str = "stdio-inherited-relay-writer";
const INHERITED_RELAY_BYTES: usize = 64 * 1024 + 13;
const AFTER_INHERITED_RELAY: &[u8] = b"after-inherited-relay\n";
const INPUT_RECLAIM_PARENT: &str = "stdio-input-reclaim-parent";
const INPUT_RECLAIM_IDLE: &str = "stdio-input-reclaim-idle";
const INPUT_RECLAIM_BYTES: usize = 8 * 1024 + 37;
const INPUT_CLAIM_WAIT_PARENT: &str = "stdio-input-claim-wait-parent";

pub fn is_inherited_relay_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| {
        matches!(
            arg.as_str(),
            INHERITED_RELAY_MIDDLE | INHERITED_RELAY_WRITER
        )
    })
}

pub fn run_inherited_relay_child(args: &[String]) -> ! {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if args[1] == INHERITED_RELAY_WRITER {
        std::io::stdout()
            .write_all(&vec![b'x'; INHERITED_RELAY_BYTES])
            .unwrap();
        std::process::exit(0);
    }

    let status = Command::new(std::env::current_exe().unwrap())
        .arg(INHERITED_RELAY_WRITER)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    std::io::stdout().write_all(AFTER_INHERITED_RELAY).unwrap();
    std::process::exit(0);
}

pub fn test_wait_drains_inherited_output() {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(INHERITED_RELAY_MIDDLE)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).unwrap();
        output
    });
    assert!(child.wait().unwrap().success());
    let output = reader.join().unwrap();
    assert_eq!(
        output.len(),
        INHERITED_RELAY_BYTES + AFTER_INHERITED_RELAY.len()
    );
    assert!(
        output[..INHERITED_RELAY_BYTES]
            .iter()
            .all(|byte| *byte == b'x')
    );
    assert_eq!(&output[INHERITED_RELAY_BYTES..], AFTER_INHERITED_RELAY);
    println!("test_wait_drains_inherited_output PASS");
}

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

fn test_stdio_pipe_ctrl_c_scan() {
    use moto_ipc::stdio_pipe::CtrlCAction;
    use moto_sys::SysHandle;

    let (reader_data, writer_data) =
        moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();
    let ring_len = writer_data.buf_size >> 1;
    let reader = unsafe { StdioPipe::new_reader(reader_data) };
    let writer = unsafe { StdioPipe::new_writer(writer_data) };

    let full = vec![b'x'; ring_len];
    assert_eq!(writer.nonblocking_write(&full).unwrap(), ring_len);
    assert!(!writer.can_write());

    let batch = b"old\x03middle\x03tail";
    let mut actions = Vec::new();
    let consumed = writer
        .ctrl_c_scan(batch, |action| actions.push(action))
        .unwrap()
        .unwrap();
    assert_eq!(actions, [CtrlCAction::Default, CtrlCAction::Default]);
    assert_eq!(&batch[consumed..], b"tail");
    assert!(!writer.can_write());

    let mut drained = vec![0; ring_len];
    assert_eq!(reader.read(&mut drained).unwrap(), ring_len);
    assert_eq!(drained, full);

    let ordinary = b"a\x03b";
    assert_eq!(writer.write(ordinary).unwrap(), ordinary.len());
    let mut read = [0; 3];
    assert_eq!(reader.read(&mut read).unwrap(), read.len());
    assert_eq!(&read, ordinary);

    println!("test_stdio_pipe_ctrl_c_scan PASS");
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

fn test_child_stdout_reader_drop() {
    use std::io::{Read, Write};

    let mut child = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .env("some_key", "some_val")
        .env("none_key", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    child_stdin.write_all(b"write_until_closed\n").unwrap();
    child_stdin.flush().unwrap();
    let mut first_byte = [0];
    child_stdout.read_exact(&mut first_byte).unwrap();
    drop(child_stdout);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("child writer did not observe the dropped stdout reader");
        }
        std::thread::yield_now();
    }

    println!("test_child_stdout_reader_drop PASS");
}

fn positive_stdio_spawn_error(fd: moto_rt::RtFd) -> moto_rt::ErrorCode {
    let spawn_args = moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args: vec!["spawn-result-pid-child".to_owned()],
        env: std::env::vars().collect(),
        cwd: None,
        stdin: fd,
        stdout: moto_rt::process::STDIO_NULL,
        stderr: moto_rt::process::STDIO_NULL,
    };

    match moto_rt::process::spawn(spawn_args) {
        Err(err) => err.into(),
        Ok(_) => panic!("positive stdio fd unexpectedly succeeded"),
    }
}

pub fn is_stdio_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "pipe-stdio-vectored-child"
                | "file-stdio-child"
                | "file-relay-output-parent"
                | "file-relay-output-writer"
                | "file-relay-input-parent"
                | "file-relay-input-reader"
                | "file-relay-input-idle"
                | "file-relay-stdio-parent"
                | "file-stdio-marker-writer"
                | "self-stdio-close-child"
                | INPUT_RECLAIM_PARENT
                | INPUT_RECLAIM_IDLE
                | INPUT_CLAIM_WAIT_PARENT
        )
    })
}

pub fn run_stdio_child(args: &[String]) -> ! {
    match args[1].as_str() {
        "pipe-stdio-vectored-child" => run_pipe_stdio_vectored_child(),
        "file-stdio-child" => run_direct_file_stdio_child(args),
        "file-relay-output-parent" => run_file_relay_output_parent(),
        "file-relay-output-writer" => run_file_relay_output_writer(args),
        "file-relay-input-parent" => run_file_relay_input_parent(),
        "file-relay-input-reader" => run_file_relay_input_reader(),
        "file-relay-stdio-parent" => run_file_relay_stdio_parent(),
        "file-stdio-marker-writer" => run_file_stdio_marker_writer(args),
        "self-stdio-close-child" => run_self_stdio_close_child(),
        INPUT_RECLAIM_PARENT => run_input_reclaim_parent(),
        INPUT_CLAIM_WAIT_PARENT => run_input_claim_wait_parent(),
        INPUT_RECLAIM_IDLE => {
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::process::exit(0)
        }
        "file-relay-input-idle" => {
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::process::exit(0)
        }
        _ => unreachable!(),
    }
}

fn run_input_claim_wait_parent() -> ! {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(INPUT_RECLAIM_IDLE)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let reader = std::thread::spawn(|| {
        let mut byte = [0];
        std::io::stdin().read_exact(&mut byte).unwrap();
        byte
    });
    assert!(child.wait().unwrap().success());
    std::io::stdout()
        .write_all(&reader.join().unwrap())
        .unwrap();
    std::process::exit(0)
}

fn test_input_claim_waiter_wakes() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(INPUT_CLAIM_WAIT_PARENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"w").unwrap();
    let mut returned = [0];
    child
        .stdout
        .take()
        .unwrap()
        .read_exact(&mut returned)
        .unwrap();
    assert_eq!(&returned, b"w");
    drop(stdin);
    assert!(child.wait().unwrap().success());
    println!("test_input_claim_waiter_wakes PASS");
}

fn run_input_reclaim_parent() -> ! {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    for _ in 0..2 {
        let status = Command::new(std::env::current_exe().unwrap())
            .arg(INPUT_RECLAIM_IDLE)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    let mut returned = vec![0; INPUT_RECLAIM_BYTES];
    std::io::stdin().read_exact(&mut returned).unwrap();
    std::io::stdout().write_all(&returned).unwrap();
    std::process::exit(0)
}

fn test_inherited_input_reclaim_order() {
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};

    let expected: Vec<u8> = (0..INPUT_RECLAIM_BYTES)
        .map(|idx| (idx % 251) as u8)
        .collect();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(INPUT_RECLAIM_PARENT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer_bytes = expected.clone();
    let writer = std::thread::spawn(move || stdin.write_all(&writer_bytes).unwrap());
    let mut returned = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut returned)
        .unwrap();
    writer.join().unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(returned, expected);
    println!("test_inherited_input_reclaim_order PASS");
}

/// Vectored I/O on a descriptor kind with no native vectored path. Only
/// regular files and TCP streams implement one, so every other kind -- here a
/// child's own pipe-backed stdio, and the parent's end of that pipe -- relies
/// on the descriptor-table default serving the first non-empty buffer.
fn run_pipe_stdio_vectored_child() -> ! {
    let mut empty: [u8; 0] = [];
    let mut head = [0_u8; 2];
    let mut spare = [0_u8; 8];
    let mut bufs: [&mut [u8]; 3] = [&mut empty, &mut head, &mut spare];
    assert_eq!(
        moto_rt::fs::read_vectored(moto_rt::FD_STDIN, &mut bufs).unwrap(),
        2
    );
    assert_eq!(&head, b"he");
    let mut rest = [0_u8; 8];
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut rest).unwrap(), 3);
    assert_eq!(&rest[..3], b"llo");

    assert_eq!(
        moto_rt::fs::write_vectored(moto_rt::FD_STDOUT, &[b"".as_slice(), b"vec", b"tail"])
            .unwrap(),
        3
    );
    assert_eq!(moto_rt::fs::write(moto_rt::FD_STDOUT, b"tail").unwrap(), 4);
    assert_eq!(
        moto_rt::fs::write_vectored(moto_rt::FD_STDERR, &[b"".as_slice(), b"ERR"]).unwrap(),
        3
    );
    std::process::exit(0)
}

fn test_pipe_stdio_vectored() {
    use std::io::{IoSliceMut, Read, Write};

    let mut child = std::process::Command::new(std::env::args().next().unwrap())
        .arg("pipe-stdio-vectored-child")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"hello").unwrap();
    drop(stdin);

    let mut stdout = child.stdout.take().unwrap();
    let mut empty: [u8; 0] = [];
    let mut head = [0_u8; 3];
    let read = stdout
        .read_vectored(&mut [IoSliceMut::new(&mut empty), IoSliceMut::new(&mut head)])
        .unwrap();
    assert!(read > 0 && read <= head.len());
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    assert_eq!([&head[..read], rest.as_slice()].concat(), b"vectail");

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.ends_with("ERR"), "stderr: {stderr:?}");
    assert!(child.wait().unwrap().success());
    println!("test_pipe_stdio_vectored PASS");
}

fn run_direct_file_stdio_child(args: &[String]) -> ! {
    assert_eq!(args.len(), 3);
    let expected_entry_id = args[2].parse::<u128>().unwrap();
    let stdout_attr = moto_rt::fs::get_file_attr(moto_rt::FD_STDOUT).unwrap();
    let stderr_attr = moto_rt::fs::get_file_attr(moto_rt::FD_STDERR).unwrap();
    assert_eq!(stdout_attr.entry_id, expected_entry_id);
    assert_eq!(stderr_attr.entry_id, expected_entry_id);

    let mut input = [0_u8; 5];
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut input).unwrap(), 5);
    assert_eq!(&input, b"input");
    for (fd, bytes) in [
        (moto_rt::FD_STDOUT, b"out1".as_slice()),
        (moto_rt::FD_STDERR, b"err1".as_slice()),
        (moto_rt::FD_STDOUT, b"out2".as_slice()),
        (moto_rt::FD_STDERR, b"err2".as_slice()),
    ] {
        assert_eq!(moto_rt::fs::write(fd, bytes).unwrap(), bytes.len());
    }
    moto_rt::fs::flush(moto_rt::FD_STDOUT).unwrap();
    std::process::exit(0)
}

fn spawn_self_with_stdio(
    args: Vec<String>,
    stdin: moto_rt::RtFd,
    stdout: moto_rt::RtFd,
    stderr: moto_rt::RtFd,
) -> Result<moto_rt::process::SpawnResult, moto_rt::Error> {
    moto_rt::process::spawn(moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args,
        env: std::env::vars().collect(),
        cwd: None,
        stdin,
        stdout,
        stderr,
    })
}

fn run_file_relay_output_parent() -> ! {
    for byte in *b"AB" {
        let child = spawn_self_with_stdio(
            vec!["file-relay-output-writer".to_owned(), byte.to_string()],
            moto_rt::process::STDIO_NULL,
            moto_rt::process::STDIO_INHERIT,
            moto_rt::process::STDIO_NULL,
        )
        .unwrap();

        let err: moto_rt::ErrorCode =
            moto_rt::fs::seek(moto_rt::FD_STDOUT, 0, moto_rt::fs::SEEK_CUR)
                .unwrap_err()
                .into();
        assert_eq!(err, moto_rt::E_ALREADY_IN_USE);

        let mut waiters = Vec::new();
        for _ in 0..3 {
            let handle = child.handle;
            waiters.push(std::thread::spawn(move || {
                moto_rt::process::wait(handle).unwrap()
            }));
        }
        for waiter in waiters {
            assert_eq!(waiter.join().unwrap(), 0);
        }
    }
    std::process::exit(0)
}

fn run_file_relay_output_writer(args: &[String]) -> ! {
    assert_eq!(args.len(), 3);
    std::thread::sleep(std::time::Duration::from_millis(50));
    let byte = args[2].parse::<u8>().unwrap();
    let buf = vec![byte; 512 * 1024];
    let mut written = 0;
    while written < buf.len() {
        written += moto_rt::fs::write(moto_rt::FD_STDOUT, &buf[written..]).unwrap();
    }
    std::process::exit(0)
}

fn run_file_relay_input_parent() -> ! {
    let child = spawn_self_with_stdio(
        vec!["file-relay-input-reader".to_owned()],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
    )
    .unwrap();
    let mut byte = [0_u8; 1];
    let err: moto_rt::ErrorCode = moto_rt::fs::read(moto_rt::FD_STDIN, &mut byte)
        .unwrap_err()
        .into();
    assert_eq!(err, moto_rt::E_ALREADY_IN_USE);

    let overlap = match spawn_self_with_stdio(
        vec!["file-relay-input-idle".to_owned()],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    ) {
        Err(err) => err,
        Ok(_) => panic!("overlapping inherited stdin unexpectedly succeeded"),
    };
    let overlap: moto_rt::ErrorCode = overlap.into();
    assert_eq!(overlap, moto_rt::E_ALREADY_IN_USE);
    assert_eq!(moto_rt::process::wait(child.handle).unwrap(), 0);

    let mut next = [0_u8; 3];
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut next).unwrap(), 3);
    assert_eq!(&next, b"fgh");

    let idle = spawn_self_with_stdio(
        vec!["file-relay-input-idle".to_owned()],
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(idle.handle).unwrap(), 0);
    assert_eq!(moto_rt::fs::read(moto_rt::FD_STDIN, &mut next).unwrap(), 3);
    assert_eq!(&next, b"ijk");
    std::process::exit(0)
}

fn run_file_relay_input_reader() -> ! {
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut buf = [0_u8; 5];
    let mut read = 0;
    while read < buf.len() {
        read += moto_rt::fs::read(moto_rt::FD_STDIN, &mut buf[read..]).unwrap();
    }
    assert_eq!(&buf, b"abcde");
    std::process::exit(0)
}

fn marker_command(fd: moto_rt::RtFd, marker: u8) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("file-stdio-marker-writer")
        .arg(fd.to_string())
        .arg(marker.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

fn run_file_relay_stdio_parent() -> ! {
    let mut repeated = marker_command(moto_rt::FD_STDOUT, b'A');
    repeated.stdout(std::io::stdout());
    assert!(repeated.status().unwrap().success());
    assert!(repeated.status().unwrap().success());

    let mut cross_stdout = marker_command(moto_rt::FD_STDOUT, 1);
    cross_stdout.stdout(std::io::stderr());
    assert!(cross_stdout.status().unwrap().success());

    let mut cross_stderr = marker_command(moto_rt::FD_STDERR, b'C');
    cross_stderr.stderr(std::io::stdout());
    assert!(cross_stderr.status().unwrap().success());

    let mut stderr = marker_command(moto_rt::FD_STDERR, 2);
    stderr.stderr(std::io::stderr());
    assert!(stderr.status().unwrap().success());
    std::process::exit(0)
}

fn run_file_stdio_marker_writer(args: &[String]) -> ! {
    assert_eq!(args.len(), 4);
    let fd = args[2].parse::<moto_rt::RtFd>().unwrap();
    let marker = args[3].parse::<u8>().unwrap();
    assert_eq!(moto_rt::fs::write(fd, &[marker]).unwrap(), 1);
    std::process::exit(0)
}

fn run_self_stdio_close_child() -> ! {
    let duplicate = moto_rt::fs::duplicate(moto_rt::FD_STDOUT).unwrap();
    let registry = moto_rt::poll::new().unwrap();
    moto_rt::poll::add(
        registry,
        moto_rt::FD_STDOUT,
        91,
        moto_rt::poll::POLL_WRITABLE,
    )
    .unwrap();
    moto_rt::fs::close(moto_rt::FD_STDOUT).unwrap();

    let mut event = moto_rt::poll::Event::default();
    assert_eq!(
        moto_rt::poll::wait(
            registry,
            &mut event,
            1,
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_millis(10)),
        )
        .unwrap(),
        0
    );
    let poll_error: moto_rt::ErrorCode = moto_rt::poll::del(registry, moto_rt::FD_STDOUT)
        .unwrap_err()
        .into();
    assert_eq!(poll_error, moto_rt::E_INVALID_ARGUMENT);
    moto_rt::fs::close(registry).unwrap();

    for stdout in [
        moto_rt::process::STDIO_INHERIT,
        moto_rt::process::STDIO_PARENT_STDOUT,
    ] {
        let error = match spawn_self_with_stdio(
            vec!["spawn-result-pid-child".to_owned()],
            moto_rt::process::STDIO_NULL,
            stdout,
            moto_rt::process::STDIO_NULL,
        ) {
            Err(error) => error,
            Ok(_) => panic!("closed canonical stdout unexpectedly inherited"),
        };
        let error: moto_rt::ErrorCode = error.into();
        assert_eq!(error, moto_rt::E_BAD_HANDLE);
    }

    let error = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("spawn-result-pid-child")
        .stdin(std::process::Stdio::null())
        .stdout(std::io::stdout())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(moto_rt::E_BAD_HANDLE.into()));
    let error = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("spawn-result-pid-child")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::io::stdout())
        .spawn()
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(moto_rt::E_BAD_HANDLE.into()));

    assert_eq!(
        moto_rt::fs::write(duplicate, b"duplicate-still-open").unwrap(),
        20
    );
    moto_rt::fs::close(duplicate).unwrap();
    std::process::exit(0)
}

fn test_positive_file_stdio() {
    assert_eq!(positive_stdio_spawn_error(1_000_000), moto_rt::E_BAD_HANDLE);
    assert_eq!(
        positive_stdio_spawn_error(-123_456),
        moto_rt::E_INVALID_ARGUMENT
    );

    let input_path = crate::temp_path("systest-file-stdio-input");
    let output_path = crate::temp_path("systest-file-stdio-output");
    std::fs::write(&input_path, b"input").unwrap();
    let input_fd = moto_rt::fs::open(input_path.to_str().unwrap(), moto_rt::fs::O_READ).unwrap();
    let output_fd = moto_rt::fs::open(
        output_path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let stderr_fd = moto_rt::fs::duplicate(output_fd).unwrap();
    let output_entry_id = moto_rt::fs::get_file_attr(output_fd).unwrap().entry_id;

    let failed = match moto_rt::process::spawn(moto_rt::process::SpawnArgs {
        program: crate::temp_path("definitely-missing-positive-stdio-test")
            .to_string_lossy()
            .into_owned(),
        args: Vec::new(),
        env: std::env::vars().collect(),
        cwd: None,
        stdin: input_fd,
        stdout: output_fd,
        stderr: stderr_fd,
    }) {
        Err(error) => error,
        Ok(_) => panic!("spawn with a missing executable unexpectedly succeeded"),
    };
    let failed: moto_rt::ErrorCode = failed.into();
    assert_eq!(failed, moto_rt::E_NOT_FOUND);
    moto_rt::fs::get_file_attr(input_fd).unwrap();
    moto_rt::fs::get_file_attr(output_fd).unwrap();
    assert_eq!(
        moto_rt::fs::seek(output_fd, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        0
    );

    let result = moto_rt::process::spawn(moto_rt::process::SpawnArgs {
        program: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        args: vec!["file-stdio-child".to_owned(), output_entry_id.to_string()],
        env: std::env::vars().collect(),
        cwd: None,
        stdin: input_fd,
        stdout: output_fd,
        stderr: stderr_fd,
    })
    .unwrap();
    assert_eq!(result.stdin, moto_rt::process::STDIO_NULL);
    assert_eq!(result.stdout, moto_rt::process::STDIO_NULL);
    assert_eq!(result.stderr, moto_rt::process::STDIO_NULL);
    moto_rt::fs::get_file_attr(input_fd).unwrap();
    moto_rt::fs::get_file_attr(output_fd).unwrap();
    assert_eq!(moto_rt::process::wait(result.handle).unwrap(), 0);
    let output = std::fs::read(&output_path).unwrap();
    assert!(
        output.ends_with(b"out1err1out2err2"),
        "direct file stdio: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(
        moto_rt::fs::seek(input_fd, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        0
    );
    assert_eq!(
        moto_rt::fs::seek(output_fd, 0, moto_rt::fs::SEEK_CUR).unwrap(),
        0
    );

    moto_rt::fs::close(stderr_fd).unwrap();
    moto_rt::fs::close(output_fd).unwrap();
    moto_rt::fs::close(input_fd).unwrap();
    assert_eq!(positive_stdio_spawn_error(input_fd), moto_rt::E_BAD_HANDLE);
    std::fs::remove_file(&input_path).unwrap();
    std::fs::remove_file(&output_path).unwrap();

    let addr: core::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socket_fd = moto_rt::net::bind(moto_rt::net::PROTO_UDP, &addr.into()).unwrap();
    assert_eq!(
        positive_stdio_spawn_error(socket_fd),
        moto_rt::E_NOT_IMPLEMENTED
    );
    moto_rt::fs::close(socket_fd).unwrap();

    println!("test_positive_file_stdio PASS");
}

fn test_inherited_file_relays() {
    let output_path = crate::temp_path("systest-file-relay-output");
    let input_path = crate::temp_path("systest-file-relay-input");
    let output_fd = moto_rt::fs::open(
        output_path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let output_parent = spawn_self_with_stdio(
        vec!["file-relay-output-parent".to_owned()],
        moto_rt::process::STDIO_NULL,
        output_fd,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(output_parent.handle).unwrap(), 0);
    let output = std::fs::read(&output_path).unwrap();
    assert_eq!(output.len(), 1024 * 1024);
    assert!(output[..512 * 1024].iter().all(|byte| *byte == b'A'));
    assert!(output[512 * 1024..].iter().all(|byte| *byte == b'B'));
    moto_rt::fs::close(output_fd).unwrap();

    std::fs::write(&input_path, b"abcdefghijklmnopqrstuvwxyz").unwrap();
    let input_fd = moto_rt::fs::open(input_path.to_str().unwrap(), moto_rt::fs::O_READ).unwrap();
    let input_parent = spawn_self_with_stdio(
        vec!["file-relay-input-parent".to_owned()],
        input_fd,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_INHERIT,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(input_parent.handle).unwrap(), 0);
    moto_rt::fs::close(input_fd).unwrap();
    std::fs::remove_file(&input_path).unwrap();
    std::fs::remove_file(&output_path).unwrap();
    println!("test_inherited_file_relays PASS");
}

fn test_std_file_and_parent_stream_stdio() {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};

    let direct_path = crate::temp_path("systest-std-direct-file");
    let stdout_path = crate::temp_path("systest-stdio-parent-stdout");
    let stderr_path = crate::temp_path("systest-stdio-parent-stderr");

    let direct = std::fs::File::create(&direct_path).unwrap();
    let direct_fd = direct.as_raw_fd();
    let mut command = marker_command(moto_rt::FD_STDOUT, b'Z');
    command.stdout(std::process::Stdio::from(direct));
    assert!(command.status().unwrap().success());
    assert!(command.status().unwrap().success());
    moto_rt::fs::get_file_attr(direct_fd).unwrap();
    assert_eq!(std::fs::read(&direct_path).unwrap(), b"Z");

    let stdout_fd = moto_rt::fs::open(
        stdout_path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let stderr_fd = moto_rt::fs::open(
        stderr_path.to_str().unwrap(),
        moto_rt::fs::O_CREATE | moto_rt::fs::O_TRUNCATE | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    let parent = spawn_self_with_stdio(
        vec!["file-relay-stdio-parent".to_owned()],
        moto_rt::process::STDIO_NULL,
        stdout_fd,
        stderr_fd,
    )
    .unwrap();
    assert_eq!(moto_rt::process::wait(parent.handle).unwrap(), 0);
    assert_eq!(std::fs::read(&stdout_path).unwrap(), b"AAC");
    let stderr_markers: Vec<_> = std::fs::read(&stderr_path)
        .unwrap()
        .into_iter()
        .filter(|byte| matches!(byte, 1 | 2))
        .collect();
    assert_eq!(stderr_markers, [1, 2]);
    moto_rt::fs::close(stdout_fd).unwrap();
    moto_rt::fs::close(stderr_fd).unwrap();

    let mismatch = match spawn_self_with_stdio(
        vec!["spawn-result-pid-child".to_owned()],
        moto_rt::process::STDIO_PARENT_STDOUT,
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_NULL,
    ) {
        Err(error) => error,
        Ok(_) => panic!("output stream unexpectedly accepted as child stdin"),
    };
    let mismatch: moto_rt::ErrorCode = mismatch.into();
    assert_eq!(mismatch, moto_rt::E_INVALID_ARGUMENT);

    let close_child = spawn_self_with_stdio(
        vec!["self-stdio-close-child".to_owned()],
        moto_rt::process::STDIO_NULL,
        moto_rt::process::STDIO_MAKE_PIPE,
        moto_rt::process::STDIO_NULL,
    )
    .unwrap();
    let mut output = unsafe { std::fs::File::from_raw_fd(close_child.stdout) };
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert_eq!(moto_rt::process::wait(close_child.handle).unwrap(), 0);
    assert_eq!(bytes, b"duplicate-still-open");

    for path in [&direct_path, &stdout_path, &stderr_path] {
        std::fs::remove_file(path).unwrap();
    }
    println!("test_std_file_and_parent_stream_stdio PASS");
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
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_millis(15))
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

    // Check that we have one readable event on stdout.
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

    // Check that we have one readable event on stderr.
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
    // Put some bytes into child_stderr, and don't close until the event they
    // raise is queued -- otherwise whether the close has anything to clean up
    // is a race with the child. A second registry on the same fd is the way to
    // see the event without draining it: one source posts to every registry
    // watching it under one lock, oldest id first, so `registry` has its copy
    // by the time the younger `witness` reports one.
    let witness = moto_rt::poll::new().unwrap();
    moto_rt::poll::add(witness, raw_fd, STDERR, READABLE).unwrap();
    child_stdin.write_all(msg2).unwrap();
    assert_eq!(
        1,
        moto_rt::poll::wait(witness, (&mut events) as *mut _, 3, None).unwrap()
    );
    assert_eq!(events[0].token, STDERR);
    moto_rt::fs::close(witness).unwrap();

    drop(child_stderr); // This closes the FD.
    let mut child_stderr = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    assert!(child_stderr.read(&mut buf).is_err());

    // Because we closed stderr "on our side", no events are polled.
    assert_eq!(
        0,
        moto_rt::poll::wait(
            registry,
            (&mut events) as *mut _,
            3,
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_millis(15))
        )
        .unwrap()
    );

    // Stop polling stderr.
    moto_rt::poll::del(registry, raw_fd).unwrap();

    assert_eq!(
        0,
        moto_rt::poll::wait(
            registry,
            (&mut events) as *mut _,
            3,
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_millis(15))
        )
        .unwrap()
    );

    // Tell child to exit.
    child_stdin.write_all(b"exit 0\n").unwrap();
    while child_stdin.flush().is_err() {}
    child.wait().unwrap();

    // Stdout is now closed "on the remote side", so we see an event.
    assert_eq!(
        1,
        moto_rt::poll::wait(
            registry,
            (&mut events) as *mut _,
            3,
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_millis(15))
        )
        .unwrap()
    );

    assert_eq!(events[0].token, STDOUT);
    assert_eq!(events[0].events, moto_rt::poll::POLL_READ_CLOSED);

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

fn test_stdio_pipe_take_unread() {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use moto_sys::SysHandle;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();
    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };
    assert_eq!(writer.write(b"abcdef").unwrap(), 6);
    let mut prefix = [0; 2];
    assert_eq!(reader.read(&mut prefix).unwrap(), 2);
    assert_eq!(&prefix, b"ab");
    assert_eq!(writer.take_unread().unwrap(), b"cdef");

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();
    let writer_addr = d2.buf_addr;
    let ring_len = d2.buf_size >> 1;
    let _reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };
    let counter = |offset| unsafe { &*((writer_addr + offset) as *const AtomicUsize) };

    counter(0).store(2, Ordering::SeqCst);
    counter(64).store(1, Ordering::SeqCst);
    assert_eq!(writer.take_unread(), Err(moto_rt::E_INVALID_ARGUMENT));
    counter(0).store(0, Ordering::SeqCst);
    counter(64).store(ring_len + 1, Ordering::SeqCst);
    assert_eq!(writer.take_unread(), Err(moto_rt::E_INVALID_ARGUMENT));

    println!("test_stdio_pipe_take_unread PASS");
}

fn test_stdio_reader_wake_on_writer_drop() {
    use moto_sys::SysHandle;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };

    let reader_thread = std::thread::spawn(move || {
        loop {
            let mut buf = [0; 64];

            let Ok(read) = reader.read(&mut buf) else {
                break;
            };
            if read == 0 {
                break;
            }
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

fn test_stdio_reader_drains_after_writer_drop() {
    use moto_sys::SysHandle;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };

    let _ = writer.write(b"left behind").unwrap();
    core::mem::drop(writer);

    // The writer is gone, but its bytes are still ours to deliver: a short-lived
    // child (`echo hi`) has usually exited by the time its output is read, so
    // losing them here loses the output of `foo | cat` and `ssh host 'echo hi'`.
    let mut buf = [0; 64];
    let sz = reader.nonblocking_read(&mut buf).unwrap();
    assert_eq!(&buf[0..sz], b"left behind");

    // Only once there is nothing left does the reader learn the writer is gone.
    assert!(reader.nonblocking_read(&mut buf).is_err());

    println!("test_stdio_reader_drains_after_writer_drop PASS");
}

fn test_stdio_writer_wake_on_reader_drop() {
    use moto_sys::SysHandle;

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let reader = unsafe { StdioPipe::new_reader(d1) };
    let writer = unsafe { StdioPipe::new_writer(d2) };

    let writer_thread = std::thread::spawn(move || {
        loop {
            let buf = [0; 64];

            let Ok(written) = writer.write(&buf) else {
                break;
            };
            if written == 0 {
                break;
            }
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

/// A process can poll its *own* stdio, not only a child's.
///
/// The asymmetry this covers is what kept a program from waiting a few
/// milliseconds for an answer to a query it had just written to the terminal:
/// `SelfStdio` had `read`/`write` and nothing else, so `poll` on fd 0 fell
/// through to the not-pollable default.
fn test_self_stdio_poll() {
    use std::io::BufRead;
    use std::io::Write;

    fn next_line(out: &mut std::io::BufReader<std::process::ChildStdout>) -> String {
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        line.trim_end().to_owned()
    }

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
    let mut child_stdout = std::io::BufReader::new(child.stdout.take().unwrap());

    child_stdin.write_all(b"poll_self_stdio\n").unwrap();
    child_stdin.flush().unwrap();
    assert_eq!("poll_self_stdio: idle", next_line(&mut child_stdout));

    // Nothing else is in flight, so this write is what the child's poll wakes on.
    child_stdin.write_all(b"echo1 poked\n").unwrap();
    child_stdin.flush().unwrap();
    assert_eq!("poll_self_stdio: readable", next_line(&mut child_stdout));
    assert_eq!("echo1 poked", next_line(&mut child_stdout));

    child_stdin.write_all(b"exit 0\n").unwrap();
    child_stdin.flush().unwrap();
    assert!(child.wait().unwrap().success());

    println!("test_self_stdio_poll PASS");
}

/// A process reading its own stdin under a poll of it, round after round:
/// `poll_stress` waits for each arrival, `read_stress` only registers and
/// then reads. Either way the child has two threads on one handle -- its
/// own, and the readiness task the registration spawned.
pub fn poll_stress(cmd: &str, rounds: usize) {
    use std::io::Read;
    use std::io::Write;

    let mut child = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .env("some_key", "some_val")
        .env("none_key", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();

    child_stdin
        .write_all(format!("{cmd} {rounds}\n").as_bytes())
        .unwrap();
    child_stdin.flush().unwrap();

    let mut ready = vec![0_u8; cmd.len() + 8];
    child_stdout.read_exact(&mut ready).unwrap();
    assert_eq!(format!("{cmd}: ready\n").as_bytes(), ready.as_slice());

    // The writer waits for each chunk to be taken but not for the echo, so
    // the next chunk lands on a child that has just drained its stdin --
    // the window in which a readiness bit cleared after the draining read
    // takes the arrival with it.
    let writer = std::thread::spawn(move || {
        for round in 0..rounds {
            child_stdin
                .write_all(format!("{round:07}.").as_bytes())
                .unwrap();
            child_stdin.flush().unwrap();
            if round % 3 == 0 {
                moto_sys::SysCpu::sched_yield();
            }
        }
        child_stdin
    });

    for round in 0..rounds {
        let mut echo = [0_u8; 8];
        child_stdout.read_exact(&mut echo).unwrap();
        assert_eq!(format!("{round:07}.").as_bytes(), &echo);
    }
    let mut child_stdin = writer.join().unwrap();

    let mut done = vec![0_u8; cmd.len() + 7];
    child_stdout.read_exact(&mut done).unwrap();
    assert_eq!(format!("{cmd}: done\n").as_bytes(), done.as_slice());

    child_stdin.write_all(b"exit 0\n").unwrap();
    child_stdin.flush().unwrap();
    assert!(child.wait().unwrap().success());

    println!("{cmd} PASS");
}

/// The same question from the other side of the pipe: a parent polling a
/// *child's* stdout while the child writes as fast as it can.
pub fn child_poll_stress(rounds: usize) {
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    const STDOUT_TOKEN: u64 = 75;

    let mut child = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .env("some_key", "some_val")
        .env("none_key", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    moto_rt::net::set_nonblocking(child_stdout.as_raw_fd(), true).unwrap();

    let registry = moto_rt::poll::new().unwrap();
    let mut events = [moto_rt::poll::Event::default(); 1];
    moto_rt::poll::add(
        registry,
        child_stdout.as_raw_fd(),
        STDOUT_TOKEN,
        moto_rt::poll::POLL_READABLE,
    )
    .unwrap();

    child_stdin
        .write_all(format!("spew {rounds}\n").as_bytes())
        .unwrap();
    child_stdin.flush().unwrap();

    let total = rounds * 8;
    let mut seen = 0_usize;
    let mut buf = [0_u8; 64];
    while seen < total {
        let woke = moto_rt::poll::wait(
            registry,
            (&mut events) as *mut _,
            1,
            Some(moto_rt::time::Instant::now() + std::time::Duration::from_secs(10)),
        )
        .unwrap();
        assert_eq!(
            1, woke,
            "child_poll_stress: no readable event at {seen}/{total}"
        );

        loop {
            match child_stdout.read(&mut buf) {
                Ok(sz) => seen += sz,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("child_poll_stress: {err:?}"),
            }
        }
    }

    moto_rt::fs::close(registry).unwrap();
    child_stdin.write_all(b"exit 0\n").unwrap();
    child_stdin.flush().unwrap();
    assert!(child.wait().unwrap().success());

    println!("child_poll_stress PASS");
}

pub fn run_all_tests() {
    test_stdio_pipe_basic();
    test_stdio_pipe_ctrl_c_scan();
    test_stdio_pipe_fd();
    test_child_stdout_reader_drop();
    test_pipe_stdio_vectored();
    test_positive_file_stdio();
    test_inherited_file_relays();
    test_std_file_and_parent_stream_stdio();
    test_stdio_pipe_async_fd();
    test_self_stdio_poll();
    poll_stress("poll_stress", 4000);
    poll_stress("read_stress", 4000);
    child_poll_stress(4000);
    test_stdio_pipe_flush();
    test_stdio_pipe_take_unread();
    crate::stdio_terminal::run_all_tests();
    test_stdio_reader_wake_on_writer_drop();
    test_stdio_reader_drains_after_writer_drop();
    test_stdio_writer_wake_on_reader_drop();
    test_inherited_input_reclaim_order();
    test_input_claim_waiter_wakes();
    test_wait_drains_inherited_output();
}
