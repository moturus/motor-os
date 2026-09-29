//! `moto_rt::net::peek` on a process's own stdio: what a read would return,
//! without consuming it and without waiting for it.
//!
//! Each reader is a spawned child, since only a child's stdio is a pipe this
//! test can write. A single write lands in the ring whole, so once a child has
//! read the first byte of one, the rest is waiting.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use moto_rt::{FD_STDIN, FD_STDOUT, FD_TERMINAL, RtFd};

const PEEK_CHILD: &str = "stdio-peek-child";
const PEEK_IDLE: &str = "stdio-peek-idle";
const PEEK_TERMINAL_PARENT: &str = "stdio-peek-terminal-parent";
const PEEK_TERMINAL_CHILD: &str = "stdio-peek-terminal-child";
const PEEK_WRITER: &str = "stdio-peek-writer-parent";
const PEEK_LOSS_READER: &str = "stdio-peek-loss-reader";

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| {
        matches!(
            arg.as_str(),
            PEEK_CHILD
                | PEEK_IDLE
                | PEEK_TERMINAL_PARENT
                | PEEK_TERMINAL_CHILD
                | PEEK_WRITER
                | PEEK_LOSS_READER
        )
    })
}

pub fn run_child(args: &[String]) -> ! {
    match args[1].as_str() {
        PEEK_CHILD => run_peek_child(&args[2]),
        PEEK_IDLE => run_peek_idle(&args[2]),
        PEEK_TERMINAL_PARENT => run_terminal_parent(),
        PEEK_TERMINAL_CHILD => run_terminal_child(),
        PEEK_WRITER => run_writer(&args[2], &args[3], &args[4]),
        PEEK_LOSS_READER if args[4] == "polled" => run_loss_reader(&args[2], &args[3]),
        PEEK_LOSS_READER => run_unregistered_loss_reader(&args[2], &args[3], &args[4]),
        _ => unreachable!(),
    }
}

fn peek(fd: RtFd, len: usize) -> Result<Vec<u8>, moto_rt::Error> {
    let mut buf = vec![0; len];
    let sz = moto_rt::net::peek(fd, &mut buf)?;
    buf.truncate(sz);
    Ok(buf)
}

fn read(fd: RtFd, len: usize) -> Vec<u8> {
    let mut buf = vec![0; len];
    let sz = moto_rt::fs::read(fd, &mut buf).unwrap();
    buf.truncate(sz);
    buf
}

fn say(line: &str) {
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{line}").unwrap();
    stdout.flush().unwrap();
}

fn expect_line(stdout: &mut BufReader<std::process::ChildStdout>, expected: &str) {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim_end(), expected);
}

fn run_peek_child(release: &str) -> ! {
    assert_eq!(peek(FD_STDOUT, 1), Err(moto_rt::Error::InvalidArgument));
    assert_eq!(peek(FD_STDIN, 8), Err(moto_rt::Error::NotReady));
    say("empty");

    assert_eq!(read(FD_STDIN, 1), b"X");
    assert_eq!(peek(FD_STDIN, 8).unwrap(), b"abc");
    assert_eq!(peek(FD_STDIN, 8).unwrap(), b"abc");
    assert_eq!(peek(FD_STDIN, 2).unwrap(), b"ab");
    assert_eq!(read(FD_STDIN, 8), b"abc");
    assert_eq!(peek(FD_STDIN, 8), Err(moto_rt::Error::NotReady));

    // The relay to a child that exits without reading hands its bytes back
    // to this process's stash; waiting for the child waits for the relay.
    // Until then the bytes are the child's, and a peek here says so at once
    // rather than waiting for the relay to give the reader back.
    let idle_release = std::path::Path::new(release).with_extension("idle");
    let mut idle = Command::new(std::env::current_exe().unwrap())
        .arg(PEEK_IDLE)
        .arg(&idle_release)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut idle_out = BufReader::new(idle.stdout.take().unwrap());
    say("spawned");
    expect_line(&mut idle_out, "seen");
    assert_eq!(peek_without_waiting(), Err(moto_rt::Error::NotReady));
    std::fs::write(&idle_release, b"").unwrap();
    assert!(idle.wait().unwrap().success());
    assert_eq!(peek(FD_STDIN, 8).unwrap(), b"S1");
    say("stashed");

    // The parent has written more and closed its end by the time it
    // releases this: the stash comes first, and a closed writer's bytes are
    // still there before the end of input.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !std::path::Path::new(release).exists() {
        assert!(std::time::Instant::now() < deadline, "no release");
        std::thread::yield_now();
    }
    assert_eq!(peek(FD_STDIN, 8).unwrap(), b"S1R2");
    assert_eq!(read(FD_STDIN, 8), b"S1");
    assert_eq!(read(FD_STDIN, 8), b"R2");
    assert_eq!(peek(FD_STDIN, 8).unwrap(), b"");
    std::process::exit(0)
}

/// A peek of this process's stdin, failed if it waits: a peek never may.
fn peek_without_waiting() -> Result<Vec<u8>, moto_rt::Error> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(peek(FD_STDIN, 8)));
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("a peek waited while a child owned stdin")
}

/// Waits until its inherited stdin has input, says so, and stays until
/// released, then exits without having read it.
fn run_peek_idle(release: &str) -> ! {
    let registry = moto_rt::poll::new().unwrap();
    moto_rt::poll::add(registry, FD_STDIN, 1, moto_rt::poll::POLL_READABLE).unwrap();
    let mut events = [moto_rt::poll::Event::default(); 1];
    let deadline = moto_rt::time::Instant::now() + std::time::Duration::from_secs(5);
    let ready = moto_rt::poll::wait(registry, events.as_mut_ptr(), 1, Some(deadline)).unwrap();
    assert_eq!(ready, 1, "no input");
    say("seen");
    wait_for_file(
        std::path::Path::new(release),
        "the idle child was not released",
    );
    std::process::exit(0)
}

/// A terminal-backed process: the child it spawns with a piped stdin reads
/// this process's terminal through its own `FD_TERMINAL`.
fn run_terminal_parent() -> ! {
    let status = Command::new(std::env::current_exe().unwrap())
        .arg(PEEK_TERMINAL_CHILD)
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    std::process::exit(status.code().unwrap())
}

fn run_terminal_child() -> ! {
    assert!(moto_rt::fs::is_terminal(FD_TERMINAL));
    assert_eq!(peek(FD_TERMINAL, 8), Err(moto_rt::Error::NotReady));
    say("ready");

    assert_eq!(read(FD_TERMINAL, 1), b"T");
    assert_eq!(peek(FD_TERMINAL, 8).unwrap(), b"jkl");
    assert_eq!(read(FD_TERMINAL, 8), b"jkl");
    say("done");
    std::process::exit(0)
}

/// Starts a detached reader, writes `ab` to it, and stays until it is
/// killed: the reader's input then ends by its writer vanishing, with no
/// orderly close.
fn run_writer(result: &str, got: &str, mode: &str) -> ! {
    let mut reader = Command::new(std::env::current_exe().unwrap())
        .arg(PEEK_LOSS_READER)
        .arg(result)
        .arg(got)
        .arg(mode)
        .env(moto_sys::caps::MOTOR_OS_DETACHED_ENV_KEY, "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    reader.stdin.as_mut().unwrap().write_all(b"ab").unwrap();
    let mut sink = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink);
    std::process::exit(0)
}

/// Reads its input as a line editor does: peek, read what is there, and wait
/// for readiness only when the peek says more is to come. Reports through
/// files, being detached.
fn run_loss_reader(result: &str, got_path: &str) -> ! {
    let registry = moto_rt::poll::new().unwrap();
    moto_rt::poll::add(registry, FD_STDIN, 1, moto_rt::poll::POLL_READABLE).unwrap();
    let deadline = moto_rt::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut got = Vec::new();
    let end = loop {
        match peek(FD_STDIN, 8) {
            Ok(bytes) if bytes.is_empty() => break Ok(()),
            Ok(bytes) => {
                got.extend(read(FD_STDIN, bytes.len()));
                if got == b"ab" {
                    std::fs::write(got_path, b"").unwrap();
                }
            }
            Err(moto_rt::Error::NotReady) => {
                let mut events = [moto_rt::poll::Event::default(); 1];
                let ready = moto_rt::poll::wait(registry, events.as_mut_ptr(), 1, Some(deadline));
                if ready != Ok(1) {
                    publish_result(result, "input said more was coming, then went quiet");
                    std::process::exit(1)
                }
            }
            Err(err) => break Err(err),
        }
    };
    // A vanished writer is the end of this input, reported as a read does.
    let verdict = if got == b"ab" && end == Err(moto_rt::Error::BadHandle) {
        "ok".to_owned()
    } else {
        format!("got {got:?}, ended with {end:?}")
    };
    publish_result(result, &verdict);
    std::process::exit(0)
}

/// No poll registration, including before the writer dies. A separate file
/// releases this reader only after the parent has killed and waited for the writer.
fn run_unregistered_loss_reader(result: &str, got_path: &str, mode: &str) -> ! {
    let buffered = mode == "buffered";
    let initial = if buffered { b"a".as_slice() } else { b"ab" };
    assert_eq!(read(FD_STDIN, initial.len()), initial);
    if buffered {
        assert_eq!(peek(FD_STDIN, 8).unwrap(), b"b");
    } else {
        assert_eq!(peek(FD_STDIN, 8), Err(moto_rt::Error::NotReady));
    }
    std::fs::write(got_path, b"").unwrap();
    wait_for_file(
        &std::path::Path::new(result).with_extension("release"),
        "the writer was not killed",
    );

    if buffered {
        assert_eq!(peek(FD_STDIN, 8).unwrap(), b"b");
        assert_eq!(peek(FD_STDIN, 8).unwrap(), b"b");
        assert_eq!(read(FD_STDIN, 8), b"b");
    }
    let end = peek(FD_STDIN, 8);
    let verdict = if end == Err(moto_rt::Error::BadHandle) {
        "ok".to_owned()
    } else {
        format!("unregistered {mode} reader ended with {end:?}")
    };
    publish_result(result, &verdict);
    std::process::exit(0)
}

/// Existence means the complete verdict is readable, not just that the
/// writer has created an empty file and is about to fill it.
fn publish_result(path: &str, verdict: &str) {
    let pending = std::path::Path::new(path).with_extension("pending");
    std::fs::write(&pending, verdict).unwrap();
    std::fs::rename(pending, path).unwrap();
}

fn wait_for_file(path: &std::path::Path, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.exists() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        std::thread::yield_now();
    }
}

fn test_self_stdio_peek() {
    let release = crate::temp_path("stdio-peek-release");
    let _ = std::fs::remove_file(&release);
    let _ = std::fs::remove_file(release.with_extension("idle"));
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(PEEK_CHILD)
        .arg(&release)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    expect_line(&mut stdout, "empty");
    stdin.write_all(b"Xabc").unwrap();
    expect_line(&mut stdout, "spawned");
    stdin.write_all(b"S1").unwrap();
    expect_line(&mut stdout, "stashed");
    stdin.write_all(b"R2").unwrap();
    drop(stdin);
    std::fs::write(&release, b"").unwrap();

    assert!(child.wait().unwrap().success());
    std::fs::remove_file(&release).unwrap();
    std::fs::remove_file(release.with_extension("idle")).unwrap();
    println!("test_self_stdio_peek PASS");
}

fn test_terminal_peek() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg(PEEK_TERMINAL_PARENT)
        .env(moto_rt::process::STDIO_NO_TERMINAL_ENV_KEY, "true")
        .env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    expect_line(&mut stdout, "ready");
    stdin.write_all(b"Tjkl").unwrap();
    expect_line(&mut stdout, "done");
    drop(stdin);
    assert!(child.wait().unwrap().success());
    println!("test_terminal_peek PASS");
}

/// A peek after the reader's writer has vanished says the input has ended:
/// the hangup the reader was woken for is the last readiness it gets.
///
/// Requires detached-spawn authority, so that the reader outlives its killed
/// writer, and CAP_FS_WRITE for the reader's reports.
pub fn test_peek_after_the_writer_vanishes() {
    for mode in ["polled", "empty", "buffered"] {
        peek_after_the_writer_vanishes(mode);
    }
}

fn peek_after_the_writer_vanishes(mode: &str) {
    let result = crate::temp_path(&format!("stdio-peek-loss-{mode}-result"));
    let got = crate::temp_path(&format!("stdio-peek-loss-{mode}-got"));
    let release = result.with_extension("release");
    let _ = std::fs::remove_file(&result);
    let _ = std::fs::remove_file(&got);
    let _ = std::fs::remove_file(&release);
    let caps = format!(
        "0x{:x}",
        moto_sys::caps::CAP_SPAWN
            | moto_sys::caps::CAP_SPAWN_DETACHED
            | moto_sys::caps::CAP_INTERACTIVE
            | moto_sys::caps::CAP_FS_WRITE
    );
    let mut writer = Command::new(std::env::current_exe().unwrap())
        .arg(PEEK_WRITER)
        .arg(&result)
        .arg(&got)
        .arg(mode)
        .env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, caps)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    wait_for_file(&got, "the reader did not get its input");
    writer.kill().unwrap();
    let _ = writer.wait();
    std::fs::write(&release, b"").unwrap();
    wait_for_file(&result, "the reader did not finish");
    assert_eq!(
        String::from_utf8(std::fs::read(&result).unwrap()).unwrap(),
        "ok"
    );
    std::fs::remove_file(result).unwrap();
    std::fs::remove_file(got).unwrap();
    std::fs::remove_file(release).unwrap();
}

pub fn run_all_tests() {
    test_self_stdio_peek();
    test_terminal_peek();
}
