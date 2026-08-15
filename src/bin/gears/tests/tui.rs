//! Real-terminal lifecycle coverage for the Linux TUI.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(5);

fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("gears-tui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let workspace = dir.join("work");
    std::fs::create_dir_all(&workspace).unwrap();
    let key = dir.join("key");
    std::fs::write(&key, "sk-test-only\n").unwrap();
    let config = dir.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\n\
             [provider]\n\
             base_url = \"http://127.0.0.1:9/v1\"\n\
             model = \"test/model\"\n\
             key_file = \"{}\"\n\
             [net]\n\
             egress_allowlist = [\"127.0.0.1\"]\n\
             allow_plain_http_loopback = true\n",
            key.display()
        ),
    )
    .unwrap();
    (dir, workspace, config)
}

fn pty() -> (File, File) {
    let mut master = -1;
    let mut slave = -1;
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: both output pointers and the optional window-size pointer are
    // valid for the duration of the call. No termios override is supplied.
    let status = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    assert_eq!(status, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: successful openpty returned two newly owned descriptors.
    unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
}

fn termios(file: &File) -> libc::termios {
    // SAFETY: termios is plain data and tcgetattr initializes all of it.
    let mut value = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is an open PTY slave and the pointer is valid.
    let status = unsafe { libc::tcgetattr(file.as_raw_fd(), &mut value) };
    assert_eq!(status, 0, "tcgetattr: {}", std::io::Error::last_os_error());
    value
}

fn assert_same_mode(before: &libc::termios, after: &libc::termios) {
    assert_eq!(
        before.c_iflag, after.c_iflag,
        "input flags were not restored"
    );
    assert_eq!(
        before.c_oflag, after.c_oflag,
        "output flags were not restored"
    );
    assert_eq!(
        before.c_cflag, after.c_cflag,
        "control flags were not restored"
    );
    assert_eq!(
        before.c_lflag, after.c_lflag,
        "local flags were not restored"
    );
    assert_eq!(before.c_cc, after.c_cc, "control bytes were not restored");
}

fn wait_readable(file: &File, deadline: Instant) -> bool {
    let left = deadline.saturating_duration_since(Instant::now());
    let millis = i32::try_from(left.as_millis().max(1)).unwrap_or(i32::MAX);
    let mut poll = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll points at one initialized entry for the duration of call.
    unsafe { libc::poll(&mut poll, 1, millis) > 0 && poll.revents & libc::POLLIN != 0 }
}

fn read_until(file: &mut File, marker: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + DEADLINE;
    let mut output = Vec::new();
    while !output.windows(marker.len()).any(|bytes| bytes == marker) {
        assert!(
            wait_readable(file, deadline),
            "TUI produced no frame: {output:?}"
        );
        let mut bytes = [0; 1024];
        let read = file.read(&mut bytes).unwrap();
        assert!(read > 0, "TUI closed before its frame: {output:?}");
        output.extend_from_slice(&bytes[..read]);
    }
    output
}

fn wait_child(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("TUI did not exit after Ctrl-C");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn drain(file: &mut File, output: &mut Vec<u8>) {
    while wait_readable(file, Instant::now() + Duration::from_millis(50)) {
        let mut bytes = [0; 1024];
        match file.read(&mut bytes) {
            Ok(0) | Err(_) => break,
            Ok(read) => output.extend_from_slice(&bytes[..read]),
        }
    }
}

fn position(output: &[u8], marker: &[u8]) -> usize {
    output
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap_or_else(|| panic!("missing {marker:?} in {output:?}"))
}

#[test]
fn tui_borrows_and_restores_a_linux_terminal() {
    let (dir, workspace, config) = fixture();
    let (mut master, slave) = pty();
    let before = termios(&slave);
    let mut child = Command::new(env!("CARGO_BIN_EXE_gears"));
    child
        .args(["--ui", "tui", "--config"])
        .arg(&config)
        .arg("--workspace")
        .arg(&workspace)
        .env_remove("OPENROUTER_API_KEY")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    let mut child = child.spawn().unwrap();

    let mut output = read_until(&mut master, b"Motor OS Gears");
    master.write_all(&[3]).unwrap();
    let status = wait_child(&mut child);
    drain(&mut master, &mut output);

    assert!(status.success(), "TUI exited with {status}: {output:?}");
    let enter = position(&output, b"\x1b[?1049h");
    let frame = position(&output, b"Motor OS Gears");
    let leave = position(&output, b"\x1b[?1049l");
    assert!(
        enter < frame && frame < leave,
        "bad screen order: {output:?}"
    );
    assert_same_mode(&before, &termios(&slave));
    std::fs::remove_dir_all(Path::new(&dir)).unwrap();
}
