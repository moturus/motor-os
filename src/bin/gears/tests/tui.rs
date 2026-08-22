//! Real-terminal lifecycle coverage for the Linux TUI.

#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crossterm::style::{Color, SetForegroundColor, force_color_output};
use gears::mock::{MockServer, Script, provider_scenario, sse_response};

const DEADLINE: Duration = Duration::from_secs(5);

fn says(text: &str) -> Script {
    let delta =
        serde_json::json!({"choices": [{"index": 0, "delta": {"content": text}}]}).to_string();
    sse_response(&[
        &delta,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        r#"{"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1}}"#,
    ])
}

fn fixture(name: &str, base_url: &str, permissions: &str) -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("gears-tui-{}-{name}", std::process::id()));
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
             base_url = \"{base_url}/v1\"\n\
             model = \"test/model\"\n\
             key_file = \"{}\"\n\
             [net]\n\
             egress_allowlist = [\"127.0.0.1\"]\n\
             allow_plain_http_loopback = true\n\
             [permissions]\n\
             mode = \"{permissions}\"\n",
            key.display(),
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

fn resize(file: &File, columns: u16, rows: u16) {
    let size = libc::winsize {
        ws_row: rows,
        ws_col: columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the descriptor is an open PTY and the winsize pointer is valid.
    let status = unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCSWINSZ, &size) };
    assert_eq!(status, 0, "TIOCSWINSZ: {}", std::io::Error::last_os_error());
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

fn last_frame(output: &[u8]) -> &[u8] {
    let clear = b"\x1b[2J";
    let start = output
        .windows(clear.len())
        .rposition(|bytes| bytes == clear)
        .unwrap_or_else(|| panic!("missing final screen clear in {output:?}"));
    &output[start..]
}

#[test]
fn tui_borrows_and_restores_a_linux_terminal() {
    let (dir, workspace, config) = fixture("restore", "http://127.0.0.1:9", "ask");
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
    master
        .write_all(b"\x1b[200~one\ninvalid:\xff\x1b[201~")
        .unwrap();
    // The prompt and pasted content can have distinct foreground colors, so
    // terminal styling may appear between them in the raw PTY stream.
    output.extend(read_until(&mut master, b"invalid:"));
    master.write_all(&[3]).unwrap();
    let status = wait_child(&mut child);
    drain(&mut master, &mut output);

    assert!(status.success(), "TUI exited with {status}: {output:?}");
    let enter = position(&output, b"\x1b[?1049h");
    let paste = position(&output, b"\x1b[?2004h");
    let frame = position(&output, b"Motor OS Gears");
    let no_paste = position(&output, b"\x1b[?2004l");
    let leave = position(&output, b"\x1b[?1049l");
    assert!(
        enter < paste && paste < frame && frame < no_paste && no_paste < leave,
        "bad screen order: {output:?}"
    );
    assert_same_mode(&before, &termios(&slave));
    std::fs::remove_dir_all(Path::new(&dir)).unwrap();
}

#[test]
fn tui_drives_an_attended_tool_round_on_linux() {
    let server = MockServer::start(provider_scenario("tool-round").unwrap()).unwrap();
    let (dir, workspace, config) = fixture("tool-round", server.base_url(), "ask");
    std::fs::write(workspace.join("context.txt"), "attachment fixture bytes").unwrap();
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
    master.write_all(&[16]).unwrap();
    output.extend(read_until(&mut master, b"paused"));
    master.write_all(&[16]).unwrap();
    output.extend(read_until(&mut master, b"idle"));
    master
        .write_all(b"write the file using @context.txt\r")
        .unwrap();
    output.extend(read_until(&mut master, b"digest:"));
    master.write_all(b"\x1b[6~y").unwrap();
    output.extend(read_until(&mut master, b"completed"));
    master.write_all(&[3]).unwrap();
    let status = wait_child(&mut child);
    drain(&mut master, &mut output);

    assert!(status.success(), "TUI exited with {status}: {output:?}");
    assert!(
        output.windows(13).any(|bytes| bytes == b"tool complete"),
        "missing final model response: {output:?}"
    );
    assert!(
        output
            .windows(b"attached context.txt".len())
            .any(|bytes| bytes == b"attached context.txt"),
        "missing attachment card: {output:?}"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    let request: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let first = request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|message| message["role"] == "user")
        .unwrap()["content"]
        .as_str()
        .unwrap();
    assert!(first.contains("attachment fixture bytes"));
    assert_eq!(
        std::fs::read_to_string(workspace.join("result.txt")).unwrap(),
        "made by gears\n"
    );
    assert_same_mode(&before, &termios(&slave));
    std::fs::remove_dir_all(Path::new(&dir)).unwrap();
}

#[test]
fn tui_handles_slash_commands_without_a_provider_request() {
    let server = MockServer::start(Vec::new()).unwrap();
    let (dir, workspace, config) = fixture("commands", server.base_url(), "ask");
    let (mut master, slave) = pty();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gears"));
    child
        .args(["--ui", "tui", "--config"])
        .arg(&config)
        .arg("--workspace")
        .arg(&workspace)
        .env_remove("OPENROUTER_API_KEY")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    let mut child = child.spawn().unwrap();

    let mut output = read_until(&mut master, b"Motor OS Gears");
    master.write_all(b"/status\r").unwrap();
    output.extend(read_until(&mut master, b"files changed"));
    master.write_all(b"/compact\r").unwrap();
    output.extend(read_until(&mut master, b"nothing to compact"));
    drain(&mut master, &mut output);
    master.write_all(b"/unknown\r").unwrap();
    output.extend(read_until(&mut master, b"no such command"));
    master.write_all(b"/quit\r").unwrap();
    let status = wait_child(&mut child);
    drain(&mut master, &mut output);

    assert!(status.success(), "TUI exited with {status}: {output:?}");
    assert!(server.requests().is_empty());
    std::fs::remove_dir_all(Path::new(&dir)).unwrap();
}

#[test]
fn tui_model_picker_changes_and_remembers_the_request_model() {
    let server = MockServer::start_one(says("selected model answered")).unwrap();
    let (dir, workspace, config) = fixture("model-picker", server.base_url(), "ask");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("[models]\nlast = \"test/model\"\nused = [\"test/model\", \"other/model\"]\n");
    std::fs::write(&config, text).unwrap();
    let (mut master, slave) = pty();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gears"));
    child
        .args(["--ui", "tui", "--config"])
        .arg(&config)
        .arg("--workspace")
        .arg(&workspace)
        .env_remove("OPENROUTER_API_KEY")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    let mut child = child.spawn().unwrap();

    let mut output = read_until(&mut master, b"Motor OS Gears");
    master.write_all(b"/model\r").unwrap();
    output.extend(read_until(&mut master, b"other/model"));
    drain(&mut master, &mut output);
    master.write_all(b"\x1b[B").unwrap();
    output.extend(read_until(&mut master, b">(x) "));
    drain(&mut master, &mut output);
    master.write_all(b"\r").unwrap();
    output.extend(read_until(&mut master, b"model: other/model"));
    master.write_all(b"which model is this?\r").unwrap();
    output.extend(read_until(&mut master, b"completed"));
    master.write_all(b"/quit\r").unwrap();
    let status = wait_child(&mut child);
    drain(&mut master, &mut output);

    assert!(status.success(), "TUI exited with {status}: {output:?}");
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    let request: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(request["model"], "other/model");
    let saved = gears::config::Config::load(Some(&config)).unwrap();
    assert_eq!(saved.model.as_deref(), Some("other/model"));
    assert_eq!(saved.models, ["other/model", "test/model"]);
    std::fs::remove_dir_all(Path::new(&dir)).unwrap();
}

#[test]
fn tui_compacts_locally_and_uses_the_summary_on_the_next_turn() {
    let server = MockServer::start(vec![
        says("answer one"),
        says("answer two"),
        says("answer three"),
        says("concise history"),
        says("answer four"),
    ])
    .unwrap();
    let (dir, workspace, config) = fixture("compact", server.base_url(), "ask");
    let (mut master, slave) = pty();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gears"));
    child
        .args(["--ui", "tui", "--config"])
        .arg(&config)
        .arg("--workspace")
        .arg(&workspace)
        .env_remove("OPENROUTER_API_KEY")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    let mut child = child.spawn().unwrap();

    let mut output = read_until(&mut master, b"Motor OS Gears");
    for prompt in ["question one", "question two", "question three"] {
        master.write_all(format!("{prompt}\r").as_bytes()).unwrap();
        output.extend(read_until(&mut master, b"completed"));
        drain(&mut master, &mut output);
    }
    master.write_all(b"/compact focus on decisions\r").unwrap();
    output.extend(read_until(&mut master, b"compacted 4 messages"));
    drain(&mut master, &mut output);
    master.write_all(b"question four\r").unwrap();
    output.extend(read_until(&mut master, b"completed"));
    drain(&mut master, &mut output);
    master.write_all(b"/quit\r").unwrap();
    let status = wait_child(&mut child);
    drain(&mut master, &mut output);

    assert!(status.success(), "TUI exited with {status}: {output:?}");
    let requests = server.requests();
    assert_eq!(requests.len(), 5);
    let summary: serde_json::Value = serde_json::from_slice(&requests[3].body).unwrap();
    assert!(summary.get("tools").is_none());
    assert!(
        summary["messages"].as_array().unwrap().last().unwrap()["content"]
            .as_str()
            .unwrap()
            .ends_with("focus on decisions")
    );
    let next: serde_json::Value = serde_json::from_slice(&requests[4].body).unwrap();
    let messages = serde_json::to_string(
        &next["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|message| message["role"] != "system")
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(messages.contains("concise history"), "{messages}");
    assert!(messages.contains("question three"), "{messages}");
    assert!(messages.contains("answer three"), "{messages}");
    assert!(messages.contains("question four"), "{messages}");
    assert!(!messages.contains("question one"), "{messages}");
    assert!(!messages.contains("question two"), "{messages}");
    std::fs::remove_dir_all(Path::new(&dir)).unwrap();
}

#[test]
fn cancelling_keeps_the_live_highlighted_transcript_on_screen() {
    force_color_output(true);
    let reasoning = serde_json::json!({
        "choices": [{
            "index": 0,
            "delta": {"reasoning": "```rust\nlet value: usize = 42;\n```"}
        }]
    });
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n\
         data: {reasoning}\n\n"
    );
    let server = MockServer::start_one(
        Script::new()
            .write(response)
            .pause(Duration::from_secs(2))
            .write("data: {\"choices\":[{\"index\":0,\"delta\":{\"reasoning\":\"more\"}}]}\n\n"),
    )
    .unwrap();
    let (dir, workspace, config) = fixture("cancel-transcript", server.base_url(), "ask");
    let (mut master, slave) = pty();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gears"));
    child
        .args(["--ui", "tui", "--config"])
        .arg(&config)
        .arg("--workspace")
        .arg(&workspace)
        .env_remove("OPENROUTER_API_KEY")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    let mut child = child.spawn().unwrap();

    let mut output = read_until(&mut master, b"Motor OS Gears");
    master.write_all(b"review this\r").unwrap();
    output.extend(read_until(&mut master, b"```rust"));
    master.write_all(&[3]).unwrap();
    output.extend(read_until(&mut master, b"cancelled"));
    drain(&mut master, &mut output);
    resize(&master, 79, 24);
    // SAFETY: child is live and SIGWINCH only asks it to re-read the PTY size.
    let signalled = unsafe { libc::kill(child.id() as i32, libc::SIGWINCH) };
    assert_eq!(
        signalled,
        0,
        "SIGWINCH: {}",
        std::io::Error::last_os_error()
    );
    output.extend(read_until(&mut master, b"```rust"));
    drain(&mut master, &mut output);

    let frame = last_frame(&output);
    assert!(
        frame
            .windows(b"```rust".len())
            .any(|bytes| bytes == b"```rust"),
        "cancelled frame lost reasoning: {frame:?}"
    );
    let mut keyword = Vec::new();
    crossterm::queue!(&mut keyword, SetForegroundColor(Color::Magenta)).unwrap();
    assert!(!keyword.is_empty());
    assert!(
        frame.windows(keyword.len()).any(|bytes| bytes == keyword),
        "cancelled frame lost syntax color: {frame:?}"
    );

    master.write_all(b"/quit\r").unwrap();
    let status = wait_child(&mut child);
    assert!(status.success(), "TUI exited with {status}: {output:?}");
    std::fs::remove_dir_all(Path::new(&dir)).unwrap();
}
