use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use moto_tooling::mode2048;

pub type StdinTx = tokio::sync::mpsc::Sender<SessionMessage>;

/// Something for the one task that owns a session's child stdin to do.
///
/// A pty session's size has three sources -- the SSH client, the child, and the
/// clock of neither -- and they arrive on different tasks. Making each of them a
/// message to a single owner is what puts the reports in an order at all
/// (`docs/tui.md`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionMessage {
    /// Bytes the SSH client sent.
    Input(Vec<u8>),
    /// A size control the child wrote towards its terminal, which is russhd.
    Control(mode2048::Command),
    /// A new size from `pty-req` or `window-change`.
    Resized(PtyGeometry),
}

/// Shared ownership of the one SSH `CHANNEL_CLOSE` allowed for a channel.
///
/// The SSH handler and another completion path (the child-reaping task, or the
/// special Motor shutdown path) can both finish a channel. Every explicit
/// close path must claim this guard first so russhd never sends a second close
/// after another owner has finished the channel.
#[derive(Clone, Debug, Default)]
pub struct ChannelCloseGuard(Arc<AtomicBool>);

impl ChannelCloseGuard {
    pub fn claim(&self) -> bool {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// The shell that runs client sessions and commands.
#[cfg(target_os = "motor")]
pub const SHELL: &str = "/bin/rush";
#[cfg(not(target_os = "motor"))]
pub const SHELL: &str = "/bin/bash";

/// The latest valid dimensions supplied for an SSH pseudo-terminal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PtyGeometry {
    cols: Option<u16>,
    rows: Option<u16>,
    width_px: Option<u32>,
    height_px: Option<u32>,
}

impl PtyGeometry {
    pub fn update(&mut self, cols: u32, rows: u32, width_px: u32, height_px: u32) {
        if let Ok(cols) = u16::try_from(cols)
            && cols != 0
        {
            self.cols = Some(cols);
        }
        if let Ok(rows) = u16::try_from(rows)
            && rows != 0
        {
            self.rows = Some(rows);
        }
        if width_px != 0 {
            self.width_px = Some(width_px);
        }
        if height_px != 0 {
            self.height_px = Some(height_px);
        }
    }

    /// The in-band resize report for this geometry, or `None` while the
    /// character dimensions are unknown: a size nobody knows is not reportable,
    /// and a made-up one would be believed. Pixels stay optional -- zero is how
    /// the protocol says "unknown" -- so they never hold a report back.
    fn report(&self) -> Option<Vec<u8>> {
        Some(mode2048::report(
            self.rows?,
            self.cols?,
            self.height_px.unwrap_or(0),
            self.width_px.unwrap_or(0),
        ))
    }

    fn text_area(&self) -> Option<Vec<u8>> {
        Some(mode2048::text_area(self.rows?, self.cols?))
    }
}

/// The terminal state of one session: what the child subscribed to, how big its
/// terminal is, and what that means for the bytes it is fed.
#[derive(Debug, Default)]
struct SessionState {
    geometry: PtyGeometry,
    /// Whether the child asked to be told about resizes (private mode 2048).
    subscribed: bool,
}

impl SessionState {
    /// What to write into the child's stdin for `message`, if anything.
    fn handle(&mut self, message: SessionMessage) -> Option<Vec<u8>> {
        match message {
            SessionMessage::Input(bytes) => Some(bytes),
            // An enable is answered every time, because a client that repeats it
            // is a client that wants the size again.
            SessionMessage::Control(mode2048::Command::Enable) => {
                self.subscribed = true;
                self.geometry.report()
            }
            SessionMessage::Control(mode2048::Command::Disable) => {
                self.subscribed = false;
                None
            }
            SessionMessage::Control(mode2048::Command::Query) => {
                Some(mode2048::decrpm(self.subscribed).to_vec())
            }
            SessionMessage::Control(mode2048::Command::TextArea) => self.geometry.text_area(),
            SessionMessage::Resized(geometry) => {
                self.geometry = geometry;
                self.subscribed.then(|| self.geometry.report()).flatten()
            }
        }
    }
}

/// What to run for a client, and how to wire up its output.
pub struct Command {
    /// The program and its arguments; `argv[0]` is the program to run.
    pub argv: Vec<String>,
}

impl Command {
    /// An interactive session: RFC 4254 6.5 `shell`.
    pub fn shell() -> Self {
        Self {
            argv: vec![SHELL.to_owned(), "-i".to_owned()],
        }
    }

    /// A client command: RFC 4254 6.5 `exec`.
    ///
    /// `cmdline` is a command *line*, not an argv, so it goes to the shell
    /// verbatim: clients expect `ssh host 'ls *.rs | wc -l'` to work, and
    /// OpenSSH likewise runs the user's login shell with `-c`.
    pub fn exec(cmdline: &str) -> Self {
        Self {
            argv: vec![SHELL.to_owned(), "-c".to_owned(), cmdline.to_owned()],
        }
    }
}

fn configure_terminal(cmd: &mut tokio::process::Command, pty: Option<PtyGeometry>) -> bool {
    cmd.env_remove("COLUMNS");
    cmd.env_remove("LINES");
    #[cfg(target_os = "motor")]
    cmd.env_remove(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY);

    let Some(geometry) = pty else {
        return false;
    };

    #[cfg(target_os = "motor")]
    cmd.env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");
    if let Some(cols) = geometry.cols {
        cmd.env("COLUMNS", cols.to_string());
    }
    if let Some(rows) = geometry.rows {
        cmd.env("LINES", rows.to_string());
    }

    true
}

pub async fn spawn(
    command: Command,
    pty: Option<PtyGeometry>,
    channel: russh::ChannelId,
    session: russh::server::Handle,
    close_guard: ChannelCloseGuard,
    cfg: &Arc<crate::config::Config>,
) -> Result<StdinTx, russh::Error> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let Some((program, args)) = command.argv.split_first() else {
        return Err(russh::Error::IO(std::io::ErrorKind::InvalidInput.into()));
    };

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    if !cfg.path().is_empty() {
        cmd.env("PATH", cfg.path());
    }
    let terminal = configure_terminal(&mut cmd, pty);

    // Pass CAP_SPAWN_DETACHED down to the shell (on top of the usual defaults), so
    // a program the shell trusts can start a server that outlives this ssh
    // session. The system daemon holds the bit via its service capabilities
    // (sys-init.cfg); a user-launched instance does not, and requesting caps
    // the parent lacks is E_NOT_ALLOWED -- it failed every exec through a
    // user-mode daemon ("closed by remote host") while in-process SFTP kept
    // working. Request the intersection with what this instance holds.
    #[cfg(target_os = "motor")]
    cmd.env(
        moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
        format!(
            "0x{:x}",
            moto_sys::ProcessStaticPage::get().capabilities
                & (moto_sys::caps::CAP_SPAWN
                    | moto_sys::caps::CAP_LOG
                    | moto_sys::caps::CAP_SPAWN_DETACHED)
        ),
    );

    let argv = command.argv.join(" ");
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .inspect_err(|e| log::warn!("Error spawning cmd `{argv}`: {e:?}"))?;

    log::info!("Started `{argv}`");

    // The one owner of the child's stdin: everything that reaches it -- the
    // client's keystrokes, an answer to a control the child wrote, a report of a
    // size the client changed -- is a message to this task and is written in the
    // order the messages arrived.
    let mut stdin = child.stdin.take().unwrap();
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<SessionMessage>(8);

    let mut state = SessionState {
        geometry: pty.unwrap_or_default(),
        subscribed: false,
    };
    tokio::spawn(async move {
        while let Some(message) = stdin_rx.recv().await {
            let Some(bytes) = state.handle(message) else {
                continue;
            };
            if let Err(err) = stdin.write_all(&bytes).await {
                log::debug!("stdin.write_all() failed with error '{err:?}'");
                break;
            }
        }
    });

    // Only a pty session's output is scanned: on a plain `ssh host cmd` the
    // bytes are the client's file, and each stream needs its own scanner because
    // a sequence split across reads must not be reassembled across streams.
    let coordinator = terminal.then(|| stdin_tx.clone());

    let stdout_task = tokio::spawn(pump_output(
        child.stdout.take().unwrap(),
        session.clone(),
        channel,
        "stdout",
        coordinator.clone(),
    ));
    let stderr_task = tokio::spawn(pump_output(
        child.stderr.take().unwrap(),
        session.clone(),
        channel,
        "stderr",
        coordinator,
    ));

    // Wait for the child.
    let session_handle = session.clone();
    tokio::spawn(async move {
        let status = child.wait().await;

        // The child is gone, but its output may not have reached the client
        // yet: the pipes can still hold data, and the tasks above stop only
        // once they have drained them. Closing the channel before that
        // truncates the output, which for a short command is all of it.
        let _ = stdout_task.await;
        let _ = stderr_task.await;

        match status {
            Ok(status) => {
                if let Some(code) = status.code() {
                    log::info!("child exited with {code}");
                    let _ = session_handle
                        .exit_status_request(channel, i32::cast_unsigned(code))
                        .await;
                }
            }
            Err(err) => {
                log::warn!("child.wait() failed: {err:?}");
            }
        }

        if close_guard.claim() {
            let _ = session_handle.eof(channel).await;
            let _ = session_handle.close(channel).await;
        }
    });

    Ok(stdin_tx)
}

/// Sends one of the child's output streams to the client until it ends.
///
/// With a `coordinator` the stream is a pty session's, and russhd is the
/// terminal on the far end of it: the size controls the child writes are taken
/// out of the stream and answered here rather than reaching the client's own
/// terminal, which would otherwise answer as well and with a different size.
async fn pump_output(
    mut stream: impl tokio::io::AsyncRead + Unpin,
    session: russh::server::Handle,
    channel: russh::ChannelId,
    name: &str,
    coordinator: Option<StdinTx>,
) {
    use tokio::io::AsyncReadExt;

    let mut scanner = mode2048::Scanner::new(true);
    let mut buf = [0_u8; 256];

    loop {
        let read = match stream.read(&mut buf).await {
            Ok(read) => read,
            Err(err) => {
                log::debug!("{name}.read() failed with error '{err:?}'");
                break;
            }
        };

        let Some(coordinator) = &coordinator else {
            if read == 0 {
                log::debug!("{name}.read() returned zero.");
                break;
            }
            if send_output(&session, channel, &buf[..read], false)
                .await
                .is_err()
            {
                break;
            }
            continue;
        };

        let mut output = Vec::new();
        let mut commands = Vec::new();
        if read == 0 {
            // Bytes held back as a possible control are only bytes once the
            // stream they might have been completed by has ended.
            log::debug!("{name}.read() returned zero.");
            scanner.finish(&mut output);
        } else {
            scanner.feed(&buf[..read], &mut output, &mut commands);
        }

        for command in commands {
            if coordinator
                .send(SessionMessage::Control(command))
                .await
                .is_err()
            {
                log::debug!("the session coordinator is gone.");
                return;
            }
        }
        if !output.is_empty() && send_output(&session, channel, &output, true).await.is_err() {
            break;
        }
        if read == 0 {
            break;
        }
    }
}

async fn send_output(
    session: &russh::server::Handle,
    channel: russh::ChannelId,
    bytes: &[u8],
    crlf: bool,
) -> Result<(), ()> {
    session
        .data(channel, output_bytes(bytes, crlf))
        .await
        .map_err(|_| log::debug!("Failed to send bytes to the client."))
}

/// The bytes to send to the client for `bytes` of child output.
fn output_bytes(bytes: &[u8], crlf: bool) -> Vec<u8> {
    if !crlf {
        return bytes.to_vec();
    }

    let mut out = Vec::with_capacity(bytes.len());
    for byte in bytes {
        out.push(*byte);
        if *byte == b'\n' {
            out.push(b'\r');
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_hands_the_command_line_to_a_shell() {
        // The client sends a command line, not an argv. Splitting it ourselves
        // and spawning argv[0] would make every pipe, redirection, glob and
        // variable in it either a literal argument or an error.
        let cmd = Command::exec("ls *.rs | wc -l");
        assert_eq!(cmd.argv, [SHELL, "-c", "ls *.rs | wc -l"]);
    }

    #[test]
    fn exec_passes_the_command_line_through_untouched() {
        // Quoting is the shell's job: whatever the client sent has to reach it
        // byte for byte.
        let cmdline = r#"echo "a  b" '$X' \& > /tmp/f"#;
        assert_eq!(Command::exec(cmdline).argv[2], cmdline);
    }

    #[test]
    fn a_shell_session_is_interactive() {
        assert_eq!(Command::shell().argv, [SHELL, "-i"]);
    }

    fn pty(cols: u32, rows: u32, width_px: u32, height_px: u32) -> PtyGeometry {
        let mut geometry = PtyGeometry::default();
        geometry.update(cols, rows, width_px, height_px);
        geometry
    }

    fn session(geometry: PtyGeometry) -> SessionState {
        SessionState {
            geometry,
            subscribed: false,
        }
    }

    /// What the child is fed for one control it wrote.
    fn control(state: &mut SessionState, command: mode2048::Command) -> Vec<u8> {
        state
            .handle(SessionMessage::Control(command))
            .unwrap_or_default()
    }

    #[test]
    fn a_subscriber_is_told_the_size_every_time_it_asks() {
        // Pixels in the protocol's order -- height, then width -- and kept from
        // the `pty-req` that carried them.
        let mut state = session(pty(100, 30, 1600, 900));

        assert_eq!(
            control(&mut state, mode2048::Command::Enable),
            b"\x1b[48;30;100;900;1600t"
        );
        assert_eq!(
            control(&mut state, mode2048::Command::Enable),
            b"\x1b[48;30;100;900;1600t"
        );
    }

    #[test]
    fn a_window_change_reaches_a_subscriber_whichever_arrives_first() {
        let report = b"\x1b[48;20;60;0;0t";

        let mut changed_first = session(pty(100, 30, 0, 0));
        assert_eq!(
            changed_first.handle(SessionMessage::Resized(pty(60, 20, 0, 0))),
            None,
            "a child that has not subscribed is told nothing"
        );
        assert_eq!(
            control(&mut changed_first, mode2048::Command::Enable),
            report
        );

        let mut subscribed_first = session(pty(100, 30, 0, 0));
        control(&mut subscribed_first, mode2048::Command::Enable);
        assert_eq!(
            subscribed_first.handle(SessionMessage::Resized(pty(60, 20, 0, 0))),
            Some(report.to_vec())
        );
    }

    #[test]
    fn a_child_that_unsubscribed_stops_being_told() {
        let mut state = session(pty(100, 30, 0, 0));
        control(&mut state, mode2048::Command::Enable);
        control(&mut state, mode2048::Command::Disable);

        assert_eq!(
            state.handle(SessionMessage::Resized(pty(60, 20, 0, 0))),
            None
        );
    }

    #[test]
    fn the_mode_is_reported_as_the_state_it_is_in() {
        let mut state = session(pty(100, 30, 0, 0));

        assert_eq!(
            control(&mut state, mode2048::Command::Query),
            mode2048::DECRPM_DISABLED
        );
        control(&mut state, mode2048::Command::Enable);
        assert_eq!(
            control(&mut state, mode2048::Command::Query),
            mode2048::DECRPM_ENABLED
        );
        control(&mut state, mode2048::Command::Disable);
        assert_eq!(
            control(&mut state, mode2048::Command::Query),
            mode2048::DECRPM_DISABLED
        );
    }

    #[test]
    fn the_text_area_is_answered_without_a_subscription() {
        // The rung below mode 2048: a question, answered once, and never a
        // reason to start reporting.
        let mut state = session(pty(100, 30, 0, 0));

        assert_eq!(
            control(&mut state, mode2048::Command::TextArea),
            b"\x1b[8;30;100t"
        );
        assert_eq!(
            state.handle(SessionMessage::Resized(pty(60, 20, 0, 0))),
            None
        );
    }

    #[test]
    fn a_size_nobody_supplied_is_not_invented() {
        // `ssh -tt` from a client with no terminal of its own asks for a pty and
        // sends zeroes for its size. Nothing here knows one, so nothing is said.
        let mut state = session(PtyGeometry::default());

        assert_eq!(control(&mut state, mode2048::Command::Enable), b"");
        assert_eq!(control(&mut state, mode2048::Command::TextArea), b"");
        assert_eq!(
            control(&mut state, mode2048::Command::Query),
            mode2048::DECRPM_ENABLED,
            "russhd implements the mode whether or not it has a size to report"
        );
    }

    #[test]
    fn what_the_client_types_reaches_the_child_untouched() {
        let mut state = session(pty(100, 30, 0, 0));
        let typed = b"\x03\x1b[A\r\n\x00\xff".to_vec();

        assert_eq!(
            state.handle(SessionMessage::Input(typed.clone())),
            Some(typed)
        );
    }

    #[test]
    fn a_control_is_never_assembled_out_of_two_streams() {
        // stdout and stderr each get their own scanner: half a sequence on one
        // and half on the other is text on both, not a subscription.
        let (head, tail) = mode2048::ENABLE.split_at(4);
        let mut stdout = mode2048::Scanner::new(true);
        let mut stderr = mode2048::Scanner::new(true);

        let (mut to_client, mut commands) = (Vec::new(), Vec::new());
        let mut from_stderr = Vec::new();
        stdout.feed(head, &mut to_client, &mut commands);
        stderr.feed(tail, &mut from_stderr, &mut commands);
        stdout.finish(&mut to_client);
        stderr.finish(&mut from_stderr);

        assert!(
            commands.is_empty(),
            "two streams made a control: {commands:?}"
        );
        assert_eq!(to_client, head);
        assert_eq!(from_stderr, tail);
    }

    #[test]
    fn geometry_updates_retain_previous_valid_values() {
        let mut geometry = PtyGeometry::default();
        geometry.update(120, 40, 1600, 900);
        geometry.update(0, u32::MAX, 0, 1080);

        assert_eq!(
            geometry,
            PtyGeometry {
                cols: Some(120),
                rows: Some(40),
                width_px: Some(1600),
                height_px: Some(1080),
            }
        );
    }

    #[test]
    fn only_a_pty_configures_terminal_output_and_size() {
        let mut geometry = PtyGeometry::default();
        geometry.update(132, 43, 0, 0);
        let mut pty_command = tokio::process::Command::new("unused");
        assert!(configure_terminal(&mut pty_command, Some(geometry)));

        let envs = pty_command.as_std().get_envs().collect::<Vec<_>>();
        assert!(envs.contains(&(
            std::ffi::OsStr::new("COLUMNS"),
            Some(std::ffi::OsStr::new("132"))
        )));
        assert!(envs.contains(&(
            std::ffi::OsStr::new("LINES"),
            Some(std::ffi::OsStr::new("43"))
        )));

        let mut plain_command = tokio::process::Command::new("unused");
        plain_command.env("COLUMNS", "80").env("LINES", "24");
        assert!(!configure_terminal(&mut plain_command, None));
        assert_eq!(
            plain_command.as_std().get_envs().collect::<Vec<_>>(),
            [
                (std::ffi::OsStr::new("COLUMNS"), None),
                (std::ffi::OsStr::new("LINES"), None),
            ]
        );
    }

    #[test]
    fn a_pty_client_gets_a_cr_after_every_lf() {
        // No terminal on this side, and the client's is in raw mode.
        assert_eq!(output_bytes(b"one\ntwo\n", true), b"one\n\rtwo\n\r");
    }

    #[test]
    fn output_without_a_pty_is_verbatim() {
        // `ssh host cat some-file > copy` must not corrupt the file.
        let bytes = b"\x7fELF\r\n\n\x00\xff";
        assert_eq!(output_bytes(bytes, false), bytes);
    }

    #[test]
    fn competing_channel_completion_paths_claim_exactly_one_close() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        let close_guard = ChannelCloseGuard::default();
        let start = Arc::new(Barrier::new(2));
        let winners = Arc::new(AtomicUsize::new(0));

        // Reproduce the two owners in the shutdown failure: exec("shutdown")
        // completes the channel while the client's already-sent EOF is
        // dispatched to channel_eof. Whichever is handled first must suppress
        // the other's CHANNEL_CLOSE.
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let close_guard = close_guard.clone();
                let start = start.clone();
                let winners = winners.clone();
                scope.spawn(move || {
                    start.wait();
                    if close_guard.claim() {
                        winners.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });

        assert_eq!(winners.load(Ordering::Relaxed), 1);
        assert!(!close_guard.claim(), "a completed channel must stay closed");
    }
}
