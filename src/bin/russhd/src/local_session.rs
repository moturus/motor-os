use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub type StdinTx = tokio::sync::mpsc::Sender<Vec<u8>>;

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
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let Some((program, args)) = command.argv.split_first() else {
        return Err(russh::Error::IO(std::io::ErrorKind::InvalidInput.into()));
    };

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    if !cfg.path().is_empty() {
        cmd.env("PATH", cfg.path());
    }
    let crlf = configure_terminal(&mut cmd, pty);

    // Pass CAP_SPAWN_DETACHED down to the shell (on top of the usual defaults), so
    // a program the shell trusts can start a server that outlives this ssh
    // session. russhd holds the bit via its service capabilities (sys-init.cfg).
    #[cfg(target_os = "motor")]
    cmd.env(
        moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
        format!(
            "0x{:x}",
            moto_sys::caps::CAP_SPAWN
                | moto_sys::caps::CAP_LOG
                | moto_sys::caps::CAP_SPAWN_DETACHED
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

    // Pipe stdin through.
    let mut stdin = child.stdin.take().unwrap();
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);

    tokio::spawn(async move {
        loop {
            let Some(data) = stdin_rx.recv().await else {
                log::debug!("stdin_rx.recv() returned None");
                if stdin_rx.is_closed() {
                    break;
                }
                break;
            };
            if let Err(err) = stdin.write_all(&data).await {
                log::debug!("stdin.write_all() failed with error '{err:?}'");
                break;
            }
        }
    });

    // Pipe stdout through.
    let mut stdout = child.stdout.take().unwrap();

    let session_handle = session.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0_u8; 256];
        loop {
            match stdout.read(&mut buf).await {
                Ok(sz) => {
                    if sz == 0 {
                        log::debug!("stdout.read() returned zero.");
                        break;
                    }
                    if send_output(&session_handle, channel, &buf[0..sz], crlf)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    log::debug!("stdout.read() failed with error '{err:?}'");
                    break;
                }
            }
        }
    });

    // Pipe stderr through.
    let mut stderr = child.stderr.take().unwrap();

    let session_handle = session.clone();
    let stderr_task = tokio::spawn(async move {
        let mut buf = [0_u8; 256];
        loop {
            match stderr.read(&mut buf).await {
                Ok(sz) => {
                    if sz == 0 {
                        log::debug!("stderr.read() returned zero.");
                        break;
                    }
                    if send_output(&session_handle, channel, &buf[0..sz], crlf)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    log::debug!("stderr.read() failed with error '{err:?}'");
                    break;
                }
            }
        }
    });

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
