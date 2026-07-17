use std::sync::Arc;

pub type StdinTx = tokio::sync::mpsc::Sender<Vec<u8>>;

/// The shell that runs client sessions and commands.
#[cfg(target_os = "motor")]
pub const SHELL: &str = "/bin/rush";
#[cfg(not(target_os = "motor"))]
pub const SHELL: &str = "/bin/bash";

/// What to run for a client, and how to wire up its output.
pub struct Command {
    /// The program and its arguments; `argv[0]` is the program to run.
    pub argv: Vec<String>,

    /// Translate LF into CRLF in the child's output. Needed when the client
    /// asked for a PTY: its terminal is in raw mode, and we have no real
    /// terminal on this side to do the translation. Must stay off otherwise --
    /// `ssh host cat some-file` has to receive the file's bytes unchanged.
    pub crlf: bool,
}

impl Command {
    /// An interactive session: RFC 4254 6.5 `shell`.
    pub fn shell() -> Self {
        Self {
            argv: vec![SHELL.to_owned(), "-i".to_owned()],
            // Such a session always comes with a PTY request.
            crlf: true,
        }
    }

    /// A client command: RFC 4254 6.5 `exec`.
    ///
    /// `cmdline` is a command *line*, not an argv, so it goes to the shell
    /// verbatim: clients expect `ssh host 'ls *.rs | wc -l'` to work, and
    /// OpenSSH likewise runs the user's login shell with `-c`.
    pub fn exec(cmdline: &str, crlf: bool) -> Self {
        Self {
            argv: vec![SHELL.to_owned(), "-c".to_owned(), cmdline.to_owned()],
            crlf,
        }
    }
}

pub async fn spawn(
    command: Command,
    channel: russh::ChannelId,
    session: russh::server::Handle,
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

    #[cfg(target_os = "motor")]
    cmd.env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");

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

    let crlf = command.crlf;
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

        let _ = session_handle.eof(channel).await;
        let _ = session_handle.close(channel).await;
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
        .data(channel, output_bytes(bytes, crlf).into())
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
        let cmd = Command::exec("ls *.rs | wc -l", false);
        assert_eq!(cmd.argv, [SHELL, "-c", "ls *.rs | wc -l"]);
    }

    #[test]
    fn exec_passes_the_command_line_through_untouched() {
        // Quoting is the shell's job: whatever the client sent has to reach it
        // byte for byte.
        let cmdline = r#"echo "a  b" '$X' \& > /tmp/f"#;
        assert_eq!(Command::exec(cmdline, false).argv[2], cmdline);
    }

    #[test]
    fn a_shell_session_is_interactive() {
        assert_eq!(Command::shell().argv, [SHELL, "-i"]);
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
}
