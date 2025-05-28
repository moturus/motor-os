pub type StdinTx = tokio::sync::mpsc::Sender<Vec<u8>>;

pub async fn spawn(
    cmdline: &str,
    channel: russh::ChannelId,
    session: russh::server::Handle,
) -> Result<StdinTx, russh::Error> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let Ok(words) = shell_words::split(cmdline) else {
        return Err(russh::Error::IO(std::io::ErrorKind::InvalidInput.into()));
    };

    if words.is_empty() {
        return Err(russh::Error::IO(std::io::ErrorKind::InvalidInput.into()));
    }

    let mut cmd = tokio::process::Command::new(&words[0]);
    cmd.args(&words[1..]);

    #[cfg(target_os = "moturus")]
    cmd.env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .inspect_err(|e| log::warn!("Error spawning cmd `{cmdline}`: {e:?}"))?;

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
    tokio::spawn(async move {
        let mut buf = [0_u8; 256];
        loop {
            match stdout.read(&mut buf).await {
                Ok(sz) => {
                    if sz == 0 {
                        log::debug!("stdout.read() returned zero.");
                        break;
                    }
                    if let Err(err) = send_output(&session_handle, channel, &buf[0..sz]).await {
                        log::debug!("session.data() failed with error '{err:?}'");
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
    tokio::spawn(async move {
        let mut buf = [0_u8; 256];
        loop {
            match stderr.read(&mut buf).await {
                Ok(sz) => {
                    if sz == 0 {
                        log::debug!("stderr.read() returned zero.");
                        break;
                    }
                    if let Err(err) = send_output(&session_handle, channel, &buf[0..sz]).await {
                        log::debug!("session.data() failed with error '{err:?}'");
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
        match child.wait().await {
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
) -> anyhow::Result<()> {
    use anyhow::anyhow;

    let mut start = 0;
    let mut pos = 0;
    while start < bytes.len() {
        let mut add_r = false;

        while pos < bytes.len() {
            if bytes[pos] == b'\n' {
                add_r = true;
                pos += 1;
                break;
            }

            pos += 1;
        }

        session
            .data(channel, bytes[start..pos].into())
            .await
            .map_err(|_| anyhow!("Failed to send bytes to the client."))?;

        if add_r {
            session
                .data(channel, [b'\r'].as_slice().into())
                .await
                .map_err(|_| anyhow!("Failed to send bytes to the client."))?;
        }

        start = pos;
    }

    Ok(())
}
