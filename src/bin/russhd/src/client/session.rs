use std::io::{IsTerminal, Read, Write};
#[cfg(target_os = "motor")]
use std::path::PathBuf;
use std::sync::Arc;

use russh::ChannelMsg;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

use super::args::{ConnectionOptions, Destination, PtyMode, SshArgs};
use super::local::safe_identity;
use super::prompt;
use super::terminal::{InputEvent, InputFilter};
use super::transport;

pub async fn run_ssh(args: SshArgs) -> Result<i32, russh::Error> {
    let mut session = connect_authenticated(&args.connection, &args.destination).await?;
    let terminal = std::io::stdin().is_terminal();
    let pty = match args.pty {
        PtyMode::Force if !terminal => {
            return Err(russh::Error::InvalidConfig(
                "-t requires a terminal on stdin".to_owned(),
            ));
        }
        PtyMode::Force => true,
        PtyMode::Disable => false,
        PtyMode::Auto => args.command.is_empty() && terminal,
    };
    if args.command.is_empty() && !pty {
        return Err(russh::Error::InvalidConfig(
            "an interactive shell requires a terminal on stdin".to_owned(),
        ));
    }
    let command = (!args.command.is_empty()).then(|| args.command.join(" "));
    let status = run_channel(&mut session, command, pty).await?;
    session
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await?;
    Ok(status)
}

pub async fn connect_authenticated(
    options: &ConnectionOptions,
    destination: &Destination,
) -> Result<russh::client::Handle<transport::Handler>, russh::Error> {
    let mut session = transport::connect(options, destination).await?;
    authenticate(&mut session, options, destination).await?;
    Ok(session)
}

async fn authenticate(
    session: &mut russh::client::Handle<transport::Handler>,
    options: &ConnectionOptions,
    destination: &Destination,
) -> Result<(), russh::Error> {
    let none = session.authenticate_none(destination.user.clone()).await?;
    if none.success() {
        return Ok(());
    }
    let methods = match none {
        russh::client::AuthResult::Failure {
            remaining_methods, ..
        } => remaining_methods,
        russh::client::AuthResult::Success => unreachable!(),
    };

    #[cfg(target_os = "motor")]
    let identities = {
        let mut identities = options.identities.clone();
        if !options.identities_only {
            identities.push(PathBuf::from("/user/cfg/ssh/id_ed25519"));
        }
        identities
    };
    #[cfg(not(target_os = "motor"))]
    let identities = options.identities.clone();
    if methods.contains(&russh::MethodKind::PublicKey) {
        for path in identities {
            if !path.exists() {
                continue;
            }
            if let Err(error) = safe_identity(&path) {
                eprintln!("Warning: ignoring identity '{}': {error}", path.display());
                continue;
            }
            let key = match load_secret_key(&path, None) {
                Ok(key) => key,
                Err(russh::keys::Error::KeyIsEncrypted) if !options.batch_mode => {
                    let mut passphrase = prompt::secret(&format!(
                        "Enter passphrase for key '{}': ",
                        path.display()
                    ))?;
                    let result = load_secret_key(&path, Some(&passphrase));
                    prompt::clear_secret(&mut passphrase);
                    match result {
                        Ok(key) => key,
                        Err(error) => {
                            eprintln!("Warning: ignoring identity '{}': {error}", path.display());
                            continue;
                        }
                    }
                }
                Err(error) => {
                    eprintln!("Warning: ignoring identity '{}': {error}", path.display());
                    continue;
                }
            };
            let hash = if key.algorithm().is_rsa() {
                session.best_supported_rsa_hash().await?.flatten()
            } else {
                None
            };
            if session
                .authenticate_publickey(
                    destination.user.clone(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                )
                .await?
                .success()
            {
                return Ok(());
            }
        }
    }

    if methods.contains(&russh::MethodKind::Password) && !options.batch_mode {
        let mut password = prompt::secret(&format!(
            "{}@{}'s password: ",
            destination.user, destination.host
        ))?;
        let result = session
            .authenticate_password(destination.user.clone(), password.clone())
            .await;
        prompt::clear_secret(&mut password);
        let result = result?;
        if result.success() {
            return Ok(());
        }
    }
    Err(russh::Error::NotAuthenticated)
}

async fn run_channel(
    session: &mut russh::client::Handle<transport::Handler>,
    command: Option<String>,
    pty: bool,
) -> Result<i32, russh::Error> {
    let channel = session.channel_open_session().await?;
    let mut terminal_mode = if pty {
        TerminalMode::enable()?
    } else {
        TerminalMode::disabled()
    };
    if pty {
        let (columns, rows) = fallback_size();
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_owned());
        channel
            .request_pty(true, &term, columns.into(), rows.into(), 0, 0, &[])
            .await?;
    }
    if let Some(command) = command {
        channel.exec(true, command).await?;
    } else {
        channel.request_shell(true).await?;
    }
    let (mut reader, writer) = channel.split();
    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
    #[cfg(target_os = "motor")]
    if pty {
        start_ctrl_c(input_tx.clone())?;
    }
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        loop {
            let mut bytes = vec![0_u8; 32 * 1024];
            match stdin.read(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    bytes.truncate(read);
                    if input_tx.blocking_send(bytes).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let input = forward_stdin(&writer, input_rx, pty);
    tokio::pin!(input);
    let mut input_done = false;
    let mut exit_status = None;
    loop {
        tokio::select! {
            message = reader.wait() => {
                let Some(message) = message else { break };
                match message {
                    ChannelMsg::Data { data } => {
                        std::io::stdout().write_all(&data)?;
                        std::io::stdout().flush()?;
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        std::io::stderr().write_all(&data)?;
                        std::io::stderr().flush()?;
                    }
                    ChannelMsg::ExitStatus { exit_status: status } => exit_status = Some(status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            result = &mut input, if !input_done => {
                if result? {
                    break;
                }
                input_done = true;
            }
        }
    }
    terminal_mode.disable();
    Ok(exit_status
        .and_then(|status| i32::try_from(status).ok())
        .filter(|status| *status <= 255)
        .unwrap_or(255))
}

async fn forward_stdin(
    writer: &russh::ChannelWriteHalf<russh::client::Msg>,
    mut input_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pty: bool,
) -> Result<bool, russh::Error> {
    let mut filter = pty.then(InputFilter::new);
    let mut control_deadline = None;
    loop {
        let expiry_deadline = control_deadline;
        let expiry = async move {
            if let Some(deadline) = expiry_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(expiry);
        tokio::select! {
            input = input_rx.recv() => {
                let Some(input) = input else {
                    if let Some(filter) = filter.as_mut()
                        && forward_input(writer, filter.finish()).await?
                    {
                        return Ok(true);
                    }
                    writer.eof().await?;
                    return Ok(false);
                };
                if let Some(filter) = filter.as_mut() {
                    let events = filter.feed(&input);
                    if forward_input(writer, events).await? {
                        return Ok(true);
                    }
                    control_deadline = filter.has_pending_control().then(|| {
                        tokio::time::Instant::now() + std::time::Duration::from_millis(50)
                    });
                } else {
                    writer.data_bytes(input).await?;
                }
            }
            () = &mut expiry => {
                if let Some(filter) = filter.as_mut()
                    && forward_input(writer, filter.expire()).await?
                {
                    return Ok(true);
                }
                control_deadline = None;
            }
        }
    }
}

async fn forward_input(
    writer: &russh::ChannelWriteHalf<russh::client::Msg>,
    events: Vec<InputEvent>,
) -> Result<bool, russh::Error> {
    for event in events {
        match event {
            InputEvent::Data(data) => writer.data_bytes(data).await?,
            InputEvent::Resize {
                rows,
                columns,
                height_px,
                width_px,
            } => {
                writer
                    .window_change(
                        columns.into(),
                        rows.into(),
                        width_px.into(),
                        height_px.into(),
                    )
                    .await?;
            }
            InputEvent::Disconnect => return Ok(true),
        }
    }
    Ok(false)
}

fn fallback_size() -> (u16, u16) {
    let value = |name, fallback| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| *value != 0)
            .unwrap_or(fallback)
    };
    (value("COLUMNS", 80), value("LINES", 24))
}

enum TerminalOutput {
    Stderr,
    Stdout,
}

struct TerminalMode {
    output: Option<TerminalOutput>,
}

impl TerminalMode {
    fn enable() -> std::io::Result<Self> {
        let output = if std::io::stderr().is_terminal() {
            Some(TerminalOutput::Stderr)
        } else if std::io::stdout().is_terminal() {
            Some(TerminalOutput::Stdout)
        } else {
            None
        };
        let mut mode = Self { output };
        mode.write(&[
            moto_tooling::mode2048::DECRQM,
            moto_tooling::mode2048::ENABLE,
            moto_tooling::mode2048::TEXT_AREA_QUERY,
        ])?;
        Ok(mode)
    }

    fn disabled() -> Self {
        Self { output: None }
    }

    fn disable(&mut self) {
        let _ = self.write(&[moto_tooling::mode2048::DISABLE]);
        self.output = None;
    }

    fn write(&mut self, parts: &[&[u8]]) -> std::io::Result<()> {
        let Some(output) = self.output.as_ref() else {
            return Ok(());
        };
        match output {
            TerminalOutput::Stderr => {
                let mut output = std::io::stderr().lock();
                for part in parts {
                    output.write_all(part)?;
                }
                output.flush()
            }
            TerminalOutput::Stdout => {
                let mut output = std::io::stdout().lock();
                for part in parts {
                    output.write_all(part)?;
                }
                output.flush()
            }
        }
    }
}

impl Drop for TerminalMode {
    fn drop(&mut self) {
        self.disable();
    }
}

#[cfg(target_os = "motor")]
fn start_ctrl_c(input: tokio::sync::mpsc::Sender<Vec<u8>>) -> std::io::Result<()> {
    let (setup_tx, setup_rx) = std::sync::mpsc::sync_channel(0);
    std::thread::Builder::new()
        .name("ssh-ctrl-c".to_owned())
        .spawn(move || match moto_rt::process::ctrl_c_register_handler() {
            Ok(mut last) => {
                if setup_tx.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(next) = moto_rt::process::ctrl_c_wait(last) {
                    for _ in last..next {
                        if input.blocking_send(vec![3]).is_err() {
                            return;
                        }
                    }
                    last = next;
                }
            }
            Err(error) => {
                let _ = setup_tx.send(Err(std::io::Error::other(error.to_string())));
            }
        })?;
    setup_rx
        .recv()
        .unwrap_or_else(|_| Err(std::io::Error::other("Ctrl+C handler stopped during setup")))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn unix_identity_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("motor-identity-{}", std::process::id()));
        std::fs::write(&path, b"key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        safe_identity(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            safe_identity(&path).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(path).unwrap();
    }
}
