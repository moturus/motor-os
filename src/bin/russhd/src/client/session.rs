use std::io::{IsTerminal, Read, Write};
use std::sync::Arc;

use russh::ChannelMsg;
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};

use super::args::{ConnectionOptions, Destination, PtyMode, SshArgs};
use super::forwarding::Listeners;
use super::local::safe_identity;
use super::prompt;
use super::remote;
use super::terminal::{InputEvent, InputFilter};
use super::transport;
use crate::forward::Tasks;

pub async fn run_ssh(args: SshArgs) -> Result<i32, russh::Error> {
    let mut route = connect_authenticated(&args.connection, &args.destination).await?;
    let peer = Arc::new(route.handles.pop().unwrap());
    peer.share_connection();
    let result = run_forwarding(&peer, &route.options, args).await;
    if result.is_err() || matches!(result, Ok(SessionEnd::Escape)) {
        peer.abort();
        route.abort();
    }
    let close = match Arc::try_unwrap(peer) {
        Ok(peer) => peer.close().await,
        Err(peer) => {
            peer.abort();
            Err(std::io::Error::other("forwarding retained an SSH peer").into())
        }
    };
    let route_close = route.close().await;
    let result = result?;
    close?;
    route_close?;
    Ok(match result {
        SessionEnd::Status(status) => status,
        SessionEnd::Escape => 255,
    })
}

enum SessionEnd {
    Status(i32),
    Escape,
}

#[cfg(all(test, unix))]
#[path = "session/accept_tests.rs"]
mod accept_tests;

async fn run_forwarding(
    peer: &Arc<transport::Peer>,
    options: &ConnectionOptions,
    args: SshArgs,
) -> Result<SessionEnd, russh::Error> {
    #[cfg(target_os = "motor")]
    if args.no_session {
        // Registration precedes requests that may wait indefinitely for a peer.
        start_ctrl_c(None, peer.interrupt())?;
    }
    let listeners = tokio::select! {
        result = Listeners::bind(options) => result?,
        () = peer.wait_closed() => return Err(russh::Error::Disconnect),
    };
    run_with_listeners(peer, options, args, listeners).await
}

async fn run_with_listeners(
    peer: &Arc<transport::Peer>,
    options: &ConnectionOptions,
    args: SshArgs,
    listeners: Listeners,
) -> Result<SessionEnd, russh::Error> {
    let no_session = args.no_session;
    let mut listeners = Some(listeners);
    let tasks = Arc::new(Tasks::default());
    let remote = (!options.remote_forwards.is_empty())
        .then(|| Arc::new(remote::Forwards::new(tasks.clone(), peer.receive_window())));
    if let Some(remote) = &remote {
        peer.enable_remote_forwards(remote.clone());
        if let Err(error) = setup_remote_forwards(peer, options, remote).await {
            drop(listeners);
            remote.cancel();
            tasks.wait_idle().await;
            return Err(error);
        }
    }
    let (ready, mut opened) = tokio::sync::oneshot::channel();
    let work = async {
        if no_session {
            let _ = ready.send(());
            return std::future::pending().await;
        }
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
        run_channel(peer, command, pty, ready).await
    };
    tokio::pin!(work);
    let mut accepting = false;
    let mut result = loop {
        tokio::select! {
            result = &mut work => break result,
            () = peer.wait_closed() => {
                listeners = None;
                tasks.cancel();
                break if no_session { Err(russh::Error::Disconnect) } else { work.await };
            }
            _ = &mut opened, if !accepting => accepting = true,
            () = peer.wait_session_closed(), if !no_session && listeners.is_some() => {
                listeners = None;
            }
            socket = async {
                match listeners.as_mut() {
                    Some(listeners) => listeners.accept().await,
                    None => std::future::pending().await,
                }
            }, if accepting && listeners.is_some() => match socket {
                Ok(socket) => socket.spawn(peer.clone(), &tasks),
                Err(failure) => {
                    listeners.as_mut().unwrap().failed(failure);
                    // A stream of failed incoming connections must still let
                    // the command and connection cancellation make progress.
                    tokio::task::yield_now().await;
                }
            }
        }
    };
    if let Some(remote) = &remote {
        remote.stop_accepting();
    }
    drop(listeners);
    if matches!(result, Ok(SessionEnd::Status(_))) && !peer.is_closed() {
        tokio::select! {
            () = tasks.wait_idle() => {}
            () = peer.wait_closed() => {
                tasks.cancel();
                tasks.wait_idle().await;
                result = Err(russh::Error::Disconnect);
            }
        }
    } else {
        tasks.cancel();
        tasks.wait_idle().await;
    }
    result
}

async fn setup_remote_forwards(
    peer: &transport::Peer,
    options: &ConnectionOptions,
    remote: &remote::Forwards,
) -> Result<(), russh::Error> {
    for request in &options.remote_forwards {
        let result = match peer
            .tcpip_forward(request.bind_address(), u32::from(request.listen.port))
            .await
        {
            Ok(reply) => remote.record(request, reply),
            Err(error) => Err(error),
        };
        match result {
            Ok(port) if request.listen.port == 0 => eprintln!(
                "Allocated port {port} for remote forward to {}:{}",
                request.target.host, request.target.port,
            ),
            Ok(_) => {}
            Err(error) if options.exit_on_forward_failure => return Err(error),
            Err(error) => eprintln!(
                "Warning: remote forward {}:{}: {error}",
                request.bind_address(),
                request.listen.port
            ),
        }
    }
    remote.finish_setup();
    Ok(())
}

type Handle = transport::Peer;

pub struct Connection {
    handles: Vec<Handle>,
    options: ConnectionOptions,
}

impl std::ops::Deref for Connection {
    type Target = Handle;
    fn deref(&self) -> &Handle {
        self.handles.last().unwrap()
    }
}

impl std::ops::DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Handle {
        self.handles.last_mut().unwrap()
    }
}

impl Connection {
    pub fn abort(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }

    pub async fn close(mut self) -> Result<(), russh::Error> {
        close_handles(std::mem::take(&mut self.handles)).await
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.abort();
        if !self.handles.is_empty()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let handles = std::mem::take(&mut self.handles);
            runtime.spawn(async move {
                if let Err(error) = close_handles(handles).await {
                    log::debug!("closing SSH route: {error}");
                }
            });
        }
    }
}

async fn close_handles(handles: Vec<Handle>) -> Result<(), russh::Error> {
    let mut first_error = None;
    for handle in handles.into_iter().rev() {
        let result = handle.close().await;
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

pub async fn connect_authenticated(
    options: &ConnectionOptions,
    destination: &Destination,
) -> Result<Connection, russh::Error> {
    let config = super::config::Config::load(options.config_file.as_deref())
        .map_err(|error| russh::Error::InvalidConfig(error.to_string()))?;
    let route = config
        .resolve(options, destination)
        .map_err(|error| russh::Error::InvalidConfig(error.to_string()))?;
    let mut connection = Connection {
        handles: Vec::new(),
        options: route.last().unwrap().options.clone(),
    };
    for hop in route {
        let result = async {
            let handle = if let Some(jump) = connection.handles.last() {
                transport::connect_via(jump, &hop.options, &hop.destination).await?
            } else {
                transport::connect(&hop.options, &hop.destination).await?
            };
            connection.handles.push(handle);
            authenticate(
                connection.handles.last_mut().unwrap(),
                &hop.options,
                &hop.destination,
            )
            .await
        }
        .await;
        if let Err(error) = result {
            let error = russh::Error::InvalidConfig(format!(
                "{} ({}@{}:{}): {error}",
                hop.alias, hop.destination.user, hop.destination.host, hop.options.port
            ));
            connection.abort();
            if let Err(cleanup) = connection.close().await {
                log::debug!("closing failed SSH route: {cleanup}");
            }
            return Err(error);
        }
    }
    Ok(connection)
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

    if methods.contains(&russh::MethodKind::PublicKey) {
        for path in &options.identities {
            if !path.exists() {
                continue;
            }
            if let Err(error) = safe_identity(path) {
                eprintln!("Warning: ignoring identity '{}': {error}", path.display());
                continue;
            }
            let key = match load_secret_key(path, None) {
                Ok(key) => key,
                Err(russh::keys::Error::KeyIsEncrypted) if !options.batch_mode => {
                    let mut passphrase = prompt::secret(&format!(
                        "Enter passphrase for key '{}': ",
                        path.display()
                    ))?;
                    let result = load_secret_key(path, Some(&passphrase));
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
    session: &transport::Peer,
    command: Option<String>,
    pty: bool,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<SessionEnd, russh::Error> {
    let channel = session.open_session().await?;
    let _ = ready.send(());
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
    let (reader, writer) = channel.split();
    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
    #[cfg(target_os = "motor")]
    if pty {
        start_ctrl_c(Some(input_tx.clone()), session.interrupt())?;
    }
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        #[cfg(target_os = "motor")]
        let terminal = std::io::stdin().is_terminal();
        loop {
            let mut bytes = vec![0_u8; 32 * 1024];
            #[cfg(target_os = "motor")]
            let read = if terminal {
                prompt::read_terminal(&mut stdin, &mut bytes)
            } else {
                stdin.read(&mut bytes)
            };
            #[cfg(not(target_os = "motor"))]
            let read = stdin.read(&mut bytes);
            match read {
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

    let mut input = Some(Box::pin(forward_stdin(&writer, input_rx, pty)));
    let stopped = session.wait_session_closed();
    tokio::pin!(stopped);
    let (output_tx, output_done) = output_writer();
    let mut escaped = false;
    let result = {
        let output = forward_output(reader, output_tx);
        tokio::pin!(output);
        loop {
            tokio::select! {
                () = &mut stopped, if input.is_some() => input = None,
                result = &mut output => break result,
                result = async {
                    match input.as_mut() {
                        Some(work) => work.as_mut().await,
                        None => std::future::pending().await,
                    }
                }, if input.is_some() => {
                    match result {
                        Ok(true) => {
                            session.abort();
                            escaped = true;
                            break Ok(None);
                        }
                        Ok(false) => input = None,
                        // Remote closure stops stdin before buffered output has
                        // necessarily reached stdout or supplied the exit status.
                        Err(russh::Error::SendError) if session.is_channel_closed() => {
                            input = None;
                        }
                        Err(error) => break Err(error),
                    }
                }
            }
        }
    };
    // Dropping the output future closes its queue. Drain the bounded backlog
    // before restoring terminal modes or returning the remote exit status.
    output_done
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))??;
    terminal_mode.disable();
    let status = result?
        .and_then(|status| i32::try_from(status).ok())
        .filter(|status| *status <= 255)
        .unwrap_or(255);
    Ok(if escaped {
        SessionEnd::Escape
    } else {
        SessionEnd::Status(status)
    })
}

fn output_writer() -> (
    tokio::sync::mpsc::Sender<ChannelMsg>,
    tokio::sync::oneshot::Receiver<std::io::Result<()>>,
) {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    let (done, result) = tokio::sync::oneshot::channel();
    // A pipe write can block. Keep it off the async thread that must service
    // network traffic and forward stdin, with bounded buffering in both directions.
    std::thread::spawn(move || {
        let mut write = || -> std::io::Result<()> {
            while let Some(message) = receiver.blocking_recv() {
                match message {
                    ChannelMsg::Data { data } => {
                        let mut stdout = std::io::stdout().lock();
                        stdout.write_all(&data)?;
                        stdout.flush()?;
                    }
                    ChannelMsg::ExtendedData { data, .. } => {
                        let mut stderr = std::io::stderr().lock();
                        stderr.write_all(&data)?;
                        stderr.flush()?;
                    }
                    _ => {}
                }
            }
            Ok(())
        };
        let _ = done.send(write());
    });
    (sender, result)
}

async fn forward_output(
    mut reader: russh::ChannelReadHalf,
    output: tokio::sync::mpsc::Sender<ChannelMsg>,
) -> Result<Option<u32>, russh::Error> {
    let mut exit_status = None;
    while let Some(message) = reader.wait().await {
        match message {
            ChannelMsg::Data { .. } | ChannelMsg::ExtendedData { .. } => {
                output
                    .send(message)
                    .await
                    .map_err(|_| std::io::Error::other("SSH output writer stopped"))?;
            }
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => exit_status = Some(status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(exit_status)
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
            moto_sdk::tooling::mode2048::DECRQM,
            moto_sdk::tooling::mode2048::ENABLE,
            moto_sdk::tooling::mode2048::TEXT_AREA_QUERY,
        ])?;
        Ok(mode)
    }

    fn disabled() -> Self {
        Self { output: None }
    }

    fn disable(&mut self) {
        let _ = self.write(&[moto_sdk::tooling::mode2048::DISABLE]);
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
fn start_ctrl_c(
    input: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    interrupt: impl FnOnce() + Send + 'static,
) -> std::io::Result<()> {
    use moto_sdk::rt::process::{ctrl_c_register_handler, ctrl_c_wait};

    let (setup_tx, setup_rx) = std::sync::mpsc::sync_channel(0);
    std::thread::Builder::new()
        .name("ssh-ctrl-c".to_owned())
        .spawn(move || match ctrl_c_register_handler() {
            Ok(mut last) => {
                if setup_tx.send(Ok(())).is_err() {
                    return;
                }
                while let Ok(next) = ctrl_c_wait(last) {
                    for _ in last..next {
                        if input
                            .as_ref()
                            .is_none_or(|input| input.blocking_send(vec![3]).is_err())
                        {
                            // After the session ends, Ctrl+C cancels the tunnel
                            // instead of targeting its already-closed stdin.
                            interrupt();
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

    struct Accept;

    impl russh::server::Handler for Accept {
        type Error = russh::Error;

        async fn auth_none(&mut self, _: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }
    }

    #[test]
    fn connection_loss_cancels_local_listener_resolution_during_setup() {
        use std::future::{Future, poll_fn};
        use std::os::unix::fs::DirBuilderExt;
        use std::task::Poll;

        // A concurrent fork would keep the cancelled listener open until its exec.
        let _process_and_rebind =
            crate::forward::accept::test_support::PROCESS_AND_REBIND.blocking_lock();
        let root = std::env::temp_dir().join(format!("motor-bind-cancel-{}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let mut options = ConnectionOptions::default();
                    options
                        .apply_o(&format!("Port={}", listener.local_addr().unwrap().port()))
                        .unwrap();
                    options
                        .apply_o(&format!(
                            "UserKnownHostsFile={}",
                            root.join("known_hosts").display()
                        ))
                        .unwrap();
                    options.apply_o("StrictHostKeyChecking=accept-new").unwrap();
                    options.apply_o("BatchMode=yes").unwrap();
                    let accepting = tokio::spawn(async move {
                        let (socket, _) = listener.accept().await.unwrap();
                        let config = Arc::new(russh::server::Config {
                            keys: vec![
                                russh::keys::PrivateKey::random(
                                    &mut rand::rng(),
                                    russh::keys::ssh_key::Algorithm::Ed25519,
                                )
                                .unwrap(),
                            ],
                            inactivity_timeout: None,
                            ..Default::default()
                        });
                        russh::server::run_stream(config, socket, Accept).await
                    });
                    let destination = Destination::parse("motor@127.0.0.1").unwrap();
                    let mut peer = transport::connect(&options, &destination).await.unwrap();
                    assert!(peer.authenticate_none("motor").await.unwrap().success());
                    let server = accepting.await.unwrap().unwrap();
                    let peer = Arc::new(peer);
                    peer.share_connection();
                    let reservation = tokio::net::TcpSocket::new_v4().unwrap();
                    reservation.set_reuseaddr(true).unwrap();
                    reservation.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                    let address = reservation.local_addr().unwrap();
                    let earlier = tokio::net::TcpSocket::new_v4().unwrap();
                    earlier.set_reuseaddr(true).unwrap();
                    earlier.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                    let earlier_address = earlier.local_addr().unwrap();
                    options
                        .add_local_forward(&format!(
                            "127.0.0.1:{}:localhost:80",
                            earlier_address.port()
                        ))
                        .unwrap();
                    options
                        .add_local_forward(&format!("LOCALHOST:{}:localhost:80", address.port()))
                        .unwrap();
                    options.exit_on_forward_failure = true;
                    let args = SshArgs {
                        connection: options.clone(),
                        destination,
                        command: vec![],
                        pty: PtyMode::Disable,
                        no_session: true,
                    };

                    // Occupy the only blocking worker so LOCALHOST resolution
                    // stays queued. It resolves locally when cleanup releases it.
                    let (release, released) = std::sync::mpsc::channel();
                    let (entered, started) = tokio::sync::oneshot::channel();
                    let blocked = tokio::task::spawn_blocking(move || {
                        entered.send(()).unwrap();
                        released.recv()
                    });
                    started.await.unwrap();
                    let mut forwarding = Box::pin(run_forwarding(&peer, &options, args));
                    assert!(
                        poll_fn(|cx| Poll::Ready(forwarding.as_mut().poll(cx)))
                            .await
                            .is_pending()
                    );
                    assert!(std::net::TcpStream::connect(earlier_address).is_ok());
                    assert!(std::net::TcpStream::connect(address).is_err());
                    server.abort();
                    assert!(matches!(server.await, Err(russh::Error::Disconnect)));
                    peer.wait_closed().await;
                    let result = poll_fn(|cx| Poll::Ready(forwarding.as_mut().poll(cx))).await;
                    let earlier_released = std::net::TcpStream::connect(earlier_address).is_err();
                    drop(forwarding);
                    release.send(()).unwrap();
                    blocked.await.unwrap().unwrap();
                    assert!(
                        matches!(result, Poll::Ready(Err(russh::Error::Disconnect))),
                        "listener setup ignored connection loss while resolution was pending"
                    );
                    assert!(
                        earlier_released,
                        "cancelled setup retained an earlier listener"
                    );
                })
                .await
                .expect("listener setup cancellation stalled");
            });
        std::fs::remove_dir_all(root).unwrap();
    }

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
