use std::borrow::Cow;
use std::future::Future;
use std::net::{TcpStream, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use russh::client;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::args::{ConnectionOptions, Destination, HostKeyPolicy};
use super::known_hosts;
use super::prompt;

#[derive(Clone)]
struct TransportControl {
    state: Arc<Mutex<ControlState>>,
}

struct ControlState {
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    aborted: bool,
    wakers: [Option<Waker>; 2],
}

enum IoOperation {
    Read,
    Write,
    Shutdown,
}

#[derive(Debug)]
struct Aborted;

impl std::fmt::Display for Aborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SSH transport aborted")
    }
}

impl std::error::Error for Aborted {}

struct AbortOnDrop(TransportControl);

struct ChannelState {
    single: bool,
    opening_session: bool,
    session: Option<russh::ChannelId>,
    closed: bool,
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl TransportControl {
    fn new(deadline: Option<Instant>) -> Self {
        let sleep = deadline.map(|deadline| {
            Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                deadline,
            )))
        });
        Self {
            state: Arc::new(Mutex::new(ControlState {
                sleep,
                aborted: false,
                wakers: [None, None],
            })),
        }
    }

    fn clear(&self) {
        self.state.lock().unwrap().sleep.take();
    }

    fn abort(&self) {
        let wakers = {
            let mut state = self.state.lock().unwrap();
            state.aborted = true;
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }

    fn is_aborted(&self) -> bool {
        self.state.lock().unwrap().aborted
    }

    fn poll(&self, cx: &mut Context<'_>, operation: IoOperation) -> std::io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.aborted {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                Aborted,
            ));
        }
        // Register both halves even after setup has removed the deadline.
        let slot = &mut state.wakers[usize::from(!matches!(operation, IoOperation::Read))];
        if slot
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            *slot = Some(cx.waker().clone());
        }
        if !matches!(operation, IoOperation::Shutdown)
            && state
                .sleep
                .as_mut()
                .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready())
        {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

struct ControlledStream<S> {
    stream: S,
    control: TransportControl,
}

impl<S: AsyncRead + Unpin> AsyncRead for ControlledStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.control.poll(cx, IoOperation::Read)?;
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ControlledStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.control.poll(cx, IoOperation::Write)?;
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.control.poll(cx, IoOperation::Write)?;
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.control.poll(cx, IoOperation::Shutdown)?;
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

pub struct Handler {
    control: TransportControl,
    _running: tokio::sync::watch::Sender<()>,
    destination: Destination,
    port: u16,
    known_hosts: std::path::PathBuf,
    policy: HostKeyPolicy,
    batch_mode: bool,
    channels: tokio::sync::watch::Sender<ChannelState>,
}

pub struct Peer {
    handle: client::Handle<Handler>,
    receive_window: usize,
    channels: tokio::sync::watch::Sender<ChannelState>,
    shutdown: AbortOnDrop,
    ended: tokio::sync::watch::Receiver<()>,
}

impl std::ops::Deref for Peer {
    type Target = client::Handle<Handler>;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl std::ops::DerefMut for Peer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

impl Peer {
    pub fn receive_window(&self) -> usize {
        self.receive_window
    }

    /// Interrupt transport I/O independently of SSH windows and message queues.
    pub fn abort(&self) {
        self.shutdown.0.abort();
    }

    /// Remains observable while other tasks retain this peer through an Arc.
    pub async fn wait_closed(&self) {
        let mut ended = self.ended.clone();
        let _ = ended.changed().await;
    }

    pub(super) fn share_connection(&self) {
        self.channels.send_modify(|state| state.single = false);
    }

    pub(super) async fn open_session(&self) -> Result<russh::Channel<client::Msg>, russh::Error> {
        // Listener accept tasks start after this open. Its confirmation is the
        // only locally initiated open during session setup.
        self.channels
            .send_modify(|state| state.opening_session = true);
        let result = self.handle.channel_open_session().await;
        if result.is_err() {
            self.channels
                .send_modify(|state| state.opening_session = false);
        }
        result
    }

    pub(super) async fn wait_session_closed(&self) {
        let mut channels = self.channels.subscribe();
        tokio::select! {
            _ = async {
                while !channels.borrow().closed {
                    if channels.changed().await.is_err() { break; }
                }
            } => {}
            _ = self.wait_closed() => {}
        }
    }

    #[cfg(target_os = "motor")]
    pub(super) fn interrupt(&self) -> impl FnOnce() + Send + 'static {
        let control = self.shutdown.0.clone();
        move || control.abort()
    }

    pub(super) fn is_channel_closed(&self) -> bool {
        self.channels.borrow().closed || self.handle.is_closed()
    }

    pub async fn close(self) -> Result<(), russh::Error> {
        let aborted = self.shutdown.0.is_aborted();
        let already_disconnecting = {
            let state = self.channels.borrow();
            state.single && state.closed
        };
        let requested = !aborted && !self.handle.is_closed() && !already_disconnecting;
        let enqueue = if requested {
            self.handle
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await
        } else {
            Ok(())
        };
        let result = self.handle.await;
        let channel_closed = self.channels.borrow().closed;
        if !channel_closed && !aborted {
            enqueue?;
        }
        match result {
            // russh reports a local disconnect with this sentinel, including
            // the disconnect sent directly from the channel-close callback.
            Err(russh::Error::Disconnect) if requested || channel_closed || aborted => Ok(()),
            Err(russh::Error::IO(error))
                if aborted && error.get_ref().is_some_and(|error| error.is::<Aborted>()) =>
            {
                Ok(())
            }
            result => result,
        }
    }
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn channel_close(
        &mut self,
        channel: russh::ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let mut disconnect = false;
        self.channels.send_if_modified(|state| {
            disconnect = state.single;
            if state.single || state.session == Some(channel) {
                state.closed = true;
                true
            } else {
                false
            }
        });
        if disconnect {
            // A jump owns one transport channel, so its closure ends the hop.
            session.disconnect(russh::Disconnect::ByApplication, "", "")?;
        }
        Ok(())
    }

    async fn channel_open_confirmation(
        &mut self,
        id: russh::ChannelId,
        _: u32,
        _: u32,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.channels.send_if_modified(|state| {
            if !state.opening_session {
                return false;
            }
            state.opening_session = false;
            state.session = Some(id);
            true
        });
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        self.control.clear();
        let russh::keys::PublicKeyOrCertificate::PublicKey {
            key: server_public_key,
            ..
        } = server_public_key
        else {
            // known_hosts does not implement certificate-authority trust.
            return Ok(false);
        };
        let state = known_hosts::check(
            &self.known_hosts,
            &self.destination.host,
            self.port,
            server_public_key,
        )?;
        match state {
            known_hosts::KeyState::Matching => Ok(true),
            known_hosts::KeyState::Changed => Ok(false),
            known_hosts::KeyState::Unknown if self.policy == HostKeyPolicy::Yes => Ok(false),
            known_hosts::KeyState::Unknown if self.policy == HostKeyPolicy::AcceptNew => {
                Ok(known_hosts::record(
                    &self.known_hosts,
                    &known_hosts::host_token(&self.destination.host, self.port),
                    server_public_key,
                )?)
            }
            known_hosts::KeyState::Unknown if self.batch_mode => Ok(false),
            known_hosts::KeyState::Unknown => {
                let message = format!(
                    "The authenticity of host '{}' cannot be established.\n{} fingerprint is {}.\nContinue connecting (yes/no)? ",
                    self.destination.host,
                    server_public_key.algorithm(),
                    server_public_key.fingerprint(Default::default())
                );
                let accepted = tokio::task::spawn_blocking(move || prompt::line(&message))
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))??
                    .trim()
                    == "yes";
                if !accepted {
                    return Ok(false);
                }
                Ok(known_hosts::record(
                    &self.known_hosts,
                    &known_hosts::host_token(&self.destination.host, self.port),
                    server_public_key,
                )?)
            }
        }
    }
}

pub async fn connect(
    options: &ConnectionOptions,
    destination: &Destination,
) -> Result<Peer, russh::Error> {
    let (stream, setup_deadline) = connect_tcp(options, destination)?;
    stream.set_nonblocking(true)?;
    let stream = tokio::net::TcpStream::from_std(stream)?;
    connect_stream(options, destination, stream, setup_deadline).await
}

pub async fn connect_via(
    jump: &client::Handle<Handler>,
    options: &ConnectionOptions,
    destination: &Destination,
) -> Result<Peer, russh::Error> {
    let deadline = options
        .connect_timeout
        .map(|timeout| {
            Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| std::io::Error::other("ConnectTimeout is too large"))
        })
        .transpose()?;
    let open = jump.channel_open_direct_tcpip(
        destination.host.clone(),
        options.port.into(),
        "127.0.0.1",
        0,
    );
    let channel = if let Some(deadline) = deadline {
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), open)
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??
    } else {
        open.await?
    };
    let stream = relay_through(channel.into_stream());
    connect_stream(options, destination, stream, deadline).await
}

/// Bytes the hop relay may hold per direction: more than the next session's
/// receive window plus a packet, so everything its peer may send before that
/// session reads again always fits.
fn hop_relay_capacity() -> usize {
    let defaults = client::Config::default();
    2 * (defaults.window_size as usize + defaults.maximum_packet_size as usize)
}

/// Runs the next hop's session over a buffered pipe rather than directly on
/// the jump channel. Directly on it, the session blocks in its transport flush
/// while the channel's window is exhausted and stops reading; the jump session
/// then fills the channel's bounded queue with the bytes coming back and stops
/// reading too, before the window adjustment that would release the first
/// session arrives. The pipe lets the jump session always hand over what it
/// receives.
fn relay_through<S>(mut channel: S) -> tokio::io::DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (session_end, mut relay_end) = tokio::io::duplex(hop_relay_capacity());
    tokio::spawn(async move {
        // An error ends the pipe, which the session sees as its peer closing.
        let _ = tokio::io::copy_bidirectional(&mut channel, &mut relay_end).await;
    });
    session_end
}

async fn connect_stream<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    options: &ConnectionOptions,
    destination: &Destination,
    stream: S,
    setup_deadline: Option<Instant>,
) -> Result<Peer, russh::Error> {
    let known_hosts = options.known_hosts.clone().ok_or_else(|| {
        russh::Error::InvalidConfig("UserKnownHostsFile is required on this platform".to_owned())
    })?;
    let mut preferred = russh::Preferred::default();
    preferred.key = Cow::Owned(known_hosts::prefer_algorithms(
        &known_hosts,
        &destination.host,
        options.port,
        &preferred.key,
    )?);
    let control = TransportControl::new(setup_deadline);
    let shutdown = AbortOnDrop(control.clone());
    let stream = ControlledStream {
        stream,
        control: control.clone(),
    };
    let config = client::Config {
        preferred,
        keepalive_interval: options.server_alive_interval,
        keepalive_max: usize::try_from(options.server_alive_count_max)
            .map_err(|_| russh::Error::InvalidConfig("ServerAliveCountMax is too large".into()))?,
        ..Default::default()
    };
    let (channels, _) = tokio::sync::watch::channel(ChannelState {
        single: true,
        opening_session: false,
        session: None,
        closed: false,
    });
    let (running, ended) = tokio::sync::watch::channel(());
    let handler = Handler {
        control,
        _running: running,
        destination: destination.clone(),
        port: options.port,
        known_hosts,
        policy: options.host_key_policy,
        batch_mode: options.batch_mode,
        channels: channels.clone(),
    };
    let receive_window = config.window_size as usize;
    let handle = client::connect_stream(Arc::new(config), stream, handler).await?;
    Ok(Peer {
        handle,
        receive_window,
        channels,
        shutdown,
        ended,
    })
}

fn connect_tcp(
    options: &ConnectionOptions,
    destination: &Destination,
) -> std::io::Result<(TcpStream, Option<Instant>)> {
    let addresses: Vec<_> = (destination.host.as_str(), options.port)
        .to_socket_addrs()?
        .collect();
    attempt_addresses(addresses, options.connect_timeout, |address, timeout| {
        if let Some(timeout) = timeout {
            TcpStream::connect_timeout(&address, timeout)
        } else {
            TcpStream::connect(address)
        }
    })
}

fn attempt_addresses<T>(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
    timeout: Option<std::time::Duration>,
    mut connect: impl FnMut(std::net::SocketAddr, Option<std::time::Duration>) -> std::io::Result<T>,
) -> std::io::Result<(T, Option<Instant>)> {
    let mut last_error = None;
    for address in addresses {
        let deadline = if let Some(timeout) = timeout {
            let deadline = Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| std::io::Error::other("ConnectTimeout is too large"))?;
            Some(deadline)
        } else {
            None
        };
        match connect(address, timeout) {
            Ok(stream) => return Ok((stream, deadline)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "host resolved no addresses",
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    struct ScopeServer(
        tokio::sync::mpsc::UnboundedSender<(
            russh::Channel<russh::server::Msg>,
            russh::server::ChannelOpenHandle,
        )>,
    );

    #[cfg(unix)]
    impl russh::server::Handler for ScopeServer {
        type Error = russh::Error;
        async fn auth_none(&mut self, _: &str) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }
        async fn channel_open_session(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            reply: russh::server::ChannelOpenHandle,
            _: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.0.send((channel, reply)).unwrap();
            Ok(())
        }
        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<russh::server::Msg>,
            _: &str,
            _: u32,
            _: &str,
            _: u32,
            reply: russh::server::ChannelOpenHandle,
            _: &mut russh::server::Session,
        ) -> Result<(), Self::Error> {
            self.0.send((channel, reply)).unwrap();
            Ok(())
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn final_session_is_tracked_before_resume_and_forward_closes_stay_independent() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for immediate in [false, true] {
                let root = std::env::temp_dir().join(format!("motor-peer-scope-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
                std::fs::create_dir(&root).unwrap();
                let (socket, remote) = tokio::io::duplex(64 * 1024);
                let (opened, mut opens) = tokio::sync::mpsc::unbounded_channel();
                let starting = tokio::spawn(russh::server::run_stream(Arc::new(russh::server::Config {
                    keys: vec![russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap()],
                    inactivity_timeout: None,
                    ..Default::default()
                }), socket, ScopeServer(opened)));
                let mut options = ConnectionOptions::default();
                options.known_hosts = Some(root.join("known_hosts"));
                options.host_key_policy = HostKeyPolicy::AcceptNew;
                let destination = Destination::parse_with_default("127.0.0.1", "user").unwrap();
                let mut peer = connect_stream(&options, &destination, remote, None).await.unwrap();
                let server = starting.await.unwrap().unwrap();
                assert!(peer.authenticate_none("user").await.unwrap().success());
                peer.share_connection();
                let peer = Arc::new(peer);
                let retained = peer.clone();
                let mut opening = Box::pin(peer.open_session());
                let (session, reply) = tokio::select! {
                    opened = opens.recv() => opened.unwrap(),
                    result = opening.as_mut() => panic!("session opened before acceptance: {result:?}"),
                };
                reply.accept().await;
                if immediate {
                    session.close().await.unwrap();
                    // The confirmation callback records the ID before the
                    // opener resumes, so even this close stops stdin.
                    peer.wait_session_closed().await;
                }
                let _channel = opening.await.unwrap();
                if !immediate {
                    let mut forwarding = Box::pin(peer.channel_open_direct_tcpip_with_credit("target", 80, "origin", 0));
                    let (forward, reply) = tokio::select! {
                        opened = opens.recv() => opened.unwrap(),
                        result = forwarding.as_mut() => panic!("forward opened before acceptance: {result:?}"),
                    };
                    reply.accept().await;
                    let (mut channel, _credit) = forwarding.await.unwrap();
                    forward.close().await.unwrap();
                    assert!(matches!(channel.wait().await, Some(russh::ChannelMsg::Close)));
                    assert!(!peer.is_channel_closed());
                    session.close().await.unwrap();
                    peer.wait_session_closed().await;
                }
                assert!(peer.is_channel_closed());
                assert!(!peer.handle.is_closed());
                peer.send_ping().await.unwrap();
                server.handle().disconnect(russh::Disconnect::ByApplication, "".into(), "".into()).await.unwrap();
                peer.wait_closed().await;
                // Observing transport termination must not require exclusive
                // ownership; a forward may still retain its peer reference.
                assert!(Arc::strong_count(&peer) > 1);
                drop(retained);
                drop(_channel);
                Arc::try_unwrap(peer).ok().unwrap().close().await.unwrap();
                assert!(matches!(server.await, Ok(()) | Err(russh::Error::Disconnect)));
                std::fs::remove_dir_all(root).unwrap();
            }
        }).await.expect("shared peer lifetime stalled");
    }

    #[tokio::test]
    async fn abort_wakes_stalled_read_and_write_without_peer_progress() {
        use tokio::io::AsyncWriteExt;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for writing in [false, true] {
                let control = TransportControl::new(None);
                let guard = AbortOnDrop(control.clone());
                let (socket, _peer) = tokio::io::duplex(1);
                let mut stream = ControlledStream {
                    stream: socket,
                    control: control.clone(),
                };
                if writing {
                    stream.write_all(&[1]).await.unwrap();
                }
                let (entered, ready) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(async move {
                    let mut entered = Some(entered);
                    let mut bytes = [0; 1];
                    let mut buffer = ReadBuf::new(&mut bytes);
                    std::future::poll_fn(|cx| {
                        let result = if writing {
                            Pin::new(&mut stream)
                                .poll_write(cx, &[2])
                                .map(|result| result.map(|_| ()))
                        } else {
                            Pin::new(&mut stream).poll_read(cx, &mut buffer)
                        };
                        if result.is_pending()
                            && let Some(entered) = entered.take()
                        {
                            entered.send(()).unwrap();
                        }
                        result
                    })
                    .await
                });
                ready.await.unwrap();
                if writing {
                    drop(guard);
                } else {
                    control.abort();
                }
                let error = task.await.unwrap().unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
                assert!(error.get_ref().unwrap().is::<Aborted>());
            }
        })
        .await
        .expect("transport abort did not wake blocked I/O");
    }

    #[tokio::test(start_paused = true)]
    async fn clearing_the_setup_deadline_does_not_add_an_idle_timeout() {
        let control =
            TransportControl::new(Some(Instant::now() + std::time::Duration::from_secs(1)));
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        let error = std::future::poll_fn(|cx| Poll::Ready(control.poll(cx, IoOperation::Read)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        control.clear();
        tokio::time::advance(std::time::Duration::from_secs(1000)).await;
        std::future::poll_fn(|cx| Poll::Ready(control.poll(cx, IoOperation::Read)))
            .await
            .unwrap();
        control.abort();
        let error = std::future::poll_fn(|cx| Poll::Ready(control.poll(cx, IoOperation::Shutdown)))
            .await
            .unwrap_err();
        assert!(error.get_ref().unwrap().is::<Aborted>());
    }

    #[test]
    fn zero_timeout_uses_no_setup_deadline() {
        let address = "127.0.0.1:22".parse().unwrap();
        let (_, deadline) = attempt_addresses([address], None, |_, timeout| {
            assert!(timeout.is_none());
            Ok(())
        })
        .unwrap();
        assert!(deadline.is_none());
    }

    #[test]
    fn every_address_gets_a_fresh_timeout_and_success_keeps_its_deadline() {
        let addresses = [
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let timeout = std::time::Duration::from_secs(2);
        let mut attempts = 0;
        let before = Instant::now();
        let (_, deadline) = attempt_addresses(addresses, Some(timeout), |_, supplied| {
            attempts += 1;
            assert_eq!(supplied, Some(timeout));
            if attempts == 1 {
                Err(std::io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert!(deadline.unwrap() >= before + std::time::Duration::from_secs(1));
    }
}
