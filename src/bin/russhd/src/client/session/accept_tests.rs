use super::*;
use crate::forward::accept::test_support::inject;
use std::future::{Future, poll_fn};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::task::Poll;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

struct Server {
    command: Option<russh::Channel<russh::server::Msg>>,
    commands: mpsc::UnboundedSender<russh::Channel<russh::server::Msg>>,
}

impl russh::server::Handler for Server {
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
        self.command = Some(channel);
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        _: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.commands.send(self.command.take().unwrap()).unwrap();
        Ok(())
    }
}

async fn drive_without_advancing_time<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await {
            return result;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "forwarding did not progress while accept was paused"
        );
        // Keep the driver runnable so Tokio cannot auto-advance to the accept
        // deadline while real socket I/O or the output thread makes progress.
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn command_completion_and_connection_cancellation_do_not_wait_for_accept_recovery() {
    let _process_and_rebind = crate::forward::accept::test_support::PROCESS_AND_REBIND
        .lock()
        .await;
    for (index, kind) in [
        io::ErrorKind::OutOfMemory,
        io::ErrorKind::NotConnected,
        io::ErrorKind::OutOfMemory,
    ]
    .into_iter()
    .enumerate()
    {
        let root = std::env::temp_dir().join(format!(
            "motor-accept-session-{}-{index}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let transport = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut options = ConnectionOptions::default();
        options.port = transport.local_addr().unwrap().port();
        options
            .apply_o(&format!(
                "UserKnownHostsFile={}",
                root.join("known_hosts").display()
            ))
            .unwrap();
        options.apply_o("StrictHostKeyChecking=accept-new").unwrap();
        options.apply_o("BatchMode=yes").unwrap();
        let (commands_tx, mut commands) = mpsc::unbounded_channel();
        let accepting = tokio::spawn(async move {
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
            russh::server::run_stream(
                config,
                transport.accept().await.unwrap().0,
                Server {
                    command: None,
                    commands: commands_tx,
                },
            )
            .await
        });
        let destination = Destination::parse("motor@127.0.0.1").unwrap();
        let mut peer = transport::connect(&options, &destination).await.unwrap();
        assert!(peer.authenticate_none("motor").await.unwrap().success());
        let server = accepting.await.unwrap().unwrap();
        peer.share_connection();
        let peer = Arc::new(peer);
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.set_reuseaddr(true).unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = reserved.local_addr().unwrap();
        options
            .add_local_forward(&format!("127.0.0.1:{}:localhost:80", address.port()))
            .unwrap();
        let mut listeners = Listeners::bind(&options).await.unwrap();
        let errors = listeners.inject_errors(0);
        let args = SshArgs {
            connection: options.clone(),
            destination,
            command: vec!["controlled".into()],
            pty: PtyMode::Disable,
            no_session: false,
        };
        let mut running = Box::pin(run_with_listeners(&peer, &options, args, listeners));
        let command = drive_without_advancing_time(async {
            tokio::select! {
                result = running.as_mut() => panic!("session ended before exec: {}", result.is_err()),
                command = commands.recv() => command.unwrap(),
            }
        }).await;
        let observed = inject(&errors, kind);
        drive_without_advancing_time(async {
            tokio::select! {
                result = running.as_mut() => panic!("accept error ended the session: {}", result.is_err()),
                result = observed => result.unwrap(),
            }
        }).await;
        let start = Instant::now();
        if index == 2 {
            peer.abort();
        } else {
            let handle = server.handle();
            handle.exit_status_request(command.id(), 7).await.unwrap();
            handle.eof(command.id()).await.unwrap();
            handle.close(command.id()).await.unwrap();
        }
        let result = drive_without_advancing_time(running.as_mut()).await;
        if index == 2 {
            // An interrupted command with no remote exit status returns 255.
            assert!(matches!(result, Ok(SessionEnd::Status(255))));
        } else {
            assert!(matches!(result, Ok(SessionEnd::Status(7))));
        }
        assert_eq!(Instant::now(), start);
        assert!(errors.is_closed());
        let _rebound = TcpListener::bind(address).await.unwrap();
        drop(running);
        Arc::try_unwrap(peer).ok().unwrap().close().await.unwrap();
        server.abort();
        let ended = server.await;
        match ended {
            Ok(()) | Err(russh::Error::Disconnect) => {}
            // The explicitly aborted client may reset TCP or end it without SSH shutdown.
            Err(russh::Error::IO(error))
                if index == 2
                    && matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                    ) => {}
            other => panic!("server cleanup failed: {other:?}"),
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
