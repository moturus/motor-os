use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use russh::server;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, sleep_until, timeout_at};

pub(super) struct Grace {
    deadline: Instant,
    authenticated: AtomicBool,
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "not authenticated within the login grace time",
    )
}

impl Grace {
    pub(super) fn new() -> Self {
        Self {
            deadline: Instant::now() + super::LOGIN_GRACE,
            authenticated: AtomicBool::new(false),
        }
    }

    pub(super) fn complete(&self) -> io::Result<()> {
        // A ready authentication result must not defeat an already-expired timer.
        if Instant::now() >= self.deadline {
            return Err(timed_out());
        }
        self.authenticated.store(true, Ordering::Relaxed);
        Ok(())
    }
}

pub(super) async fn run<H, R>(
    config: Arc<server::Config>,
    socket: R,
    handler: H,
    grace: Arc<Grace>,
) -> Result<(), russh::Error>
where
    H: server::Handler<Error = russh::Error> + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Before run_stream returns, its future still owns the transport directly.
    let mut session = timeout_at(grace.deadline, server::run_stream(config, socket, handler))
        .await
        .map_err(|_| timed_out())??;
    let expiry = async {
        sleep_until(grace.deadline).await;
        if grace.authenticated.load(Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(expiry);
    tokio::select! {
        biased;
        () = &mut expiry => {
            // Dropping RunningSession only drops a join wrapper. Abort and reap
            // the actual task, even if it is suspended in a credential callback.
            session.abort();
            match session.await {
                Ok(()) | Err(russh::Error::Disconnect) => Err(timed_out().into()),
                Err(error) => Err(error),
            }
        }
        result = &mut session => result,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use russh::client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio::time::{advance, timeout};

    struct Handler {
        grace: Arc<Grace>,
        entered: Option<oneshot::Sender<()>>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for Handler {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    impl server::Handler for Handler {
        type Error = russh::Error;

        async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                std::future::pending::<()>().await;
            }
            Ok(server::Auth::Accept)
        }

        async fn auth_succeeded(&mut self, _: &mut server::Session) -> Result<(), Self::Error> {
            self.grace.complete()?;
            Ok(())
        }
    }

    struct Client;

    impl client::Handler for Client {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    fn handler(grace: Arc<Grace>) -> Handler {
        Handler {
            grace,
            entered: None,
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }

    fn config() -> Arc<server::Config> {
        Arc::new(server::Config {
            keys: vec![
                russh::keys::PrivateKey::random(
                    &mut rand::rng(),
                    russh::keys::ssh_key::Algorithm::Ed25519,
                )
                .unwrap(),
            ],
            inactivity_timeout: None,
            ..Default::default()
        })
    }

    async fn connect(
        handler: Handler,
    ) -> (
        tokio::task::JoinHandle<Result<(), russh::Error>>,
        client::Handle<Client>,
    ) {
        let (socket, peer) = tokio::io::duplex(4096);
        let grace = handler.grace.clone();
        let running = tokio::spawn(run(config(), socket, handler, grace));
        let client = client::connect_stream(Arc::new(client::Config::default()), peer, Client)
            .await
            .unwrap();
        (running, client)
    }

    fn assert_timeout(result: Result<(), russh::Error>) {
        assert!(matches!(result, Err(russh::Error::IO(e)) if e.kind() == io::ErrorKind::TimedOut));
    }

    #[tokio::test(start_paused = true)]
    async fn authentication_at_the_deadline_is_rejected() {
        let grace = Grace::new();
        advance(super::super::LOGIN_GRACE).await;
        assert_eq!(
            grace.complete().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!grace.authenticated.load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_closes_silent_identification_and_blocked_banner_write() {
        for capacity in [1, 4096] {
            let grace = Arc::new(Grace::new());
            let (socket, mut peer) = tokio::io::duplex(capacity);
            let running = tokio::spawn(run(config(), socket, handler(grace.clone()), grace));
            if capacity == 4096 {
                assert_eq!(peer.read_u8().await.unwrap(), b'S');
            } else {
                tokio::task::yield_now().await;
            }
            advance(super::super::LOGIN_GRACE).await;
            assert_timeout(running.await.unwrap());
            assert!(peer.write_all(b"x").await.is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_cancels_a_pending_authentication_callback() {
        let grace = Arc::new(Grace::new());
        let (entered, started) = oneshot::channel();
        let mut handler = handler(grace);
        handler.entered = Some(entered);
        let dropped = handler.dropped.clone();
        let (running, mut client) = connect(handler).await;
        let authenticating = tokio::spawn(async move { client.authenticate_none("user").await });
        started.await.unwrap();
        advance(super::super::LOGIN_GRACE).await;
        assert_timeout(
            timeout(std::time::Duration::from_secs(1), running)
                .await
                .unwrap()
                .unwrap(),
        );
        assert!(dropped.load(Ordering::Relaxed));
        assert!(!authenticating.await.unwrap().unwrap().success());
    }

    #[tokio::test(start_paused = true)]
    async fn timely_authentication_keeps_an_idle_session_alive() {
        let grace = Arc::new(Grace::new());
        let (running, mut client) = connect(handler(grace)).await;
        assert!(client.authenticate_none("user").await.unwrap().success());
        advance(super::super::LOGIN_GRACE * 2).await;
        assert!(!running.is_finished());
        client.send_ping().await.unwrap();
        client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        assert!(matches!(
            running.await.unwrap(),
            Ok(()) | Err(russh::Error::Disconnect)
        ));
    }
}
