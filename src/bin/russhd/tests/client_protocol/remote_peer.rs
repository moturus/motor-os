use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, mpsc};

pub(super) struct Reply {
    pub accepted: bool,
    pub allocated: u32,
    pub early_opens: Vec<(String, u32)>,
}

pub(super) enum Event {
    Confirmed(ChannelId),
    Data(ChannelId, Vec<u8>),
    Eof(ChannelId),
}

struct Handler {
    replies: VecDeque<Reply>,
    events: mpsc::Sender<Event>,
    sessions: mpsc::Sender<Channel<russh::server::Msg>>,
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn tcpip_forward(
        &mut self,
        _: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let reply = self
            .replies
            .pop_front()
            .expect("unexpected forwarding request");
        *port = reply.allocated;
        // Synchronous opens precede the global reply on the encrypted wire.
        for (address, port) in reply.early_opens {
            session.channel_open_forwarded_tcpip(&address, port, "origin", 1234)?;
        }
        Ok(reply.accepted)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.sessions.send(channel).unwrap();
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"ready".as_slice())
    }

    async fn channel_open_confirmation(
        &mut self,
        channel: ChannelId,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.events.send(Event::Confirmed(channel)).unwrap();
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.events
            .send(Event::Data(channel, data.to_vec()))
            .unwrap();
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.events.send(Event::Eof(channel)).unwrap();
        Ok(())
    }
}

pub(super) struct Peer {
    pub port: u16,
    pub events: mpsc::Receiver<Event>,
    pub sessions: mpsc::Receiver<Channel<russh::server::Msg>>,
    handle: mpsc::Receiver<russh::server::Handle>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Peer {
    pub fn start(replies: Vec<Reply>) -> Self {
        let (address, listening) = mpsc::channel();
        let (events_tx, events) = mpsc::channel();
        let (sessions_tx, sessions) = mpsc::channel();
        let (handle_tx, handle) = mpsc::channel();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                address.send(listener.local_addr().unwrap().port()).unwrap();
                let socket = tokio::select! {
                    _ = &mut stopped => return,
                    socket = listener.accept() => socket.unwrap().0,
                };
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
                let handler = Handler {
                    replies: replies.into(),
                    events: events_tx,
                    sessions: sessions_tx,
                };
                let mut running = russh::server::run_stream(config, socket, handler)
                    .await
                    .unwrap();
                handle_tx.send(running.handle()).unwrap();
                let result = tokio::select! {
                    _ = &mut stopped => {
                        running.abort();
                        running.await
                    }
                    result = &mut running => result,
                };
                match result {
                    Ok(()) | Err(russh::Error::Disconnect) => {}
                    Err(russh::Error::IO(error))
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                        ) => {}
                    result => panic!("remote forwarding peer failed: {result:?}"),
                }
            });
        });
        Self {
            port: listening.recv_timeout(Duration::from_secs(5)).unwrap(),
            events,
            sessions,
            handle,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    pub fn handle(&self) -> russh::server::Handle {
        self.handle.recv_timeout(Duration::from_secs(5)).unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}
