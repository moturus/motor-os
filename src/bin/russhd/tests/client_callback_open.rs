#![cfg(unix)]

use std::sync::Arc;

use russh::{Channel, ChannelId, ChannelOpenFailure, client, server};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

#[derive(Debug)]
enum Event {
    Opened(ChannelId),
    Confirmed(ChannelId),
    Data(ChannelId, Vec<u8>),
    Closed(ChannelId),
}

struct Client(mpsc::UnboundedSender<Event>);

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _: Channel<client::Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: client::ChannelOpenHandle,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // A public Session open reports events through callbacks, without a
        // Channel receiver. Trigger it from an authenticated handler callback.
        let id = session.channel_open_session()?;
        self.0.send(Event::Opened(id)).unwrap();
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_confirmation(
        &mut self,
        id: ChannelId,
        _: u32,
        _: u32,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(Event::Confirmed(id)).unwrap();
        Ok(())
    }

    async fn data(
        &mut self,
        id: ChannelId,
        data: &[u8],
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(Event::Data(id, data.to_vec())).unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        id: ChannelId,
        _: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.send(Event::Closed(id)).unwrap();
        Ok(())
    }
}

struct Server(mpsc::UnboundedSender<(Channel<server::Msg>, server::ChannelOpenHandle)>);

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.0.send((channel, reply)).unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn session_callback_open_delivers_confirmation_data_and_close_over_ssh() {
    timeout(Duration::from_secs(5), async {
        let (socket, peer) = tokio::io::duplex(64 * 1024);
        let (opened, mut opens) = mpsc::unbounded_channel();
        let config = Arc::new(server::Config {
            keys: vec![russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519).unwrap()],
            inactivity_timeout: None,
            ..Default::default()
        });
        let starting = tokio::spawn(server::run_stream(config, socket, Server(opened)));
        let (events, mut received) = mpsc::unbounded_channel();
        let mut client = client::connect_stream(Arc::new(client::Config::default()), peer, Client(events)).await.unwrap();
        let server = starting.await.unwrap().unwrap();
        assert!(client.authenticate_none("user").await.unwrap().success());
        let trigger_handle = server.handle();
        let trigger = tokio::spawn(async move {
            trigger_handle.channel_open_forwarded_tcpip("trigger", 0, "origin", 0).await
        });
        let id = match received.recv().await.unwrap() {
            Event::Opened(id) => id,
            event => panic!("expected callback open: {event:?}"),
        };
        let (channel, reply) = opens.recv().await.unwrap();
        reply.accept().await;
        assert!(matches!(received.recv().await, Some(Event::Confirmed(found)) if found == id));
        channel.data(b"callback data".as_slice()).await.unwrap();
        assert!(matches!(received.recv().await, Some(Event::Data(found, data)) if found == id && data == b"callback data"));
        channel.eof().await.unwrap();
        channel.close().await.unwrap();
        assert!(matches!(received.recv().await, Some(Event::Closed(found)) if found == id));
        // The ping follows the close acknowledgement on the same transport.
        client.send_ping().await.unwrap();
        assert!(matches!(trigger.await.unwrap(), Err(russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited))));
        client.disconnect(russh::Disconnect::ByApplication, "", "").await.unwrap();
        assert!(matches!(client.await, Ok(()) | Err(russh::Error::Disconnect)));
        assert!(matches!(server.await, Ok(()) | Err(russh::Error::Disconnect)));
    }).await.expect("callback session open stalled");
}
