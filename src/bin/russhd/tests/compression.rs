use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::compression::{self, Compress, Compression, Decompress};
use russh::{Channel, ChannelMsg, client, server};
use tokio::sync::oneshot;
use tokio::time::timeout;

#[test]
fn partial_flush_packets_are_drained_before_the_next_packet() {
    let mut compressor = Compress::None;
    let mut decompressor = Decompress::None;
    Compression::Zlib.init_compress(&mut compressor);
    Compression::Zlib.init_decompress(&mut decompressor);

    // A continuous SSH stream with changing packet sizes exercises buffered
    // output at packet boundaries, including the miniz_oxide 0.9 regression.
    for len in 1..=4096 {
        let payload: Vec<_> = (0..len).map(|i| b"abcdefgh"[i % 8]).collect();
        let mut compressed = vec![0xa5; 4];
        let written = compressor
            .compress_into(&payload, &mut compressed, 4)
            .unwrap();
        assert_eq!(&compressed[..4], &[0xa5; 4]);
        assert_eq!(compressed.len(), written + 4);

        let mut output = Vec::new();
        assert_eq!(
            decompressor
                .decompress(&compressed[4..], &mut output)
                .unwrap(),
            payload,
            "packet of {len} bytes was truncated"
        );
        assert!(
            decompressor
                .decompress(&[], &mut output)
                .unwrap()
                .is_empty(),
            "packet of {len} bytes left decoded output buffered"
        );
    }
}

fn incompressible(len: usize) -> Vec<u8> {
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 24) as u8
        })
        .collect()
}

#[test]
fn full_size_incompressible_packet_does_not_spill_into_the_next_packet() {
    let mut compressor = Compress::None;
    let mut decompressor = Decompress::None;
    Compression::Zlib.init_compress(&mut compressor);
    Compression::Zlib.init_decompress(&mut decompressor);

    // A full CHANNEL_DATA packet includes its message, channel, and length fields.
    for payload in [incompressible(32_768 + 9), b"next packet".to_vec()] {
        let mut compressed = vec![0xa5; 4];
        let written = compressor
            .compress_into(&payload, &mut compressed, 4)
            .unwrap();
        assert_eq!(&compressed[..4], &[0xa5; 4]);
        assert_eq!(compressed.len(), written + 4);
        let mut output = Vec::new();
        let decoded = decompressor
            .decompress(&compressed[4..], &mut output)
            .unwrap();
        assert_eq!(
            decoded.len(),
            payload.len(),
            "compressed packet was truncated"
        );
        assert_eq!(decoded, payload);
        assert!(
            decompressor
                .decompress(&[], &mut output)
                .unwrap()
                .is_empty()
        );
    }
}

const TRANSFER_SIZE: usize = 256 * 1024;

struct CompressionServer {
    sent: Option<oneshot::Sender<()>>,
}

impl server::Handler for CompressionServer {
    type Error = russh::Error;

    async fn auth_none(&mut self, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let handle = session.handle();
        let sent = self.sent.take().unwrap();
        tokio::spawn(async move {
            let id = channel.id();
            let _channel = channel;
            handle
                .data(id, incompressible(TRANSFER_SIZE))
                .await
                .unwrap();
            handle.eof(id).await.unwrap();
            handle.close(id).await.unwrap();
            sent.send(()).unwrap();
        });
        Ok(())
    }
}

struct CompressionClient;

impl client::Handler for CompressionClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn compressed_sessions_carry_incompressible_data() {
    timeout(Duration::from_secs(10), async {
        for algorithm in [compression::ZLIB, compression::ZLIB_LEGACY] {
            let preferred = russh::Preferred {
                compression: Cow::Owned(vec![algorithm]),
                ..Default::default()
            };
            let server_config = Arc::new(server::Config {
                keys: vec![
                    russh::keys::PrivateKey::random(
                        &mut rand::rng(),
                        russh::keys::ssh_key::Algorithm::Ed25519,
                    )
                    .unwrap(),
                ],
                preferred: preferred.clone(),
                inactivity_timeout: None,
                ..Default::default()
            });
            let (server_socket, client_socket) = tokio::io::duplex(32 * 1024);
            let (sent, sending) = oneshot::channel();
            let server = tokio::spawn(async move {
                server::run_stream(
                    server_config,
                    server_socket,
                    CompressionServer { sent: Some(sent) },
                )
                .await?
                .await
            });
            let config = Arc::new(client::Config {
                preferred,
                inactivity_timeout: None,
                ..Default::default()
            });
            let mut client = client::connect_stream(config, client_socket, CompressionClient)
                .await
                .unwrap();
            assert!(client.authenticate_none("user").await.unwrap().success());
            let mut channel = client.channel_open_session().await.unwrap();
            let mut received = Vec::new();
            while let Some(message) = channel.wait().await {
                match message {
                    ChannelMsg::Data { data } => received.extend_from_slice(&data),
                    ChannelMsg::Eof => break,
                    _ => {}
                }
            }
            assert_eq!(received.len(), TRANSFER_SIZE, "transfer with {algorithm:?}");
            assert_eq!(received, incompressible(TRANSFER_SIZE));
            sending.await.unwrap();
            client
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await
                .unwrap();
            assert!(matches!(
                client.await,
                Ok(()) | Err(russh::Error::Disconnect)
            ));
            assert!(matches!(
                server.await.unwrap(),
                Ok(()) | Err(russh::Error::Disconnect)
            ));
        }
    })
    .await
    .expect("compressed transfer stalled");
}
