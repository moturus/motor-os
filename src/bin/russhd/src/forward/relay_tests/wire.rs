use super::*;
use std::borrow::Cow;
use tokio::io::{AsyncBufReadExt, BufReader};

// Local test peers negotiate plaintext to permit malformed packet injection.
fn plain_config() -> client::Config {
    client::Config {
        preferred: russh::Preferred {
            cipher: Cow::Borrowed(&[russh::cipher::NONE]),
            mac: Cow::Borrowed(&[russh::mac::NONE]),
            compression: Cow::Borrowed(&[russh::compression::NONE]),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn data_packet(recipient: &[u8], data: &[u8]) -> Vec<u8> {
    let mut payload = vec![94]; // SSH_MSG_CHANNEL_DATA
    payload.extend_from_slice(recipient);
    payload.extend_from_slice(&(data.len() as u32).to_be_bytes());
    payload.extend_from_slice(data);
    let mut padding = 8 - (payload.len() + 5) % 8;
    if padding < 4 {
        padding += 8;
    }
    let length = 1 + payload.len() + padding;
    let mut packet = Vec::with_capacity(4 + length);
    packet.extend_from_slice(&(length as u32).to_be_bytes());
    packet.push(padding as u8);
    packet.extend_from_slice(&payload);
    packet.resize(4 + length, 0);
    packet
}

async fn inject(
    client: DuplexStream,
    server: DuplexStream,
    after: usize,
    extra: Vec<u8>,
    injected: oneshot::Sender<()>,
) -> io::Result<()> {
    let (from_client, mut to_client) = tokio::io::split(client);
    let (mut from_server, mut to_server) = tokio::io::split(server);
    let upstream = async {
        let mut input = BufReader::new(from_client);
        let mut banner = String::new();
        input.read_line(&mut banner).await?;
        to_server.write_all(banner.as_bytes()).await?;
        let mut count = 0;
        let mut injected = Some(injected);
        loop {
            let length = match input.read_u32().await {
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error),
            };
            assert!((5..=128 * 1024).contains(&length));
            let mut packet = vec![0; length as usize];
            input.read_exact(&mut packet).await?;
            to_server.write_all(&length.to_be_bytes()).await?;
            to_server.write_all(&packet).await?;
            if packet[1] == 94 {
                count += u32::from_be_bytes(packet[6..10].try_into().unwrap()) as usize;
                if count >= after
                    && let Some(done) = injected.take()
                {
                    to_server
                        .write_all(&data_packet(&packet[2..6], &extra))
                        .await?;
                    let _ = done.send(());
                }
            }
        }
        to_server.shutdown().await
    };
    let downstream = async {
        tokio::io::copy(&mut from_server, &mut to_client).await?;
        to_client.shutdown().await
    };
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}

async fn fixture(
    after: usize,
    extra: Vec<u8>,
    capacity: usize,
) -> (
    Fixture,
    oneshot::Receiver<()>,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let (server, bridge_server) = tokio::io::duplex(32 * 1024);
    let (bridge_client, client) = tokio::io::duplex(32 * 1024);
    let (injected, observed) = oneshot::channel();
    let bridge = tokio::spawn(inject(bridge_client, bridge_server, after, extra, injected));
    let fixture =
        Fixture::connect_streams(plain_config(), 32 * 1024, capacity, server, client).await;
    (fixture, observed, bridge)
}

#[tokio::test]
async fn tolerated_wire_overrun_closes_only_the_full_forward() {
    timeout(Duration::from_secs(5), async {
        let (mut fixture, injected, bridge) = fixture(WINDOW as usize, vec![23], 0).await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let finished = opened.start(fixture.socket, || false);
        channel.data_bytes(vec![7; WINDOW as usize]).await.unwrap();
        injected.await.unwrap();
        assert_eq!(
            finished.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            fixture.target.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        drop(channel);
        fixture.client.send_ping().await.unwrap();
        finish(fixture.client, fixture.server).await;
        bridge.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn empty_wire_data_is_not_eof() {
    timeout(Duration::from_secs(5), async {
        let (mut fixture, injected, bridge) = fixture(1, Vec::new(), 1024).await;
        let channel = fixture.client.channel_open_session().await.unwrap();
        let opened = fixture.opened.recv().await.unwrap();
        let finished = opened.start(fixture.socket, || false);
        channel.data_bytes(vec![3]).await.unwrap();
        injected.await.unwrap();
        assert_eq!(fixture.target.read_u8().await.unwrap(), 3);
        channel.data_bytes(vec![5]).await.unwrap();
        assert_eq!(fixture.target.read_u8().await.unwrap(), 5);
        channel.eof().await.unwrap();
        fixture.target.shutdown().await.unwrap();
        finished.await.unwrap().unwrap();
        drop(channel);
        finish(fixture.client, fixture.server).await;
        bridge.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}
