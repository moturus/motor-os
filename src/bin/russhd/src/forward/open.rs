use std::future::Future;
use std::io;
use std::net::SocketAddr;

use russh::{Channel, ChannelOpenFailure, ReceiveCredit, server};
use tokio::net::{TcpStream, lookup_host};

pub fn validate_target(host: &str, port: u32) -> Result<u16, ChannelOpenFailure> {
    if port > u16::MAX as u32 {
        return Err(ChannelOpenFailure::AdministrativelyProhibited);
    }
    if port == 0
        || host.is_empty()
        || host.len() > 255
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ChannelOpenFailure::ConnectFailed);
    }
    Ok(port as u16)
}

#[cfg(target_os = "motor")]
pub fn memory_pressure() -> bool {
    moto_sdk::sys::free_pages() < 512 // 2 MiB in 4 KiB pages.
}

#[cfg(not(target_os = "motor"))]
pub fn memory_pressure() -> bool {
    false
}

/// The caller reserves admission and runs this future in the connection scope.
pub async fn direct_tcpip(
    channel: Channel<server::Msg>,
    reply: server::ChannelOpenHandle,
    host: String,
    port: u16,
    credit: ReceiveCredit,
    window: usize,
) -> io::Result<()> {
    let connected = connect_resolved(lookup_host((host.as_str(), port)))
        .await
        .and_then(|socket| {
            socket.set_nodelay(true)?;
            Ok(socket)
        });
    let socket = match connected {
        Ok(socket) => socket,
        Err(_) => {
            reply.reject(ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        }
    };
    credit.defer_close();
    reply.accept().await;
    super::relay(channel, socket, credit, window, memory_pressure).await
}

async fn connect_resolved<F, I>(resolved: F) -> io::Result<TcpStream>
where
    F: Future<Output = io::Result<I>>,
    I: IntoIterator<Item = SocketAddr>,
{
    let mut last = io::Error::from(io::ErrorKind::AddrNotAvailable);
    for address in resolved.await? {
        match TcpStream::connect(address).await {
            Ok(socket) => return Ok(socket),
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::future::ready;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpSocket};
    use tokio::time::{Duration, timeout};

    #[test]
    fn destinations_enforce_the_host_and_port_contract() {
        for host in [
            "127.0.0.1",
            "::1",
            "host-name.example",
            "name_1",
            &"a".repeat(255),
        ] {
            assert_eq!(validate_target(host, 65535), Ok(65535));
        }
        for host in [
            "",
            "has space",
            "a/b",
            "[::1]",
            "a%scope",
            "a\0b",
            "a\nb",
            "é",
            &"a".repeat(256),
        ] {
            assert_eq!(
                validate_target(host, 22),
                Err(ChannelOpenFailure::ConnectFailed)
            );
        }
        assert_eq!(
            validate_target("localhost", 0),
            Err(ChannelOpenFailure::ConnectFailed)
        );
        for port in [65536, u32::MAX] {
            assert_eq!(
                validate_target("", port),
                Err(ChannelOpenFailure::AdministrativelyProhibited)
            );
        }
    }

    #[tokio::test]
    async fn resolver_errors_and_empty_results_are_hermetic() {
        let failed = ready(Err::<Vec<SocketAddr>, _>(io::Error::from(
            io::ErrorKind::NotFound,
        )));
        assert_eq!(
            connect_resolved(failed).await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let empty = ready(Ok(Vec::<SocketAddr>::new()));
        assert_eq!(
            connect_resolved(empty).await.unwrap_err().kind(),
            io::ErrorKind::AddrNotAvailable
        );
    }

    #[tokio::test]
    async fn connection_tries_the_resolved_addresses_in_order() {
        timeout(Duration::from_secs(5), async {
            // A bound, non-listening socket reserves a deterministic refused port.
            let refused = TcpSocket::new_v4().unwrap();
            refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addresses = vec![
                refused.local_addr().unwrap(),
                listener.local_addr().unwrap(),
            ];
            let (outgoing, incoming) =
                tokio::join!(connect_resolved(ready(Ok(addresses))), listener.accept());
            let mut outgoing = outgoing.unwrap();
            let (mut incoming, _) = incoming.unwrap();
            outgoing.write_all(b"ok").await.unwrap();
            let mut data = [0; 2];
            incoming.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ok");
        })
        .await
        .unwrap();
    }
}
