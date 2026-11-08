use super::tests::options;
use super::*;
use crate::forward::accept::test_support::reserve_loopback_port;
use std::future::{Future, poll_fn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant, advance};

async fn fail(listeners: &mut Listeners) {
    let failure = listeners
        .accept()
        .await
        .err()
        .expect("expected an accept error");
    listeners.failed(failure);
}

async fn assert_pending(listeners: &mut Listeners) {
    assert!(
        poll_fn(|cx| Poll::Ready(Box::pin(listeners.accept()).as_mut().poll(cx)))
            .await
            .is_pending()
    );
}

#[tokio::test]
async fn failed_connections_leave_the_listener_usable_for_traffic() {
    let mut listeners = Listeners::bind(&options(Some("127.0.0.1"), false))
        .await
        .unwrap();
    let errors = listeners.inject_errors(0);
    for kind in [
        io::ErrorKind::ConnectionAborted,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::Interrupted,
    ] {
        errors.send(kind.into()).unwrap();
        fail(&mut listeners).await;
        assert_eq!(listeners.sockets.len(), 1);
    }
    let mut client = TcpStream::connect(listeners.sockets[0].socket.local_addr().unwrap())
        .await
        .unwrap();
    let mut accepted = listeners.accept().await.unwrap();
    accepted.socket.write_all(b"after-error").await.unwrap();
    let mut bytes = [0; 11];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"after-error");
}

#[tokio::test(start_paused = true)]
async fn exhaustion_pauses_only_its_socket_and_preserves_the_deadline_across_polls() {
    let mut config = options(Some("127.0.0.1"), false);
    let mut other = config.local_forwards[0].clone();
    other.target.as_mut().unwrap().host = "healthy.invalid".into();
    config.local_forwards.push(other);
    let mut listeners = Listeners::bind(&config).await.unwrap();
    let mut clients = Vec::new();
    for listener in &listeners.sockets {
        clients.push(
            TcpStream::connect(listener.socket.local_addr().unwrap())
                .await
                .unwrap(),
        );
    }
    let errors = listeners.inject_errors(0);
    errors.send(io::ErrorKind::OutOfMemory.into()).unwrap();
    errors.send(io::ErrorKind::OutOfMemory.into()).unwrap();
    let start = Instant::now();
    fail(&mut listeners).await;
    assert_eq!(
        listeners.accept().await.unwrap().target.unwrap().host,
        "healthy.invalid"
    );
    assert_pending(&mut listeners).await;
    advance(Duration::from_millis(99)).await;
    assert_pending(&mut listeners).await;
    advance(Duration::from_millis(1)).await;
    fail(&mut listeners).await;
    assert_eq!(Instant::now() - start, crate::forward::ACCEPT_PAUSE);
    assert_pending(&mut listeners).await;
    advance(crate::forward::ACCEPT_PAUSE).await;
    assert_eq!(
        listeners.accept().await.unwrap().target.unwrap().host,
        "unresolved.invalid"
    );
    assert_eq!(Instant::now() - start, 2 * crate::forward::ACCEPT_PAUSE);
}

#[tokio::test]
async fn permanent_failure_retires_one_forward_without_affecting_another() {
    let _process_and_rebind = crate::forward::accept::test_support::PROCESS_AND_REBIND
        .lock()
        .await;
    let (port, _reservations) = reserve_loopback_port();
    let mut config = options(Some("127.0.0.1"), false);
    config.local_forwards.push(config.local_forwards[0].clone());
    config.local_forwards[0].listen.port = port;
    let mut listeners = Listeners::bind(&config).await.unwrap();
    let address = listeners.sockets[0].socket.local_addr().unwrap();
    let errors = listeners.inject_errors(0);
    errors.send(io::ErrorKind::NotConnected.into()).unwrap();
    fail(&mut listeners).await;
    assert_eq!(listeners.sockets.len(), 1);
    assert_eq!(listeners.sockets[0].forward, 1);
    let _rebound = TcpListener::bind(address).await.unwrap();
    let client = TcpStream::connect(listeners.sockets[0].socket.local_addr().unwrap())
        .await
        .unwrap();
    assert_eq!(
        listeners.accept().await.unwrap().originator,
        client.local_addr().unwrap()
    );
    let errors = listeners.inject_errors(0);
    errors.send(io::ErrorKind::Other.into()).unwrap();
    fail(&mut listeners).await;
    assert!(listeners.sockets.is_empty());
    assert_pending(&mut listeners).await;
}

#[tokio::test]
async fn losing_one_family_keeps_the_same_forward_on_the_other_family() {
    let mut listeners = Listeners::bind(&options(None, false)).await.unwrap();
    assert_eq!(listeners.sockets.len(), 2);
    let errors = listeners.inject_errors(0);
    errors.send(io::ErrorKind::NotConnected.into()).unwrap();
    fail(&mut listeners).await;
    assert_eq!(listeners.sockets.len(), 1);
    assert_eq!(listeners.sockets[0].forward, 0);
    let client = TcpStream::connect(listeners.sockets[0].socket.local_addr().unwrap())
        .await
        .unwrap();
    assert_eq!(
        listeners.accept().await.unwrap().originator,
        client.local_addr().unwrap()
    );
}
