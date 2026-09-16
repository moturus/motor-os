//! Native `NetDriver` host tests (vdso-rewrite.md, git history, section 4).
//!
//! The executable statement of what vDSO Stage 4 delivers, grown patch by
//! patch: a native host that names nothing from the vdso creates its own
//! LocalRuntime, connects a `NetClient`/`NetDriver` pair, drives the driver
//! explicitly, and observes a clean driver exit.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use moto_io::net::ReserveError;

use crate::net_harness::{bounded, bounded_output, host_channel};

const VSOCK_DISCOVERY_DENIED_CHILD: &str = "vsock-discovery-denied-child";

async fn expect_raw_vsock_error(
    sender: &moto_ipc::io_channel::Sender,
    receiver: &mut moto_ipc::io_channel::Receiver,
    request: moto_ipc::io_channel::Msg,
    expected: moto_rt::Error,
) {
    sender.send(request).await.unwrap();
    let response = bounded_output(receiver.recv(), 2)
        .await
        .unwrap_or_else(|| panic!("timed out waiting for raw vsock response {:#x}", request.id))
        .unwrap();
    assert_eq!(response.id, request.id);
    assert_eq!(response.command, request.command);
    assert_eq!(response.handle, request.handle);
    assert_eq!(response.wake_handle, request.wake_handle);
    assert_eq!(response.flags, request.flags);
    assert_eq!(response.payload.args_64(), request.payload.args_64());
    assert_eq!(response.status(), Err(expected));
}

fn raw_vsock_controls(first_id: u64) -> [moto_ipc::io_channel::Msg; 3] {
    let mut shutdown = moto_sys_io::api_vsock::shutdown_request(
        0xfeed_cafe,
        moto_sys_io::api_vsock::SHUTDOWN_SEND,
    )
    .unwrap();
    shutdown.id = first_id;
    let mut close = moto_sys_io::api_vsock::close_request(0xfeed_cafe);
    close.id = first_id + 1;
    let mut drop = moto_sys_io::api_vsock::listener_drop_request(0xfeed_cafe);
    drop.id = first_id + 2;
    [shutdown, close, drop]
}

fn raw_vsock_bind(id: u64) -> moto_ipc::io_channel::Msg {
    let mut bind = moto_sys_io::api_vsock::listener_bind_request(70_000).unwrap();
    bind.id = id;
    bind
}

async fn raw_vsock_response(
    sender: &moto_ipc::io_channel::Sender,
    receiver: &mut moto_ipc::io_channel::Receiver,
    request: moto_ipc::io_channel::Msg,
) -> moto_ipc::io_channel::Msg {
    sender.send(request).await.unwrap();
    let response = bounded_output(receiver.recv(), 2)
        .await
        .unwrap_or_else(|| panic!("timed out waiting for raw vsock response {:#x}", request.id))
        .unwrap();
    assert_eq!(response.id, request.id);
    assert_eq!(response.command, request.command);
    assert_eq!(response.wake_handle, request.wake_handle);
    response
}

async fn raw_vsock_listener_drop(
    sender: &moto_ipc::io_channel::Sender,
    receiver: &mut moto_ipc::io_channel::Receiver,
    handle: u64,
    id: u64,
) {
    let mut request = moto_sys_io::api_vsock::listener_drop_request(handle);
    request.id = id;
    let response = raw_vsock_response(sender, receiver, request).await;
    assert_eq!(response.handle, handle);
    assert_eq!(response.flags, 0);
    assert_eq!(response.payload.args_64(), &[0; 3]);
    assert_eq!(response.status(), Ok(()));
}

pub struct RawVsockListener {
    owner: moto_ipc::io_channel::Sender,
    owner_rx: moto_ipc::io_channel::Receiver,
    handle: u64,
    next_id: u64,
}

impl RawVsockListener {
    pub async fn bind(port: u32) -> Self {
        let (owner, mut owner_rx) = moto_ipc::io_channel::connect("sys-io").unwrap();
        let mut request = moto_sys_io::api_vsock::listener_bind_request(port).unwrap();
        request.id = 0x564f_7000;
        let response = raw_vsock_response(&owner, &mut owner_rx, request).await;
        let listener = moto_sys_io::api_vsock::decode_listener_bind_response(&response).unwrap();
        assert_eq!(listener.local.port, port);
        Self {
            owner,
            owner_rx,
            handle: listener.handle,
            next_id: request.id + 1,
        }
    }

    pub async fn close(mut self) {
        raw_vsock_listener_drop(&self.owner, &mut self.owner_rx, self.handle, self.next_id).await;
    }
}

pub async fn test_raw_vsock_listener_bind() {
    const EXPLICIT_PORT: u32 = 0xf123_4567;
    const QUOTA_PORT_START: u32 = 0xf200_0000;
    const LISTENER_LIMIT: usize = 32;

    let (owner, mut owner_rx) = moto_ipc::io_channel::connect("sys-io").unwrap();
    let mut bind = moto_sys_io::api_vsock::listener_bind_request(EXPLICIT_PORT).unwrap();
    bind.id = 0x564f_6000;
    bind.wake_handle = 0x1234;
    let response = raw_vsock_response(&owner, &mut owner_rx, bind).await;
    let explicit = moto_sys_io::api_vsock::decode_listener_bind_response(&response).unwrap();
    assert_eq!(explicit.local.port, EXPLICIT_PORT);

    let mut conflict = moto_sys_io::api_vsock::listener_bind_request(EXPLICIT_PORT).unwrap();
    conflict.id = bind.id + 1;
    expect_raw_vsock_error(
        &owner,
        &mut owner_rx,
        conflict,
        moto_rt::Error::AlreadyInUse,
    )
    .await;

    let mut auto = moto_sys_io::api_vsock::listener_bind_request(0).unwrap();
    auto.id = bind.id + 2;
    let response = raw_vsock_response(&owner, &mut owner_rx, auto).await;
    let auto = moto_sys_io::api_vsock::decode_listener_bind_response(&response).unwrap();
    assert!((49_152..u32::MAX).contains(&auto.local.port));
    assert_eq!(auto.local.cid, explicit.local.cid);
    assert_ne!(auto.local.port, explicit.local.port);
    assert_ne!(auto.handle, explicit.handle);

    let (foreign, mut foreign_rx) = moto_ipc::io_channel::connect("sys-io").unwrap();
    let mut foreign_drop = moto_sys_io::api_vsock::listener_drop_request(explicit.handle);
    foreign_drop.id = bind.id + 3;
    expect_raw_vsock_error(
        &foreign,
        &mut foreign_rx,
        foreign_drop,
        moto_rt::Error::NotFound,
    )
    .await;

    raw_vsock_listener_drop(&owner, &mut owner_rx, explicit.handle, bind.id + 4).await;
    let mut stale_drop = moto_sys_io::api_vsock::listener_drop_request(explicit.handle);
    stale_drop.id = bind.id + 5;
    expect_raw_vsock_error(&owner, &mut owner_rx, stale_drop, moto_rt::Error::NotFound).await;
    let mut rebound = moto_sys_io::api_vsock::listener_bind_request(EXPLICIT_PORT).unwrap();
    rebound.id = bind.id + 6;
    let response = raw_vsock_response(&owner, &mut owner_rx, rebound).await;
    let rebound = moto_sys_io::api_vsock::decode_listener_bind_response(&response).unwrap();
    assert_eq!(rebound.local.cid, explicit.local.cid);
    assert_eq!(rebound.local.port, EXPLICIT_PORT);
    assert_ne!(rebound.handle, explicit.handle);

    raw_vsock_listener_drop(&owner, &mut owner_rx, auto.handle, bind.id + 7).await;
    raw_vsock_listener_drop(&owner, &mut owner_rx, rebound.handle, bind.id + 8).await;

    let first_quota_id = bind.id + 9;
    let mut listeners: Vec<moto_sys_io::api_vsock::ListenerBindResponse> =
        Vec::with_capacity(LISTENER_LIMIT);
    for index in 0..LISTENER_LIMIT {
        let port = QUOTA_PORT_START + index as u32;
        let mut request = moto_sys_io::api_vsock::listener_bind_request(port).unwrap();
        request.id = first_quota_id + index as u64;
        let response = raw_vsock_response(&owner, &mut owner_rx, request).await;
        let listener = moto_sys_io::api_vsock::decode_listener_bind_response(&response).unwrap();
        assert_eq!(listener.local.cid, explicit.local.cid);
        assert_eq!(listener.local.port, port);
        assert!(listeners.iter().all(|existing| {
            existing.handle != listener.handle && existing.local != listener.local
        }));
        listeners.push(listener);
    }

    let mut overflow =
        moto_sys_io::api_vsock::listener_bind_request(QUOTA_PORT_START + LISTENER_LIMIT as u32)
            .unwrap();
    overflow.id = first_quota_id + LISTENER_LIMIT as u64;
    expect_raw_vsock_error(&owner, &mut owner_rx, overflow, moto_rt::Error::OutOfMemory).await;

    let released = listeners.pop().unwrap();
    let release_id = overflow.id + 1;
    raw_vsock_listener_drop(&owner, &mut owner_rx, released.handle, release_id).await;
    let mut replacement =
        moto_sys_io::api_vsock::listener_bind_request(released.local.port).unwrap();
    replacement.id = release_id + 1;
    let response = raw_vsock_response(&owner, &mut owner_rx, replacement).await;
    let replacement = moto_sys_io::api_vsock::decode_listener_bind_response(&response).unwrap();
    assert_eq!(replacement.local, released.local);
    assert_ne!(replacement.handle, released.handle);
    listeners.push(replacement);

    for (index, listener) in listeners.into_iter().enumerate() {
        raw_vsock_listener_drop(
            &owner,
            &mut owner_rx,
            listener.handle,
            release_id + 2 + index as u64,
        )
        .await;
    }
    println!("net_driver::test_raw_vsock_listener_bind PASS");
}

pub fn is_vsock_discovery_denied_child(args: &[String]) -> bool {
    (args.len() == 2 || (args.len() == 3 && args[2] == "with-ip"))
        && args[1] == VSOCK_DISCOVERY_DENIED_CHILD
}

pub fn run_vsock_discovery_denied_child(with_ip: bool) -> ! {
    assert_eq!(
        0x4c,
        moto_sys::ProcessStaticPage::get().capabilities,
        "discovery child unexpectedly has CAP_VSOCK"
    );

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;
        assert_eq!(
            moto_io::net::vsock::availability(&client).await,
            Err(moto_rt::Error::NotAllowed)
        );
        assert_eq!(
            moto_io::net::vsock::local_cid(&client).await,
            Err(moto_rt::Error::NotAllowed)
        );
        assert_eq!(client.reservations(), 0);

        if with_ip {
            let socket = moto_io::net::udp::UdpSocket::bind_reserved(
                client.try_reserve().unwrap(),
                &"127.0.0.1:0".parse().unwrap(),
                None,
            )
            .await
            .unwrap();
            drop(socket);
            assert!(bounded(driver_task, 5).await);
        } else {
            crate::net_harness::drain_host_channel(client, driver_task).await;
        }

        let (sender, mut receiver) = moto_ipc::io_channel::connect("sys-io").unwrap();
        let mut request = moto_sys_io::api_vsock::availability_request();
        request.id = 0x564f_434b;
        assert_eq!(request.handle, 0);
        assert_eq!(request.flags, 0);
        assert_eq!(request.payload.args_64(), &[0; 3]);
        sender.send(request).await.unwrap();
        let response = bounded_output(receiver.recv(), 2)
            .await
            .expect("timed out waiting for raw vsock discovery response")
            .unwrap();
        assert_eq!(response.id, request.id);
        assert_eq!(response.command, request.command);
        assert_eq!(response.status(), Err(moto_rt::Error::NotAllowed));

        let mut cid = moto_sys_io::api_vsock::local_cid_request();
        cid.id = request.id + 1;
        expect_raw_vsock_error(&sender, &mut receiver, cid, moto_rt::Error::NotAllowed).await;
        cid.id += 1;
        cid.flags = 1;
        expect_raw_vsock_error(&sender, &mut receiver, cid, moto_rt::Error::NotAllowed).await;

        let mut malformed = moto_sys_io::api_vsock::availability_request();
        malformed.id = request.id + 1;
        malformed.flags = 1;
        sender.send(malformed).await.unwrap();
        let response = bounded_output(receiver.recv(), 2)
            .await
            .expect("timed out waiting for denied malformed discovery response")
            .unwrap();
        assert_eq!(response.id, malformed.id);
        assert_eq!(response.command, malformed.command);
        assert_eq!(response.flags, malformed.flags);
        assert_eq!(response.status(), Err(moto_rt::Error::NotAllowed));

        let peer = moto_sys_io::api_vsock::VsockAddr {
            cid: 2,
            port: 70_000,
        };
        let mut connect = moto_sys_io::api_vsock::connect_request(peer, 0).unwrap();
        connect.id = 0x564f_5000;
        expect_raw_vsock_error(&sender, &mut receiver, connect, moto_rt::Error::NotAllowed).await;
        let mut malformed_connect = connect;
        malformed_connect.id += 1;
        malformed_connect.flags = 1;
        expect_raw_vsock_error(
            &sender,
            &mut receiver,
            malformed_connect,
            moto_rt::Error::NotAllowed,
        )
        .await;
        for request in raw_vsock_controls(connect.id + 2) {
            expect_raw_vsock_error(&sender, &mut receiver, request, moto_rt::Error::NotAllowed)
                .await;
        }
        expect_raw_vsock_error(
            &sender,
            &mut receiver,
            raw_vsock_bind(connect.id + 5),
            moto_rt::Error::NotAllowed,
        )
        .await;
    });
    std::process::exit(0)
}

fn test_vsock_discovery_inner(mode: &str, with_ip: bool) {
    if mode == "disabled" {
        assert_eq!(
            moto_ipc::io_channel::ClientConnection::connect("sys-io").err(),
            Some(moto_rt::Error::NotFound)
        );
        println!("vsock discovery: disabled PASS");
        return;
    }
    let expected = match mode {
        "present" => Ok(()),
        "absent" => Err(moto_rt::Error::NotFound),
        _ => panic!("unknown vsock discovery mode: {mode}"),
    };
    let expected_cid = match mode {
        "present" => Ok(3_u32),
        "absent" => Err(moto_rt::Error::NotFound),
        _ => unreachable!(),
    };

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;
        assert_eq!(moto_io::net::vsock::availability(&client).await, expected);
        assert_eq!(moto_io::net::vsock::availability(&client).await, expected);
        assert_eq!(moto_io::net::vsock::local_cid(&client).await, expected_cid);
        assert_eq!(moto_io::net::vsock::local_cid(&client).await, expected_cid);
        assert_eq!(client.reservations(), 0);
        crate::net_harness::drain_host_channel(client, driver_task).await;

        let (sender, mut receiver) = moto_ipc::io_channel::connect("sys-io").unwrap();
        let mut malformed = [
            moto_sys_io::api_vsock::availability_request(),
            moto_sys_io::api_vsock::availability_request(),
            moto_sys_io::api_vsock::availability_request(),
        ];
        malformed[0].handle = 1;
        malformed[1].flags = 1;
        malformed[2].payload.args_64_mut()[0] = 1;
        for (idx, mut request) in malformed.into_iter().enumerate() {
            request.id = 0x564f_4300 + idx as u64;
            sender.send(request).await.unwrap();
            let response = bounded_output(receiver.recv(), 2)
                .await
                .expect("timed out waiting for malformed discovery response")
                .unwrap();
            assert_eq!(response.id, request.id);
            assert_eq!(response.command, request.command);
            assert_eq!(response.handle, request.handle);
            assert_eq!(response.flags, request.flags);
            assert_eq!(response.payload.args_64(), request.payload.args_64());
            assert_eq!(response.status(), Err(moto_rt::Error::InvalidArgument));
        }

        let mut malformed_cid = moto_sys_io::api_vsock::local_cid_request();
        malformed_cid.id = 0x564f_4400;
        malformed_cid.flags = 1;
        expect_raw_vsock_error(
            &sender,
            &mut receiver,
            malformed_cid,
            moto_rt::Error::InvalidArgument,
        )
        .await;

        let mut cid = moto_sys_io::api_vsock::local_cid_request();
        cid.id = malformed_cid.id + 1;
        let response = raw_vsock_response(&sender, &mut receiver, cid).await;
        assert_eq!(
            moto_sys_io::api_vsock::decode_local_cid_response(&response),
            expected_cid
        );

        let peer = moto_sys_io::api_vsock::VsockAddr {
            cid: 2,
            port: 70_000,
        };
        let mut connect = moto_sys_io::api_vsock::connect_request(peer, 0).unwrap();
        connect.id = 0x564f_5000;
        let mut malformed_connect = connect;
        malformed_connect.id += 1;
        malformed_connect.flags = 1;
        expect_raw_vsock_error(
            &sender,
            &mut receiver,
            malformed_connect,
            moto_rt::Error::InvalidArgument,
        )
        .await;

        if mode == "absent" {
            expect_raw_vsock_error(&sender, &mut receiver, connect, moto_rt::Error::NotFound).await;
            expect_raw_vsock_error(
                &sender,
                &mut receiver,
                raw_vsock_bind(connect.id + 5),
                moto_rt::Error::NotFound,
            )
            .await;
        }
        for request in raw_vsock_controls(connect.id + 2) {
            expect_raw_vsock_error(&sender, &mut receiver, request, moto_rt::Error::NotFound).await;
        }
    });

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(VSOCK_DISCOVERY_DENIED_CHILD)
        .args(with_ip.then_some("with-ip"))
        .env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, "0x4c")
        .status()
        .unwrap();
    assert_eq!(Some(0), status.code());
    println!("vsock discovery: {mode} PASS");
}

pub fn test_vsock_discovery(mode: &str) {
    test_vsock_discovery_inner(mode, false);
}

/// Connect, drive, shut down: a host-owned channel comes up without a
/// thread, a pool entry, or a vdso object, and `request_shutdown` alone (no
/// reservation was ever taken) drains its driver to completion. I/O through
/// a host-owned channel becomes provable once explicit reservations land;
/// the driver's liveness is meanwhile covered by every other net test, since
/// the compatibility host runs the same `NetDriver::run`.
fn test_connect_drive_shutdown() {
    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;
        client.request_shutdown();
        bounded(driver_task, 5).await
    });
    assert!(
        completed,
        "the NetDriver did not exit after request_shutdown()"
    );

    println!("net_driver::test_connect_drive_shutdown PASS");
}

/// Dropping a driver immediately after connect, before staging any work,
/// disconnects without allocation and leaves the retained client unusable.
fn test_drop_driver_immediately_after_connect() {
    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        drop(driver);
        assert_eq!(client.reservations(), 0);
        assert_eq!(client.try_reserve().err(), Some(ReserveError::ShuttingDown));
        assert_eq!(
            moto_io::net::vsock::availability(&client).await,
            Err(moto_rt::Error::NotConnected)
        );
    });

    println!("net_driver::test_drop_driver_immediately_after_connect PASS");
}

/// Reservation-free RPCs staged before a closing driver starts cannot hold
/// that driver open or be reused after its RX task has exited.
fn test_queued_queries_fail_after_driver_exit() {
    use std::future::Future;
    use std::task::{Context, Poll};

    struct WakeFlag(std::sync::atomic::AtomicBool);

    impl std::task::Wake for WakeFlag {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::Release);
        }
    }

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver) = moto_io::net::connect()
            .await
            .expect("async connect to sys-io failed");
        let mut availability = Box::pin(moto_io::net::vsock::availability(&client));
        let mut local_cid = Box::pin(moto_io::net::vsock::local_cid(&client));
        let availability_woke = Arc::new(WakeFlag(std::sync::atomic::AtomicBool::new(false)));
        let local_cid_woke = Arc::new(WakeFlag(std::sync::atomic::AtomicBool::new(false)));
        {
            let waker = std::task::Waker::from(availability_woke.clone());
            let mut context = Context::from_waker(&waker);
            assert!(matches!(
                availability.as_mut().poll(&mut context),
                Poll::Pending
            ));
            let waker = std::task::Waker::from(local_cid_woke.clone());
            let mut context = Context::from_waker(&waker);
            assert!(matches!(
                local_cid.as_mut().poll(&mut context),
                Poll::Pending
            ));
        }

        // Closing precedes task creation. RX therefore observes an empty
        // response ring and exits before TX publishes either queued request.
        client.request_shutdown();
        driver.run().await;
        assert_eq!(client.try_reserve().err(), Some(ReserveError::ShuttingDown));
        assert!(availability_woke.0.load(Ordering::Acquire));
        assert!(local_cid_woke.0.load(Ordering::Acquire));

        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        assert_eq!(
            availability.as_mut().poll(&mut context),
            Poll::Ready(Err(moto_rt::Error::NotConnected))
        );
        assert_eq!(
            local_cid.as_mut().poll(&mut context),
            Poll::Ready(Err(moto_rt::Error::NotConnected))
        );
        drop((availability, local_cid));

        assert_eq!(client.reservations(), 0);
        assert_eq!(
            moto_io::net::vsock::availability(&client).await,
            Err(moto_rt::Error::NotConnected)
        );
    });

    println!("net_driver::test_queued_queries_fail_after_driver_exit PASS");
}

/// The reservation protocol: `try_reserve` fills exactly `capacity()`
/// slots, refuses the next with `AtCapacity`, and releasing the last
/// reservation -- with no `request_shutdown` anywhere -- closes the channel
/// to new reservations and exits the driver.
fn test_reservation_lifecycle() {
    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;

        let capacity = client.capacity();
        assert!(capacity > 0);
        let mut reservations = Vec::new();
        for held in 0..capacity {
            assert_eq!(client.reservations(), held);
            reservations.push(client.try_reserve().expect("reserve within capacity"));
        }
        assert_eq!(
            client.try_reserve().err(),
            Some(ReserveError::AtCapacity),
            "a full channel accepted a fifth reservation"
        );

        // Not the last release: the channel must stay open.
        drop(reservations.pop());
        assert_eq!(client.reservations(), capacity - 1);
        reservations.push(client.try_reserve().expect("a freed slot was not reusable"));

        drop(reservations);
        assert_eq!(client.reservations(), 0);
        assert_eq!(
            client.try_reserve().err(),
            Some(ReserveError::ShuttingDown),
            "the last release did not close the channel"
        );
        bounded(driver_task, 5).await
    });
    assert!(
        completed,
        "the NetDriver did not exit after the last reservation was released"
    );

    println!("net_driver::test_reservation_lifecycle PASS");
}

/// Real I/O over a host-owned channel. Two UDP sockets bound with this
/// client's reservations exchange a datagram, and a TCP stream connected
/// with a third writes to a std echo peer (which runs on the ordinary pool
/// path) and reads its own bytes back -- all progress made only because
/// this host drives the channel's `NetDriver`. Dropping the sockets then
/// releases the last reservation and the driver exits on its own.
fn test_reserved_socket_io() {
    let echo_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut peer, _) = echo_listener.accept().unwrap();
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).unwrap();
        peer.write_all(&buf).unwrap();
    });

    let completed = moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;

        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let a = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved UDP bind (a)");
        let b = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved UDP bind (b)");

        assert_eq!(
            a.try_send_to(b"host channel", b.local_addr()),
            Ok(b"host channel".len())
        );
        let mut buf = [0u8; 64];
        let (len, from) = b
            .recv_from_future(&mut buf, false)
            .await
            .expect("reserved UDP recv");
        assert_eq!(&buf[..len], b"host channel");
        assert_eq!(&from, a.local_addr());

        let stream = moto_io::net::tcp::TcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &echo_addr,
            None,
            None,
            None,
        )
        .await
        .expect("reserved TCP connect");
        let mut written = 0;
        while written < 4 {
            match stream.try_write(&[&b"ping"[written..]]) {
                Ok(n) => written += n,
                Err(moto_rt::E_NOT_READY) => stream.writable().await,
                Err(err) => panic!("reserved TCP write failed: {err:?}"),
            }
        }
        let mut echoed = Vec::new();
        while echoed.len() < 4 {
            let mut buf = [0u8; 8];
            match stream.try_read(&mut [&mut buf], false) {
                Ok(0) => panic!("reserved TCP stream closed before the echo"),
                Ok(n) => echoed.extend_from_slice(&buf[..n]),
                Err(moto_rt::E_NOT_READY) => stream.readable().await,
                Err(err) => panic!("reserved TCP read failed: {err:?}"),
            }
        }
        assert_eq!(&echoed, b"ping");

        assert_eq!(client.reservations(), 3);
        drop((a, b, stream));
        bounded(driver_task, 5).await && client.reservations() == 0
    });
    assert!(
        completed,
        "the NetDriver did not exit after the reserved sockets dropped"
    );
    echo_thread.join().unwrap();

    println!("net_driver::test_reserved_socket_io PASS");
}

/// A host-owned listener: bound on one reservation, accepts armed only by
/// donation (`post_accept`), served by `try_accept`. This is the decision 2
/// flow end to end: sys-io completes the pre-posted request when the
/// connection arrives, this host's own driver poll queues it locally, and
/// `try_accept` claims it -- with no request posted, `try_accept` could
/// never succeed. The donated reservation becomes the accepted stream's
/// channel slot, and everything releases back to zero.
fn test_reserved_listener_accept() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver_task) = host_channel().await;

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        // The accept load the vdso pump's policy reads: nothing before the
        // donation, one posted request after it.
        assert_eq!(listener.accept_load(), (0, 0));
        listener.post_accept(client.try_reserve().unwrap());
        assert_eq!(listener.accept_load(), (1, 0));
        assert_eq!(client.reservations(), 2);

        // Nothing is queued before a connection arrives.
        assert_eq!(listener.try_accept().err(), Some(moto_rt::E_NOT_READY));

        let listener_addr = *listener.socket_addr();
        let peer_thread = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let mut peer = std::net::TcpStream::connect(listener_addr).unwrap();
            peer.write_all(b"ping").unwrap();
            let mut buf = [0u8; 4];
            peer.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"pong");
        });

        // The completion is local: it is queued only once this host's
        // driver polls it in. Wait for the ready queue, bounded; the
        // posted request has then become the queued connection, and the
        // load must track that transition and empty after the claim.
        let mut arrived = false;
        for _ in 0..2000 {
            if listener.has_async_accepts() {
                arrived = true;
                break;
            }
            moto_async::sleep(Duration::from_millis(5)).await;
        }
        assert!(arrived, "no connection within 10s");
        assert_eq!(listener.accept_load(), (0, 1));
        let (stream, _remote_addr) = listener.try_accept().expect("queued reserved accept");
        assert_eq!(listener.accept_load(), (0, 0));
        // The donated slot became the stream's; the listener keeps its own.
        assert_eq!(client.reservations(), 2);

        let mut pinged = Vec::new();
        while pinged.len() < 4 {
            let mut buf = [0u8; 8];
            match stream.try_read(&mut [&mut buf], false) {
                Ok(0) => panic!("reserved accepted stream closed early"),
                Ok(n) => pinged.extend_from_slice(&buf[..n]),
                Err(moto_rt::E_NOT_READY) => stream.readable().await,
                Err(err) => panic!("reserved accepted read failed: {err:?}"),
            }
        }
        assert_eq!(&pinged, b"ping");
        let mut written = 0;
        while written < 4 {
            match stream.try_write(&[&b"pong"[written..]]) {
                Ok(n) => written += n,
                Err(moto_rt::E_NOT_READY) => stream.writable().await,
                Err(err) => panic!("reserved accepted write failed: {err:?}"),
            }
        }

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(
        completed,
        "the NetDriver did not exit after the reserved listener and stream dropped"
    );
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_listener_accept PASS");
}

/// Spawn a std-path peer that connects, pings, and expects the pong. The
/// byte round-trip is what proves a redelivered connection live.
fn spawn_pingpong_peer(addr: std::net::SocketAddr) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut peer = std::net::TcpStream::connect(addr).unwrap();
        peer.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    })
}

/// Serve one ping/pong exchange on the native side of an accepted stream.
async fn serve_pingpong(stream: &moto_io::net::tcp::TcpStream) {
    let mut pinged = Vec::new();
    while pinged.len() < 4 {
        let mut buf = [0u8; 8];
        match stream.try_read(&mut [&mut buf], false) {
            Ok(0) => panic!("peer closed before the ping"),
            Ok(n) => pinged.extend_from_slice(&buf[..n]),
            Err(moto_rt::E_NOT_READY) => stream.readable().await,
            Err(err) => panic!("native read failed: {err:?}"),
        }
    }
    assert_eq!(&pinged, b"ping");
    let mut written = 0;
    while written < 4 {
        match stream.try_write(&[&b"pong"[written..]]) {
            Ok(n) => written += n,
            Err(moto_rt::E_NOT_READY) => stream.writable().await,
            Err(err) => panic!("native write failed: {err:?}"),
        }
    }
}

/// Decision 2's park contract, pinned from the sharp side: with a
/// connection already established and waiting inside sys-io, an accept on
/// a host-owned listener with no donation outstanding must NOT complete --
/// nothing was posted, so nothing may arrive. The donation then completes
/// the same accept flow and serves that waiting connection.
fn test_reserved_accept_parks_until_donation() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver_task) = host_channel().await;

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        let peer_thread = spawn_pingpong_peer(*listener.socket_addr());

        // The peer's connect establishes inside sys-io regardless; the
        // undonated accept still must sit out the whole bound.
        assert!(
            !bounded(listener.accept(), 2).await,
            "an accept with no donation outstanding completed"
        );

        listener.post_accept(client.try_reserve().unwrap());
        let (stream, _addr) = bounded_output(listener.accept(), 5)
            .await
            .expect("donated accept did not complete")
            .expect("donated accept failed");
        serve_pingpong(&stream).await;

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(completed, "the NetDriver did not exit after teardown");
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_accept_parks_until_donation PASS");
}

/// Reserved sibling of `test_cancelled_native_accept_redelivers_connection`
/// (Stage 4 decision 5): an accept cancelled while parked on a host-owned
/// listener spends nothing -- the donated request's connection reaches the
/// next caller, alive.
fn test_reserved_cancelled_accept_redelivers() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver_task) = host_channel().await;

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        listener.post_accept(client.try_reserve().unwrap());

        // Park a caller (the donation is the outstanding request; parking
        // posts nothing), then cancel it before any connection exists.
        {
            let mut accept = Box::pin(listener.accept());
            let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
            assert!(accept.as_mut().poll(&mut cx).is_pending());
        }

        let peer_thread = spawn_pingpong_peer(*listener.socket_addr());
        let (stream, _addr) = bounded_output(listener.accept(), 5)
            .await
            .expect("the connection was not redelivered to the next caller")
            .expect("redelivered accept failed");
        serve_pingpong(&stream).await;

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(completed, "the NetDriver did not exit after teardown");
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_cancelled_accept_redelivers PASS");
}

/// Reserved sibling of `test_delivered_then_cancelled_native_accept_
/// redelivers` (Stage 4 decision 5): the response reaches the cancelled
/// caller's one-shot, the caller drops without polling, and the rollback
/// re-queues the live connection for the next caller.
fn test_reserved_delivered_then_cancelled_accept_redelivers() {
    struct WakeFlag(std::sync::atomic::AtomicBool);

    impl std::task::Wake for WakeFlag {
        fn wake(self: std::sync::Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let (completed, peer_thread) = runtime.block_on(async {
        let (client, driver_task) = host_channel().await;

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
            None,
        )
        .await
        .expect("reserved TCP listener bind");
        listener.post_accept(client.try_reserve().unwrap());

        let mut accept = Box::pin(listener.accept());
        let flag = std::sync::Arc::new(WakeFlag(std::sync::atomic::AtomicBool::new(false)));
        let waker = std::task::Waker::from(flag.clone());
        let mut cx = core::task::Context::from_waker(&waker);
        assert!(accept.as_mut().poll(&mut cx).is_pending());

        let peer_thread = spawn_pingpong_peer(*listener.socket_addr());

        // The driver task delivers the response into the parked caller's
        // one-shot and fires this waker; only then is dropping the future
        // the delivered-then-cancelled window.
        let mut waited = 0;
        while !flag.0.load(std::sync::atomic::Ordering::Acquire) {
            assert!(waited < 2000, "accept response was never delivered");
            moto_async::sleep(Duration::from_millis(5)).await;
            waited += 1;
        }
        drop(accept);

        let (stream, _addr) = bounded_output(listener.accept(), 5)
            .await
            .expect("the connection was not redelivered after cancellation")
            .expect("redelivered accept failed");
        serve_pingpong(&stream).await;

        drop(stream);
        drop(listener);
        let exited = bounded(driver_task, 5).await;
        (exited && client.reservations() == 0, peer_thread)
    });
    assert!(completed, "the NetDriver did not exit after teardown");
    peer_thread.join().unwrap();

    println!("net_driver::test_reserved_delivered_then_cancelled_accept_redelivers PASS");
}

/// Read this process's published-channel count from its vdso pool.
fn pool_client_count() -> u64 {
    moto_rt::internal_helper(0, 1, 0, 0, 0, 0)
}

/// The Stage 5 coalescing regression: from a cold pool, N simultaneous
/// sockets must share channels (about ceil(N / capacity) of them), not get
/// one each. Runs in a spawned child so its pool really is cold.
pub fn pool_cold_start_child() -> ! {
    use std::sync::{Arc, Barrier};

    const N: usize = 16;
    let barrier = Arc::new(Barrier::new(N));
    let sockets: Vec<_> = (0..N)
        .map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
            })
        })
        .collect();
    let sockets: Vec<_> = sockets.into_iter().map(|t| t.join().unwrap()).collect();

    // 16 concurrent sockets, capacity 4 per channel: 4 channels, with +1 of
    // provisioning-race slack.
    let channels = pool_client_count();
    assert!(
        (4..=5).contains(&channels),
        "cold start provisioned {channels} channels for {N} sockets"
    );
    drop(sockets);
    std::process::exit(0);
}

fn test_pool_cold_start_coalesces() {
    let status = std::process::Command::new(std::env::args().next().unwrap())
        .arg("pool-cold-start-child")
        .status()
        .expect("failed to spawn the cold-start child");
    assert!(status.success(), "cold-start child failed: {status:?}");
    println!("net_driver::test_pool_cold_start_coalesces PASS");
}

fn wait_for_cold_pool() {
    // The pool must be cold, or an existing channel satisfies the
    // reservation without provisioning. Idle channels self-close when
    // their last reservation releases; earlier tests' have drained by now.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while pool_client_count() != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the pool did not go cold; {} channel(s) live",
            pool_client_count()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The fail-all policy: with sys-io connects poisoned and the pool cold,
/// a socket constructor fails promptly instead of hanging; unpoisoning
/// restores service.
fn test_sys_io_unavailable_fails_all() {
    wait_for_cold_pool();
    moto_rt::internal_helper(0, 2, 1, 0, 0, 0);
    let result = std::net::UdpSocket::bind("127.0.0.1:0");
    moto_rt::internal_helper(0, 2, 0, 0, 0, 0);
    assert!(
        result.is_err(),
        "a bind succeeded while sys-io connects were poisoned"
    );

    let recovered = std::net::UdpSocket::bind("127.0.0.1:0");
    assert!(recovered.is_ok(), "bind did not recover after unpoisoning");
    println!("net_driver::test_sys_io_unavailable_fails_all PASS");
}

fn test_channel_allocation_failure() {
    wait_for_cold_pool();
    moto_rt::internal_helper(0, 4, 1, 0, 0, 0);
    // Fail after connecting IPC and allocating queue storage. Both bind
    // veneers must receive the error; neither may publish a partial channel.
    for _ in 0..4 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0");
        let udp = std::net::UdpSocket::bind("127.0.0.1:0");
        assert_eq!(tcp.unwrap_err().kind(), std::io::ErrorKind::OutOfMemory);
        assert_eq!(udp.unwrap_err().kind(), std::io::ErrorKind::OutOfMemory);
        assert_eq!(pool_client_count(), 0);
    }
    moto_rt::internal_helper(0, 4, 0, 0, 0, 0);
    moto_rt::internal_helper(0, 0, 0, 0, 0, 0); // No waiters or in-flight provisions.
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    drop((tcp, udp));
    println!("net_driver::test_channel_allocation_failure PASS");
}

fn test_pool_runtime_allocation_failure() {
    wait_for_cold_pool();
    moto_rt::internal_helper(0, 5, 1, 0, 0, 0);
    for _ in 0..4 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0");
        let udp = std::net::UdpSocket::bind("127.0.0.1:0");
        assert_eq!(tcp.unwrap_err().kind(), std::io::ErrorKind::OutOfMemory);
        assert_eq!(udp.unwrap_err().kind(), std::io::ErrorKind::OutOfMemory);
        assert_eq!(pool_client_count(), 0);
    }
    moto_rt::internal_helper(0, 5, 0, 0, 0, 0);
    moto_rt::internal_helper(0, 0, 0, 0, 0, 0);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    drop((tcp, udp));
    println!("net_driver::test_pool_runtime_allocation_failure PASS");
}

/// Accept requests riding donations from two different channels must not
/// collide in the listener's in-flight map. Request ids were per-channel
/// counters, each starting at 1, and the map is keyed by bare id: with one
/// accept outstanding on channel A (its id 2, after the bind's id 1), the
/// second accept on a fresh channel B also drew id 2 and hit the
/// `post_accept_reservation` uniqueness assert -- a vdso panic that killed
/// the process with 0xbadc0de (observed as systest dying with ssh status
/// 222). Ids are process-global now; this pins the cross-channel shape the
/// vdso accept pump produces whenever the pool hands it another channel's
/// slot.
fn test_accept_ids_unique_across_channels() {
    let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Channel B on its own runtime thread, as in production: one
    // LocalRuntime hosts one channel driver (the wake-on-sleep slot is
    // single-handle). The thread ends when B's last reservation releases.
    let (client_b_tx, client_b_rx) = std::sync::mpsc::channel();
    let driver_b_thread = std::thread::spawn(move || {
        moto_async::LocalRuntime::new().block_on(async move {
            let (client, driver) = moto_io::net::connect()
                .await
                .expect("async connect to sys-io failed");
            client_b_tx.send(client).unwrap();
            driver.run().await;
        });
    });
    let client_b = client_b_rx.recv().unwrap();

    let mut runtime = moto_async::LocalRuntime::new();
    let result = runtime.block_on(async {
        let (client_a, driver_a) = host_channel().await;

        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client_a.try_reserve().unwrap(),
            &loopback,
            None,
            None,
        )
        .await
        .expect("reserved TCP listener bind");

        // One in-flight accept on A, then two on B: the pre-fix
        // per-channel id counters made the second B request reuse A's
        // outstanding id.
        listener.post_accept(client_a.try_reserve().unwrap());
        listener.post_accept(client_b.try_reserve().unwrap());
        listener.post_accept(client_b.try_reserve().unwrap());
        assert_eq!(listener.accept_load(), (3, 0));

        let listener_addr = *listener.socket_addr();
        let peer_threads: Vec<_> = (0..3)
            .map(|_| {
                std::thread::spawn(move || {
                    use std::io::Write;
                    let mut peer = std::net::TcpStream::connect(listener_addr).unwrap();
                    peer.write_all(b"ping").unwrap();
                })
            })
            .collect();

        // Hold the accepted streams until the peers are done: dropping one
        // eagerly closes it, and a peer whose 4-byte write loses that race
        // sees NotConnected (observed as a release-gate flake).
        let mut accepted = Vec::new();
        let mut all_accepted = true;
        for _ in 0..3 {
            match bounded_output(listener.accept(), 5).await {
                Some(result) => accepted.push(result.expect("cross-channel accept failed")),
                None => all_accepted = false,
            }
        }
        (all_accepted, accepted, peer_threads, driver_a)
    });
    let (all_accepted, accepted, peer_threads, driver_a) = result;
    assert!(all_accepted, "cross-channel accept did not complete");
    for peer in peer_threads {
        peer.join().unwrap();
    }
    drop(accepted);
    // Socket drops queue their closes; keep A running until it sends them.
    assert!(
        runtime.block_on(async { bounded(driver_a, 5).await }),
        "cross-channel accept driver A did not exit"
    );
    drop(client_b);
    driver_b_thread.join().unwrap();
    println!("net_driver::test_accept_ids_unique_across_channels PASS");
}

/// A partial nonblocking write must be answered by a WRITABLE edge once
/// space returns. Under epoll semantics a partial write means "buffer
/// full, an edge is owed when it drains", and tokio's PollEvented clears
/// its cached WRITABLE on `n < buf.len()` without ever seeing a
/// WouldBlock; before the fix only an E_NOT_READY armed the re-raise, so
/// a mid-write page-pool exhaustion parked such a writer forever (the
/// russhd SFTP stall).
///
/// The channel TX pool is finite and the peer reads nothing during the
/// fill, so exhaustion is deterministic. A 4-page write returns partial
/// when fewer than 4 pages remain; if the pool size is an exact multiple
/// of 4 the first fill ends in E_NOT_READY instead -- then the peer
/// drains, and a second fill led by one 1-page write shifts alignment so
/// its tail is guaranteed partial.
fn test_partial_write_raises_writable() {
    use moto_io::net::readiness::{NetEventListener, Readiness};

    struct CountingObserver {
        writable: AtomicUsize,
    }
    impl NetEventListener for CountingObserver {
        fn on_readiness(&self, edges: Readiness) {
            if edges.contains(Readiness::WRITABLE) {
                self.writable.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    const PAGE: usize = moto_ipc::io_channel::PAGE_SIZE;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let (drain_tx, drain_rx) = std::sync::mpsc::channel::<()>();
    let peer_thread = std::thread::spawn(move || {
        use std::io::Read;
        let (mut peer, _) = listener.accept().unwrap();
        // Bounded reads: each drain pass ends at a timeout, not at EOF.
        peer.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut total = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        // Drain on demand; EOF or a dropped sender ends the loop.
        while drain_rx.recv().is_ok() {
            loop {
                match peer.read(&mut buf) {
                    Ok(0) => return total,
                    Ok(n) => total += n,
                    Err(_) => break, // timeout: drained for now
                }
            }
        }
        total
    });

    let observer = Arc::new(CountingObserver {
        writable: AtomicUsize::new(0),
    });

    let mut runtime = moto_async::LocalRuntime::new();
    let saw_edge = runtime.block_on(async {
        let (client, driver_task) = host_channel().await;

        let stream = moto_io::net::tcp::TcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &peer_addr,
            None,
            Some(observer.clone() as Arc<dyn NetEventListener>),
            None,
        )
        .await
        .expect("reserved TCP connect");

        let big = vec![7u8; 4 * PAGE];
        let lead = vec![7u8; PAGE];

        let mut partial = false;
        for fill in 0..2 {
            if fill == 1 {
                // Exact-multiple pool: drain, then shift alignment by one
                // page so this fill's tail cannot land on a boundary.
                drain_tx.send(()).unwrap();
                let mut spins = 0;
                loop {
                    match stream.try_write(&[&lead]) {
                        Ok(n) if n == PAGE => break,
                        Ok(_) | Err(_) => {
                            spins += 1;
                            assert!(spins < 2000, "pool never refilled after drain");
                            moto_async::sleep(Duration::from_millis(5)).await;
                        }
                    }
                }
            }
            loop {
                match stream.try_write(&[&big]) {
                    Ok(n) if n == big.len() => continue,
                    Ok(n) => {
                        assert!(n > 0 && n < big.len());
                        partial = true;
                        break;
                    }
                    Err(err) => {
                        assert_eq!(err, moto_rt::E_NOT_READY);
                        break;
                    }
                }
            }
            if partial {
                break;
            }
        }
        assert!(partial, "the fill never produced a partial write");

        // The claim: draining (space returning) must raise WRITABLE even
        // though the last write was partial, not E_NOT_READY.
        let edges_before = observer.writable.load(Ordering::SeqCst);
        drain_tx.send(()).unwrap();
        let mut saw_edge = false;
        for _ in 0..2000 {
            if observer.writable.load(Ordering::SeqCst) > edges_before {
                saw_edge = true;
                break;
            }
            moto_async::sleep(Duration::from_millis(5)).await;
        }
        drop(stream);
        assert!(
            bounded(driver_task, 5).await,
            "partial-write test driver did not exit"
        );
        saw_edge
    });
    assert!(saw_edge, "no WRITABLE edge after a partial write");

    drop(drain_tx);
    drop(runtime);
    let _ = peer_thread.join().unwrap();
    println!("net_driver::test_partial_write_raises_writable PASS");
}

/// A connected UDP socket must not raise READABLE for a foreign
/// datagram: the source filter ran only at read time, so an arrival from
/// a non-peer raised a spurious READABLE with nothing readable -- the
/// mio udp discard contract (kernel-side filtering on Linux), seen as a
/// storm-soak mio-test flake. The observer is installed at bind and the
/// sends happen after, so the arrival exercises the edge path, not the
/// registration-time synthesis.
fn test_connected_udp_ignores_foreign_datagrams() {
    use moto_io::net::readiness::{NetEventListener, Readiness};

    struct CountingObserver {
        readable: AtomicUsize,
    }
    impl NetEventListener for CountingObserver {
        fn on_readiness(&self, edges: Readiness) {
            if edges.contains(Readiness::READABLE) {
                self.readable.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    let observer = Arc::new(CountingObserver {
        readable: AtomicUsize::new(0),
    });

    let mut runtime = moto_async::LocalRuntime::new();
    runtime.block_on(async {
        let (client, driver_task) = host_channel().await;
        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

        let rx = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            Some(observer.clone() as Arc<dyn NetEventListener>),
        )
        .await
        .expect("reserved UDP bind (rx)");
        let peer = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved UDP bind (peer)");
        let outside = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved UDP bind (outside)");

        rx.connect(peer.local_addr());

        assert_eq!(
            outside.try_send_to(b"foreign", rx.local_addr()),
            Ok(b"foreign".len())
        );
        // Bounded settle for the negative claim; the spurious edge fired
        // within delivery latency (milliseconds) when present.
        for _ in 0..100 {
            if observer.readable.load(Ordering::SeqCst) > 0 {
                break;
            }
            moto_async::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            observer.readable.load(Ordering::SeqCst),
            0,
            "spurious READABLE for a foreign datagram on a connected socket"
        );
        let mut buf = [0u8; 64];
        assert_eq!(
            rx.try_recv_from(&mut buf, false).err(),
            Some(moto_rt::E_NOT_READY),
            "a foreign datagram was delivered to a connected socket"
        );

        // The peer's datagram must still raise the edge and arrive.
        assert_eq!(
            peer.try_send_to(b"from-peer", rx.local_addr()),
            Ok(b"from-peer".len())
        );
        let mut edged = false;
        for _ in 0..2000 {
            if observer.readable.load(Ordering::SeqCst) > 0 {
                edged = true;
                break;
            }
            moto_async::sleep(Duration::from_millis(5)).await;
        }
        assert!(edged, "no READABLE for the connected peer's datagram");
        let (len, from) = rx
            .try_recv_from(&mut buf, false)
            .expect("the peer's datagram was not readable");
        assert_eq!(&buf[..len], b"from-peer");
        assert_eq!(&from, peer.local_addr());
        drop((rx, peer, outside));
        assert!(
            bounded(driver_task, 5).await,
            "connected-UDP test driver did not exit"
        );
    });
    println!("net_driver::test_connected_udp_ignores_foreign_datagrams PASS");
}

/// The enabling invariant of the vDSO recheck removal (networking plan
/// step 3): dropping parked futures on a quiet socket leaves every waiter
/// count at zero on its own -- no later packet, page-free, or recheck tick
/// cleans up after them. The RX counts are exact (nothing ever arrives);
/// the TX round tolerates sys-io still draining early fills and only
/// commits once registrations stick.
fn test_dropped_futures_leave_no_waiters() {
    use core::pin::Pin;
    use core::task::Poll;

    const PAGE: usize = moto_ipc::io_channel::PAGE_SIZE;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let (drain_tx, drain_rx) = std::sync::mpsc::channel::<()>();
    let peer_thread = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        // Quiet until asked; a drain request empties what is queued (the
        // timeout ends a pass), then acks so the test can read something.
        let mut buf = vec![0u8; 64 * 1024];
        while drain_rx.recv().is_ok() {
            loop {
                match peer.read(&mut buf) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            peer.write_all(b"ack!").unwrap();
        }
    });

    let mut runtime = moto_async::LocalRuntime::new();
    runtime.block_on(async {
        let (client, driver_task) = host_channel().await;

        let stream = moto_io::net::tcp::TcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &peer_addr,
            None,
            None,
            None,
        )
        .await
        .expect("reserved TCP connect");
        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let udp = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .expect("reserved UDP bind");

        // RX: park readiness futures and full read futures on sockets with
        // nothing readable, then drop them.
        let mut tcp_readables: Vec<_> = (0..16).map(|_| stream.readable()).collect();
        let mut udp_readables: Vec<_> = (0..16).map(|_| udp.readable()).collect();
        let mut tcp_buf = [0u8; 8];
        let mut tcp_bufs = [&mut tcp_buf[..]];
        let mut tcp_read = stream.read_future(&mut tcp_bufs, false);
        let mut udp_buf = [0u8; 8];
        let mut udp_read = udp.recv_from_future(&mut udp_buf, false);
        core::future::poll_fn(|cx| {
            for f in tcp_readables.iter_mut() {
                assert!(Pin::new(f).poll(cx).is_pending());
            }
            for f in udp_readables.iter_mut() {
                assert!(Pin::new(f).poll(cx).is_pending());
            }
            assert!(Pin::new(&mut tcp_read).poll(cx).is_pending());
            assert!(Pin::new(&mut udp_read).poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(stream.rx_waiter_count(), 17);
        assert_eq!(udp.rx_waiter_count(), 17);

        drop((tcp_readables, tcp_read, udp_readables, udp_read));
        assert_eq!(stream.rx_waiter_count(), 0, "TCP rx waiters retained");
        assert_eq!(udp.rx_waiter_count(), 0, "UDP rx waiters retained");

        // TX: exhaust the channel page pool, park writers, drop them. A
        // round where everything still polls Ready (sys-io mid-drain) is
        // retried; with the peer not reading, capacity is finite.
        let big = vec![7u8; 4 * PAGE];
        let wbufs = [&big[..]];
        let mut registered = 0;
        for _round in 0..100 {
            loop {
                match stream.try_write(&[&big]) {
                    Ok(_) => continue,
                    Err(err) => {
                        assert_eq!(err, moto_rt::E_NOT_READY);
                        break;
                    }
                }
            }
            let mut writables: Vec<_> = (0..16).map(|_| stream.writable()).collect();
            let mut tcp_write = stream.write_future(&wbufs);
            let pending = core::future::poll_fn(|cx| {
                let mut pending = 0;
                for f in writables.iter_mut() {
                    if Pin::new(f).poll(cx).is_pending() {
                        pending += 1;
                    }
                }
                if Pin::new(&mut tcp_write).poll(cx).is_pending() {
                    pending += 1;
                }
                Poll::Ready(pending)
            })
            .await;
            drop((writables, tcp_write));
            if pending > 0 {
                registered = pending;
                break;
            }
        }
        assert!(registered > 0, "no TX waiter ever registered");
        assert_eq!(stream.tx_waiter_count(), 0, "TX waiters retained");

        // Functional tail: the same socket still moves data both ways, and
        // the drain-driven page-free wake reaches a fresh writable().
        drain_tx.send(()).unwrap();
        let mut done = 0;
        while done < 4 {
            match stream.try_write(&[&b"tail"[done..]]) {
                Ok(n) => done += n,
                Err(moto_rt::E_NOT_READY) => stream.writable().await,
                Err(err) => panic!("post-drop write failed: {err:?}"),
            }
        }
        let mut acked = Vec::new();
        while acked.len() < 4 {
            let mut buf = [0u8; 8];
            match stream.try_read(&mut [&mut buf], false) {
                Ok(0) => panic!("peer closed before the ack"),
                Ok(n) => acked.extend_from_slice(&buf[..n]),
                Err(moto_rt::E_NOT_READY) => stream.readable().await,
                Err(err) => panic!("post-drop read failed: {err:?}"),
            }
        }
        assert_eq!(&acked, b"ack!");
        drop((stream, udp));
        assert!(
            bounded(driver_task, 5).await,
            "dropped-future test driver did not exit"
        );
    });

    drop(drain_tx);
    peer_thread.join().unwrap();
    println!("net_driver::test_dropped_futures_leave_no_waiters PASS");
}

/// Losing sys-io fails every kind of work parked on the channel and retires
/// the driver instead of spinning on the dead server handle.
fn test_channel_failure_wakes_every_waiter() {
    use std::future::Future;
    use std::sync::atomic::AtomicBool;
    use std::task::Poll;

    let peer_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_addr = peer_listener.local_addr().unwrap();
    let release_peer = Arc::new(AtomicBool::new(false));
    let peer_release = release_peer.clone();
    let peer = std::thread::spawn(move || {
        let (_stream, _) = peer_listener.accept().unwrap();
        while !peer_release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
    });

    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;
        let stream = moto_io::net::tcp::TcpStream::connect_reserved(
            client.try_reserve().unwrap(),
            &peer_addr,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let loopback: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let udp = moto_io::net::udp::UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
        )
        .await
        .unwrap();
        let listener = moto_io::net::tcp::TcpListener::bind_reserved(
            client.try_reserve().unwrap(),
            &loopback,
            None,
            None,
        )
        .await
        .unwrap();
        listener.post_accept(client.try_reserve().unwrap());

        let mut tcp_byte = [0_u8; 1];
        let mut tcp_bufs = [&mut tcp_byte[..]];
        let mut tcp_read = Box::pin(stream.read_future(&mut tcp_bufs, false));
        let mut udp_byte = [0_u8; 1];
        let mut udp_read = Box::pin(udp.recv_from_future(&mut udp_byte, false));
        let mut accept = Box::pin(listener.accept());
        let mut ttl = Box::pin(stream.ttl_async());
        let mut local_cid = Box::pin(moto_io::net::vsock::local_cid(&client));

        core::future::poll_fn(|cx| {
            assert!(tcp_read.as_mut().poll(cx).is_pending());
            assert!(udp_read.as_mut().poll(cx).is_pending());
            assert!(accept.as_mut().poll(cx).is_pending());
            assert!(ttl.as_mut().poll(cx).is_pending());
            assert!(local_cid.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(stream.rx_waiter_count(), 1);
        assert_eq!(udp.rx_waiter_count(), 1);
        assert_eq!(listener.channel_rpc_waiter_count_for_test(), 3);

        client.fail_for_test();

        core::future::poll_fn(|cx| {
            assert_eq!(
                tcp_read.as_mut().poll(cx),
                Poll::Ready(Err(moto_rt::E_NOT_CONNECTED))
            );
            assert!(matches!(
                udp_read.as_mut().poll(cx),
                Poll::Ready(Err(moto_rt::E_NOT_CONNECTED))
            ));
            assert!(matches!(
                accept.as_mut().poll(cx),
                Poll::Ready(Err(moto_rt::E_NOT_CONNECTED))
            ));
            assert_eq!(
                ttl.as_mut().poll(cx),
                Poll::Ready(Err(moto_rt::E_NOT_CONNECTED))
            );
            assert_eq!(
                local_cid.as_mut().poll(cx),
                Poll::Ready(Err(moto_rt::Error::NotConnected))
            );
            Poll::Ready(())
        })
        .await;
        assert_eq!(stream.rx_waiter_count(), 0);
        assert_eq!(udp.rx_waiter_count(), 0);
        assert_eq!(listener.channel_rpc_waiter_count_for_test(), 0);
        assert_eq!(client.try_reserve().err(), Some(ReserveError::ShuttingDown));

        drop((tcp_read, udp_read, accept, ttl, local_cid));
        drop((stream, udp, listener));
        assert_eq!(client.reservations(), 0);
        assert!(
            bounded(driver_task, 5).await,
            "failed NetDriver did not exit"
        );
    });

    release_peer.store(true, Ordering::Release);
    peer.join().unwrap();
    println!("net_driver::test_channel_failure_wakes_every_waiter PASS");
}

pub fn run_all_tests() {
    crate::vsock::run_wire_tests();
    test_vsock_discovery_inner("absent", true);
    test_connect_drive_shutdown();
    test_drop_driver_immediately_after_connect();
    test_queued_queries_fail_after_driver_exit();
    test_reservation_lifecycle();
    test_reserved_socket_io();
    test_reserved_listener_accept();
    test_reserved_accept_parks_until_donation();
    test_reserved_cancelled_accept_redelivers();
    test_reserved_delivered_then_cancelled_accept_redelivers();
    test_accept_ids_unique_across_channels();
    test_partial_write_raises_writable();
    test_connected_udp_ignores_foreign_datagrams();
    test_dropped_futures_leave_no_waiters();
    test_channel_failure_wakes_every_waiter();
    test_pool_cold_start_coalesces();
    test_sys_io_unavailable_fails_all();
    test_channel_allocation_failure();
    test_pool_runtime_allocation_failure();
}
