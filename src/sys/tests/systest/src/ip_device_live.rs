use futures::FutureExt;
use moto_sdk::io::ip_device::IpDevice;
use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub(super) fn config(n: u8) -> Registration {
    let v4 = Cidr {
        address: Ipv4Addr::new(10, 242, n, 1).into(),
        prefix_len: 24,
    };
    let v6 = Cidr {
        address: Ipv6Addr::new(0xfd42, n as u16, 0, 0, 0, 0, 0, 1).into(),
        prefix_len: 64,
    };
    Registration {
        name: format!("test_wg{n}"),
        mtu: 1420,
        addresses: vec![v4, v6],
        routes: vec![v4.network().unwrap(), v6.network().unwrap()],
    }
}

struct Provider {
    shutdown: Box<dyn FnOnce(bool)>,
    observed: std::sync::mpsc::Receiver<u8>,
}

impl Provider {
    fn start(n: u8) -> Self {
        Self::start_mode(n, true)
    }

    fn start_mode(n: u8, reflecting: bool) -> Self {
        let (stop, stopped) = moto_sdk::async_runtime::oneshot();
        let (ready, wait_ready) = std::sync::mpsc::channel();
        let (done_tx, done) = std::sync::mpsc::channel();
        let (observe, observed) = std::sync::mpsc::sync_channel(16);
        let thread = std::thread::spawn(move || {
            moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
                let mut device = IpDevice::register(&config(n)).await.unwrap();
                ready.send(()).unwrap();
                let orderly = {
                    let reflect = async {
                        let (tx, mut rx) = device.split();
                        let mut bytes = [0; 4096];
                        let mut batch = 0;
                        loop {
                            let len = rx.receive(&mut bytes).await.unwrap();
                            if !reflecting {
                                let protocol = if bytes[0] >> 4 == 4 { bytes[9] } else { bytes[6] };
                                let _ = observe.try_send(protocol);
                                continue;
                            }
                            let (offset, size) = match bytes[0] >> 4 { 4 => (12, 4), 6 => (8, 16), _ => panic!("non-IP frame") };
                            for i in 0..size { bytes.swap(offset + i, offset + size + i); }
                            // Swapping the pseudo-header addresses preserves IP
                            // and transport checksum sums, including ICMPv6.
                            tx.send(&bytes[..len]).await.unwrap();
                            batch += 1;
                            if batch == 32 { batch = 0; moto_sdk::async_runtime::yield_to_io().await; }
                        }
                    }.fuse();
                    let stopped = stopped.fuse();
                    futures::pin_mut!(reflect, stopped);
                    futures::select_biased! { stop = stopped => stop.unwrap(), _ = reflect => unreachable!() }
                };
                if orderly { device.unregister().await.unwrap(); }
            });
            done_tx.send(()).unwrap();
        });
        wait_ready.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            shutdown: Box::new(move |orderly| {
                stop.send(orderly).unwrap();
                done.recv_timeout(Duration::from_secs(5)).unwrap();
                thread.join().unwrap();
            }),
            observed,
        }
    }

    fn start_process() -> Self {
        use moto_sys::caps::{CAP_INTERACTIVE, CAP_NET, MOTOR_OS_CAPS_ENV_KEY};
        use std::io::{BufRead, BufReader};
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["ip-device-admission-child", "provider"])
            .env(
                MOTOR_OS_CAPS_ENV_KEY,
                format!("0x{:x}", CAP_INTERACTIVE | CAP_NET),
            )
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let (send, observed) = std::sync::mpsc::sync_channel(16);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let _ = send.try_send(line.unwrap().parse().unwrap());
            }
        });
        assert_eq!(observed.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
        Self {
            shutdown: Box::new(move |orderly| {
                assert!(!orderly);
                child.kill().unwrap();
                assert!(!child.wait().unwrap().success());
                reader.join().unwrap();
            }),
            observed,
        }
    }

    fn stop(self, orderly: bool) {
        (self.shutdown)(orderly);
    }
}

fn remote(local: IpAddr) -> IpAddr {
    match local {
        IpAddr::V4(ip) => {
            let mut bytes = ip.octets();
            bytes[3] = 2;
            Ipv4Addr::from(bytes).into()
        }
        IpAddr::V6(ip) => {
            let mut words = ip.segments();
            words[7] = 2;
            Ipv6Addr::from(words).into()
        }
    }
}

pub fn test_reflected_transport_and_removal() {
    let baseline = crate::tcp::read_sys_io_metric("net.num_devices");
    let provider = Provider::start(0);
    let mut streams = Vec::new();
    for local in config(0).addresses.into_iter().map(|cidr| cidr.address) {
        let peer = remote(local);
        let listener = std::net::TcpListener::bind(SocketAddr::new(local, 0)).unwrap();
        let mut stream = std::net::TcpStream::connect_timeout(
            &SocketAddr::new(peer, listener.local_addr().unwrap().port()),
            Duration::from_secs(2),
        )
        .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut accepted, from) = listener.accept().unwrap();
        assert_eq!(from.ip(), peer);
        accepted
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let data = [73; 2048];
        stream.write_all(&data).unwrap();
        let mut received = [0; 2048];
        accepted.read_exact(&mut received).unwrap();
        assert_eq!(received, data);
        accepted.write_all(&received).unwrap();
        stream.read_exact(&mut received).unwrap();
        assert_eq!(received, data);
        let reply = moto_sdk::sys_io::icmp::IcmpEchoClient::connect()
            .unwrap()
            .echo(peer, 9, 32, Duration::from_secs(2))
            .unwrap();
        assert_eq!(reply.source, peer);
        test_udp(local, peer);
        streams.push((stream, accepted, listener));
    }
    provider.stop(true);
    for (mut stream, mut accepted, _) in streams {
        for stream in [&mut stream, &mut accepted] {
            let error = stream.read(&mut [0]).unwrap_err();
            assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::NotConnected
                ),
                "{error:?}"
            );
        }
    }
    crate::tcp::wait_for_sys_io_metric("net.num_devices", |n| n == baseline);
    // Reusing a name requires a fresh registration channel and still works.
    Provider::start(0).stop(false);
    crate::tcp::wait_for_sys_io_metric("net.num_devices", |n| n == baseline);
    println!("ip_device::test_reflected_transport_and_removal PASS");
}

fn test_udp(local: IpAddr, peer: IpAddr) {
    use crate::net_harness::{bounded, bounded_output, host_channel};
    use moto_sdk::io::net::udp::UdpSocket;
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let (client, driver) = host_channel().await;
        let server = UdpSocket::bind_reserved(
            client.try_reserve().unwrap(),
            &SocketAddr::new(local, 0),
            None,
        )
        .await
        .unwrap();
        let destination = SocketAddr::new(peer, server.local_addr().port());
        let sender =
            UdpSocket::bind_for_remote_reserved(client.try_reserve().unwrap(), &destination, None)
                .await
                .unwrap();
        assert_eq!(sender.local_addr().ip(), local);
        let data = [92; 512];
        assert_eq!(sender.try_send_to(&data, &destination), Ok(data.len()));
        let mut buffer = [0; 512];
        let (len, from) = bounded_output(server.recv_from_future(&mut buffer, false), 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(len, data.len());
        assert_eq!(buffer, data);
        assert_eq!(from, SocketAddr::new(peer, sender.local_addr().port()));
        assert_eq!(server.try_send_to(&buffer, &from), Ok(buffer.len()));
        let (len, from) = bounded_output(sender.recv_from_future(&mut buffer, false), 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(len, data.len());
        assert_eq!(buffer, data);
        assert_eq!(from, destination);
        drop((server, sender));
        assert!(bounded(driver, 2).await);
    });
}

pub fn test_provider_death_wakes_pending_ops() {
    use crate::net_harness::{bounded_output, host_channel_on_thread};
    use moto_sdk::io::net::{
        tcp::{TcpListener, TcpStream},
        udp::UdpSocket,
    };

    let baseline = crate::tcp::read_sys_io_metric("net.num_devices");
    for (local, separate_process) in config(2)
        .addresses
        .into_iter()
        .flat_map(|cidr| [(cidr.address, false), (cidr.address, true)])
    {
        let provider = if separate_process {
            Provider::start_process()
        } else {
            Provider::start_mode(2, false)
        };
        let peer = remote(local);
        let probe = std::thread::spawn(move || {
            moto_sdk::sys_io::icmp::IcmpEchoClient::connect()
                .unwrap()
                .echo(peer, 10, 32, Duration::from_secs(5))
        });
        let (client, driver) = host_channel_on_thread();
        moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
            let listener = TcpListener::bind_reserved(
                client.try_reserve().unwrap(),
                &SocketAddr::new(local, 0),
                None,
                None,
            )
            .await
            .unwrap();
            listener.post_accept(client.try_reserve().unwrap());
            let accept = listener.accept();
            let destination = SocketAddr::new(peer, listener.socket_addr().port());
            let connect = TcpStream::connect_reserved(
                client.try_reserve().unwrap(),
                &destination,
                Some(Duration::from_secs(5)),
                None,
                None,
            );
            let udp = UdpSocket::bind_reserved(
                client.try_reserve().unwrap(),
                &SocketAddr::new(local, 0),
                None,
            )
            .await
            .unwrap();
            let mut bytes = [0; 64];
            let receive = udp.recv_from_future(&mut bytes, false);
            futures::pin_mut!(accept, connect, receive);
            assert!(futures::poll!(&mut accept).is_pending());
            assert!(futures::poll!(&mut connect).is_pending());
            assert!(futures::poll!(&mut receive).is_pending());

            // Seeing both packets proves the connect and probe reached the
            // device before its owner exits; the provider deliberately drops them.
            let until = std::time::Instant::now() + Duration::from_secs(2);
            let (mut syn, mut echo) = (false, false);
            while !syn || !echo {
                let protocol = provider
                    .observed
                    .recv_timeout(until.saturating_duration_since(std::time::Instant::now()))
                    .unwrap();
                syn |= protocol == 6;
                echo |= protocol == if local.is_ipv4() { 1 } else { 58 };
            }
            provider.stop(false);
            assert_eq!(
                bounded_output(connect, 2).await.unwrap().err(),
                Some(moto_rt::E_NOT_CONNECTED)
            );
            assert_eq!(
                bounded_output(accept, 2).await.unwrap().err(),
                Some(moto_rt::E_NOT_CONNECTED)
            );
            assert_eq!(
                bounded_output(receive, 2).await.unwrap(),
                Err(moto_rt::E_NOT_CONNECTED)
            );
            assert_eq!(
                udp.try_send_to(&[1], &destination),
                Err(moto_rt::E_NOT_CONNECTED)
            );
            assert_eq!(bounded_output(udp.writable(), 2).await, Some(()));
        });
        client.request_shutdown();
        driver.join().unwrap();
        assert_eq!(
            probe.join().unwrap().err(),
            Some(moto_rt::Error::NotConnected)
        );
        crate::tcp::wait_for_sys_io_metric("net.num_devices", |n| n == baseline);
    }
    println!("ip_device::test_provider_death_wakes_pending_ops PASS");
}

pub fn test_multiple_devices_and_wildcard_listener() {
    use crate::tcp::{read_sys_io_metric as metric, wait_for_sys_io_metric as wait};
    let slots = metric("net.device_slots");
    let bytes = metric("net.device_slot_bytes");
    let buffers = metric("net.ip_device.buffer_bytes");
    let devices = metric("net.num_devices");
    // Wildcard port zero is unsupported; acquire a free loopback port first.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let listener = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap();
    let first = Provider::start(0);
    let other = Provider::start(1);
    assert_eq!(metric("net.device_slots"), slots + 2);
    assert_eq!(metric("net.ip_device.devices"), 2);
    assert!(metric("net.ip_device.buffer_bytes") > buffers);
    for address in ["10.242.0.2", "10.242.1.2"] {
        wildcard_exchange(&listener, address.parse().unwrap());
    }
    first.stop(true);
    wildcard_exchange(&listener, "10.242.1.2".parse().unwrap());
    wildcard_exchange(&listener, Ipv4Addr::LOCALHOST.into());
    let replacement = Provider::start(0);
    assert_eq!(metric("net.device_slots"), slots + 3);
    wildcard_exchange(&listener, "10.242.0.2".parse().unwrap());
    replacement.stop(true);
    other.stop(false);
    wait("net.ip_device.devices", |n| n == 0);
    wait("net.ip_device.buffer_bytes", |n| n == buffers);
    assert_eq!(metric("net.num_devices"), devices);
    for n in 0..8 {
        Provider::start(0).stop(n % 2 == 0);
        wait("net.ip_device.devices", |n| n == 0);
        wait("net.ip_device.buffer_bytes", |n| n == buffers);
    }
    assert_eq!(metric("net.device_slots"), slots + 11);
    assert!(metric("net.device_slot_bytes") >= bytes);
    wildcard_exchange(&listener, Ipv4Addr::LOCALHOST.into());
    println!("ip_device::test_multiple_devices_and_wildcard_listener PASS");
}

fn wildcard_exchange(listener: &std::net::TcpListener, peer: IpAddr) {
    let mut stream = std::net::TcpStream::connect_timeout(
        &SocketAddr::new(peer, listener.local_addr().unwrap().port()),
        Duration::from_secs(2),
    )
    .unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    for socket in [&stream, &accepted] {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    stream.write_all(b"device").unwrap();
    let mut buffer = [0; 6];
    accepted.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, b"device");
    accepted.write_all(&buffer).unwrap();
    stream.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, b"device");
}
