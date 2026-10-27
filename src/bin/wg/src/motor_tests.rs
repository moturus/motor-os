//! Native coverage of the production adapter using the SDK's test notification.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;
use std::time::Duration;

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn transport_invalidation(address: &str) {
    let address: std::net::IpAddr = address.parse().unwrap();
    LocalRuntime::new().block_on(async {
        let (client, driver) = moto_sdk::io::net::connect().await.unwrap();
        let anchor = client.try_reserve().unwrap();
        let driver = LocalRuntime::spawn(driver.run());
        let ready = Arc::new(Ready::default());
        let socket = UdpSocket::bind_physical_reserved(
            client.try_reserve().unwrap(),
            &SocketAddr::new(address, 0),
            Some(ready.clone()),
        )
        .await
        .unwrap();
        let config = Config {
            name: "wg_invalidation_test".into(),
            private_key: [7; 32],
            transport_addresses: vec![address],
            listen_port: socket.local_addr().port(),
            cidrs: vec!["10.249.0.2/32".parse().unwrap()],
            peers: vec![crate::config::Peer {
                public_key: [9; 32],
                preshared_key: None,
                endpoint: None,
                allowed_ips: vec!["10.249.0.1/32".parse().unwrap()],
                persistent_keepalive: None,
            }],
        };
        let device = IpDevice::register(&Registration {
            name: config.name.clone(),
            mtu: MTU as u16,
            addresses: vec![Cidr {
                address: "10.249.0.2".parse().unwrap(),
                prefix_len: 32,
            }],
            routes: vec![Cidr {
                address: "10.249.0.1".parse().unwrap(),
                prefix_len: 32,
            }],
        })
        .await
        .unwrap();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut stats = stats::Stats::start(&config, "/user/cfg/wireguard/invalidation.toml");
        {
            let mut forwarding = std::pin::pin!(forward(
                device,
                Scheduler::new(&config, Instant::now()).unwrap(),
                vec![socket.clone()],
                queue::Queue::new().unwrap(),
                ready,
                &mut stats,
            ));
            assert!(forwarding.as_mut().poll(&mut cx).is_pending());
            let before = wakes.0.load(Ordering::Relaxed);
            let handles = client.udp_handles_for_test();
            assert_eq!(handles.len(), 1);
            // Dispatch the same terminal event emitted on physical address loss.
            // The adapter must wake while idle, report failure and close its device.
            client.invalidate_udp_for_test(handles[0]);
            assert!(wakes.0.load(Ordering::Relaxed) > before);
            assert_eq!(
                forwarding.as_mut().poll(&mut cx),
                Poll::Ready(Err("physical UDP binding failed")),
            );
        }
        assert_eq!(
            socket.try_send_to(&[1], socket.local_addr()),
            Err(moto_sdk::rt::E_NOT_CONNECTED)
        );
        drop((socket, anchor));
        let mut driver = std::pin::pin!(driver);
        let mut deadline = std::pin::pin!(async_runtime::sleep(Duration::from_secs(2)));
        std::future::poll_fn(|cx| {
            if driver.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            assert!(
                deadline.as_mut().poll(cx).is_pending(),
                "transport driver did not retire"
            );
            Poll::Pending
        })
        .await;
    });

    let sys_io = moto_sdk::stats::ProviderInfo {
        id: moto_sdk::sys::stats::PID_SYS_IO,
        name: "sys-io".into(),
        url: "sys-io-stats".into(),
    };
    let metric = moto_sdk::stats::Collector::describe(&sys_io)
        .unwrap()
        .into_iter()
        .find(|metric| metric.name == "net.ip_device.devices")
        .unwrap()
        .id;
    let deadline = Instant::now() + Duration::from_secs(2);
    while moto_sdk::stats::Collector::read(&sys_io, metric, moto_sdk::stats::SCOPE_GLOBAL).unwrap()
        != 0
    {
        assert!(
            Instant::now() < deadline,
            "packet device did not retire after fatal transport exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    println!("wg native transport invalidation {address} PASS");
}
