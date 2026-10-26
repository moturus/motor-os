//! Isolated native network runtimes for device-lifetime regressions.
use super::*;
use crate::self_test::{SelfTest, st_assert, st_assert_eq};
use futures::FutureExt;
use moto_sdk::ipc::io_channel::{self, Msg};

pub(super) const TESTS: &[SelfTest] = &[
    (
        "net::removal_waits_for_unpolled_tasks",
        removal_waits_for_unpolled_tasks,
    ),
    (
        "net::removal_with_pending_replies",
        removal_with_pending_replies,
    ),
];

fn runtime() -> std::result::Result<NetRuntime, String> {
    let fs = crate::runtime::fs::self_test::runtime().map_err(|error| error.to_string())?;
    let stats = Rc::new(stats::NetStats::default());
    Ok(NetRuntime {
        inner: Rc::new(RefCell::new(NetRuntimeInner {
            next_socket_id: 1,
            sockets: HashMap::new(),
            tcp_listeners: HashMap::new(),
            devices: Default::default(),
            ip_addresses: HashMap::new(),
            dns_servers: Vec::new(),
            vsock: vsock::VsockRuntime::new(None),
            clients: HashMap::new(),
        })),
        half_open: Rc::new(HalfOpenBudget::new(
            16.try_into().unwrap(),
            8.try_into().unwrap(),
        )),
        backlog: Rc::new(backlog::BacklogBudget::new(
            stats.clone(),
            32.try_into().unwrap(),
            16.try_into().unwrap(),
        )),
        completed: Rc::new(completed::CompletedBacklog::new(
            stats.clone(),
            16.try_into().unwrap(),
            8.try_into().unwrap(),
        )),
        pressure: Rc::new(pressure::Pressure::new(
            stats.clone(),
            fs.free_caches.clone(),
        )),
        stats,
        orphan_lingers: Rc::new(Cell::new(0)),
        fs: fs.root_fs(),
        dns_write_lock: Rc::new(moto_sdk::async_runtime::LocalMutex::new(())),
        channel_budget: Default::default(),
    })
}

fn add_device(runtime: &NetRuntime, name: &str, address: &str) -> usize {
    let config: config::NetConfig =
        toml::from_str("auto_icmp_echo_reply = false\nloopback = true\n[devices]\n").unwrap();
    let mut cfg = config::DeviceCfg::new("02:00:00:00:00:01");
    cfg.cidrs.push(address.parse().unwrap());
    let device = device::NetDev::new(
        name,
        &cfg,
        &config,
        device::NetstackDevice::Loopback(moto_netstack::phy::Loopback::new(
            moto_netstack::phy::Medium::Ip,
        )),
    );
    let index = runtime.inner.borrow_mut().devices.push(device);
    runtime
        .stats
        .num_devices
        .set(runtime.stats.num_devices.get() + 1);
    runtime.rebuild_ip_addresses();
    runtime.spawn_device_runtime(index);
    index
}

fn removal_waits_for_unpolled_tasks() -> std::result::Result<(), String> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let runtime = runtime()?;
        let index = add_device(&runtime, "wg0", "10.21.0.1/24");
        let life = Rc::downgrade(&runtime.inner.borrow().devices[index].device_runtime_notify);
        let notify = life.upgrade().unwrap();
        let started = Rc::new(Cell::new(false));
        let started_task = started.clone();
        let (resume, resumed) = moto_sdk::async_runtime::oneshot();
        let (done, completed) = moto_sdk::async_runtime::oneshot();
        runtime.spawn_device_task(index, async move {
            started_task.set(true);
            resumed.await.unwrap();
            done.send(()).unwrap();
        });
        st_assert!(!started.get());
        st_assert_eq!(runtime.inner.borrow().devices[index].pending_tasks, 2);
        st_assert!(runtime.inner.borrow_mut().devices.retire(index));
        runtime.inner.borrow_mut().devices.finish_removal(index);
        st_assert!(life.upgrade().is_some());

        let rejected = Rc::new(());
        let captured = rejected.clone();
        runtime.spawn_device_task(index, async move { drop(captured) });
        st_assert_eq!(Rc::strong_count(&rejected), 1);
        resume.send(()).unwrap();
        completed.await.unwrap();
        st_assert!(started.get());
        loop {
            let changed = notify.notified();
            if runtime
                .inner
                .borrow_mut()
                .devices
                .retained_mut(index)
                .is_none()
            {
                break;
            }
            changed.await;
        }
        drop(notify);
        st_assert!(life.upgrade().is_none());
        Ok(())
    })
}

fn removal_with_pending_replies() -> std::result::Result<(), String> {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let runtime = runtime()?;
        let first = add_device(&runtime, "wg0", "10.21.0.1/24");
        let listener = io_channel::listen("sys_io_net_removal_self_test");
        let client = io_channel::ClientConnection::connect("sys_io_net_removal_self_test").unwrap();
        let (sender, _receiver) = listener.await.unwrap();
        let sender = runtime.channel_budget.admit_net(sender).ok().unwrap();
        runtime.inner.borrow_mut().clients.insert(
            sender.remote_handle(),
            ClientConnection::new(sender.clone(), u64::MAX),
        );
        runtime.stats.active_clients.set(1);

        for address in ["0.0.0.0:1234", "10.21.0.1:1235"] {
            tcp_listener::TcpListener::bind(
                &runtime,
                api_net::bind_tcp_listener_request(&address.parse().unwrap(), Some(1)),
                &sender,
            )
            .await
            .unwrap();
        }
        let wildcard = client.recv().unwrap().handle;
        let explicit = client.recv().unwrap().handle;
        let other = add_device(&runtime, "wg1", "10.22.0.1/24");
        st_assert!(
            runtime.inner.borrow().tcp_listeners[&wildcard]
                .borrow()
                .has_device(other)
        );
        let mut accept = api_net::accept_tcp_listener_request(explicit, 0xffff);
        accept.id = 91;
        tcp_listener::TcpListener::accept(&runtime, accept, &sender)
            .await
            .unwrap();

        let mut connect =
            api_net::tcp_stream_connect_request(&"10.21.0.2:1234".parse().unwrap(), 0);
        connect.id = 93;
        MotoSocket::tcp_connect(&runtime, connect, &sender)
            .await
            .unwrap();

        for _ in 0..io_channel::QUEUE_SIZE {
            st_assert_eq!(sender.send(Msg::new()).now_or_never(), Some(Ok(())));
        }
        st_assert!(sender.send(Msg::new()).now_or_never().is_none());
        let mut request = Msg::new();
        request.command = NetCmd::UdpSocketBind as u16;
        request.id = 92;
        api_net::put_socket_addr(&mut request.payload, &"10.21.0.1:0".parse().unwrap());
        let bind = MotoSocket::udp_bind(&runtime, request, &sender);
        futures::pin_mut!(bind);
        st_assert!(futures::poll!(&mut bind).is_pending());

        let mut ping = api_net::icmp_echo_request(
            "10.21.0.2".parse().unwrap(),
            1,
            16,
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        ping.id = 94;
        let probe = icmp::echo(&runtime, ping, &sender);
        futures::pin_mut!(probe);
        st_assert_eq!(
            futures::poll!(&mut probe).map(|result| result.map_err(|err| err.kind())),
            std::task::Poll::Pending
        );

        let life = Rc::downgrade(&runtime.inner.borrow().devices[first].device_runtime_notify);
        let removal = runtime.remove_device(first);
        futures::pin_mut!(removal);
        st_assert!(futures::poll!(&mut removal).is_pending());
        st_assert!(runtime.find_route(&"10.21.0.2".parse().unwrap()).is_none());
        st_assert!(runtime.inner.borrow().devices.get(first).is_none());
        st_assert!(life.upgrade().is_some());
        st_assert!(!runtime.inner.borrow().tcp_listeners.contains_key(&explicit));
        for _ in 0..io_channel::QUEUE_SIZE {
            client.recv().unwrap();
        }
        bind.await.unwrap();
        st_assert!(futures::poll!(&mut removal).is_pending());
        let bound = client.recv().unwrap();
        st_assert_eq!(bound.id, 92);
        let mut seen = [false; 3];
        for _ in 0..3 {
            let message = client.recv().unwrap();
            if message.id == 91 {
                st_assert!(!seen[0]);
                seen[0] = true;
                st_assert_eq!(message.status, moto_rt::E_NOT_CONNECTED);
            } else if message.id == 93 {
                st_assert!(!seen[1]);
                seen[1] = true;
                st_assert_eq!(message.status, moto_rt::E_NOT_CONNECTED);
            } else {
                st_assert!(!seen[2]);
                seen[2] = true;
                st_assert_eq!(message.command, NetCmd::EvtUdpSocketInvalidated as u16);
                st_assert_eq!(message.handle, bound.handle);
            }
        }
        st_assert!(seen.into_iter().all(|seen| seen));
        st_assert_eq!(runtime.stats.udp_sockets.get(), 0);
        st_assert!(life.upgrade().is_some());
        st_assert_eq!(probe.await.unwrap_err().kind(), ErrorKind::NotConnected);
        removal.await;
        st_assert!(life.upgrade().is_none());
        st_assert_eq!(
            runtime.find_route(&"10.22.0.2".parse().unwrap()),
            Some((other, "10.22.0.1".parse().unwrap()))
        );
        let replacement = add_device(&runtime, "wg0", "10.21.0.1/24");
        st_assert!(replacement > other);
        runtime.remove_device(replacement).await;
        runtime.remove_device(other).await;
        runtime.on_connection_done(sender.remote_handle()).await;
        st_assert_eq!(runtime.stats.tcp_listening_sockets.get(), 0);
        st_assert_eq!(runtime.stats.tcp_sockets.get(), 0);
        st_assert!(runtime.inner.borrow().sockets.is_empty());
        Ok(())
    })
}
