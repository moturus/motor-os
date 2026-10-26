//! Isolated native network runtimes for device-lifetime regressions.
use super::*;
use crate::self_test::{SelfTest, st_assert, st_assert_eq};

pub(super) const TESTS: &[SelfTest] = &[
    (
        "net::removal_waits_for_unpolled_tasks",
        removal_waits_for_unpolled_tasks,
    ),
    (
        "net::invalidation_waits_for_bind_reply",
        invalidation_waits_for_bind_reply,
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

fn invalidation_waits_for_bind_reply() -> std::result::Result<(), String> {
    use futures::FutureExt;
    use moto_sdk::ipc::io_channel::{self, Msg};

    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let runtime = runtime()?;
        let index = add_device(&runtime, "wg0", "10.21.0.1/24");
        let listener = io_channel::listen("sys_io_socket_invalidation_self_test");
        let client =
            io_channel::ClientConnection::connect("sys_io_socket_invalidation_self_test").unwrap();
        let (sender, _receiver) = listener.await.unwrap();
        let sender = runtime.channel_budget.admit_net(sender).ok().unwrap();
        runtime.inner.borrow_mut().clients.insert(
            sender.remote_handle(),
            ClientConnection::new(sender.clone(), u64::MAX),
        );
        runtime.stats.active_clients.set(1);
        let mut connect =
            api_net::tcp_stream_connect_request(&"10.21.0.2:1234".parse().unwrap(), 0);
        connect.id = 93;
        MotoSocket::tcp_connect(&runtime, connect, &sender)
            .await
            .unwrap();
        for _ in 0..io_channel::QUEUE_SIZE {
            st_assert_eq!(sender.send(Msg::new()).now_or_never(), Some(Ok(())));
        }
        let mut request = api_net::bind_udp_socket_request(&"10.21.0.1:0".parse().unwrap(), 0);
        request.id = 92;
        let bind = MotoSocket::udp_bind(&runtime, request, &sender);
        futures::pin_mut!(bind);
        st_assert!(futures::poll!(&mut bind).is_pending());

        st_assert!(runtime.inner.borrow_mut().devices.retire(index));
        let sockets: Vec<_> = runtime.inner.borrow().sockets.values().cloned().collect();
        let mut notices = Vec::new();
        for socket in sockets {
            notices.push(MotoSocket::invalidate_ip_socket(socket).await.unwrap());
        }
        let notices = futures::future::join_all(notices.into_iter().map(|notice| notice.send()));
        futures::pin_mut!(notices);
        st_assert!(futures::poll!(&mut notices).is_pending());
        st_assert_eq!(runtime.stats.udp_sockets.get(), 0);
        st_assert_eq!(runtime.stats.tcp_sockets.get(), 0);
        for _ in 0..io_channel::QUEUE_SIZE {
            client.recv().unwrap();
        }
        // The terminal UDP notice must wait for this successful creation reply.
        bind.await.unwrap();
        let mut seen_bind = false;
        let mut seen_closed = false;
        let mut seen_connect = false;
        notices.await;
        for _ in 0..3 {
            let message = client.recv().unwrap();
            if message.id == 92 {
                st_assert!(!seen_bind);
                st_assert_eq!(message.status, moto_rt::E_OK);
                seen_bind = true;
            } else if message.id == 93 {
                st_assert!(!seen_connect);
                st_assert_eq!(message.status, moto_rt::E_NOT_CONNECTED);
                seen_connect = true;
            } else {
                st_assert!(seen_bind && !seen_closed);
                st_assert_eq!(message.command, NetCmd::EvtUdpSocketInvalidated as u16);
                seen_closed = true;
            }
        }
        st_assert!(seen_bind && seen_connect && seen_closed);
        runtime.inner.borrow_mut().devices.finish_removal(index);
        runtime.on_connection_done(sender.remote_handle()).await;
        Ok(())
    })
}
