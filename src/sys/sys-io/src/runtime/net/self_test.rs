//! Isolated native network runtimes for device-lifetime regressions.
use super::*;
use crate::self_test::{SelfTest, st_assert, st_assert_eq};

pub(super) const TESTS: &[SelfTest] = &[(
    "net::removal_waits_for_unpolled_tasks",
    removal_waits_for_unpolled_tasks,
)];

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
