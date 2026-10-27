//! Device admission and publication on the single-threaded net runtime.
use super::*;
use futures::Stream;
use moto_sdk::sys_io::api_ip_device::Registration;
use moto_sdk::{
    ipc::io_channel::{self, Msg},
    sys_io::api_ip_device,
};

const MAX_DEVICES: usize = 4;

impl NetRuntime {
    pub(super) async fn serve_packet_provider(
        &self,
        first: Msg,
        sender: &channel_budget::ClientSender,
        receiver: io_channel::Receiver,
    ) {
        let role = moto_sys::caps::ProcessRole::from_caps(
            self.inner.borrow().clients[&sender.remote_handle()].capabilities,
        );
        if role == moto_sys::caps::ProcessRole::None
            || self.connection_pid(sender.remote_handle()) == 0
        {
            let _ = sender.send(reply(&first, moto_rt::E_NOT_ALLOWED)).await;
            return;
        }
        if first.id != 1 {
            let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
            return;
        }
        let framing = (|| {
            let length = api_ip_device::page_length(&first)?;
            let page = sender.get_remote_page(first.payload.shared_pages()[11])?;
            Ok::<_, moto_rt::Error>((length, page))
        })();
        let registration = if let Ok((length, page)) = framing {
            let mut bytes = [0; io_channel::PAGE_SIZE];
            bytes[..length].copy_from_slice(&page.bytes()[..length]);
            drop(page);
            Registration::decode(&bytes[..length])
        } else {
            let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
            return;
        };
        let registration = match registration {
            Ok(registration) => registration,
            Err(error) => {
                let _ = sender.send(reply(&first, error.into())).await;
                return;
            }
        };
        let (index, packet) = match self.register_packet_device(registration).await {
            Ok(device) => device,
            Err(error) => {
                let _ = sender
                    .send(reply(
                        &first,
                        crate::util::map_err_into_native(error).into(),
                    ))
                    .await;
                return;
            }
        };
        let terminal = if sender.send(reply(&first, moto_rt::E_OK)).await.is_ok() {
            // Both directions keep progressing when the other's ring or page
            // pool fills. Leaving this scope drops in-flight page guards first.
            transfer_packets(sender, receiver, &packet).await
        } else {
            None
        };
        drop(packet);
        self.remove_device(index).await;
        if let Some(terminal) = terminal {
            let _ = sender.send(reply(&terminal, moto_rt::E_OK)).await;
        }
    }

    pub(super) async fn register_packet_device(
        &self,
        registration: Registration,
    ) -> Result<(usize, packet_device::PacketDevice)> {
        registration
            .validate()
            .map_err(crate::util::map_native_error)?;
        self.pressure.admit()?;
        let mut cfg = config::DeviceCfg {
            mac: None,
            dhcp: false,
            cidrs: Vec::new(),
            routes: Vec::new(),
            dns_servers: Vec::new(),
        };
        cfg.cidrs
            .try_reserve_exact(registration.addresses.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        cfg.routes
            .try_reserve_exact(registration.routes.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        cfg.cidrs.extend(
            registration
                .addresses
                .iter()
                .map(|cidr| IpNetwork::new(cidr.address, cidr.prefix_len).unwrap()),
        );
        cfg.routes
            .extend(registration.routes.iter().map(|cidr| config::IpRoute {
                ip_network: IpNetwork::new(cidr.address, cidr.prefix_len).unwrap(),
                gateway: None,
            }));
        let mut listeners = Vec::new();
        {
            let mut inner = self.inner.borrow_mut();
            if inner.devices.packet_count() >= MAX_DEVICES {
                return Err(ErrorKind::OutOfMemory.into());
            }
            for (_, device) in inner.devices.iter() {
                if device.name() == registration.name {
                    return Err(ErrorKind::AlreadyExists.into());
                }
                if device.is_packet()
                    && cfg.routes.iter().any(|route| {
                        device
                            .config()
                            .routes
                            .iter()
                            .any(|existing| existing.ip_network == route.ip_network)
                    })
                {
                    return Err(ErrorKind::AddrInUse.into());
                }
            }
            if cfg
                .cidrs
                .iter()
                .any(|cidr| inner.ip_addresses.contains_key(&cidr.ip()))
            {
                return Err(ErrorKind::AddrInUse.into());
            }
            inner.devices.prepare_push()?;
            inner
                .ip_addresses
                .try_reserve(cfg.cidrs.len())
                .map_err(|_| ErrorKind::OutOfMemory)?;
            listeners
                .try_reserve_exact(inner.tcp_listeners.len())
                .map_err(|_| ErrorKind::OutOfMemory)?;
            listeners.extend(inner.tcp_listeners.values().cloned());
        }
        // An explicit listener with a withdrawn address can coexist with a
        // wildcard until that address returns. Refuse conflicting expansion.
        let mut ports = HashSet::new();
        ports
            .try_reserve(listeners.len())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        for address in &registration.addresses {
            ports.clear();
            for listener in &listeners {
                let listener = listener.borrow();
                if listener.accepts_address(address.address) && !ports.insert(listener.port()) {
                    return Err(ErrorKind::AddrInUse.into());
                }
            }
        }
        let packet =
            packet_device::PacketDevice::new(registration.mtu as usize, self.stats.clone())?;
        let device = device::NetDev::try_new(
            registration.name,
            cfg,
            self.interface_policy,
            device::NetstackDevice::Packet(packet.clone()),
        )?;
        let index = {
            let mut inner = self.inner.borrow_mut();
            let index = inner.devices.push(device);
            for address in &registration.addresses {
                inner.ip_addresses.insert(address.address, index);
            }
            index
        };
        self.stats.num_devices.set(self.stats.num_devices.get() + 1);
        // No await can expose the temporary tables. A failure withdraws them
        // before yielding to any tasks spawned by listener construction.
        for address in &registration.addresses {
            for listener in &listeners {
                if let Err(error) =
                    tcp_listener::TcpListener::try_add_address(listener, address.address, index)
                {
                    drop(listeners);
                    drop(packet);
                    self.remove_device_inner(index, false).await;
                    return Err(error);
                }
            }
        }
        self.spawn_device_runtime(index);
        Ok((index, packet))
    }
}

fn reply(request: &Msg, status: moto_rt::ErrorCode) -> Msg {
    let mut msg = Msg::new();
    msg.id = request.id;
    msg.command = request.command;
    msg.status = status;
    msg
}

async fn transfer_packets(
    sender: &channel_budget::ClientSender,
    mut receiver: io_channel::Receiver,
    packet: &packet_device::PacketDevice,
) -> Option<Msg> {
    use core::task::Poll;
    enum Event {
        Received(moto_rt::Result<Msg>),
        Sent(moto_rt::Result<()>),
    }
    // The stream retains a pending send and its token/page when input wins.
    // One outer loop owns the I/O yield: sibling futures must not request
    // multiple runtime I/O turns during one executor poll.
    let outgoing = futures::stream::unfold((), |_| async {
        Some((send_packet(sender, packet).await, ()))
    });
    futures::pin_mut!(outgoing);
    let mut prefer_rx = true;
    let mut batch = 0;
    loop {
        let event = core::future::poll_fn(|cx| {
            for rx in [prefer_rx, !prefer_rx] {
                if rx {
                    if let Poll::Ready(result) = receiver.poll_recv(cx) {
                        return Poll::Ready(Event::Received(result));
                    }
                } else if let Poll::Ready(Some(result)) = outgoing.as_mut().poll_next(cx) {
                    return Poll::Ready(Event::Sent(result));
                }
            }
            Poll::Pending
        })
        .await;
        match event {
            Event::Sent(Ok(())) => prefer_rx = true,
            Event::Sent(Err(_)) | Event::Received(Err(_)) => return None,
            Event::Received(Ok(msg)) => {
                prefer_rx = false;
                match receive_packet(&receiver, packet, msg) {
                    Ok(Some(terminal)) => return Some(terminal),
                    Ok(None) => {}
                    Err(_) => {
                        let _ = moto_sys::SysCpu::kill_remote(sender.remote_handle());
                        return None;
                    }
                }
            }
        }
        batch += 1;
        if batch == 32 {
            batch = 0;
            moto_sdk::async_runtime::yield_to_io().await;
        }
    }
}

fn receive_packet(
    receiver: &io_channel::Receiver,
    packet: &packet_device::PacketDevice,
    msg: Msg,
) -> moto_rt::Result<Option<Msg>> {
    if msg.command == NetCmd::IpDeviceUnregister.as_u16()
        && msg.id == 2
        && msg.handle == 0
        && msg.flags == 0
        && msg.wake_handle == 0
        && msg.payload.args_8().iter().all(|byte| *byte == 0)
    {
        return Ok(Some(msg));
    }
    if msg.command != NetCmd::IpDevicePacket.as_u16() || msg.id != 0 {
        return Err(moto_rt::Error::InvalidArgument);
    }
    let length = api_ip_device::page_length(&msg)?;
    let page = receiver.get_remote_page(msg.payload.shared_pages()[11])?;
    packet.submit(&page.bytes()[..length]);
    Ok(None)
}

async fn send_packet(
    sender: &channel_budget::ClientSender,
    packet: &packet_device::PacketDevice,
) -> moto_rt::Result<()> {
    loop {
        let ready = packet.tx_ready.notified();
        let Some(outbound) = packet.take_outbound() else {
            ready.await;
            continue;
        };
        let page = sender.alloc_page(u64::MAX).await?;
        page.bytes_mut()[..outbound.bytes().len()].copy_from_slice(outbound.bytes());
        let page = io_channel::IoPage::into_u16(page);
        let msg = api_ip_device::page_message(NetCmd::IpDevicePacket, page, outbound.bytes().len())
            .unwrap();
        sender.send_with_owned_page(msg, page).await?;
        return Ok(());
    }
}

#[cfg(debug_assertions)]
#[path = "registration_tests.rs"]
pub(crate) mod self_test;
