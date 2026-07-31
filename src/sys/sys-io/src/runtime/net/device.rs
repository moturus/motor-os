//! This is mostly plumbing moto-netstack into our async runtime.
use std::{
    cell::RefCell,
    collections::VecDeque,
    io::ErrorKind,
    mem::ManuallyDrop,
    net::{IpAddr, SocketAddr},
    rc::Rc,
};

use super::config;
use super::stats::NetStats;
use virtio_async::virtio_net::NetDevice;
use virtio_async::virtio_net::RxMeta;

use moto_tooling::iobuf::IoBuf;

// Received frames travel with the per-frame metadata their virtio-net header
// carried; today that is the L4 checksum verdict the netstack honors.
type RxQueue = Rc<RefCell<VecDeque<(IoBuf, RxMeta)>>>;
// Egress packets travel with their TSO segment size (0 = a regular
// MTU-bounded packet; nonzero = a TCP super-segment the device splits).
type TxQueue = Rc<RefCell<VecDeque<(IoBuf, u16)>>>;

/// Max TCP payload of one TSO super-segment we ask moto-netstack to emit.
/// Bounded by BIG_BUF_SIZE minus headers; 60K leaves comfortable room
/// (the IPv4 total-length field caps a packet at 65535 anyway).
const TSO_MAX_PAYLOAD: usize = 60 * 1024;

const SMALL_BUF_SIZE: usize = 2048; // RX buffers + MTU-sized TX packets.
const BIG_BUF_SIZE: usize = 65536; // TSO TX super-segments.

#[derive(Default, Clone)]
struct BufCache {
    small: Rc<RefCell<Vec<IoBuf>>>,
    big: Rc<RefCell<Vec<IoBuf>>>,
}

impl BufCache {
    /// `None` when `len` exceeds the largest pooled buffer, or when the
    /// allocation fails. Both are for the caller to recover from: a device
    /// buffer is not worth aborting every connection on the machine for.
    fn pop_buf(&self, len: usize) -> Option<IoBuf> {
        let (pool, size) = if len <= SMALL_BUF_SIZE {
            (&self.small, SMALL_BUF_SIZE)
        } else if len <= BIG_BUF_SIZE {
            (&self.big, BIG_BUF_SIZE)
        } else {
            return None;
        };
        pool.borrow_mut()
            .pop()
            .map(|mut buf| {
                buf.set_len(size);
                buf
            })
            .or_else(|| IoBuf::new_from_size_align(size))
    }

    fn push_buf(&self, buf: IoBuf) {
        if buf.capacity() <= SMALL_BUF_SIZE {
            self.small.borrow_mut().push(buf);
        } else {
            self.big.borrow_mut().push(buf);
        }
    }
}

pub(super) struct VirtioDevice {
    inner: Rc<NetDevice>,
    rx_queue: RxQueue,
    tx_queue: TxQueue,

    // The device will notify rx_notify when it updates rx_queue.
    rx_notify: Rc<moto_async::LocalNotify>,
    // The device will listen on tx_notify for tx_queue updates.
    tx_notify: Rc<moto_async::LocalNotify>,
    mtu: u16,
    csum_offload: bool,
    tso: bool,

    buf_cache: BufCache,
}

impl VirtioDevice {
    pub(super) fn new(inner: Rc<NetDevice>, stats: Rc<NetStats>) -> Self {
        let mtu = inner.mtu().unwrap_or(1536);
        let csum_offload = inner.csum_offload();
        let tso = inner.tso();
        let this = Self {
            inner,
            rx_queue: Default::default(),
            tx_queue: Default::default(),
            rx_notify: Default::default(),
            tx_notify: Default::default(),
            mtu,
            csum_offload,
            tso,
            buf_cache: Default::default(),
        };

        let _ = moto_async::LocalRuntime::spawn(Self::rx_task(
            this.inner.clone(),
            this.rx_queue.clone(),
            this.rx_notify.clone(),
            this.buf_cache.clone(),
            stats.clone(),
        ));
        let _ = moto_async::LocalRuntime::spawn(Self::tx_task(
            this.inner.clone(),
            this.tx_queue.clone(),
            this.tx_notify.clone(),
            this.buf_cache.clone(),
            stats,
        ));

        this
    }

    async fn rx_task(
        net_dev: Rc<NetDevice>,
        rx_queue: RxQueue,
        rx_notify: Rc<moto_async::LocalNotify>,
        buf_cache: BufCache,
        stats: Rc<NetStats>,
    ) {
        // Submit RX buffers to net_dev. Wait. Once RX happens, push
        // the buffer into rx_queue, notify. Once RX buffer is consumed,
        // push it again into net_dev.

        // TODO: optimize.

        let rxq_sz = net_dev.rxq_sz() as usize;

        // Pre-submit blocks.
        let mut completions = VecDeque::with_capacity(rxq_sz);
        for _ in 0..rxq_sz {
            let Some(buf) = buf_cache.pop_buf(SMALL_BUF_SIZE) else {
                log::error!("NET: RX: could not allocate a receive buffer.");
                break;
            };
            completions.push_back(net_dev.clone().post_read(buf).await);
        }

        #[cfg(debug_assertions)]
        {
            log::debug!(
                "\n\nNET: RX: current task: {}",
                moto_async::current_task_id()
            );
            moto_async::debug_current_task(true);
        }

        loop {
            let Some(completion) = completions.pop_front() else {
                // Nothing is posted, so no completion can ever arrive. A
                // receive path that is logged as dead beats an abort that
                // takes every other device and socket with it.
                log::error!("NET: RX: no posted buffers left; RX stopped.");
                return;
            };
            log::debug!("NET: RX: waiting for completion");
            let (packet, result) = completion.await;

            // A failed or rejected completion carries no data and its buffer
            // keeps the length we posted it with, so re-post that buffer
            // itself. The driver logs why it rejected the frame; the counter
            // is what makes a misbehaving device visible from outside.
            let next_buf = match result {
                Err(err) => {
                    log::error!("NET: RX: completion failed: {err:?}.");
                    stats
                        .device_rx_dropped
                        .set(stats.device_rx_dropped.get() + 1);
                    packet
                }
                Ok(meta) => {
                    log::debug!("NET: RX {} bytes.", packet.len());
                    stats
                        .device_rx_packets
                        .set(stats.device_rx_packets.get() + 1);
                    stats
                        .device_rx_bytes
                        .set(stats.device_rx_bytes.get() + packet.len() as u64);
                    rx_queue.borrow_mut().push_back((packet, meta));
                    rx_notify.notify_one();

                    let Some(buf) = buf_cache.pop_buf(SMALL_BUF_SIZE) else {
                        // One fewer buffer in flight; the queue keeps working.
                        log::error!("NET: RX: could not allocate a receive buffer.");
                        continue;
                    };
                    buf
                }
            };

            log::debug!("NET: RX: posting read");
            completions.push_back(net_dev.clone().post_read(next_buf).await);
        }
    }

    async fn tx_task(
        net_dev: Rc<NetDevice>,
        tx_queue: TxQueue,
        tx_notify: Rc<moto_async::LocalNotify>,
        buf_cache: BufCache,
        stats: Rc<NetStats>,
    ) {
        // (completion, descriptors it holds); descriptors are released
        // only when the completion resolves AND is dropped here.
        let mut completions: VecDeque<(_, usize)> = VecDeque::new();
        // txq_sz() halves the queue size assuming 2-slot chains; the real
        // descriptor count is what matters now that TSO chains span up to
        // MAX_TX_DESCS slots.
        let txq_descs = (net_dev.txq_sz() as usize) * 2;
        let mut inflight_descs = 0_usize;

        loop {
            // Guarantee descriptor headroom BEFORE post_write: post_write
            // waits for descriptors internally, and if this task blocked
            // there while every descriptor was owned by the resolved-but-
            // undropped completions in our deque, nothing would ever free
            // them — a self-deadlock (hit by the first TSO chain: the
            // deque held 128 two-descriptor chains = the entire table).
            while txq_descs - inflight_descs < virtio_async::virtio_net::MAX_TX_DESCS {
                let (completion, descs) = completions.pop_front().unwrap();
                let (buf, _) = completion.await;
                buf_cache.push_buf(buf);
                inflight_descs -= descs;
            }
            let maybe_tx_vec = tx_queue.borrow_mut().pop_front();

            if let Some((packet, tso_seg_size)) = maybe_tx_vec {
                log::debug!("NET TX {} bytes", packet.len());
                stats
                    .device_tx_packets
                    .set(stats.device_tx_packets.get() + 1);
                stats
                    .device_tx_bytes
                    .set(stats.device_tx_bytes.get() + packet.len() as u64);
                let (completion, descs) = net_dev.clone().post_write(packet, tso_seg_size).await;
                inflight_descs += descs;
                completions.push_back((completion, descs));
            } else {
                tx_notify.notified().await;
            }
        }
    }
}

pub struct VirtioRxToken {
    buf: ManuallyDrop<IoBuf>,
    buf_cache: BufCache,
    // The device vouched for this frame's L4 checksum, so the netstack must
    // not verify it (see RxMeta::l4_csum_vouched).
    l4_csum_vouched: bool,
}

impl Drop for VirtioRxToken {
    fn drop(&mut self) {
        // SAFETY: safe as self.buf will never be accessed again.
        let buf = unsafe { ManuallyDrop::take(&mut self.buf) };
        self.buf_cache.push_buf(buf);
    }
}

impl moto_netstack::phy::RxToken for VirtioRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        log::debug!("RxToken: consume {}", self.buf.len());
        f(self.buf.as_ref())
    }

    fn meta(&self) -> moto_netstack::phy::PacketMeta {
        moto_netstack::phy::PacketMeta::default().with_l4_csum_vouched(self.l4_csum_vouched)
    }
}

pub struct VirtioTxToken {
    tx_queue: TxQueue,
    tx_notify: Rc<moto_async::LocalNotify>,
    buf_cache: BufCache,
    // From PacketMeta::tso_seg_size via set_meta (the iface calls it just
    // before consume): nonzero marks a TCP super-segment.
    tso_seg_size: u16,
}

impl moto_netstack::phy::TxToken for VirtioTxToken {
    fn set_meta(&mut self, meta: moto_netstack::phy::PacketMeta) {
        self.tso_seg_size = meta.tso_seg_size;
    }

    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let Some(mut packet) = self.buf_cache.pop_buf(len) else {
            // The netstack is owed its slice whatever happens, so fill an
            // ordinary heap buffer and drop it: the packet is lost, which
            // TCP recovers from and UDP is already allowed. The pooled
            // buffers are DMA-capable and page-aligned, a scarcer resource
            // than the plain allocation used here.
            log::error!("NET: TX: dropping a {len}-byte packet: no buffer.");
            let mut scratch = vec![0u8; len];
            return f(scratch.as_mut_slice());
        };
        packet.set_len(len);
        let result = f(packet.as_mut());
        self.tx_queue
            .borrow_mut()
            .push_back((packet, self.tso_seg_size));
        self.tx_notify.notify_one();
        log::debug!("TxToken: consume {len}.");
        result
    }
}

impl moto_netstack::phy::Device for VirtioDevice {
    type RxToken<'a>
        = VirtioRxToken
    where
        Self: 'a;

    type TxToken<'a>
        = VirtioTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        timestamp: moto_netstack::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        log::debug!("VirtioDevice::receive()");
        self.rx_queue.borrow_mut().pop_front().map(|(buf, meta)| {
            log::debug!("VirtioDevice::receive(): have {} bytes.", buf.len());
            (
                VirtioRxToken {
                    buf: ManuallyDrop::new(buf),
                    buf_cache: self.buf_cache.clone(),
                    l4_csum_vouched: meta.l4_csum_vouched,
                },
                VirtioTxToken {
                    tx_queue: self.tx_queue.clone(),
                    tx_notify: self.tx_notify.clone(),
                    buf_cache: self.buf_cache.clone(),
                    tso_seg_size: 0,
                },
            )
        })
    }

    fn transmit(&mut self, timestamp: moto_netstack::time::Instant) -> Option<Self::TxToken<'_>> {
        log::debug!("VirtioDevice::transmit()");
        Some(VirtioTxToken {
            tx_queue: self.tx_queue.clone(),
            tx_notify: self.tx_notify.clone(),
            buf_cache: self.buf_cache.clone(),
            tso_seg_size: 0,
        })
    }

    fn capabilities(&self) -> moto_netstack::phy::DeviceCapabilities {
        use moto_netstack::phy::Checksum;
        let mut caps = moto_netstack::phy::DeviceCapabilities::default();
        caps.medium = moto_netstack::phy::Medium::Ethernet;
        caps.max_transmission_unit = self.mtu as usize;
        // Checksum policy. RX verification is on for every frame here, and is
        // waived per frame instead: the device says whether it vouched for a
        // frame's L4 checksum (VIRTIO_NET_F_GUEST_CSUM lets it deliver frames
        // whose checksum field holds only a pseudo-header sum, or that it
        // verified itself), and that verdict rides PacketMeta from
        // VirtioRxToken::meta() to moto-netstack's TCP and UDP ingress. So the
        // GUEST_CSUM saving is kept exactly where the host actually vouched,
        // while a frame nobody vouched for — which is what QEMU delivers for
        // traffic the host did not validate — is verified rather than trusted.
        //
        // TX is unchanged: with csum_offload (VIRTIO_NET_F_CSUM) moto-netstack
        // skips computing TCP checksums (zeroes the field) and the driver's
        // post_write seeds the pseudo-header sum and sets NEEDS_CSUM instead,
        // saving a full write-side pass over TX payload. UDP TX stays in
        // software: a fragmented UDP datagram carries its L4 header only in
        // the first fragment, which NEEDS_CSUM can't describe. IPv4 *header*
        // checksums (20-ish bytes) are always computed and verified — near-free
        // and not covered by the L4 offload contract.
        caps.checksum.tcp = if self.csum_offload {
            Checksum::Rx
        } else {
            Checksum::Both
        };
        caps.checksum.udp = Checksum::Both;
        // TCP segmentation offload (VIRTIO_NET_F_HOST_TSO4+6): moto-netstack may
        // emit TCP super-segments up to this payload size; post_write marks
        // them with gso_type/gso_size and the host segments them (or, for
        // host-local delivery, consumes them whole). Requires csum_offload
        // — a TSO packet is by definition NEEDS_CSUM.
        if self.tso && self.csum_offload {
            caps.max_tso_size = TSO_MAX_PAYLOAD;
        }
        caps
    }
}

pub(super) enum NetstackDevice {
    VirtIo(VirtioDevice),
    Loopback(moto_netstack::phy::Loopback),
}

pub(super) struct NetDev<'a> {
    name: String,
    config: config::DeviceCfg,

    device: NetstackDevice,
    iface: moto_netstack::iface::Interface,
    pub(super) sockets: moto_netstack::iface::SocketSet<'a>,

    udp_ports_in_use: std::collections::HashSet<u16>,
    udp_addresses_in_use: std::collections::HashSet<SocketAddr>,

    tcp_ports_in_use: std::collections::HashSet<u16>,
    icmp_identifiers_in_use: std::collections::HashSet<u16>,

    // This is the notify that drives the netstack device runtime in net.rs.
    pub(super) device_runtime_notify: Rc<moto_async::LocalNotify>,
}

impl<'a> NetDev<'a> {
    pub(super) fn new(
        name: &str,
        dev_cfg: &config::DeviceCfg,
        auto_icmp_echo_reply: bool,
        mut device: NetstackDevice,
    ) -> Self {
        let hardware_addr = match &device {
            NetstackDevice::VirtIo(_) => moto_netstack::wire::HardwareAddress::Ethernet(
                moto_netstack::wire::EthernetAddress::from_bytes(&dev_cfg.mac.raw()),
            ),
            NetstackDevice::Loopback(_) => moto_netstack::wire::HardwareAddress::Ip,
        };
        let mut config = moto_netstack::iface::Config::new(hardware_addr);
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|dur| dur.as_nanos() as u64)
            .unwrap_or(1234);
        config.auto_icmp_echo_reply = auto_icmp_echo_reply;
        config.discovery_silent_time = moto_netstack::time::Duration::from_millis(5);
        log::debug!(
            "Initializing net device {name} with\nmac {:x?}",
            dev_cfg.mac
        );

        let (mut iface, notify) = match &mut device {
            NetstackDevice::VirtIo(dev) => (
                moto_netstack::iface::Interface::new(
                    config,
                    dev,
                    moto_netstack::time::Instant::now(),
                ),
                // Netstack interfaces have a single poll() that does both RX and TX.
                // RX is driven by VirtioNET device; TX is driven by user sockets.
                //
                // A better stack would have these separate.
                dev.rx_notify.clone(),
            ),
            NetstackDevice::Loopback(dev) => (
                moto_netstack::iface::Interface::new(
                    config,
                    dev,
                    moto_netstack::time::Instant::now(),
                ),
                // The loopback device has a self-contained runtime notify.
                Rc::new(moto_async::LocalNotify::default()),
            ),
        };

        iface.update_ip_addrs(|ip_addrs| {
            for cidr in &dev_cfg.cidrs {
                log::debug!("added IP \n\t{:?} to {}", cidr.ip(), name);
                ip_addrs
                    .push(moto_netstack::wire::IpCidr::new(
                        <moto_netstack::wire::IpAddress as From<std::net::IpAddr>>::from(cidr.ip()),
                        cidr.prefix(),
                    ))
                    .unwrap();
            }
        });

        iface.routes_mut().update(|storage| {
            for route in &dev_cfg.routes {
                let rt = moto_netstack::iface::Route {
                    cidr: config::ip_network_to_cidr(&route.ip_network),
                    via_router: route.gateway.into(),
                    preferred_until: None,
                    expires_at: None,
                };
                log::debug!("adding route \n{route:#?} to {name}");
                storage.push(rt).unwrap();
            }
        });

        log::debug!("New NET device {name}.");

        Self {
            name: name.to_owned(),
            config: dev_cfg.clone(),
            device,
            iface,
            sockets: moto_netstack::iface::SocketSet::new(vec![]),
            udp_ports_in_use: std::collections::HashSet::new(),
            udp_addresses_in_use: std::collections::HashSet::new(),
            tcp_ports_in_use: std::collections::HashSet::new(),
            icmp_identifiers_in_use: std::collections::HashSet::new(),
            device_runtime_notify: notify,
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn config(&self) -> &config::DeviceCfg {
        &self.config
    }

    // Have to have this as a method here because it borrows self twice: for the socket and for the iface.
    pub(super) fn tcp_connect(
        &mut self,
        handle: moto_netstack::iface::SocketHandle,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(), ()> {
        let netstack_socket = self
            .sockets
            .get_mut::<moto_netstack::socket::tcp::Socket>(handle);
        netstack_socket
            .connect(self.iface.context(), remote_addr, local_addr)
            .map_err(|_err| {
                log::warn!("Connect {local_addr:?} => {remote_addr:?} failed: {_err:?}");
            })?;

        self.device_runtime_notify.notify_one();
        Ok(())
    }

    pub(super) fn poll(&mut self, stats: &NetStats) -> moto_netstack::iface::PollResult {
        let NetDev {
            name,
            config,
            device,
            iface,
            sockets,
            udp_ports_in_use,
            udp_addresses_in_use,
            tcp_ports_in_use,
            icmp_identifiers_in_use,
            device_runtime_notify: notify,
        } = self;
        let result = match device {
            NetstackDevice::Loopback(loopback) => {
                iface.poll(moto_netstack::time::Instant::now(), loopback, sockets)
            }
            NetstackDevice::VirtIo(virtio_device) => {
                iface.poll(moto_netstack::time::Instant::now(), virtio_device, sockets)
            }
        };

        // One poll drains the whole receive queue, so a batch of dropped
        // frames costs one counter update here rather than one per frame.
        let csum_failed = iface.take_rx_csum_failed();
        if csum_failed != 0 {
            log::warn!("{name}: dropped {csum_failed} frames with a bad TCP/UDP checksum.");
            stats
                .rx_csum_failed
                .set(stats.rx_csum_failed.get() + csum_failed);
        }

        let syn_rst = iface.take_tcp_syn_rst_unmatched();
        if syn_rst != 0 {
            stats
                .tcp_syn_rst_unmatched
                .set(stats.tcp_syn_rst_unmatched.get() + syn_rst);
        }

        result
    }

    pub(super) fn poll_delay(&mut self) -> Option<std::time::Duration> {
        let NetDev {
            name,
            config,
            device,
            iface,
            sockets,
            udp_ports_in_use,
            udp_addresses_in_use,
            tcp_ports_in_use,
            icmp_identifiers_in_use,
            device_runtime_notify: notify,
        } = self;
        match device {
            NetstackDevice::Loopback(loopback) => iface
                .poll_delay(moto_netstack::time::Instant::now(), sockets)
                .map(|d| d.into()),
            NetstackDevice::VirtIo(virtio_device) => iface
                .poll_delay(moto_netstack::time::Instant::now(), sockets)
                .map(|d| d.into()),
        }
    }

    pub(super) fn ip_addesses(&self) -> Vec<IpAddr> {
        let cidrs = self.iface.ip_addrs();
        let mut addresses = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            addresses.push(cidr.address().into());
        }

        addresses
    }

    pub(super) fn get_ephemeral_udp_port(&mut self, _local_ip_addr: &IpAddr) -> Option<u16> {
        // See https://en.wikipedia.org/wiki/Ephemeral_port.
        const EPHEMERAL_PORT_MIN: u16 = 49152;
        const EPHEMERAL_PORT_MAX: u16 = 65535;

        // TODO: do better than a linear search.
        for port in EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX {
            if !self.udp_ports_in_use.contains(&port) {
                self.udp_ports_in_use.insert(port);
                return Some(port);
            }
        }

        None
    }

    pub(super) fn free_ephemeral_udp_port(&mut self, port: u16) {
        self.udp_ports_in_use.remove(&port);
    }

    pub(super) fn add_udp_addr_in_use(&mut self, addr: SocketAddr) -> std::io::Result<()> {
        if self.udp_addresses_in_use.insert(addr) {
            Ok(())
        } else {
            Err(std::io::Error::from(ErrorKind::AddrInUse))
        }
    }

    pub(super) fn remove_udp_addr_in_use(&mut self, addr: &SocketAddr) {
        if self.udp_addresses_in_use.remove(addr) {
            log::debug!("{}: removed udp addr in use {addr:?}", self.name);
        } else {
            log::error!("{}: udp addr {addr:?} was not in use.", self.name);
        }
    }

    pub(super) fn get_ephemeral_tcp_port(
        &mut self,
        _local_ip_addr: &IpAddr,
        is_reserved: impl Fn(u16) -> bool,
    ) -> Option<u16> {
        // See https://en.wikipedia.org/wiki/Ephemeral_port.
        const EPHEMERAL_PORT_MIN: u16 = 49152;
        const EPHEMERAL_PORT_MAX: u16 = 65535;

        // TODO: do better than a linear search.
        for port in EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX {
            if !self.tcp_ports_in_use.contains(&port) && !is_reserved(port) {
                self.tcp_ports_in_use.insert(port);
                return Some(port);
            }
        }

        None
    }

    pub(super) fn free_ephemeral_tcp_port(&mut self, port: u16) {
        self.tcp_ports_in_use.remove(&port);
    }

    pub(super) fn ip_mtu(&self) -> usize {
        use moto_netstack::phy::Device;

        match &self.device {
            NetstackDevice::VirtIo(device) => device.capabilities().ip_mtu(),
            NetstackDevice::Loopback(device) => device.capabilities().ip_mtu(),
        }
    }

    pub(super) fn get_icmp_identifier(&mut self) -> Option<u16> {
        (1..=u16::MAX).find(|identifier| self.icmp_identifiers_in_use.insert(*identifier))
    }

    pub(super) fn free_icmp_identifier(&mut self, identifier: u16) {
        if !self.icmp_identifiers_in_use.remove(&identifier) {
            log::error!(
                "{}: ICMP identifier {identifier} was not in use.",
                self.name
            );
        }
    }
}
