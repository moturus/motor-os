//! This is mostly plumbing moto-netstack into our async runtime.
use std::{
    cell::RefCell,
    collections::VecDeque,
    io::ErrorKind,
    mem::ManuallyDrop,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
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
enum TxWork {
    Packet(IoBuf, u16),
    Barrier(moto_async::oneshot::Sender<()>),
}

/// Bytes owned by one admitted TX token before its packet size is known.
/// [`BIG_BUF_SIZE`] is the largest buffer the token can consume.
const TX_RESERVATION: usize = BIG_BUF_SIZE;

struct TxQueueState {
    work: VecDeque<TxWork>,
    bytes: usize,
    byte_limit: usize,
}

impl TxQueueState {
    fn new(byte_limit: usize) -> Self {
        assert!(byte_limit >= TX_RESERVATION);
        Self {
            work: VecDeque::new(),
            bytes: 0,
            byte_limit,
        }
    }

    fn reserve(&mut self) -> bool {
        if self.bytes > self.byte_limit - TX_RESERVATION {
            return false;
        }
        self.bytes += TX_RESERVATION;
        true
    }

    fn cancel_reservation(&mut self) {
        self.bytes -= TX_RESERVATION;
    }

    fn push_packet(&mut self, packet: IoBuf, tso_seg_size: u16) {
        debug_assert!(packet.capacity() <= TX_RESERVATION);
        self.bytes -= TX_RESERVATION - packet.capacity();
        self.work.push_back(TxWork::Packet(packet, tso_seg_size));
    }

    /// Pop work and report whether doing so reopened packet admission.
    fn pop_front(&mut self) -> (Option<TxWork>, bool) {
        let was_full = self.bytes > self.byte_limit - TX_RESERVATION;
        let work = self.work.pop_front();
        if let Some(TxWork::Packet(packet, _)) = &work {
            self.bytes -= packet.capacity();
        }
        (
            work,
            was_full && self.bytes <= self.byte_limit - TX_RESERVATION,
        )
    }

    fn push_barriers(&mut self, waiters: Vec<moto_async::oneshot::Sender<()>>) {
        self.work.extend(waiters.into_iter().map(TxWork::Barrier));
    }
}

type TxQueue = Rc<RefCell<TxQueueState>>;

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

/// Allocate one missing RX-ring buffer, retaining the deficit on failure.
fn allocate_rx_refill<T>(deficit: &mut usize, allocate: impl FnOnce() -> Option<T>) -> Option<T> {
    if *deficit == 0 {
        return None;
    }
    let buffer = allocate()?;
    *deficit -= 1;
    Some(buffer)
}

pub(super) struct VirtioDevice {
    inner: Rc<NetDevice>,
    rx_queue: RxQueue,
    tx_queue: TxQueue,

    // The device will notify rx_notify when it updates rx_queue.
    rx_notify: Rc<moto_async::LocalNotify>,
    // The device will listen on tx_notify for tx_queue updates.
    tx_notify: Rc<moto_async::LocalNotify>,
    /// Largest Ethernet frame this device carries, headers included, which is
    /// what moto-netstack means by `max_transmission_unit`. See [`frame_mtu`].
    frame_mtu: usize,
    csum_offload: bool,
    tso: bool,

    buf_cache: BufCache,
    stats: Rc<NetStats>,
}

/// The IP MTU to assume when the device reports none. Ethernet's default, and
/// what a tap gets unless it was configured otherwise.
const DEFAULT_IP_MTU: u16 = 1500;

/// The largest IP MTU the receive path can actually take delivery of.
///
/// `rx_task` posts [`SMALL_BUF_SIZE`] buffers, and without
/// `VIRTIO_NET_F_MRG_RXBUF` -- which is not negotiated -- the device cannot
/// continue one frame into a second buffer. A larger MTU would advertise an MSS
/// we are unable to receive, so believe the device only this far.
const MAX_IP_MTU: u16 = (SMALL_BUF_SIZE - moto_netstack::wire::ETHERNET_HEADER_LEN) as u16;

/// The smallest IP MTU worth believing.
///
/// moto-netstack derives the advertised MSS as
/// `ip_mtu() - ip_header_len - TCP_HEADER_LEN` on `usize`, which underflows
/// below 40 (IPv4) or 60 (IPv6); sys-io is `panic = "abort"`, so a device
/// reporting nonsense would take the whole network stack down with it. 576 is
/// IPv4's minimum reassembly buffer and no usable link is smaller, so anything
/// under it is a broken device rather than a small link.
const MIN_IP_MTU: u16 = 576;

const _: () = assert!(
    moto_netstack::config::FRAGMENTATION_BUFFER_SIZE == 65_536,
    "sys-io source fragmentation requires a 65536-byte staging buffer"
);
const _: () = assert!(
    moto_netstack::config::REASSEMBLY_BUFFER_SIZE == 65_536,
    "sys-io reassembly requires a 65536-byte per-datagram bound"
);
const _: () = assert!(
    moto_netstack::config::REASSEMBLY_BUFFER_COUNT == 4,
    "sys-io reassembly requires four bounded per-interface slots"
);

/// The `max_transmission_unit` moto-netstack wants -- a whole Ethernet frame --
/// from the IP MTU virtio reports, or from nothing when it reports nothing.
///
/// The two are 14 bytes apart and conflating them lands in the advertised MSS,
/// which is `ip_mtu()` less the IP and TCP headers. Advertising too little only
/// wastes payload; advertising too much invites a peer to send segments the
/// link cannot carry, and there is no path-MTU discovery here to recover. The
/// old fallback was 1536 used as a frame size, which is the second kind: MSS
/// 1482 on a 1500-byte link.
///
/// The device's own number is not trusted any further than the receive path can
/// honor it; see [`MAX_IP_MTU`] and [`MIN_IP_MTU`].
fn frame_mtu(device_ip_mtu: Option<u16>) -> usize {
    let ip_mtu = match device_ip_mtu {
        None => DEFAULT_IP_MTU,
        Some(mtu) if mtu < MIN_IP_MTU => {
            log::warn!("virtio-net: device reports MTU {mtu}; using {DEFAULT_IP_MTU}.");
            DEFAULT_IP_MTU
        }
        Some(mtu) if mtu > MAX_IP_MTU => {
            log::warn!("virtio-net: device reports MTU {mtu}; capped at {MAX_IP_MTU}.");
            MAX_IP_MTU
        }
        Some(mtu) => mtu,
    };
    ip_mtu as usize + moto_netstack::wire::ETHERNET_HEADER_LEN
}

impl VirtioDevice {
    pub(super) fn new(inner: Rc<NetDevice>, stats: Rc<NetStats>) -> Self {
        let frame_mtu = frame_mtu(inner.mtu());
        let csum_offload = inner.csum_offload();
        let tso = inner.tso();
        // Match the software queue to one hardware ring of ordinary frames.
        // TSO buffers are charged by their 64 KiB allocation, so they consume
        // 32 times as much of this bound as an MTU-sized frame.
        let tx_queue_bytes = (inner.txq_sz() as usize)
            .saturating_mul(SMALL_BUF_SIZE)
            .max(TX_RESERVATION);
        let this = Self {
            inner,
            rx_queue: Default::default(),
            tx_queue: Rc::new(RefCell::new(TxQueueState::new(tx_queue_bytes))),
            rx_notify: Default::default(),
            tx_notify: Default::default(),
            frame_mtu,
            csum_offload,
            tso,
            buf_cache: Default::default(),
            stats: stats.clone(),
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
            this.rx_notify.clone(),
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
        let mut rx_deficit = rxq_sz - completions.len();

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
                    let bucket = &stats.rx_size[super::stats::rx_size_bucket(packet.len())];
                    bucket.set(bucket.get() + 1);
                    rx_queue.borrow_mut().push_back((packet, meta));
                    rx_notify.notify_one();

                    let Some(buf) = buf_cache.pop_buf(SMALL_BUF_SIZE) else {
                        // One fewer buffer in flight; the queue keeps working.
                        log::error!("NET: RX: could not allocate a receive buffer.");
                        rx_deficit += 1;
                        debug_assert!(rx_deficit <= rxq_sz);
                        continue;
                    };
                    buf
                }
            };

            log::debug!("NET: RX: posting read.");
            completions.push_back(net_dev.clone().post_read(next_buf).await);
            while let Some(refill) =
                allocate_rx_refill(&mut rx_deficit, || buf_cache.pop_buf(SMALL_BUF_SIZE))
            {
                log::debug!("NET: RX: refilling missing read.");
                completions.push_back(net_dev.clone().post_read(refill).await);
            }
            debug_assert_eq!(completions.len() + rx_deficit, rxq_sz);
        }
    }

    async fn tx_task(
        net_dev: Rc<NetDevice>,
        tx_queue: TxQueue,
        tx_notify: Rc<moto_async::LocalNotify>,
        capacity_notify: Rc<moto_async::LocalNotify>,
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
            let (maybe_tx_vec, capacity_reopened) = tx_queue.borrow_mut().pop_front();
            if capacity_reopened {
                capacity_notify.notify_one();
            }

            match maybe_tx_vec {
                Some(TxWork::Packet(packet, tso_seg_size)) => {
                    log::debug!("NET TX {} bytes", packet.len());
                    stats
                        .device_tx_packets
                        .set(stats.device_tx_packets.get() + 1);
                    stats
                        .device_tx_bytes
                        .set(stats.device_tx_bytes.get() + packet.len() as u64);
                    let (completion, descs) =
                        net_dev.clone().post_write(packet, tso_seg_size).await;
                    inflight_descs += descs;
                    completions.push_back((completion, descs));
                }
                Some(TxWork::Barrier(waiter)) => {
                    while let Some((completion, descs)) = completions.pop_front() {
                        let (buf, _) = completion.await;
                        buf_cache.push_buf(buf);
                        inflight_descs -= descs;
                    }
                    let _ = waiter.send(());
                }
                None => tx_notify.notified().await,
            }
        }
    }

    fn complete_transmits(&self, waiters: Vec<moto_async::oneshot::Sender<()>>) {
        if waiters.is_empty() {
            return;
        }
        self.tx_queue.borrow_mut().push_barriers(waiters);
        self.tx_notify.notify_one();
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
    stats: Rc<NetStats>,
    // From PacketMeta::tso_seg_size via set_meta (the iface calls it just
    // before consume): nonzero marks a TCP super-segment.
    tso_seg_size: u16,
    reserved: bool,
}

impl Drop for VirtioTxToken {
    fn drop(&mut self) {
        if self.reserved {
            self.tx_queue.borrow_mut().cancel_reservation();
        }
    }
}

impl moto_netstack::phy::TxToken for VirtioTxToken {
    fn set_meta(&mut self, meta: moto_netstack::phy::PacketMeta) {
        self.tso_seg_size = meta.tso_seg_size;
    }

    fn consume<R, F>(mut self, len: usize, f: F) -> R
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
            self.stats
                .device_tx_allocation_drops
                .set(self.stats.device_tx_allocation_drops.get() + 1);
            let mut scratch = vec![0u8; len];
            return f(scratch.as_mut_slice());
        };
        packet.set_len(len);
        let result = f(packet.as_mut());
        self.tx_queue
            .borrow_mut()
            .push_packet(packet, self.tso_seg_size);
        self.reserved = false;
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
        if self.rx_queue.borrow().is_empty() || !self.tx_queue.borrow_mut().reserve() {
            return None;
        }
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
                    stats: self.stats.clone(),
                    tso_seg_size: 0,
                    reserved: true,
                },
            )
        })
    }

    fn transmit(&mut self, timestamp: moto_netstack::time::Instant) -> Option<Self::TxToken<'_>> {
        log::debug!("VirtioDevice::transmit()");
        if !self.tx_queue.borrow_mut().reserve() {
            return None;
        }
        Some(VirtioTxToken {
            tx_queue: self.tx_queue.clone(),
            tx_notify: self.tx_notify.clone(),
            buf_cache: self.buf_cache.clone(),
            stats: self.stats.clone(),
            tso_seg_size: 0,
            reserved: true,
        })
    }

    fn capabilities(&self) -> moto_netstack::phy::DeviceCapabilities {
        use moto_netstack::phy::Checksum;
        let mut caps = moto_netstack::phy::DeviceCapabilities::default();
        caps.medium = moto_netstack::phy::Medium::Ethernet;
        caps.max_transmission_unit = self.frame_mtu;
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

impl NetstackDevice {
    /// Whether this device can carry traffic from off this machine.
    ///
    /// The two things that turn on this answer -- randomized ephemeral ports
    /// and the loopback-address ingress drop -- are one decision seen from
    /// either end: ports are randomized where an off-path attacker can exist,
    /// and loopback addresses are refused everywhere one can. The match is
    /// exhaustive so a third kind of device cannot be added without answering
    /// for it.
    fn is_external(&self) -> bool {
        match self {
            NetstackDevice::VirtIo(_) => true,
            NetstackDevice::Loopback(_) => false,
        }
    }
}

/// RFC 7323's TCP timestamp clock.
///
/// The netstack asks for one through a bare `fn() -> u32`, so the clock has to
/// live somewhere global. It is read once per emitted segment, which is the
/// reason it is a cached value advanced by [`tick`] at the top of each poll
/// rather than a clock read on the emit path: a poll is also exactly the
/// granularity that matters, since every segment a poll emits leaves together.
pub(super) mod tsval {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// The current value, as [`generator`] hands it out.
    static NOW: AtomicU32 = AtomicU32::new(0);

    /// Added to every reading, drawn once at startup.
    ///
    /// Without it the timestamps a machine puts on the wire are its uptime, in
    /// milliseconds, told to everyone it talks to -- which dates its last
    /// reboot, and so its patch level, and lets two connections be recognized
    /// as coming from one host behind a NAT. RFC 7323 section 7.1 asks for an
    /// offset for exactly this. Note what it does *not* buy: one offset for the
    /// whole machine still leaves connections linkable to each other, which
    /// wants a per-connection offset and a netstack that can hold one.
    static OFFSET: AtomicU32 = AtomicU32::new(0);

    /// Draws the offset, before any socket exists. Idempotent, because each
    /// interface constructs itself and there is one clock between them.
    pub(super) fn init() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            OFFSET.store(u32::from_ne_bytes(super::random_bytes()), Ordering::Relaxed);
        });
        tick();
    }

    /// Advances the clock. Called at the top of every poll.
    ///
    /// The tick is a millisecond: the fast end of RFC 7323 section 5.4's 1 ms
    /// to 1 s range, and what Linux uses. Fast enough that the value always
    /// advances within one wrap of the sequence space -- which at this link's
    /// rates goes by in seconds, and is the whole reason PAWS has anything to
    /// do -- and slow enough that the 32-bit field itself takes 49 days to come
    /// around, far longer than a segment can outlive the connection it belongs
    /// to. The truncation to `u32` *is* that wrap, and the comparison in the
    /// netstack is modular to match.
    pub(super) fn tick() {
        // Monotonic, unlike the wall clock the netstack's own timers run on. A
        // clock that stepped backwards here would take our timestamps with it,
        // and the peer's PAWS would then refuse everything we sent until its
        // own view caught up.
        let millis = moto_rt::time::since_system_start().as_millis() as u32;
        NOW.store(
            OFFSET.load(Ordering::Relaxed).wrapping_add(millis),
            Ordering::Relaxed,
        );
    }

    /// What the netstack installs on each TCP socket.
    pub(in crate::runtime::net) fn generator() -> u32 {
        NOW.load(Ordering::Relaxed)
    }
}

/// Bytes from the CPU's hardware RNG, for one interface at initialization.
///
/// The netstack's seed used to be the boot wall clock, which an off-path peer
/// that knows roughly when the machine booted can search offline. RDRAND costs
/// a handful of draws per device at initialization and nothing per packet or
/// per connection.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    moto_rt::fill_random_bytes(&mut bytes);
    bytes
}

/// How many automatic ICMP error replies one external device may send per
/// second. Legitimate errors are rare, while each triggering packet may carry
/// a forged source address and turn the reply into reflected traffic.
/// `max_icmp_error_rate` in `/system/cfg/sys-net.toml` overrides it.
pub(super) const DEFAULT_MAX_ICMP_ERROR_RATE: NonZeroU32 = NonZeroU32::new(200).unwrap();

/// How many no-listener resets one external device may send per second:
/// FreeBSD has shipped this figure for its closed-port response limit for
/// decades. Legitimate traffic rarely draws these at all -- a real client
/// connects to ports that answer -- so the budget is only ever spent by scans
/// and floods, and a suppressed reset costs its peer one retransmission
/// round. `max_rst_rate` in `/system/cfg/sys-net.toml` overrides it.
pub(super) const DEFAULT_MAX_RST_RATE: NonZeroU32 = NonZeroU32::new(200).unwrap();

/// The cookie SYN|ACK bound, higher because these answer the opposite
/// population: connection requests at a listener that is merely flooded, so
/// every suppression may delay a legitimate client. 1000/s is Linux's
/// long-standing challenge-ACK figure -- its closest bound on protocol
/// responses -- and an order above any connection rate this rig's serving
/// workloads have shown. `max_syn_cookie_rate` overrides it.
pub(super) const DEFAULT_MAX_SYN_COOKIE_RATE: NonZeroU32 = NonZeroU32::new(1000).unwrap();

/// The netstack configuration every interface is constructed from, so that the
/// draws above have exactly one call site and a self-test can take
/// configurations the way two devices would.
fn iface_config(
    hardware_addr: moto_netstack::wire::HardwareAddress,
    net_cfg: &config::NetConfig,
    external: bool,
) -> moto_netstack::iface::Config {
    let auto_icmp_echo_reply = net_cfg.auto_icmp_echo_reply;
    let mut config = moto_netstack::iface::Config::new(hardware_addr);
    // The seed drives IPv4 identifiers and DNS transaction ids from a small
    // linear generator, so a peer that sees a few of them can recover it; it is
    // not a secret and the netstack does not treat it as one. The ISN key is,
    // and is drawn separately for exactly that reason: deriving it from the
    // seed would leave RFC 6528's hash keyed by a recoverable value.
    config.random_seed = u64::from_ne_bytes(random_bytes());
    config.tcp_isn_key = random_bytes();
    config.tcp_cookie_key = random_bytes();
    config.loopback = !external;
    config.auto_icmp_echo_reply = auto_icmp_echo_reply;
    // 200x more aggressive than the netstack's 1 s default, from `fa203b4b`
    // ("reduce ARP delay"): the first packet to an unresolved peer waits out
    // this delay whenever its request is lost, and a second of that is a
    // second of connect latency. The delay is per destination, so the price
    // of the aggressive value is 200 requests/s aimed at one address that
    // does not answer, not 200 requests/s from the interface as a whole.
    config.discovery_silent_time = moto_netstack::time::Duration::from_millis(5);
    // The egress limits on socketless replies -- no-listener resets and
    // cookie SYN|ACKs -- exist because those replies go wherever a spoofable
    // source address says. On loopback the only peer is this machine, already
    // trusted with far more, and limiting resets there would turn a burst of
    // connects to a closed local port from prompt `ECONNREFUSED` into
    // retransmit stalls: same trust argument as the ephemeral-port
    // randomization exemption above, so loopback keeps the netstack's
    // unlimited default.
    if external {
        config.icmp_error_rate_limit = net_cfg.max_icmp_error_rate.get();
        config.tcp_rst_rate_limit = net_cfg.max_rst_rate.get();
        config.tcp_cookie_rate_limit = net_cfg.max_syn_cookie_rate.get();
    }
    config
}

/// The ephemeral port range, per IANA and RFC 6056 section 3.2.
const EPHEMERAL_PORT_MIN: u16 = 49152;
const EPHEMERAL_PORT_MAX: u16 = 65535;
const EPHEMERAL_PORT_COUNT: u16 = EPHEMERAL_PORT_MAX - EPHEMERAL_PORT_MIN + 1;

/// Where an ephemeral allocation starts looking.
///
/// RFC 6056: on a device carrying external traffic this is a uniform point in
/// the range, so an off-path attacker cannot name the 4-tuple of the next
/// connection and forge segments into it -- which, with the ISNs of patch 18
/// already unguessable, is the last piece of that tuple left to guess. On
/// loopback it stays the bottom of the range: local ports are already
/// enumerable through the socket-stats service, so randomizing them buys
/// nothing against the only attacker there is, and lowest-free keeps the
/// deterministic self-connect that covers RFC 9293 simultaneous open.
///
/// One hardware draw per allocation, not a PRNG seeded once: the state of a
/// small generator is recoverable from a few of its outputs, which is exactly
/// the weakness patch 18 removed from sequence numbers.
fn ephemeral_scan_start(external: bool) -> u16 {
    if !external {
        return EPHEMERAL_PORT_MIN;
    }

    // The range is a power of two, so the fold is exactly uniform.
    EPHEMERAL_PORT_MIN + u16::from_ne_bytes(random_bytes()) % EPHEMERAL_PORT_COUNT
}

/// The first port from `start` upwards, wrapping at the top of the range, that
/// `taken` does not claim. Scanning the whole range keeps the guarantee the
/// lowest-free search had: a port is refused only when all of them are in use.
///
/// `start` must be in the ephemeral range; [`ephemeral_scan_start`] is where
/// both callers get one.
///
// TODO: do better than a linear search. Inherited from the lowest-free
// allocator this replaced, and still true of it: a machine holding most of the
// range costs one lookup per occupied port per allocation.
fn find_ephemeral_port(start: u16, taken: impl Fn(u16) -> bool) -> Option<u16> {
    let offset = start - EPHEMERAL_PORT_MIN;
    (0..EPHEMERAL_PORT_COUNT)
        .map(|step| EPHEMERAL_PORT_MIN + (offset + step) % EPHEMERAL_PORT_COUNT)
        .find(|port| !taken(*port))
}

pub(super) struct NetDev<'a> {
    name: String,
    config: config::DeviceCfg,

    device: NetstackDevice,
    iface: moto_netstack::iface::Interface,
    pub(super) sockets: moto_netstack::iface::SocketSet<'a>,

    /// [`NetstackDevice::is_external`], taken once at construction because both
    /// the netstack configuration and every ephemeral allocation need it.
    external: bool,

    udp_ports_in_use: std::collections::HashSet<u16>,
    udp_addresses_in_use: std::collections::HashSet<SocketAddr>,

    tcp_ports_in_use: std::collections::HashSet<u16>,
    icmp_identifiers_in_use: std::collections::HashSet<u16>,

    // This is the notify that drives the netstack device runtime in net.rs.
    pub(super) device_runtime_notify: Rc<moto_async::LocalNotify>,
    transmit_waiters: Vec<moto_async::oneshot::Sender<()>>,
}

impl<'a> NetDev<'a> {
    pub(super) fn new(
        name: &str,
        dev_cfg: &config::DeviceCfg,
        net_cfg: &config::NetConfig,
        mut device: NetstackDevice,
    ) -> Self {
        let hardware_addr = match &device {
            NetstackDevice::VirtIo(_) => moto_netstack::wire::HardwareAddress::Ethernet(
                moto_netstack::wire::EthernetAddress::from_bytes(&dev_cfg.mac.raw()),
            ),
            NetstackDevice::Loopback(_) => moto_netstack::wire::HardwareAddress::Ip,
        };
        let external = device.is_external();
        // Before any socket, since a socket's first SYN already carries a
        // timestamp and an unoffset one would be this machine's uptime.
        tsval::init();
        let config = iface_config(hardware_addr, net_cfg, external);
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
        // The clock behind the cookie SYN|ACK's timestamp: the same one every
        // socket gets, so the stateless segment is indistinguishable.
        iface.set_tsval_generator(Some(tsval::generator));

        // The interface's tables grow to hold whatever `/system/cfg/sys-net.toml`
        // wrote, so installation is total: every configured address and route
        // exists after boot or the config did not parse. The overflow behavior
        // history here -- `unwrap()` that took sys-io down at boot (`0xbadc0de`),
        // then drop-and-log at fixed capacity -- is retired with the capacity
        // itself; the config loader's 64 KiB file bound is what keeps the counts
        // finite.
        iface.update_ip_addrs(|ip_addrs| {
            for cidr in &dev_cfg.cidrs {
                ip_addrs.push(moto_netstack::wire::IpCidr::new(
                    <moto_netstack::wire::IpAddress as From<std::net::IpAddr>>::from(cidr.ip()),
                    cidr.prefix(),
                ));
                log::debug!("added IP \n\t{:?} to {}", cidr.ip(), name);
            }
        });

        iface.routes_mut().update(|storage| {
            for route in &dev_cfg.routes {
                storage.push(moto_netstack::iface::Route {
                    cidr: config::ip_network_to_cidr(&route.ip_network),
                    via_router: route.gateway.into(),
                    preferred_until: None,
                    expires_at: None,
                });
                log::debug!("adding route \n{route:#?} to {name}");
            }
        });

        log::debug!("New NET device {name}.");

        Self {
            name: name.to_owned(),
            config: dev_cfg.clone(),
            device,
            iface,
            sockets: moto_netstack::iface::SocketSet::new(),
            external,
            udp_ports_in_use: std::collections::HashSet::new(),
            udp_addresses_in_use: std::collections::HashSet::new(),
            tcp_ports_in_use: std::collections::HashSet::new(),
            icmp_identifiers_in_use: std::collections::HashSet::new(),
            device_runtime_notify: notify,
            transmit_waiters: Vec::new(),
        }
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn config(&self) -> &config::DeviceCfg {
        &self.config
    }

    pub(super) fn transmit_completion(&mut self) -> moto_async::oneshot::Receiver<()> {
        let (waiter, completion) = moto_async::oneshot();
        self.transmit_waiters.push(waiter);
        self.device_runtime_notify.notify_one();
        completion
    }

    // Have to have this as a method here because it borrows self twice: for the socket and for the iface.
    pub(super) fn tcp_connect(
        &mut self,
        handle: moto_netstack::iface::SocketHandle,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<(), ()> {
        self.sockets
            .tcp_connect(handle, self.iface.context(), remote_addr, local_addr)
            .map_err(|_err| {
                log::warn!("Connect {local_addr:?} => {remote_addr:?} failed: {_err:?}");
            })?;

        self.device_runtime_notify.notify_one();
        Ok(())
    }

    /// Switch `addr` to SYN-cookie admission, advertising what a backlog
    /// socket built under `sizes` would: the floor ring's window and the
    /// shift sized for the configured buffer. Called at the half-open cap;
    /// re-engaging just refreshes the numbers.
    pub(super) fn engage_syn_cookies(
        &mut self,
        addr: SocketAddr,
        sizes: super::socket::tcp::TcpBufferSizes,
    ) {
        let config = moto_netstack::iface::TcpSynCookieConfig {
            window_len: super::socket::tcp::TcpBufferSizes::FLOOR as u16,
            wscale: moto_netstack::socket::tcp::win_shift_for_capacity(sizes.rx),
        };
        if !self.iface.engage_tcp_syn_cookies(addr.into(), config) {
            // The mode table is full; this endpoint keeps drop-and-retransmit.
            log::warn!("{}: no SYN-cookie slot for {addr:?}", self.name);
        }
    }

    /// Stop minting cookies for `addr`. Handshakes already on the wire keep
    /// verifying through the netstack's drain window.
    pub(super) fn disengage_syn_cookies(&mut self, addr: SocketAddr) {
        self.iface.disengage_tcp_syn_cookies(addr.into());
    }

    pub(super) fn tcp_cookie_restores_pending(&self) -> bool {
        self.iface.tcp_cookie_restores_pending()
    }

    pub(super) fn take_tcp_cookie_restores(
        &mut self,
    ) -> impl Iterator<Item = moto_netstack::socket::tcp::TcpCookieRestore> + use<> {
        self.iface.take_tcp_cookie_restores().into_iter()
    }

    // Like tcp_connect above: borrows self twice, for the socket and the iface.
    pub(super) fn tcp_restore(
        &mut self,
        handle: moto_netstack::iface::SocketHandle,
        restore: &moto_netstack::socket::tcp::TcpCookieRestore,
        sizes: super::socket::tcp::TcpBufferSizes,
    ) -> Result<(), ()> {
        self.sockets
            .tcp_restore_from_cookie(handle, self.iface.context(), restore)
            .map_err(|_err| {
                log::warn!(
                    "Cookie restore {:?} => {:?} failed: {_err:?}",
                    restore.remote,
                    restore.local
                );
            })?;
        // Established with empty rings, so the configured growth applies now.
        let netstack_socket = self
            .sockets
            .get_mut::<moto_netstack::socket::tcp::Socket>(handle);
        netstack_socket.grow_rx_capacity(sizes.rx);
        netstack_socket.grow_tx_capacity(sizes.tx);

        self.device_runtime_notify.notify_one();
        Ok(())
    }

    pub(super) fn poll(
        &mut self,
        stats: &NetStats,
        backlog: &super::backlog::BacklogBudget,
    ) -> moto_netstack::iface::PollResult {
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
            transmit_waiters,
            external: _,
        } = self;
        // Every segment this poll emits reads the timestamp clock, so it is
        // advanced once here rather than per segment.
        tsval::tick();

        let waiters = std::mem::take(transmit_waiters);
        let result = match device {
            NetstackDevice::Loopback(loopback) => {
                iface.poll(moto_netstack::time::Instant::now(), loopback, sockets)
            }
            NetstackDevice::VirtIo(virtio_device) => {
                iface.poll(moto_netstack::time::Instant::now(), virtio_device, sockets)
            }
        };
        match device {
            NetstackDevice::Loopback(_) => {
                for waiter in waiters {
                    let _ = waiter.send(());
                }
            }
            NetstackDevice::VirtIo(virtio_device) => virtio_device.complete_transmits(waiters),
        }

        // One poll drains the whole receive queue, so a batch of dropped
        // frames costs one counter update here rather than one per frame.
        stats.add_ip_packet_stats(iface.take_ip_packet_stats());

        let csum_failed = iface.take_rx_csum_failed();
        if csum_failed != 0 {
            log::warn!("{name}: dropped {csum_failed} frames with a bad TCP/UDP checksum.");
            stats
                .rx_csum_failed
                .set(stats.rx_csum_failed.get() + csum_failed);
        }

        let loopback_dropped = iface.take_rx_loopback_dropped();
        if loopback_dropped != 0 {
            log::warn!(
                "{name}: dropped {loopback_dropped} frames carrying a loopback address: \
                 only loopback may."
            );
            stats
                .rx_loopback_dropped
                .set(stats.rx_loopback_dropped.get() + loopback_dropped);
        }

        let neighbors_refused = iface.take_neighbor_admission_refused();
        if neighbors_refused != 0 {
            log::warn!(
                "{name}: refused {neighbors_refused} neighbor mappings: the cache is full and \
                 an unsolicited packet may not displace an entry."
            );
            stats
                .neighbor_admission_refused
                .set(stats.neighbor_admission_refused.get() + neighbors_refused);
        }

        let syn_rst = iface.take_tcp_syn_rst_unmatched();
        if syn_rst != 0 {
            stats
                .tcp_syn_rst_unmatched
                .set(stats.tcp_syn_rst_unmatched.get() + syn_rst);
        }

        // Suppressions are the limits working as configured under a flood, so
        // they count without logging -- a warn per poll would let the flood
        // write the log.
        let icmp_suppressed = iface.take_icmp_error_suppressed();
        if icmp_suppressed != 0 {
            stats
                .icmp_errors_suppressed
                .set(stats.icmp_errors_suppressed.get() + icmp_suppressed);
        }
        let rst_suppressed = iface.take_tcp_rst_suppressed();
        if rst_suppressed != 0 {
            stats
                .tcp_rst_suppressed
                .set(stats.tcp_rst_suppressed.get() + rst_suppressed);
        }
        let cookies_suppressed = iface.take_tcp_syn_cookies_suppressed();
        if cookies_suppressed != 0 {
            stats
                .tcp_syn_cookies_suppressed
                .set(stats.tcp_syn_cookies_suppressed.get() + cookies_suppressed);
        }

        let syn_dropped = iface.take_tcp_syn_backlog_dropped();
        if syn_dropped != 0 {
            stats
                .tcp_syn_backlog_dropped
                .set(stats.tcp_syn_backlog_dropped.get() + syn_dropped);
            // A dropped request is a listening pool that ran out during this
            // poll, which is the one thing its own socket accounting cannot
            // see (see [`super::backlog::BacklogBudget::refused`]). The
            // netstack drops only for endpoints a listener owns, but the pool
            // can still be gone -- teardown races the poll -- so an address
            // owning no pool is ignored.
            for endpoint in iface.take_tcp_backlog_endpoints() {
                backlog.refused(super::config::socket_addr_from_endpoint(endpoint));
            }
        }

        let cookies_sent = iface.take_tcp_syn_cookies_sent();
        if cookies_sent != 0 {
            stats
                .tcp_syn_cookies_sent
                .set(stats.tcp_syn_cookies_sent.get() + cookies_sent);
        }
        let cookies_rejected = iface.take_tcp_syn_cookies_rejected();
        if cookies_rejected != 0 {
            stats
                .tcp_syn_cookies_rejected
                .set(stats.tcp_syn_cookies_rejected.get() + cookies_rejected);
        }
        let restores_dropped = iface.take_tcp_cookie_restores_dropped();
        if restores_dropped != 0 {
            log::warn!(
                "{name}: dropped {restores_dropped} verified cookie restorations: the per-poll \
                 queue was full."
            );
            stats
                .tcp_cookie_restores_dropped
                .set(stats.tcp_cookie_restores_dropped.get() + restores_dropped);
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
            transmit_waiters: _,
            external: _,
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
        let port = find_ephemeral_port(ephemeral_scan_start(self.external), |port| {
            self.udp_ports_in_use.contains(&port)
        })?;
        self.udp_ports_in_use.insert(port);
        Some(port)
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
        let port = find_ephemeral_port(ephemeral_scan_start(self.external), |port| {
            self.tcp_ports_in_use.contains(&port) || is_reserved(port)
        })?;
        self.tcp_ports_in_use.insert(port);
        Some(port)
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

/// Debug-only tests of the code above, run inside a live sys-io. See
/// [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};

    pub(crate) const TESTS: &[SelfTest] = &[
        (
            "net::device::interfaces_do_not_share_a_seed",
            interfaces_do_not_share_a_seed,
        ),
        (
            "net::device::interfaces_do_not_share_an_isn_key",
            interfaces_do_not_share_an_isn_key,
        ),
        (
            "net::device::only_the_loopback_device_is_a_loopback_iface",
            only_the_loopback_device_is_a_loopback_iface,
        ),
        (
            "net::device::external_ephemeral_ports_are_random",
            external_ephemeral_ports_are_random,
        ),
        (
            "net::device::loopback_ephemeral_ports_are_lowest_free",
            loopback_ephemeral_ports_are_lowest_free,
        ),
        (
            "net::device::the_ephemeral_scan_wraps",
            the_ephemeral_scan_wraps,
        ),
        (
            "net::device::the_frame_mtu_survives_the_round_trip",
            the_frame_mtu_survives_the_round_trip,
        ),
        (
            "net::device::the_timestamp_clock_is_offset_and_advances",
            the_timestamp_clock_is_offset_and_advances,
        ),
        (
            "net::device::a_large_config_is_installed_whole",
            a_large_config_is_installed_whole,
        ),
        (
            "net::device::only_external_devices_rate_limit_egress",
            only_external_devices_rate_limit_egress,
        ),
        (
            "net::device::rx_ring_refills_after_transient_allocation_failure",
            rx_ring_refills_after_transient_allocation_failure,
        ),
        (
            "net::device::tx_queue_is_bounded_and_reopens",
            tx_queue_is_bounded_and_reopens,
        ),
    ];

    /// A minimal parsed `NetConfig`, carrying the compiled-in defaults for
    /// everything the caps and limits read: what a device constructed by
    /// [`super::super::init`] sees when the operator wrote no overrides.
    fn net_cfg() -> config::NetConfig {
        toml::from_str("auto_icmp_echo_reply = false\nloopback = true\n[devices]\n").unwrap()
    }

    /// A failed refill remains recorded and is retried after a later RX
    /// completion makes another allocation opportunity.
    fn rx_ring_refills_after_transient_allocation_failure() -> Result<(), String> {
        let mut deficit = 2;

        let first = allocate_rx_refill(&mut deficit, || Some(1_u8));
        st_assert_eq!(first, Some(1));
        st_assert_eq!(deficit, 1);

        let failed = allocate_rx_refill(&mut deficit, || None::<u8>);
        st_assert_eq!(failed, None);
        st_assert_eq!(deficit, 1);

        let second = allocate_rx_refill(&mut deficit, || Some(2_u8));
        st_assert_eq!(second, Some(2));
        st_assert_eq!(deficit, 0);

        let mut calls = 0;
        st_assert_eq!(
            allocate_rx_refill::<()>(&mut deficit, || {
                calls += 1;
                Some(())
            }),
            None
        );
        st_assert_eq!(calls, 0);
        Ok(())
    }

    /// Admission reserves the largest possible packet, never exceeds its byte
    /// bound, and reports the full-to-writable edge when the device dequeues.
    fn tx_queue_is_bounded_and_reopens() -> Result<(), String> {
        let mut queue = TxQueueState::new(TX_RESERVATION * 2);

        st_assert!(queue.reserve());
        st_assert!(queue.reserve());
        st_assert!(!queue.reserve());
        queue.cancel_reservation();
        st_assert!(queue.reserve());
        queue.cancel_reservation();
        queue.cancel_reservation();
        st_assert_eq!(queue.bytes, 0);

        for _ in 0..2 {
            st_assert!(queue.reserve());
            let packet = IoBuf::new_from_size_align(BIG_BUF_SIZE)
                .ok_or_else(|| "could not allocate TX self-test buffer".to_owned())?;
            queue.push_packet(packet, 0);
        }
        st_assert_eq!(queue.bytes, queue.byte_limit);
        st_assert!(!queue.reserve());

        let (packet, reopened) = queue.pop_front();
        st_assert!(matches!(packet, Some(TxWork::Packet(_, 0))));
        st_assert!(reopened);
        let (packet, reopened) = queue.pop_front();
        st_assert!(matches!(packet, Some(TxWork::Packet(_, 0))));
        st_assert!(!reopened);
        st_assert_eq!(queue.bytes, 0);
        Ok(())
    }

    /// The egress rate limits reach external interfaces and skip loopback.
    ///
    /// Both directions, like the loopback-bit test below: a limiter left off
    /// an external device silently reopens the reflector, and one applied to
    /// loopback silently turns local connects to closed ports into
    /// retransmit stalls. Neither failure announces itself.
    fn only_external_devices_rate_limit_egress() -> Result<(), String> {
        let cfg = net_cfg();

        let external = iface_config(moto_netstack::wire::HardwareAddress::Ip, &cfg, true);
        st_assert_eq!(
            external.icmp_error_rate_limit,
            DEFAULT_MAX_ICMP_ERROR_RATE.get()
        );
        st_assert_eq!(external.tcp_rst_rate_limit, DEFAULT_MAX_RST_RATE.get());
        st_assert_eq!(
            external.tcp_cookie_rate_limit,
            DEFAULT_MAX_SYN_COOKIE_RATE.get()
        );

        let loopback = iface_config(moto_netstack::wire::HardwareAddress::Ip, &cfg, false);
        st_assert_eq!(loopback.icmp_error_rate_limit, 0);
        st_assert_eq!(loopback.tcp_rst_rate_limit, 0);
        st_assert_eq!(loopback.tcp_cookie_rate_limit, 0);
        Ok(())
    }

    /// `/system/cfg/sys-net.toml` names as many addresses and routes as it
    /// likes, and every one of them exists after boot: the interface's tables
    /// grow to the configuration. The two behaviors this replaced -- an
    /// `unwrap()` that took the I/O server down at boot (`0xbadc0de`,
    /// reproduced at three routes against a two-slot table), then
    /// drop-and-log at a fixed eight -- both left the machine routing
    /// something other than what the file says; totality is the property now,
    /// so the count is asserted exact at well past either old capacity.
    fn a_large_config_is_installed_whole() -> Result<(), String> {
        const ENTRIES: usize = 100;

        let mut cfg = config::DeviceCfg::new("02:00:00:00:00:7f");
        for n in 1..=ENTRIES {
            cfg.cidrs.push(
                format!("10.{n}.0.1/16")
                    .parse()
                    .map_err(|e| format!("{}:{}: {e:?}", file!(), line!()))?,
            );
            cfg.routes.push(config::IpRoute {
                ip_network: format!("10.{n}.0.0/16")
                    .parse()
                    .map_err(|e| format!("{}:{}: {e:?}", file!(), line!()))?,
                gateway: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, n as u8, 0, 254)),
            });
        }

        let mut dev = NetDev::new(
            "self-test",
            &cfg,
            &net_cfg(),
            NetstackDevice::Loopback(moto_netstack::phy::Loopback::new(
                moto_netstack::phy::Medium::Ip,
            )),
        );

        st_assert_eq!(dev.iface.ip_addrs().len(), ENTRIES);

        let mut routes = 0;
        dev.iface
            .routes_mut()
            .update(|storage| routes = storage.len());
        st_assert_eq!(routes, ENTRIES);

        Ok(())
    }

    /// [`tsval`]'s contract: the clock is uptime plus a constant drawn once.
    ///
    /// Both halves matter and neither is the netstack's to check. Without the
    /// offset the timestamps on the wire *are* this machine's uptime, told to
    /// every peer. Without tracking the clock they would never advance, which
    /// disables PAWS at the peer as surely as never offering the option --
    /// a TS.Recent that stands still can only ever compare equal.
    ///
    /// Testing the relation rather than the two properties separately is what
    /// lets this run with no wait in it: both terms advance together, so the
    /// difference holds whether or not a millisecond passes in between. (An
    /// earlier version of this comment justified that by saying a boot
    /// self-test must not spend time. The suite is not on the boot path at all
    /// -- `CMD_SELF_TEST` drives it on demand, under `debug_assertions` -- so
    /// the real reason is the plainer one: a test that sleeps buys nothing.)
    fn the_timestamp_clock_is_offset_and_advances() -> Result<(), String> {
        tsval::init();

        let offset_of = || {
            tsval::tick();
            let now = tsval::generator();
            let uptime = moto_rt::time::since_system_start().as_millis() as u32;
            now.wrapping_sub(uptime)
        };

        let first = offset_of();
        // Zero is what an unoffset clock reads, and only a 1-in-2^32 draw.
        st_assert!(first != 0);

        // A clock that ignored `tick` would drift away from this by exactly the
        // milliseconds in between; one that tracked something other than
        // uptime would not hold the relation at all. One tick of slack, for the
        // two reads inside `offset_of` landing either side of a millisecond.
        let second = offset_of();
        st_assert!(second.wrapping_sub(first) <= 1);

        Ok(())
    }

    /// What [`frame_mtu`] puts in must be what the netstack takes back out.
    ///
    /// The units are the whole bug: `max_transmission_unit` is a frame and the
    /// virtio MTU is a packet, and the 14 bytes between them reach the wire as
    /// the advertised MSS. Going through `ip_mtu()` rather than re-deriving the
    /// arithmetic is the point -- that accessor is the other half of the
    /// contract, and a test that did its own subtraction would agree with a
    /// wrong answer.
    fn the_frame_mtu_survives_the_round_trip() -> Result<(), String> {
        let ip_mtu_of = |frame: usize| {
            let mut caps = moto_netstack::phy::DeviceCapabilities::default();
            caps.medium = moto_netstack::phy::Medium::Ethernet;
            caps.max_transmission_unit = frame;
            caps.ip_mtu()
        };

        for reported in [None, Some(1500_u16), Some(576), Some(MAX_IP_MTU)] {
            st_assert_eq!(
                ip_mtu_of(frame_mtu(reported)),
                reported.unwrap_or(DEFAULT_IP_MTU) as usize
            );
        }

        // A device that says nothing is an ordinary Ethernet link, so the
        // default has to be the ordinary answer: a 1514-byte frame and IPv4 MSS
        // 1460. The fallback this replaced gave 1536 and 1482, which is 22
        // bytes more than a 1500-byte link carries.
        st_assert_eq!(frame_mtu(None), 1514);
        st_assert_eq!(ip_mtu_of(frame_mtu(None)) - 20 - 20, 1460);

        // A jumbo link is capped, not honored: the receive path posts
        // SMALL_BUF_SIZE buffers and cannot take delivery of more, so promising
        // a peer more would be promising what we cannot receive.
        st_assert_eq!(ip_mtu_of(frame_mtu(Some(9000))), MAX_IP_MTU as usize);
        st_assert!(frame_mtu(Some(9000)) <= SMALL_BUF_SIZE);

        // Below the smallest usable link the device is not believed at all: the
        // netstack's own MSS arithmetic underflows down there, and sys-io
        // aborts on panic.
        st_assert_eq!(ip_mtu_of(frame_mtu(Some(68))), DEFAULT_IP_MTU as usize);
        st_assert_eq!(ip_mtu_of(frame_mtu(Some(0))), DEFAULT_IP_MTU as usize);
        Ok(())
    }

    /// How many interfaces one process's worth of configurations stands in for.
    const DEVICES: usize = 8;

    /// Every interface is seeded independently, and not from the clock.
    ///
    /// [`iface_config`] is the single source of a seed, so what two devices
    /// would receive is what taking two configurations here produces. The high
    /// half is checked separately because that is where a clock-derived seed
    /// betrays itself: wall-clock nanoseconds advance through the low bits, so
    /// draws taken moments apart share their top 32 bits for seconds at a time.
    /// Against a working RNG both checks fail with probability below 1e-8.
    fn interfaces_do_not_share_a_seed() -> Result<(), String> {
        let seeds: [u64; DEVICES] = core::array::from_fn(|_| {
            iface_config(moto_netstack::wire::HardwareAddress::Ip, &net_cfg(), true).random_seed
        });

        all_distinct(seeds, "seed")?;
        all_distinct(seeds.map(|seed| seed >> 32), "seed's high half")
    }

    /// Every interface's RFC 6528 key is drawn independently.
    ///
    /// This key is what keeps one peer from computing the sequence numbers of
    /// connections it cannot see, so a key shared between interfaces -- or one
    /// left at [`moto_netstack::iface::Config`]'s all-zero default -- gives the
    /// whole property away silently. Distinctness catches both.
    fn interfaces_do_not_share_an_isn_key() -> Result<(), String> {
        let keys: [[u8; 16]; DEVICES] = core::array::from_fn(|_| {
            iface_config(moto_netstack::wire::HardwareAddress::Ip, &net_cfg(), true).tcp_isn_key
        });

        all_distinct(keys, "TCP ISN key")
    }

    /// Only the loopback device is configured as a loopback interface.
    ///
    /// Everything the netstack decides from that bit -- today, refusing
    /// loopback addresses on ingress -- turns on this one call, and a wrong bit is
    /// silent: the machine keeps working and merely stops refusing. Both
    /// directions, since either one alone is satisfied by a constant.
    fn only_the_loopback_device_is_a_loopback_iface() -> Result<(), String> {
        for external in [true, false] {
            let config = iface_config(
                moto_netstack::wire::HardwareAddress::Ip,
                &net_cfg(),
                external,
            );
            if config.loopback == external {
                return Err(format!(
                    "{}:{}: a device with external={external} was configured loopback={}",
                    file!(),
                    line!(),
                    config.loopback
                ));
            }
        }

        Ok(())
    }

    /// How many starts one round of the randomization check takes.
    const STARTS: usize = 16;

    /// An external device starts its scan somewhere unpredictable.
    ///
    /// Ascending order is the shape every way of getting this wrong produces:
    /// a stuck entropy source repeats one start, and losing the randomization
    /// altogether pins every start to the bottom of the range. Sixteen draws
    /// from a working source land in ascending order with probability 1/16!,
    /// about 5e-14.
    fn external_ephemeral_ports_are_random() -> Result<(), String> {
        let starts: [u16; STARTS] = core::array::from_fn(|_| ephemeral_scan_start(true));

        if let Some(port) = starts.iter().find(|port| !is_ephemeral(**port)) {
            return Err(format!(
                "{}:{}: start {port} is outside the ephemeral range",
                file!(),
                line!()
            ));
        }
        if starts.is_sorted() {
            return Err(format!(
                "{}:{}: {STARTS} scan starts came out in ascending order, so they are not \
                 random: {starts:?}",
                file!(),
                line!()
            ));
        }

        Ok(())
    }

    /// A loopback device keeps allocating the lowest free port, which is what
    /// makes systest's `test_simultaneous_open` deterministic: the port a
    /// just-released listener held is the port the next connect is given.
    fn loopback_ephemeral_ports_are_lowest_free() -> Result<(), String> {
        let mut taken = std::collections::HashSet::new();
        for expected in EPHEMERAL_PORT_MIN..(EPHEMERAL_PORT_MIN + 4) {
            let port =
                find_ephemeral_port(ephemeral_scan_start(false), |port| taken.contains(&port))
                    .ok_or_else(|| format!("{}:{}: the range ran out", file!(), line!()))?;
            if port != expected {
                return Err(format!(
                    "{}:{}: loopback allocated {port}, not the lowest free {expected}",
                    file!(),
                    line!()
                ));
            }
            taken.insert(port);
        }

        Ok(())
    }

    /// A scan that starts high still finds a port low in the range, so
    /// randomizing the start does not cost the exhaustiveness the lowest-free
    /// search had. Both edges: the last port of the range, and the wrap past
    /// it that only a range-relative offset gets right.
    fn the_ephemeral_scan_wraps() -> Result<(), String> {
        let only = |wanted: u16| move |port: u16| port != wanted;

        for wanted in [EPHEMERAL_PORT_MAX, EPHEMERAL_PORT_MIN] {
            let found = find_ephemeral_port(EPHEMERAL_PORT_MAX, only(wanted));
            if found != Some(wanted) {
                return Err(format!(
                    "{}:{}: a scan from {EPHEMERAL_PORT_MAX} for the only free port {wanted} \
                     found {found:?}",
                    file!(),
                    line!()
                ));
            }
        }

        if find_ephemeral_port(EPHEMERAL_PORT_MAX, |_| true).is_some() {
            return Err(format!(
                "{}:{}: a fully occupied range still yielded a port",
                file!(),
                line!()
            ));
        }

        Ok(())
    }

    fn is_ephemeral(port: u16) -> bool {
        (EPHEMERAL_PORT_MIN..=EPHEMERAL_PORT_MAX).contains(&port)
    }

    /// Fails naming both draws that matched, so a stuck source is obvious.
    fn all_distinct<T: PartialEq + core::fmt::Debug>(
        values: [T; DEVICES],
        what: &str,
    ) -> Result<(), String> {
        for (i, value) in values.iter().enumerate() {
            if let Some(j) = values[i + 1..].iter().position(|other| other == value) {
                return Err(format!(
                    "{}:{}: draws {i} and {} share a {what}: {value:02x?}",
                    file!(),
                    line!(),
                    i + 1 + j
                ));
            }
        }

        Ok(())
    }
}
