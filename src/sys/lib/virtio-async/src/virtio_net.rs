use core::mem::offset_of;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;

use moto_sys::sys_mem::PAGE_SIZE_SMALL;
use moto_tooling::iobuf::IoBuf;

use super::le16;
use super::pci::PciBar;
use super::virtio_device::VirtioDevice;
use crate::WriteCompletion;
use crate::virtio_queue::ReadCompletion;
use crate::virtio_queue::Virtqueue;
use crate::virtio_queue::VqAlloc;

// Feature bits.
const VIRTIO_NET_F_CSUM: u64 = 1_u64 << 0;
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1_u64 << 1;
const VIRTIO_NET_F_MTU: u64 = 1_u64 << 3;
const VIRTIO_NET_F_HOST_TSO4: u64 = 1_u64 << 11;
const VIRTIO_NET_F_HOST_TSO6: u64 = 1_u64 << 12;
const VIRTIO_NET_F_MAC: u64 = 1_u64 << 5;
#[allow(unused)]
const VIRTIO_NET_F_STATUS: u64 = 1_u64 << 16;

#[allow(unused)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: le16,
    max_virtqueue_pairs: le16,
    mtu: le16,
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct NetHeader {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

pub(super) const NET_HEADER_LEN: usize = core::mem::size_of::<NetHeader>();

/// The packet's L4 checksum field holds the pseudo-header sum; the device
/// (or the host stack, lazily) completes the checksum.
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

// NetHeader::gso_type values (virtio 1.1 §5.1.6.2).
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// The most data descriptors one TX packet may need: buffers are
/// physically contiguous only within 4K pages, so a 64K (max) buffer
/// spans at most 17 pages (16 + 1 if the start is not page-aligned).
const MAX_TX_RUNS: usize = 17;

/// The most descriptors one post_write may consume (header + data runs).
/// The caller MUST keep at least this many descriptors free (see
/// post_write's return value) or post_write can deadlock: descriptors of
/// completed chains are only released when their completions are dropped,
/// so a task that blocks inside post_write while holding unreaped
/// completions starves itself forever.
pub const MAX_TX_DESCS: usize = 1 + MAX_TX_RUNS;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

/// What maybe_set_needs_csum learned about an egress TCP packet; feeds the
/// TSO fields in post_write.
struct TcpTxInfo {
    csum_start: u16, // Ethernet + IP header lengths.
    ipv6: bool,
}

/// TX checksum offload (VIRTIO_NET_F_CSUM): smoltcp is told (via sys-io's
/// ChecksumCapabilities) not to compute TCP checksums — it zeroes the field
/// — so every egress TCP packet must get VIRTIO_NET_HDR_F_NEEDS_CSUM here:
/// seed the checksum field with the TCP pseudo-header sum and point the
/// device at it (virtio 1.1 §5.1.6.2). Everything else (ARP, ICMP, UDP,
/// IPv4 headers) is still fully checksummed by smoltcp and passes through
/// with flags == 0 (and `None` returned). UDP is deliberately not
/// offloaded: a fragmented UDP datagram carries its L4 header only in the
/// first fragment, which NEEDS_CSUM cannot describe.
fn maybe_set_needs_csum(packet: &mut [u8], header: &mut NetHeader) -> Option<TcpTxInfo> {
    const ETH: usize = 14; // dst(6) + src(6) + ethertype(2)
    const TCP_CSUM_OFFSET: u16 = 16; // checksum position in the TCP header
    const TCP: u8 = 6;

    if packet.len() < ETH + 40 {
        // Smaller than the smallest (IPv4 + TCP) header pair.
        return None;
    }

    // (csum_start, ones'-complement pseudo-header sum), or not ours.
    let (csum_start, mut sum): (usize, u32) = match u16::from_be_bytes([packet[12], packet[13]])
    {
        ETHERTYPE_IPV4 => {
            let ip = &packet[ETH..];
            let ihl = ((ip[0] & 0xf) as usize) * 4;
            let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
            if ip[0] >> 4 != 4
                || ihl < 20
                || total_len < ihl + 20
                || ETH + total_len > packet.len()
                || ip[9] != TCP
                // A fragment's checksum can't be offloaded; smoltcp never
                // fragments TCP, but be safe: reject a set MF flag or a
                // nonzero fragment offset (DF is fine).
                || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
            {
                return None;
            }
            let mut sum = TCP as u32 + (total_len - ihl) as u32; // proto + TCP len
            for word in ip[12..20].chunks_exact(2) {
                // src + dst addresses
                sum += u16::from_be_bytes([word[0], word[1]]) as u32;
            }
            (ETH + ihl, sum)
        }
        ETHERTYPE_IPV6 => {
            let ip = &packet[ETH..];
            let payload_len = u16::from_be_bytes([ip[4], ip[5]]) as usize;
            if ip[0] >> 4 != 6
                // TCP as the direct next header only — smoltcp emits no
                // extension headers for TCP.
                || ip[6] != TCP
                || payload_len < 20
                || ETH + 40 + payload_len > packet.len()
            {
                return None;
            }
            let mut sum = TCP as u32 + payload_len as u32; // next-hdr + TCP len
            for word in ip[8..40].chunks_exact(2) {
                // src + dst addresses
                sum += u16::from_be_bytes([word[0], word[1]]) as u32;
            }
            (ETH + 40, sum)
        }
        _ => return None, // ARP etc. — fully checksummed by the stack.
    };

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Seed the TCP checksum field with the pseudo-header sum, NOT
    // complemented: whoever completes the checksum sums [csum_start..]
    // with this field as-is and stores the complement.
    let csum_field = csum_start + TCP_CSUM_OFFSET as usize;
    packet[csum_field] = (sum >> 8) as u8;
    packet[csum_field + 1] = sum as u8;

    header.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header.csum_start = csum_start as u16;
    header.csum_offset = TCP_CSUM_OFFSET;

    Some(TcpTxInfo {
        csum_start: csum_start as u16,
        ipv6: packet[12] == 0x86,
    })
}

pub struct NetDevice {
    dev: Rc<RefCell<VirtioDevice>>,
    mac: [u8; 6],
    mtu: Option<u16>,
    csum_offload: bool,
    tso: bool, // Both HOST_TSO4 and HOST_TSO6 negotiated.
    virtq_tx: Rc<RefCell<Virtqueue>>,
    virtq_rx: Rc<RefCell<Virtqueue>>,
}

impl Drop for NetDevice {
    fn drop(&mut self) {
        log::error!("VirtIO NetDev must not be dropped: RxPackets reference it statically.");
    }
}

unsafe impl Send for NetDevice {}

static NET_DEVICES: moto_rt::spinlock::SpinLock<Vec<NetDevice>> =
    moto_rt::spinlock::SpinLock::new(Vec::new());

impl NetDevice {
    const VIRTQ_RX: usize = 0;
    const VIRTQ_TX: usize = 1;

    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    pub fn rxq_sz(&self) -> u16 {
        // We consume two slots on rx, so for outsiders rxq size is half of virtq sz.
        self.virtq_rx.borrow().queue_size() / 2
    }

    pub fn txq_sz(&self) -> u16 {
        // We consume two slots on tx, so for outsiders txq size is half of virtq sz.
        self.virtq_tx.borrow().queue_size() / 2
    }

    pub fn from(dev: VirtioDevice) -> Result<Rc<Self>> {
        let dev = Rc::new(RefCell::new(dev));
        let dev_clone = dev.clone();

        Self::init(dev).inspect_err(|err| {
            dev_clone.borrow_mut().mark_failed();
            log::error!("Failed initializing VirtIO Net device");
        })
    }

    fn init(dev: Rc<RefCell<VirtioDevice>>) -> Result<Rc<Self>> {
        let mut dev_mut = dev.borrow_mut();
        dev_mut.init();
        dev_mut.reset();
        dev_mut.acknowledge_device();

        dev_mut.acknowledge_driver(); // Step 3
        let (mac, mtu) = Self::negotiate_features(&mut dev_mut)?; // Steps 4, 5, 6
        let csum_offload = (dev_mut.virtio_features_negotiated & VIRTIO_NET_F_CSUM) != 0;
        let tso = (dev_mut.virtio_features_negotiated
            & (VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6))
            == (VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6);
        dev_mut.init_virtqueues(2, 2)?; // Step 7
        dev_mut.driver_ok(); // Step 8

        if dev_mut.device_cfg.is_none() {
            log::warn!("Skiping Virtio NET device without device configuration.");
            return Err(ErrorKind::Other.into());
        }

        let virtq_rx = dev_mut.virtqueues[Self::VIRTQ_RX].clone();
        let virtq_tx = dev_mut.virtqueues[Self::VIRTQ_TX].clone();

        drop(dev_mut);

        Ok(Rc::new(NetDevice {
            dev,
            mac,
            mtu,
            csum_offload,
            tso,
            virtq_rx,
            virtq_tx,
        }))
    }

    // Step 4. Returns mac, mtu
    fn negotiate_features(dev: &mut VirtioDevice) -> Result<([u8; 6], Option<u16>)> {
        let features_available = dev.get_available_features();
        let mut features_acked = 0_u64;

        // NOTE: neither CHV nor QEMU have VIRTIO_F_IN_ORDER available.
        #[cfg(debug_assertions)]
        log::debug!("NET features available: 0x{features_available:x}");

        if (features_available & super::virtio_device::VIRTIO_F_VERSION_1) == 0 {
            log::warn!(
                "Virtio NET device {:?}: VIRTIO_F_VERSION_1 feature not available; features: 0x{:x}.",
                dev.pci_device.id,
                features_available
            );
            return Err(ErrorKind::Other.into());
        }
        features_acked |= super::virtio_device::VIRTIO_F_VERSION_1;

        if (features_available & VIRTIO_NET_F_MTU) != 0 {
            features_acked |= VIRTIO_NET_F_MTU;
        }

        if (features_available & VIRTIO_NET_F_MAC) == 0 {
            log::warn!(
                "Virtio NET device {:?}: VIRTIO_NET_F_MAC feature not available; features: 0x{:x}.",
                dev.pci_device.id,
                features_available
            );
            return Err(ErrorKind::Other.into());
        }
        features_acked |= VIRTIO_NET_F_MAC;

        if (features_available & super::virtio_device::VIRTIO_F_RING_EVENT_IDX) != 0 {
            log::debug!(
                "Virtio NET device {:?}:\n\tVIRTIO_F_RING_EVENT_IDX feature IS available.",
                dev.pci_device.id,
            );
            features_acked |= super::virtio_device::VIRTIO_F_RING_EVENT_IDX;
        } else {
            log::debug!(
                "Virtio NET device {:?}:\n\tVIRTIO_F_RING_EVENT_IDX feature is NOT available.",
                dev.pci_device.id,
            );
        }

        /*
        if (features_available & VIRTIO_NET_F_STATUS) == 0 {
            log::warn!(
                "Virtio NET device {:?}: VIRTIO_NET_F_STATUS feature not available; features: 0x{:x}.",
                self.dev.pci_device.id,
                features_available
            );
            return Err(());
        }
        */

        // VIRTIO_NET_F_GUEST_CSUM: the driver accepts packets with partial
        // checksums. Once negotiated, the device may deliver packets flagged
        // VIRTIO_NET_HDR_F_NEEDS_CSUM whose L4 checksum field holds only the
        // pseudo-header sum (host-originated traffic; the host kernel vouches
        // for the payload and skips its software checksum-completion pass) or
        // VIRTIO_NET_HDR_F_DATA_VALID (the device already verified). Either
        // way the driver must NOT software-verify L4 checksums on RX;
        // sys-io keys smoltcp's ChecksumCapabilities off guest_csum().
        if (features_available & VIRTIO_NET_F_GUEST_CSUM) != 0 {
            features_acked |= VIRTIO_NET_F_GUEST_CSUM;
            log::info!("virtio-net: VIRTIO_NET_F_GUEST_CSUM negotiated.");
        }

        // VIRTIO_NET_F_CSUM: the device completes partially-checksummed
        // packets from the driver (virtio 1.1 §5.1.6.2): flags has
        // VIRTIO_NET_HDR_F_NEEDS_CSUM set, the L4 checksum field is seeded
        // with the pseudo-header sum, and csum_start/csum_offset point at
        // it. post_write derives all three by parsing its own egress
        // packet (maybe_set_needs_csum below), freeing the network stack
        // from a full write-side pass over TX payload — sys-io keys its
        // smoltcp ChecksumCapabilities off csum_offload(). Bonus: for
        // host-local delivery the checksum is typically never computed by
        // anyone at all (the host keeps the packet CHECKSUM_PARTIAL).
        if (features_available & VIRTIO_NET_F_CSUM) != 0 {
            features_acked |= VIRTIO_NET_F_CSUM;
            log::info!("virtio-net: VIRTIO_NET_F_CSUM negotiated.");
        }

        // VIRTIO_NET_F_HOST_TSO4/6: the device accepts TCP "super-segments"
        // (up to 64K in one packet, NetHeader.gso_size = the wire MSS) and
        // segments them itself; for host-local delivery the packet is
        // typically consumed whole, never segmented at all. Requires F_CSUM
        // (§5.1.3.1): per-segment checksum completion starts from the
        // seeded pseudo-header sum.
        if (features_acked & VIRTIO_NET_F_CSUM) != 0 {
            if (features_available & VIRTIO_NET_F_HOST_TSO4) != 0 {
                features_acked |= VIRTIO_NET_F_HOST_TSO4;
                log::info!("virtio-net: VIRTIO_NET_F_HOST_TSO4 negotiated.");
            }
            if (features_available & VIRTIO_NET_F_HOST_TSO6) != 0 {
                features_acked |= VIRTIO_NET_F_HOST_TSO6;
                log::info!("virtio-net: VIRTIO_NET_F_HOST_TSO6 negotiated.");
            }
        }

        dev.write_enabled_features(features_acked);
        dev.confirm_features()?;
        dev.virtio_features_negotiated = features_acked;

        let device_cfg = dev.device_cfg.as_ref().unwrap();
        let cfg_bar: &PciBar = dev.pci_device.bars[device_cfg.bar as usize]
            .as_ref()
            .unwrap();

        let mut mac: [u8; 6] = [0; 6];
        for (index, b) in mac.iter_mut().enumerate() {
            *b = cfg_bar.readb(device_cfg.offset as u64 + index as u64);
        }

        log::debug!("NET MAC: {:02x?}", mac);

        let mtu = if (features_acked & VIRTIO_NET_F_MTU) != 0 {
            let mtu = cfg_bar
                .read_u16(device_cfg.offset as u64 + offset_of!(VirtioNetConfig, mtu) as u64);
            if mtu < 68 {
                log::error!(
                    "Virtio NET device {:?}: bad MTU: {}.",
                    dev.pci_device.id,
                    mtu
                );
                return Err(ErrorKind::Other.into());
            }

            Some(mtu)
        } else {
            None
        };

        Ok((mac, mtu))
    }

    pub fn mtu(&self) -> Option<u16> {
        self.mtu
    }

    /// True if VIRTIO_NET_F_GUEST_CSUM was negotiated: received TCP/UDP
    /// packets must be accepted without software checksum verification
    /// (their L4 checksum field may hold only the pseudo-header sum).
    pub fn guest_csum(&self) -> bool {
        (self.dev.borrow().virtio_features_negotiated & VIRTIO_NET_F_GUEST_CSUM) != 0
    }

    /// True if VIRTIO_NET_F_CSUM was negotiated: post_write offloads TCP
    /// checksums (NEEDS_CSUM + pseudo-header seed), so the network stack
    /// must not compute them.
    pub fn csum_offload(&self) -> bool {
        self.csum_offload
    }

    /// True if TCP segmentation offload was negotiated for BOTH IP versions
    /// (VIRTIO_NET_F_HOST_TSO4 + HOST_TSO6): post_write accepts TCP
    /// super-segments with a nonzero tso_seg_size. Both are required
    /// because the network stack's TSO capability is not per-IP-version.
    pub fn tso(&self) -> bool {
        self.tso
    }

    #[inline(never)]
    pub async fn post_read(self: Rc<Self>, mut bytes: IoBuf) -> ReadCompletion<IoBuf> {
        let chain_head = VqAlloc::new(self.virtq_rx.clone(), 2).await;
        let mut virtqueue = self.virtq_rx.borrow_mut();

        let (header, phys_addr, next_idx) = virtqueue.get_buffer::<NetHeader>(chain_head);
        *header = NetHeader::default();

        use super::virtio_queue::UserData;
        let buffs: [UserData; 2] = [
            UserData {
                phys_addr,
                len: core::mem::size_of::<NetHeader>() as u32,
            },
            UserData {
                phys_addr: bytes.phys_addr() as u64,
                len: bytes.len() as u32,
            },
        ];

        drop(virtqueue);

        const RX_SIZE_ADJUSTOR: fn(u32) -> u32 =
            |val| val - (core::mem::size_of::<NetHeader>() as u32);

        let vq_completion =
            Virtqueue::add_buffs(self.virtq_rx.clone(), &buffs, 0, 2, chain_head, bytes);

        ReadCompletion {
            vq_completion,
            size_adjustor: RX_SIZE_ADJUSTOR,
        }
    }

    /// Post one egress packet. `tso_seg_size != 0` marks a TCP
    /// super-segment (payload larger than the connection's MSS) that the
    /// device must split into wire segments of at most `tso_seg_size`
    /// payload bytes each; the caller may only pass nonzero values when
    /// `tso()` is true.
    ///
    /// Returns the completion and the number of descriptors the packet
    /// occupies (released when the completion is dropped after resolving).
    /// The caller must ensure MAX_TX_DESCS descriptors are free before
    /// calling — see MAX_TX_DESCS.
    #[inline(never)]
    pub async fn post_write(
        self: Rc<Self>,
        mut bytes: IoBuf,
        tso_seg_size: u16,
    ) -> (WriteCompletion<IoBuf>, usize) {
        use super::virtio_queue::UserData;

        // Split the packet into physically-contiguous runs: the buffer is
        // physically contiguous only within 4K pages (phys addrs are
        // cached on the pooled buffer, so this loop does no syscalls in
        // steady state). Runs that happen to be phys-adjacent merge.
        let len = bytes.len();
        let mut runs = [UserData {
            phys_addr: 0,
            len: 0,
        }; MAX_TX_RUNS];
        let mut num_runs = 0_usize;
        let mut offset = 0_usize;
        while offset < len {
            let phys = bytes.phys_addr_at(offset);
            let run_len = ((PAGE_SIZE_SMALL as usize) - (phys as usize & 0xfff)).min(len - offset);
            if num_runs > 0
                && runs[num_runs - 1].phys_addr + runs[num_runs - 1].len as u64 == phys
            {
                runs[num_runs - 1].len += run_len as u32;
            } else {
                runs[num_runs] = UserData {
                    phys_addr: phys,
                    len: run_len as u32,
                };
                num_runs += 1;
            }
            offset += run_len;
        }

        let chain_head = VqAlloc::new(self.virtq_tx.clone(), (1 + num_runs) as u16).await;
        let mut virtqueue = self.virtq_tx.borrow_mut();

        let (header, phys_addr, _next_idx) = virtqueue.get_buffer::<NetHeader>(chain_head);
        *header = NetHeader::default();
        if self.csum_offload {
            let tcp_info = maybe_set_needs_csum(bytes.as_mut(), header);
            if tso_seg_size != 0 {
                // The stack only marks TCP packets as super-segments, and
                // the parse above recognizes every TCP packet it emits.
                let info = tcp_info.expect("TSO packet did not parse as TCP");
                let packet: &[u8] = bytes.as_ref();
                let csum_start = info.csum_start as usize;
                // TCP data offset: header length including options.
                let tcp_hdr_len = ((packet[csum_start + 12] >> 4) as u16) * 4;
                header.gso_type = if info.ipv6 {
                    VIRTIO_NET_HDR_GSO_TCPV6
                } else {
                    VIRTIO_NET_HDR_GSO_TCPV4
                };
                header.gso_size = tso_seg_size;
                header.hdr_len = info.csum_start + tcp_hdr_len;
            }
        }

        let mut buffs = [UserData {
            phys_addr: 0,
            len: 0,
        }; 1 + MAX_TX_RUNS];
        buffs[0] = UserData {
            phys_addr,
            len: core::mem::size_of::<NetHeader>() as u32,
        };
        buffs[1..1 + num_runs].copy_from_slice(&runs[..num_runs]);

        drop(virtqueue);
        let vq_completion = Virtqueue::add_buffs(
            self.virtq_tx.clone(),
            &buffs[..1 + num_runs],
            (1 + num_runs) as u16,
            0,
            chain_head,
            bytes,
        );

        (WriteCompletion { vq_completion }, 1 + num_runs)
    }
}
