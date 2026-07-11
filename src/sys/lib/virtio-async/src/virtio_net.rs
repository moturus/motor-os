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

pub struct NetDevice {
    dev: Rc<RefCell<VirtioDevice>>,
    mac: [u8; 6],
    mtu: Option<u16>,
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

        if (features_available & VIRTIO_NET_F_CSUM) == VIRTIO_NET_F_CSUM {
            // Note: in VirtIO 1.1. spec, section 5.1.6.2, it says:
            /*
                If the driver negotiated VIRTIO_NET_F_CSUM, it can skip checksumming the packet:
                • flags has the VIRTIO_NET_HDR_F_NEEDS_CSUM set,
                • csum_start is set to the offset within the packet to begin checksumming, and
                • csum_offset indicates how many bytes after the csum_start the new (16 bit ones’ complement)
                checksum is placed by the device.
                • The TCP checksum field in the packet is set to the sum of the TCP pseudo header, so that replacing
                it by the ones’ complement checksum of the TCP header and body will give the correct result.
                Note: For example, consider a partially checksummed TCP (IPv4) packet. It will have a 14 byte ether-
                net header and 20 byte IP header followed by the TCP header (with the TCP checksum field 16
                bytes into that header). csum_start will be 14+20 = 34 (the TCP checksum includes the header),
                and csum_offset will be 16.
            */
            // Basically, that means that the header should be populated with the knowledge of the packet structure,
            // i.e. passed in; but smoltcp does not expose this capability, so we can't offload checksums at the moment.
            log::debug!("{}:{} - VIRTIO_NET_F_CSUM.", file!(), line!());
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

    #[inline(never)]
    pub async fn post_write(self: Rc<Self>, bytes: IoBuf) -> WriteCompletion<IoBuf> {
        let chain_head = VqAlloc::new(self.virtq_tx.clone(), 2).await;
        let mut virtqueue = self.virtq_tx.borrow_mut();

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
        let vq_completion =
            Virtqueue::add_buffs(self.virtq_tx.clone(), &buffs, 2, 0, chain_head, bytes);

        WriteCompletion { vq_completion }
    }
}
