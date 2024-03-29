use super::pci::PciBar;
use super::virtio_device::VirtioDevice;

// Feature bits.
const VIRTIO_NET_F_CSUM: u64 = 1_u64 << 0;
const VIRTIO_NET_F_MAC: u64 = 1_u64 << 5;
#[allow(unused)]
const VIRTIO_NET_F_STATUS: u64 = 1_u64 << 16;

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct Header {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

pub struct NetDev {
    dev: alloc::boxed::Box<VirtioDevice>,
    mac: [u8; 6],
}

static NET_DEVICES: spin::Mutex<alloc::vec::Vec<alloc::sync::Arc<NetDev>>> =
    spin::Mutex::new(alloc::vec::Vec::new());

impl NetDev {
    const VIRTQ_RX: usize = 0;
    const VIRTQ_TX: usize = 1;

    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    fn self_init(&mut self) -> Result<(), ()> {
        self.dev.acknowledge_driver(); // Step 3
        self.negotiate_features()?; // Steps 4, 5, 6
        self.dev.init_virtqueues(2, 2)?; // Step 7
        self.dev.driver_ok(); // Step 8
        Ok(())
    }

    pub(super) fn init(dev: alloc::boxed::Box<VirtioDevice>) {
        if dev.device_cfg.is_none() {
            log::warn!("Skiping Virtio NET device without device configuration.");
            return;
        }

        let mut net = NetDev { dev, mac: [0; 6] };

        if net.self_init().is_ok() {
            log::debug!("Initialized Virtio NET device {:?}.", net.dev.pci_device.id,);
            #[cfg(debug_assertions)]
            moto_sys::syscalls::SysMem::log("Initialized Virtio NET device.").ok();
            NET_DEVICES.lock().push(alloc::sync::Arc::new(net));
        } else {
            moto_sys::syscalls::SysMem::log("Failed to initialize Virtio NET device.").ok();
            net.dev.mark_failed();
        }
    }

    // Step 4
    fn negotiate_features(&mut self) -> Result<(), ()> {
        let features_available = self.dev.get_available_features();
        #[cfg(debug_assertions)]
        moto_sys::syscalls::SysMem::log(
            alloc::format!("NET features available: 0x{:x}", features_available).as_str(),
        )
        .ok();

        if (features_available & super::virtio_device::VIRTIO_F_VERSION_1) == 0 {
            log::warn!("Virtio NET device {:?}: VIRTIO_F_VERSION_1 feature not available; features: 0x{:x}.",
                self.dev.pci_device.id, features_available);
            return Err(());
        }

        if (features_available & VIRTIO_NET_F_MAC) == 0 {
            log::warn!(
                "Virtio NET device {:?}: VIRTIO_NET_F_MAC feature not available; features: 0x{:x}.",
                self.dev.pci_device.id,
                features_available
            );
            return Err(());
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

        let features_acked = super::virtio_device::VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC; // | VIRTIO_NET_F_STATUS;
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

        self.dev.write_enabled_features(features_acked);
        self.dev.confirm_features()?;

        let device_cfg = self.dev.device_cfg.as_ref().unwrap();
        let cfg_bar: &PciBar = self.dev.pci_device.bars[device_cfg.bar as usize]
            .as_ref()
            .unwrap();

        for (index, b) in self.mac.iter_mut().enumerate() {
            *b = cfg_bar.readb(device_cfg.offset as u64 + index as u64);
        }

        log::debug!("NET MAC: {:02x?}", self.mac);

        Ok(())
    }

    pub fn wait_handles(&self) -> alloc::vec::Vec<crate::WaitHandle> {
        let mut result = alloc::vec::Vec::new();
        for q in &self.dev.virtqueues {
            for h in &*q.lock().wait_handles() {
                result.push(*h);
            }
        }

        result
    }

    #[inline(never)]
    pub fn post_receive(&self, buf: &mut [u8]) -> Result<(), ()> {
        use super::virtio_queue::UserData;
        let user_data = UserData {
            addr: buf.as_mut_ptr() as usize as u64,
            len: buf.len() as u32,
        };

        assert_eq!(self.dev.virtqueues.len(), 2);
        let mut virtqueue = self.dev.virtqueues[Self::VIRTQ_RX].lock();

        virtqueue.add_buf(&[user_data], 0, 1);

        // Notify
        let notify_cap = self.dev.notify_cfg.unwrap();
        let cfg_bar: &PciBar = self.dev.pci_device.bars[notify_cap.bar as usize]
            .as_ref()
            .unwrap();
        let notify_offset = notify_cap.offset as u64
            + (notify_cap.notify_off_multiplier as u64 * virtqueue.queue_notify_off as u64);

        cfg_bar.write_u16(notify_offset, virtqueue.queue_num);
        Ok(())
    }

    #[inline(never)]
    pub fn consume_receive(&self) -> u32 {
        assert_eq!(self.dev.virtqueues.len(), 2);
        let mut virtqueue = self.dev.virtqueues[Self::VIRTQ_RX].lock();

        virtqueue.consume_used()
    }

    #[inline(never)]
    pub fn post_send(&self, header: &mut Header, buf: &[u8]) -> Result<(), ()> {
        use super::virtio_queue::UserData;

        *header = Header::default();

        let buffs: [UserData; 2] = [
            UserData {
                addr: header as *const Header as usize as u64,
                len: core::mem::size_of::<Header>() as u32,
            },
            UserData {
                addr: buf.as_ptr() as usize as u64,
                len: buf.len() as u32,
            },
        ];

        assert_eq!(self.dev.virtqueues.len(), 2);
        let mut virtqueue = self.dev.virtqueues[Self::VIRTQ_TX].lock();

        virtqueue.add_buf(&buffs, 2, 0);

        // Notify
        let notify_cap = self.dev.notify_cfg.unwrap();
        let cfg_bar: &PciBar = self.dev.pci_device.bars[notify_cap.bar as usize]
            .as_ref()
            .unwrap();
        let notify_offset = notify_cap.offset as u64
            + (notify_cap.notify_off_multiplier as u64 * virtqueue.queue_notify_off as u64);

        cfg_bar.write_u16(notify_offset, virtqueue.queue_num);
        Ok(())
    }

    #[inline(never)]
    pub fn poll_send(&self) -> bool {
        assert_eq!(self.dev.virtqueues.len(), 2);
        let mut virtqueue = self.dev.virtqueues[Self::VIRTQ_TX].lock();

        if virtqueue.more_used() {
            virtqueue.reclaim_used();
            true
        } else {
            false
        }
    }
}

pub const fn header_len() -> usize {
    core::mem::size_of::<Header>()
}

pub fn find_by_mac(mac: &[u8; 6]) -> Option<alloc::sync::Arc<NetDev>> {
    for dev in &*NET_DEVICES.lock() {
        if dev.mac == *mac {
            return Some(dev.clone());
        }
    }

    None
}
