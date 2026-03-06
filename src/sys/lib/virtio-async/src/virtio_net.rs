use core::mem::offset_of;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;

use super::le16;
use super::pci::PciBar;
use super::virtio_device::VirtioDevice;

// Feature bits.
const VIRTIO_NET_F_CSUM: u64 = 1_u64 << 0;
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
pub struct Header {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

pub(super) const NET_HEADER_LEN: usize = core::mem::size_of::<Header>();

type IoBuf = [u8; 2048];

pub struct RxPacket {
    idx: u8,
    len: u16,
    netdev: *mut NetDev,
}

impl Drop for RxPacket {
    fn drop(&mut self) {
        unsafe { (*self.netdev).release_rx_packet(self.idx) }
    }
}

impl RxPacket {
    #[allow(clippy::mut_from_ref)]
    pub fn bytes_mut(&self) -> &mut [u8] {
        let netdev: &'static mut NetDev = unsafe { &mut *self.netdev };
        &mut netdev.rx_bufs[self.idx as usize][NET_HEADER_LEN..(self.len as usize)]
    }
}

pub struct TxPacket {
    idx: u8,
    netdev: *mut NetDev,
}

impl Drop for TxPacket {
    fn drop(&mut self) {
        unsafe { (*self.netdev).release_tx_packet(self.idx) }
    }
}

impl TxPacket {
    #[allow(clippy::mut_from_ref)]
    pub fn bytes_mut(&self) -> &mut [u8] {
        let netdev: &'static mut NetDev = unsafe { &mut *self.netdev };
        &mut netdev.tx_bufs[self.idx as usize][NET_HEADER_LEN..2048]
    }

    pub fn consume(self, len: u16) {
        unsafe { (*self.netdev).send_tx_packet(self.idx, len) }
        core::mem::forget(self);
    }
}

pub struct NetDev {
    dev: Rc<RefCell<VirtioDevice>>,
    mac: [u8; 6],
    mtu: Option<u16>,

    rx_bufs: &'static mut [IoBuf; 256],
    tx_bufs: &'static mut [IoBuf; 128], // A single TX buf consumes two descriptors in virtqueue.

    tx_buf_freelist: VecDeque<u8>,

    rx_bufs_phys_addr: u64,
    tx_bufs_phys_addr: u64,
    // notify_bar: *const PciBar,
    // txq_notify_offset: u64,
    // rxq_notify_offset: u64,
}

impl Drop for NetDev {
    fn drop(&mut self) {
        // panic!("VirtIO NetDev must not be dropped: RxPackets reference it statically.")
        log::error!("VirtIO NetDev must not be dropped: RxPackets reference it statically.");
    }
}

unsafe impl Send for NetDev {}

static NET_DEVICES: moto_rt::spinlock::SpinLock<Vec<NetDev>> =
    moto_rt::spinlock::SpinLock::new(Vec::new());

impl NetDev {
    const VIRTQ_RX: usize = 0;
    const VIRTQ_TX: usize = 1;

    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    pub(super) fn init(dev: Rc<RefCell<VirtioDevice>>) -> Result<Rc<Self>> {
        let mut dev_mut = dev.borrow_mut();

        dev_mut.acknowledge_driver(); // Step 3
        let (mac, mtu) = Self::negotiate_features(&mut dev_mut)?; // Steps 4, 5, 6
        dev_mut.init_virtqueues(2, 2)?; // Step 7
        dev_mut.driver_ok(); // Step 8

        if dev_mut.device_cfg.is_none() {
            log::warn!("Skiping Virtio NET device without device configuration.");
            return Err(ErrorKind::Other.into());
        }

        let bufs = crate::mapper()
            .alloc_contiguous_pages(2048 * 256)
            .expect("Failed to allocate RX buffers.");
        let rx_bufs = unsafe { (bufs as usize as *mut [IoBuf; 256]).as_mut().unwrap() };
        let rx_bufs_phys_addr = crate::mapper().virt_to_phys(bufs).unwrap();

        let bufs = crate::mapper()
            .alloc_contiguous_pages(2048 * 128)
            .expect("Failed to allocate RX buffers.");
        let tx_bufs = unsafe { (bufs as usize as *mut [IoBuf; 128]).as_mut().unwrap() };
        let tx_bufs_phys_addr = crate::mapper().virt_to_phys(bufs).unwrap();

        let mut tx_buf_freelist = VecDeque::new();
        tx_buf_freelist.reserve_exact(256);
        for idx in 0..128 {
            tx_buf_freelist.push_back(idx)
        }

        drop(dev_mut);

        Ok(Rc::new(NetDev {
            dev,
            mac,
            mtu,
            rx_bufs,
            tx_bufs,
            tx_buf_freelist,
            rx_bufs_phys_addr,
            tx_bufs_phys_addr,
            // notify_bar: core::ptr::null(),
            // txq_notify_offset: 0,
            // rxq_notify_offset: 0,
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

        if (features_available & super::virtio_device::VIRTIO_F_RING_EVENT_IDX) == 0 {
            log::warn!(
                "Virtio NET device {:?}: VIRTIO_F_RING_EVENT_IDX feature not available; features: 0x{:x}.",
                dev.pci_device.id,
                features_available
            );
            return Err(ErrorKind::Other.into());
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

        features_acked |= super::virtio_device::VIRTIO_F_VERSION_1
            | VIRTIO_NET_F_MAC
            | super::virtio_device::VIRTIO_F_RING_EVENT_IDX; // | VIRTIO_NET_F_STATUS;

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

    pub fn wait_handles(&self) -> Vec<moto_sys::SysHandle> {
        let mut result = Vec::new();
        for q in &self.dev.borrow().virtqueues {
            result.push(q.borrow().wait_handle());
        }

        result
    }

    /*
    pub fn start_receiving(&mut self) {
        use super::virtio_queue::UserData;

        let rxq = &mut self.dev.virtqueues[Self::VIRTQ_RX];
        assert_eq!(rxq.queue_size as usize, self.rx_bufs.len());

        for pos in 0..self.rx_bufs.len() {
            let buf = &mut self.rx_bufs[pos];
            let user_data = UserData {
                addr: buf.as_mut_ptr() as usize as u64,
                len: buf.len() as u32,
            };

            assert_eq!(pos as u16, rxq.add_buf(&[user_data], 0, 1));
        }

        // Kick unconditionally: it's done only once, so let's not complicate things.
        unsafe { (*self.notify_bar).write_u16(self.rxq_notify_offset, rxq.queue_num) };
    }

    // Get incoming bytes, if any, with an id of the buffer.
    pub fn rx_get(&mut self) -> Option<RxPacket> {
        let rxq = &mut self.dev.virtqueues[Self::VIRTQ_RX];
        if let Some((idx, len)) = rxq.get_completed_rx_buf() {
            Some(RxPacket {
                idx: idx as u8,
                len: len as u16,
                netdev: self as *mut _,
            })
        } else {
            None
        }
    }

    pub fn tx_get(&mut self) -> Option<TxPacket> {
        if let Some(idx) = self.tx_buf_freelist.pop_front() {
            Some(TxPacket {
                idx,
                netdev: self as *mut _,
            })
        } else {
            let txq = &mut self.dev.virtqueues[Self::VIRTQ_TX];
            while let Some(idx) = txq.get_completed_tx_buf() {
                self.tx_buf_freelist.push_back(idx as u8);
            }
            self.tx_buf_freelist.pop_front().map(|idx| TxPacket {
                idx,
                netdev: self as *mut _,
            })
        }
    }

    fn send_tx_packet(&mut self, idx: u8, len: u16) {
        let pos = idx as usize;
        let buf = &mut self.tx_bufs[pos];

        let header = buf.as_ptr() as usize as *mut Header;
        unsafe { *header = Header::default() };

        let phys_addr = self.tx_bufs_phys_addr + ((idx as u64) << 11);

        let txq = &mut self.dev.virtqueues[Self::VIRTQ_TX];
        let should_notify = txq.add_tx_buf(phys_addr, idx as u16, len as u32);

        if should_notify {
            // unsafe { (*self.notify_bar).write_u16_unfenced(self.txq_notify_offset, txq.queue_num) };
            unsafe { (*self.notify_bar).write_u16(self.txq_notify_offset, txq.queue_num) };
        }
    }

    fn release_rx_packet(&mut self, idx: u8) {
        let phys_addr = self.rx_bufs_phys_addr + ((idx as u64) << 11);

        let rxq = &mut self.dev.virtqueues[Self::VIRTQ_RX];
        let should_notify = rxq.add_rx_buf(phys_addr, 2048, idx as u16);

        if should_notify {
            // unsafe { (*self.notify_bar).write_u16_unfenced(self.rxq_notify_offset, rxq.queue_num) };
            unsafe { (*self.notify_bar).write_u16(self.rxq_notify_offset, rxq.queue_num) };
        }
    }

    fn release_tx_packet(&mut self, idx: u8) {
        self.tx_buf_freelist.push_back(idx);
    }
    */
    fn send_tx_packet(&mut self, idx: u8, len: u16) {
        todo!()
    }

    fn release_rx_packet(&mut self, idx: u8) {
        todo!()
    }

    fn release_tx_packet(&mut self, idx: u8) {
        self.tx_buf_freelist.push_back(idx);
    }
}

pub const fn header_len() -> usize {
    core::mem::size_of::<Header>()
}

/*
pub fn take_by_mac(mac: &[u8; 6]) -> Option<NetDev> {
    let devices = &mut *NET_DEVICES.lock();
    for idx in 0..devices.len() {
        if devices[idx].mac == *mac {
            return Some(devices.remove(idx));
        }
    }

    None
}
*/
