// VirtIO Devices.

use core::sync::atomic::*;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::rc::Rc;

use super::pci;
use super::pci::PciBar;
use super::pci::PciDevice;
use super::pci::PciDeviceID;
use super::pci::le16;
use super::pci::le32;
use super::pci::le64;
use super::virtio_queue::Virtqueue;
use crate::virtio_blk::BlockDevice;
use core::mem::offset_of;
use std::io::Result;

#[derive(Clone, Copy, Debug)]
pub enum VirtioDeviceKind {
    Unknown(u16),
    Net,
    Block,
    Mem,
    Console,
    Rng,
}

impl VirtioDeviceKind {
    fn from_device_id(device_id: u16) -> Self {
        match device_id {
            // We work only with standard/modern VirtIO devices.
            0x1041 => VirtioDeviceKind::Net,
            0x1042 => VirtioDeviceKind::Block,
            0x1045 => VirtioDeviceKind::Mem,
            0x1043 => VirtioDeviceKind::Console,
            0x1044 => VirtioDeviceKind::Rng,
            x => VirtioDeviceKind::Unknown(x),
        }
    }
}

// From virtio 1.1 spec.
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1; // Common configuration.
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2; // Notifications.
// const VIRTIO_PCI_CAP_ISR_CFG    : u8 = 3;  // ISR status.
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4; // Device specific configuration.
#[allow(dead_code)]
const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5; // PCI configuration access.

const ACKNOWLEDGE_DEVICE_STATUS_BIT: u8 = 1;
const ACKNOWLEDGE_DRIVER_STATUS_BIT: u8 = 2;
const FEATURES_OK_STATUS_BIT: u8 = 8;
const DRIVER_OK_STATUS_BIT: u8 = 4;
const FAILED_STATUS_BIT: u8 = 128;

// Device/driver features.
pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1u64 << 28;
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1u64 << 29;
// pub const VIRTIO_F_EVENT_IDX: u64 = 1u64 << 29; // Same as VIRTIO_F_RING_EVENT_IDX.
pub const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;
pub const _VIRTIO_F_IN_ORDER: u64 = 1u64 << 35;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub(super) struct VirtioPciCap {
    // cap_vndr: u8,  // PCI_CAP_VENDOR
    // cap_next: u8,
    // cap_len: u8,
    pub(super) cfg_type: u8,
    pub(super) bar: u8,
    pub(super) offset: le32, // Offset within bar.
    pub(super) length: le32,
    pub(super) notify_off_multiplier: le32, // Optional; used in VirtioPciNotifyCap.
}

impl VirtioPciCap {
    fn init(device_id: PciDeviceID, cap_offset: u8) -> Self {
        let cfg_type = device_id.read_config_u8(cap_offset + 3);
        let bar = device_id.read_config_u8(cap_offset + 4);
        let offset = device_id.read_config_u32(cap_offset + 8);
        let length = device_id.read_config_u32(cap_offset + 12);

        let notify_off_multiplier = if cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG {
            device_id.read_config_u32(cap_offset + 16)
        } else {
            0
        };

        VirtioPciCap {
            cfg_type,
            bar,
            offset,
            length,
            notify_off_multiplier,
        }
    }
}

// See secion 4.1.4.3 in virtio 1.1 spec.
#[allow(dead_code)]
#[repr(C, packed)]
struct VirtioPciCommonCfgLayout {
    /* About the whole device. */
    device_feature_select: le32, /* read-write */
    device_feature: le32,        /* read-only for driver */
    driver_feature_select: le32, /* read-write */
    driver_feature: le32,        /* read-write */
    msix_config: le16,           /* read-write */
    num_queues: le16,            /* read-only for driver */
    device_status: u8,           /* read-write */
    config_generation: u8,       /* read-only for driver */

    /* About a specific virtqueue. */
    queue_select: le16,      /* read-write */
    queue_size: le16,        /* read-write */
    queue_msix_vector: le16, /* read-write */
    queue_enable: le16,      /* read-write */
    queue_notify_off: le16,  /* read-only for driver */
    queue_desc: le64,        /* read-write */
    queue_driver: le64,      /* read-write */
    queue_device: le64,      /* read-write */
}

#[allow(dead_code)]
#[derive(Debug)]
pub(super) struct Msix {
    msgnum: u16,       // Number of messages.
    location: u8,      // Offset of msix capability reg.
    table_bar: u8,     // BAR containing vector table.
    pba_bar: u8,       // BAR containing PBA.
    table_offset: u32, // Offset within table BAR mmio.
    pba_offset: u32,   // Offset within PBA BAR mmio.
}

#[allow(dead_code)]
pub(super) struct VirtioDevice {
    pub(super) pci_device: PciDevice,
    pub(super) kind: VirtioDeviceKind,
    pub(super) common_cfg: VirtioPciCap,
    pub(super) device_cfg: Option<VirtioPciCap>,
    pub(super) notify_cfg: Option<VirtioPciCap>,
    pub(super) msix: Option<Box<Msix>>,

    // Each virtqueue is protected by a mutex so that the guest does not
    // access them concurrently.
    pub(super) virtqueues: Vec<Rc<RefCell<Virtqueue>>>,
}

impl VirtioDevice {
    // VirtIO device initialization steps, see osv virtio.cc, virtio-rng.cc,
    // and section 3.1.1 in VirtIO 1.1. spec:
    //   step 0 parse/init
    //   step 1 reset
    //   step 2 ack device: the guest OS has noticed the device
    //   step 3 ack driver: the guest OS knows how to drive the device
    //   step 4 negotiate features
    //   step 5 confirm features
    //   step 6 re-read dev status to ensure FEATURES_OK
    //   step 7 generic init of virtqueues
    //   step 8 confirm drive ok
    fn parse(device_id: PciDeviceID) -> Result<Rc<RefCell<Self>>> {
        // Step 0: init.
        if device_id.vendor_id() != 0x1af4 {
            log::debug!(
                "Skipping non-VirtIO device_id with vendor 0x{:x}",
                device_id.vendor_id()
            );
            return Err(ErrorKind::Unsupported.into());
        }

        if device_id.header_type() & 0x7F != 0 {
            log::warn!(
                "Skipping VirtIO device_id with wrong header type {}",
                device_id.header_type()
            );
            return Err(ErrorKind::InvalidData.into());
        }

        let kind = VirtioDeviceKind::from_device_id(device_id.device_id());
        if let VirtioDeviceKind::Unknown(x) = kind {
            log::warn!("Skipping VirtIO device_id with unknown device_id id 0x{x:x}");
            return Err(ErrorKind::Unsupported.into());
        }

        let reg_1 = device_id.read_config_u32(0x04);
        let status = ((reg_1 >> 16) & 0xFFFF) as u16;
        if status & pci::PCI_STATUS_CAP_LIST == 0 {
            log::warn!("VirtIO device_id {device_id:?}: wrong status: {status:x}");
            return Err(ErrorKind::InvalidData.into());
        }

        let reg_2 = device_id.read_config_u32(0x08);
        let revision_id = (reg_2 & 0xff) as u8;
        if revision_id == 0 {
            log::warn!("VirtIO device_id {device_id:?}: legacy device_id (revision_id)");
            return Err(ErrorKind::Unsupported.into());
        }

        let caps = device_id.find_capabilities(pci::PCI_CAP_VENDOR);

        let mut virtio_caps = Vec::<VirtioPciCap>::new();
        for c in caps {
            virtio_caps.push(VirtioPciCap::init(device_id, c));
        }

        let mut common_cap: Option<&VirtioPciCap> = None;
        for cap in &virtio_caps {
            if cap.cfg_type == VIRTIO_PCI_CAP_COMMON_CFG {
                common_cap = Some(cap);
                break;
            }
        }

        if common_cap.is_none() {
            log::warn!("VirtIO device_id {device_id:?}: VirtioPciCommonCfg not found.");
            return Err(ErrorKind::InvalidData.into());
        }

        let common_cfg = common_cap.unwrap();
        log::trace!("VirtIO device_id {device_id:?}: common cap (cfg): {common_cfg:?}");

        let min_len = core::mem::size_of::<VirtioPciCommonCfgLayout>();
        if (common_cfg.length as usize) < min_len {
            log::warn!("VirtIO device_id {device_id:?}: VirtioPciCommonCfg: bad length.");
            return Err(ErrorKind::InvalidData.into());
        }

        let mut pci_device = PciDevice::new(device_id);
        pci_device.bars[common_cfg.bar as usize] = Some(PciBar::init(device_id, common_cfg.bar));

        let cfg_bar: &PciBar = pci_device.bars[common_cfg.bar as usize].as_ref().unwrap();
        let status = cfg_bar.readb(
            common_cfg.offset as u64 + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64,
        );
        log::debug!("Detected VirtIO device {kind:?} status: {status}.");

        let mut device_cfg: Option<VirtioPciCap> = None;
        for cap in &virtio_caps {
            if cap.cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG {
                device_cfg = Some(*cap);
                if cap.bar != common_cfg.bar {
                    pci_device.bars[cap.bar as usize] = Some(PciBar::init(device_id, cap.bar));
                }
                log::trace!("VirtIO device_id {device_id:?}: device cap: {cap:?}");
                break;
            }
        }

        let mut notify_cfg = None;
        for cap in &virtio_caps {
            if cap.cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG {
                notify_cfg = Some(*cap);
                if cap.bar != common_cfg.bar {
                    pci_device.bars[cap.bar as usize] = Some(PciBar::init(device_id, cap.bar));
                }
            }
        }

        Ok(Rc::new(RefCell::new(VirtioDevice {
            pci_device,
            kind,
            common_cfg: *common_cfg,
            device_cfg,
            notify_cfg,
            msix: None,
            virtqueues: Vec::new(),
        })))
    }

    // Step 0: see virtio_pci_device::init() in osv.
    fn init(&mut self) {
        // Set bus master, enable I/O and memory space.
        let mut command = self.pci_device.id.read_config_u16(pci::PCI_CFG_COMMAND);
        command |= pci::PCI_COMMAND_BUS_MASTER | pci::PCI_COMMAND_BUS_IO | pci::PCI_COMMAND_BUS_MEM;
        self.pci_device
            .id
            .write_config_u16(pci::PCI_CFG_COMMAND, command);

        // Enable MSI-X.
        let caps = self.pci_device.id.find_capabilities(pci::PCI_CAP_MSIX);
        if !caps.is_empty() {
            self.enable_msix(caps[0]);
        } else {
            let caps = self.pci_device.id.find_capabilities(pci::PCI_CAP_MSI);
            if !caps.is_empty() {
                log::warn!(
                    "VirtIO {:?} device has MSI but not MSI-X capability.",
                    self.kind
                );
            }
        }
    }

    #[allow(unused_variables)]
    fn enable_msix(&mut self, offset: u8) {
        assert!(self.msix.is_none());

        // see void function::msix_enable() in drivers/pci-function.cc in osv.
        let location = offset;
        let ctrl = self
            .pci_device
            .id
            .read_config_u16(location + pci::PCIR_MSIX_CTRL);
        let msgnum = (ctrl & pci::PCIM_MSIXCTRL_TABLE_SIZE) + 1;

        let mut val: u32 = self
            .pci_device
            .id
            .read_config_u32(location + pci::PCIR_MSIX_TABLE);
        let table_bar = (val & pci::PCIM_MSIX_BIR_MASK) as u8;
        let table_offset: u32 = val & !pci::PCIM_MSIX_BIR_MASK;

        val = self
            .pci_device
            .id
            .read_config_u32(location + pci::PCIR_MSIX_PBA);
        let pba_bar = (val & pci::PCIM_MSIX_BIR_MASK) as u8;
        let pba_offset: u32 = val & !pci::PCIM_MSIX_BIR_MASK;

        assert!(table_bar < 6);
        assert!(pba_bar < 6);

        let msix = Msix {
            msgnum,
            location,
            table_bar,
            pba_bar,
            table_offset,
            pba_offset,
        };

        if self.pci_device.bars[msix.table_bar as usize].is_none() {
            self.pci_device.bars[msix.table_bar as usize] =
                Some(PciBar::init(self.pci_device.id, msix.table_bar));
        }
        if self.pci_device.bars[msix.pba_bar as usize].is_none() {
            self.pci_device.bars[msix.pba_bar as usize] =
                Some(PciBar::init(self.pci_device.id, msix.pba_bar));
        }

        // Disable INTX.
        let mut command = self.pci_device.id.read_config_u16(pci::PCI_CFG_COMMAND);
        command |= pci::PCI_COMMAND_INTX_DISABLE;
        self.pci_device
            .id
            .write_config_u16(pci::PCI_CFG_COMMAND, command);

        // Enable MSIX.
        let mut msix_ctrl = self
            .pci_device
            .id
            .read_config_u16(msix.location + pci::PCIR_MSIX_CTRL);
        msix_ctrl |= pci::PCIM_MSIXCTRL_MSIX_ENABLE;
        msix_ctrl |= pci::PCIM_MSIXCTRL_FUNCTION_MASK;
        self.pci_device
            .id
            .write_config_u16(msix.location + pci::PCIR_MSIX_CTRL, msix_ctrl);
        // Validate success.
        assert_eq!(
            msix_ctrl,
            self.pci_device
                .id
                .read_config_u16(msix.location + pci::PCIR_MSIX_CTRL)
        );

        // Mask off all entries.
        let table_bar = &(self.pci_device.bars[msix.table_bar as usize]);
        let table_bar = table_bar.as_ref().unwrap();
        for idx in 0..msix.msgnum {
            const PCI_MSIX_ENTRY_VECTOR_CTRL: u64 = 12;
            const PCI_MSIX_ENTRY_SIZE: u64 = 16;
            let offset = (msix.table_offset as u64)
                + PCI_MSIX_ENTRY_SIZE * (idx as u64)
                + PCI_MSIX_ENTRY_VECTOR_CTRL;
            // let mut entry_ctrl = table_bar.read_u32(offset);
            // moto_sys::syscalls::SysMem::log("enable_msix 110").ok();
            // entry_ctrl |= pci::PCI_MSIX_ENTRY_CTRL_MASKBIT;
            let entry_ctrl = pci::PCI_MSIX_ENTRY_CTRL_MASKBIT;
            table_bar.write_u32(offset, entry_ctrl);
        }
        // Unmask the main block (see void function::msix_enable() in drivers/pci-function.cc in osv).
        msix_ctrl &= !pci::PCIM_MSIXCTRL_FUNCTION_MASK;
        self.pci_device
            .id
            .write_config_u16(msix.location + pci::PCIR_MSIX_CTRL, msix_ctrl);
        // Validate success.
        assert_eq!(
            msix_ctrl,
            self.pci_device
                .id
                .read_config_u16(msix.location + pci::PCIR_MSIX_CTRL)
        );

        log::debug!(
            "MSI-X enabled for {:?} : {:?}.",
            self.kind,
            self.pci_device.id
        );
        self.msix = Some(Box::new(msix));
    }

    // Indicate that the driver encountered an error and it has given up on the device.
    pub(super) fn mark_failed(&self) {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let status_offset = self.common_cfg.offset as u64
            + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64;

        let mut status = cfg_bar.readb(status_offset);
        status |= FAILED_STATUS_BIT;
        cfg_bar.writeb(status_offset, status);
    }

    // Step 1
    fn reset(&self) {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        cfg_bar.writeb(
            self.common_cfg.offset as u64
                + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64,
            0,
        );
    }

    // Step 2
    fn acknowledge_device(&self) {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        cfg_bar.writeb(
            self.common_cfg.offset as u64
                + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64,
            ACKNOWLEDGE_DEVICE_STATUS_BIT,
        );
    }

    // Step 3
    pub(super) fn acknowledge_driver(&self) {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let status_offset = self.common_cfg.offset as u64
            + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64;

        cfg_bar.writeb(
            status_offset,
            ACKNOWLEDGE_DEVICE_STATUS_BIT | ACKNOWLEDGE_DRIVER_STATUS_BIT,
        );
    }

    // Step 4.1
    pub(super) fn get_available_features(&self) -> u64 {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let feature_select_offset = self.common_cfg.offset as u64;
        let feature_offset = self.common_cfg.offset as u64 + 4;

        cfg_bar.write_u32(feature_select_offset, 0);
        let features_lo = cfg_bar.read_u32(feature_offset);
        cfg_bar.write_u32(feature_select_offset, 1);
        let features_hi = cfg_bar.read_u32(feature_offset);

        let features: u64 = ((features_hi as u64) << 32) | (features_lo as u64);
        features
    }

    // Step 4.2
    pub(super) fn write_enabled_features(&self, val: u64) {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let feature_select_offset = self.common_cfg.offset as u64 + 0x8;
        let feature_offset = self.common_cfg.offset as u64 + 0xc;

        cfg_bar.write_u32(feature_select_offset, 0);
        cfg_bar.write_u32(feature_offset, (val & 0xff_ff_ff_ff) as u32);
        cfg_bar.write_u32(feature_select_offset, 1);
        cfg_bar.write_u32(feature_offset, (val >> 32) as u32);
    }

    // Steps 5 and 6
    pub(super) fn confirm_features(&self) -> Result<()> {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let status_offset = self.common_cfg.offset as u64
            + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64;

        // Step 5: write FEATURES_OK
        let mut status = cfg_bar.readb(status_offset);
        if status != (ACKNOWLEDGE_DEVICE_STATUS_BIT | ACKNOWLEDGE_DRIVER_STATUS_BIT) {
            log::error!(
                "VirtioDevice {:?}: unexpected device status 0x{:x} in Step 5.",
                self.pci_device.id,
                status
            );
            return Err(ErrorKind::InvalidData.into());
        }
        status |= FEATURES_OK_STATUS_BIT;

        cfg_bar.writeb(status_offset, status);

        // Step 6: confirm FEATURES_OK
        let status_back = cfg_bar.readb(status_offset);
        if status != status_back {
            log::error!(
                "VirtioDevice {:?}: unexpected device status 0x{:x} in Step 6.",
                self.pci_device.id,
                status_back
            );
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(())
    }

    fn setup_queue_msix(
        &self,
        cfg_bar: &PciBar,
        bar_offset: u64,
        virtqueue: &mut Virtqueue,
    ) -> Result<()> {
        if self.msix.is_none() {
            return Ok(());
        }

        let msix = self.msix.as_ref().unwrap();
        let table_bar = &(self.pci_device.bars[msix.table_bar as usize]);
        let table_bar = table_bar.as_ref().unwrap();

        if virtqueue.queue_num >= msix.msgnum {
            // TODO: do we ever need to share IRQs between virtqueues?
            moto_sys::SysRay::log("Having more virtqueues than MSIX vectors is not supported.")
                .ok();
            return Err(ErrorKind::Unsupported.into());
        }

        let irq_idx = virtqueue.queue_num;

        // Use the default APIC base (super::rdmsr(IA32_APIC_BASE) & MASK).
        // Motor OS kernel in irq.rs asserts that this is correct.
        const APIC_BASE: u64 = 0xfee00000_u64;

        let (wait_handle, irq_num) = mapper().create_irq_wait_handle()?;
        virtqueue.set_wait_handle(wait_handle);

        let apic_id = 0_u64; // CPU: in motor os, most IRQs are affined to CPU 0.
        let msi_msg_addr = APIC_BASE & 0xFFF00000_u64 | (apic_id << 12);
        let msi_msg_data: u32 = (1 << 14) | (irq_num as u32);

        let offset = (msix.table_offset as u64) + (16 * irq_idx as usize) as u64;
        table_bar.write_u64(offset, msi_msg_addr);
        table_bar.write_u32(offset + 8, msi_msg_data);
        let offset = (msix.table_offset as u64) + (16 * irq_idx as usize + 12) as u64;
        let mut entry_ctrl = table_bar.read_u32(offset);
        entry_ctrl &= !(pci::PCI_MSIX_ENTRY_CTRL_MASKBIT);
        table_bar.write_u32(offset, entry_ctrl);

        let queue_msix_vector_offset =
            bar_offset + offset_of!(VirtioPciCommonCfgLayout, queue_msix_vector) as u64;
        cfg_bar.write_u16(queue_msix_vector_offset, virtqueue.queue_num);
        if virtqueue.queue_num != cfg_bar.read_u16(queue_msix_vector_offset) {
            log::error!(
                "VirtioDevice {:?}: setting MSIX entry for queue {} failed.",
                self.pci_device.id,
                virtqueue.queue_num
            );
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(())
    }

    fn setup_queue_data(&self, cfg_bar: &PciBar, bar_offset: u64, virtqueue: &Virtqueue) {
        cfg_bar.write_u16(
            bar_offset + offset_of!(VirtioPciCommonCfgLayout, queue_size) as u64,
            virtqueue.queue_size,
        );

        let desc_addr = mapper().virt_to_phys(virtqueue.virt_addr);
        if desc_addr.is_err() {
            log::trace!("virt_to_phys() failed for 0x{:x}", virtqueue.virt_addr);
            panic!();
        }
        let desc_addr = desc_addr.unwrap();
        let avail_addr = desc_addr + virtqueue.queue_size as u64 * 16;
        let used_addr = super::align_up(avail_addr + virtqueue.queue_size as u64 * 2 + 6, 4);

        cfg_bar.write_u64(
            bar_offset + offset_of!(VirtioPciCommonCfgLayout, queue_desc) as u64,
            desc_addr,
        );
        cfg_bar.write_u64(
            bar_offset + offset_of!(VirtioPciCommonCfgLayout, queue_driver) as u64,
            avail_addr,
        );
        cfg_bar.write_u64(
            bar_offset + offset_of!(VirtioPciCommonCfgLayout, queue_device) as u64,
            used_addr,
        );
    }

    // Step 7: virtqueues
    //      7.1: allocate
    //      7.2: msix and notifications
    //      7.3: pass addresses to the device
    //      7.4: activate
    pub(super) fn init_virtqueues(
        &mut self,
        min_virtqueues: u16,
        max_virtqueues: u16,
    ) -> Result<()> {
        assert!(max_virtqueues <= 64);
        assert!(min_virtqueues <= max_virtqueues);

        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let bar_offset = self.common_cfg.offset as u64;
        let queue_select_offset = offset_of!(VirtioPciCommonCfgLayout, queue_select) as u64;
        let queue_size_offset = offset_of!(VirtioPciCommonCfgLayout, queue_size) as u64;
        let queue_notify_off_offset = offset_of!(VirtioPciCommonCfgLayout, queue_notify_off) as u64;

        let mut queue_num = 0u16;

        let mut virtqueues = Vec::<Rc<RefCell<Virtqueue>>>::new();

        loop {
            cfg_bar.write_u16(bar_offset + queue_select_offset, queue_num);

            const MAX_QUEUE_SIZE: u16 = 256;
            let mut queue_size = cfg_bar.read_u16(bar_offset + queue_size_offset);
            if queue_size == 0 {
                break;
            }

            if queue_size > MAX_QUEUE_SIZE {
                cfg_bar.write_u16(bar_offset + queue_size_offset, MAX_QUEUE_SIZE);
                queue_size = cfg_bar.read_u16(bar_offset + queue_size_offset);
                if queue_size > MAX_QUEUE_SIZE {
                    log::error!("VirtIO queue size too large: {queue_size}");
                    return Err(ErrorKind::InvalidData.into());
                }
            }

            // Step 7.1: allocate virtqueues
            let virtqueue = Virtqueue::allocate(self, queue_num, queue_size)?;
            let mut virtq_borrowed = virtqueue.borrow_mut();

            virtq_borrowed.queue_notify_off =
                cfg_bar.read_u16(bar_offset + queue_notify_off_offset);
            self.setup_queue_msix(cfg_bar, bar_offset, &mut virtq_borrowed)?; // Step 7.2
            self.setup_queue_data(cfg_bar, bar_offset, &virtq_borrowed); // Step 7.3

            // Step 7.4
            cfg_bar.write_u16(
                bar_offset + offset_of!(VirtioPciCommonCfgLayout, queue_enable) as u64,
                1,
            );

            core::mem::drop(virtq_borrowed);
            virtqueues.push(virtqueue);
            queue_num += 1;
            if queue_num == max_virtqueues {
                break;
            }
        }

        if queue_num < min_virtqueues {
            Err(ErrorKind::InvalidData.into())
        } else {
            self.virtqueues = virtqueues;
            Ok(())
        }
    }

    // Step 8 (final)
    pub(super) fn driver_ok(&self) {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let status_offset = self.common_cfg.offset as u64
            + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64;

        // Step 5: write FEATURES_OK
        let mut status = cfg_bar.readb(status_offset);
        status |= DRIVER_OK_STATUS_BIT;
        cfg_bar.writeb(status_offset, status);
    }
}

static mut MAPPER: Option<&'static dyn super::KernelAdapter> = None;

pub(super) fn mapper() -> &'static dyn super::KernelAdapter {
    unsafe { MAPPER.unwrap() }
}

pub fn init_virtio_devices(
    mapper: &'static dyn super::KernelAdapter,
) -> std::io::Result<Vec<Device>> {
    static ONCE: AtomicBool = AtomicBool::new(false);
    assert!(
        ONCE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    );

    unsafe { MAPPER = Some(mapper) };

    let pci_devices = pci::brute_force_scan();
    let mut devices = vec![];

    for dev in &pci_devices {
        if let Ok(device) = VirtioDevice::parse(*dev) {
            let kind = {
                let mut device = device.borrow_mut();
                device.init();
                device.reset();
                device.acknowledge_device();
                device.kind
            };

            match kind {
                VirtioDeviceKind::Block => {
                    devices.push(Device::Block(super::virtio_blk::BlockDevice::init(device)?));
                }
                /*
                VirtioDeviceKind::Net => {
                    super::virtio_net::NetDev::init(device);
                }
                */
                VirtioDeviceKind::Rng => {
                    // We are not using Rng for now, so let's not waste resources on it.
                    continue;
                    // devices.push(Device::Rng(super::virtio_rng::Rng::init(device)?));
                }
                _ => {}
            }
        }
    }
    #[cfg(debug_assertions)]
    log::debug!("done initializing VirtIO");
    Ok(devices)
}

pub enum Device {
    Block(Rc<crate::virtio_blk::BlockDevice>),
    // Rng(crate::virtio_rng::Rng),
}
