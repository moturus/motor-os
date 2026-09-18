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
    Vsock,
    Mem,
    Console,
    Rng,
}

impl VirtioDeviceKind {
    pub(crate) fn from_device_id(device_id: u16) -> Self {
        match device_id {
            // Modern IDs select this transport; PCI Revision ID may be any value.
            0x1041 => VirtioDeviceKind::Net,
            0x1042 => VirtioDeviceKind::Block,
            0x1053 => VirtioDeviceKind::Vsock,
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
pub const _VIRTIO_F_IN_ORDER: u64 = 1u64 << 35; // Usually is not available.

pub(crate) fn validate_msix_vectors(vectors: Option<u16>, required: u16) -> Result<()> {
    match vectors {
        Some(vectors) if vectors >= required => Ok(()),
        _ => Err(ErrorKind::Unsupported.into()),
    }
}

pub fn supported_virtio_cap(cap_offset: u8, header: u32) -> Option<u8> {
    let cap_len = ((header >> 16) & 0xff) as u8;
    let cfg_type = (header >> 24) as u8;
    let required_len = match cfg_type {
        VIRTIO_PCI_CAP_COMMON_CFG | VIRTIO_PCI_CAP_DEVICE_CFG => 16,
        VIRTIO_PCI_CAP_NOTIFY_CFG => 20,
        _ => return None,
    };
    (cap_len >= required_len && usize::from(cap_offset) + usize::from(required_len) <= 256)
        .then_some(cfg_type)
}

pub fn valid_virtio_cap_bar(bar: u8) -> bool {
    bar < 6
}

pub fn valid_msix_cap_offset(offset: u8) -> bool {
    usize::from(offset) + 12 <= 256
}

pub fn msix_region_lengths(vectors: u16) -> Option<(u64, u64)> {
    if !(1..=2048).contains(&vectors) {
        return None;
    }
    let vectors = u64::from(vectors);
    Some((vectors * 16, vectors.div_ceil(64) * 8))
}

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
    fn parse(device_id: PciDeviceID, cap_offset: u8) -> Option<Self> {
        let header = device_id.read_config_u32(cap_offset);
        let cfg_type = supported_virtio_cap(cap_offset, header)?;
        let bar = device_id.read_config_u32(cap_offset.checked_add(4)?) as u8;
        if !valid_virtio_cap_bar(bar) {
            return None;
        }
        let offset = device_id.read_config_u32(cap_offset.checked_add(8)?);
        let length = device_id.read_config_u32(cap_offset.checked_add(12)?);

        let notify_off_multiplier = if cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG {
            device_id.read_config_u32(cap_offset.checked_add(16)?)
        } else {
            0
        };

        Some(VirtioPciCap {
            cfg_type,
            bar,
            offset,
            length,
            notify_off_multiplier,
        })
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
pub struct VirtioDevice {
    pub(super) pci_device: PciDevice,
    pub(super) kind: VirtioDeviceKind,
    pub(super) common_cfg: VirtioPciCap,
    pub(super) device_cfg: Option<VirtioPciCap>,
    pub(super) notify_cfg: Option<VirtioPciCap>,
    pub(super) msix: Option<Box<Msix>>,

    // Each virtqueue is protected by a mutex so that the guest does not
    // access them concurrently.
    pub(super) virtqueues: Vec<Rc<RefCell<Virtqueue>>>,
    pub(super) virtio_features_negotiated: u64,
}

impl VirtioDevice {
    pub fn kind(&self) -> VirtioDeviceKind {
        self.kind
    }

    pub(super) fn device_config(&self, required: u32) -> Result<(&PciBar, u64)> {
        let config = self.device_cfg.as_ref().ok_or(ErrorKind::InvalidData)?;
        let bar = self
            .pci_device
            .bars
            .get(config.bar as usize)
            .and_then(Option::as_ref)
            .ok_or(ErrorKind::InvalidData)?;
        if !bar.contains_cap_access(config.offset, config.length, 0, u64::from(required), 4) {
            return Err(ErrorKind::InvalidData.into());
        }
        Ok((bar, u64::from(config.offset)))
    }

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
    fn parse(device_id: PciDeviceID) -> Result<Self> {
        // Step 0: init.
        if device_id.vendor_id() != 0x1af4 {
            log::debug!(
                "\n\tSkipping non-VirtIO device_id with vendor 0x{:x}",
                device_id.vendor_id()
            );
            return Err(ErrorKind::Unsupported.into());
        }

        if device_id.header_type() & 0x7F != 0 {
            log::warn!(
                "\n\tSkipping VirtIO device_id with wrong header type {}",
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

        let caps = device_id.find_capabilities(pci::PCI_CAP_VENDOR);

        let mut virtio_caps = Vec::<VirtioPciCap>::new();
        for c in caps {
            if let Some(cap) = VirtioPciCap::parse(device_id, c) {
                virtio_caps.push(cap);
            }
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

        let mut pci_device = PciDevice::new(device_id);
        pci_device.bars[common_cfg.bar as usize] = Some(PciBar::init(device_id, common_cfg.bar));

        let cfg_bar: &PciBar = pci_device.bars[common_cfg.bar as usize].as_ref().unwrap();
        let common_len = core::mem::size_of::<VirtioPciCommonCfgLayout>() as u64;
        if !cfg_bar.contains_cap_access(common_cfg.offset, common_cfg.length, 0, common_len, 4) {
            log::warn!("VirtIO device_id {device_id:?}: invalid common configuration range.");
            return Err(ErrorKind::InvalidData.into());
        }
        let status = cfg_bar.readb(
            common_cfg.offset as u64 + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64,
        );
        log::debug!("Detected VirtIO device {kind:?} status: {status}.");

        let mut device_cfg: Option<VirtioPciCap> = None;
        for cap in &virtio_caps {
            if cap.cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG {
                device_cfg = Some(*cap);
                if pci_device.bars[cap.bar as usize].is_none() {
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
                if pci_device.bars[cap.bar as usize].is_none() {
                    pci_device.bars[cap.bar as usize] = Some(PciBar::init(device_id, cap.bar));
                }
                break;
            }
        }

        Ok(VirtioDevice {
            pci_device,
            kind,
            common_cfg: *common_cfg,
            device_cfg,
            notify_cfg,
            msix: None,
            virtqueues: Vec::new(),
            virtio_features_negotiated: 0,
        })
    }

    // Step 0: see virtio_pci_device::init() in osv.
    pub(crate) fn init(&mut self) -> Result<()> {
        // Set bus master, enable I/O and memory space.
        let mut command = self.pci_device.id.read_config_u16(pci::PCI_CFG_COMMAND);
        command |= pci::PCI_COMMAND_BUS_MASTER | pci::PCI_COMMAND_BUS_IO | pci::PCI_COMMAND_BUS_MEM;
        self.pci_device
            .id
            .write_config_u16(pci::PCI_CFG_COMMAND, command);

        // Enable MSI-X.
        let caps = self.pci_device.id.find_capabilities(pci::PCI_CAP_MSIX);
        if !caps.is_empty() {
            self.enable_msix(caps[0])?;
        } else {
            let caps = self.pci_device.id.find_capabilities(pci::PCI_CAP_MSI);
            if !caps.is_empty() {
                log::warn!(
                    "VirtIO {:?} device has MSI but not MSI-X capability.",
                    self.kind
                );
            }
        }
        Ok(())
    }

    fn enable_msix(&mut self, offset: u8) -> Result<()> {
        assert!(self.msix.is_none());

        // see void function::msix_enable() in drivers/pci-function.cc in osv.
        let location = offset;
        if !valid_msix_cap_offset(location) {
            log::error!(
                "VirtIO {:?} device has truncated MSI-X capability at 0x{location:x}.",
                self.kind
            );
            return Err(ErrorKind::InvalidData.into());
        }
        let ctrl_offset = location
            .checked_add(pci::PCIR_MSIX_CTRL)
            .ok_or(ErrorKind::InvalidData)?;
        let table_cfg_offset = location
            .checked_add(pci::PCIR_MSIX_TABLE)
            .ok_or(ErrorKind::InvalidData)?;
        let pba_cfg_offset = location
            .checked_add(pci::PCIR_MSIX_PBA)
            .ok_or(ErrorKind::InvalidData)?;
        let ctrl = self.pci_device.id.read_config_u16(ctrl_offset);
        let msgnum = (ctrl & pci::PCIM_MSIXCTRL_TABLE_SIZE) + 1;

        let mut val: u32 = self.pci_device.id.read_config_u32(table_cfg_offset);
        let table_bar = (val & pci::PCIM_MSIX_BIR_MASK) as u8;
        let table_offset: u32 = val & !pci::PCIM_MSIX_BIR_MASK;

        val = self.pci_device.id.read_config_u32(pba_cfg_offset);
        let pba_bar = (val & pci::PCIM_MSIX_BIR_MASK) as u8;
        let pba_offset: u32 = val & !pci::PCIM_MSIX_BIR_MASK;

        if !valid_virtio_cap_bar(table_bar) || !valid_virtio_cap_bar(pba_bar) {
            log::error!(
                "VirtIO {:?} device has invalid MSI-X BARs: table {table_bar}, PBA {pba_bar}.",
                self.kind
            );
            return Err(ErrorKind::InvalidData.into());
        }

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

        let (table_length, pba_length) =
            msix_region_lengths(msix.msgnum).ok_or(ErrorKind::InvalidData)?;
        let table_bar = self.pci_device.bars[msix.table_bar as usize]
            .as_ref()
            .unwrap();
        let pba_bar = self.pci_device.bars[msix.pba_bar as usize]
            .as_ref()
            .unwrap();
        if !table_bar.contains_access(u64::from(msix.table_offset), table_length, 8)
            || !pba_bar.contains_access(u64::from(msix.pba_offset), pba_length, 8)
        {
            log::error!(
                "VirtIO {:?} device has MSI-X table/PBA outside mapped BARs.",
                self.kind
            );
            return Err(ErrorKind::InvalidData.into());
        }

        // Disable INTX.
        let mut command = self.pci_device.id.read_config_u16(pci::PCI_CFG_COMMAND);
        command |= pci::PCI_COMMAND_INTX_DISABLE;
        self.pci_device
            .id
            .write_config_u16(pci::PCI_CFG_COMMAND, command);

        // Enable MSIX.
        let mut msix_ctrl = self.pci_device.id.read_config_u16(ctrl_offset);
        msix_ctrl |= pci::PCIM_MSIXCTRL_MSIX_ENABLE;
        msix_ctrl |= pci::PCIM_MSIXCTRL_FUNCTION_MASK;
        self.pci_device.id.write_config_u16(ctrl_offset, msix_ctrl);
        // Validate success.
        let readback = self.pci_device.id.read_config_u16(ctrl_offset);
        if readback != msix_ctrl {
            log::error!(
                "VirtIO {:?} device failed to enable/mask MSI-X: wrote 0x{msix_ctrl:x}, read 0x{readback:x}.",
                self.kind
            );
            return Err(ErrorKind::InvalidData.into());
        }

        // Mask off all entries.
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
        self.pci_device.id.write_config_u16(ctrl_offset, msix_ctrl);
        // Validate success.
        let readback = self.pci_device.id.read_config_u16(ctrl_offset);
        if readback != msix_ctrl {
            log::error!(
                "VirtIO {:?} device failed to unmask MSI-X: wrote 0x{msix_ctrl:x}, read 0x{readback:x}.",
                self.kind
            );
            return Err(ErrorKind::InvalidData.into());
        }

        log::debug!(
            "MSI-X enabled for {:?} : {:?}.",
            self.kind,
            self.pci_device.id
        );
        self.msix = Some(Box::new(msix));
        Ok(())
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
    pub(crate) fn reset(&self) -> Result<()> {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let status_offset = self.common_cfg.offset as u64
            + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64;

        cfg_bar.writeb(status_offset, 0);
        let status = cfg_bar.readb(status_offset);
        if status != 0 {
            log::error!(
                "VirtioDevice {:?}: reset did not complete, status is 0x{status:x}.",
                self.pci_device.id
            );
            return Err(ErrorKind::InvalidData.into());
        }

        Ok(())
    }

    // Step 2
    pub(crate) fn acknowledge_device(&self) {
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
            return Err(ErrorKind::Unsupported.into());
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

        let msix_vectors = self.msix.as_ref().map(|msix| msix.msgnum);
        if let Err(err) = validate_msix_vectors(msix_vectors, min_virtqueues) {
            match msix_vectors {
                Some(vectors) => log::error!(
                    "VirtIO {:?} device has {vectors} MSI-X vectors; at least {min_virtqueues} required.",
                    self.kind
                ),
                None => log::error!(
                    "VirtIO {:?} device has no MSI-X capability; at least {min_virtqueues} vectors required.",
                    self.kind
                ),
            }
            return Err(err);
        }
        if self.notify_cfg.is_none() {
            log::error!("VirtIO device has no notification capability.");
            return Err(ErrorKind::InvalidData.into());
        }

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
            let virtqueue = Virtqueue::allocate_virtqueue(self, queue_num, queue_size)?;
            let mut virtq_borrowed = virtqueue.borrow_mut();

            if self.virtio_features_negotiated & VIRTIO_F_RING_EVENT_IDX != 0 {
                virtq_borrowed.set_f_event_idx_negotiated();
            }

            virtq_borrowed.queue_notify_off =
                cfg_bar.read_u16(bar_offset + queue_notify_off_offset);
            self.setup_queue_msix(cfg_bar, bar_offset, &mut virtq_borrowed)?; // Step 7.2
            self.setup_queue_data(cfg_bar, bar_offset, &virtq_borrowed); // Step 7.3

            // Step 7.4
            cfg_bar.write_u16(
                bar_offset + offset_of!(VirtioPciCommonCfgLayout, queue_enable) as u64,
                1,
            );

            // Sert VirtQ notify params.
            let notify_cap = self.notify_cfg.unwrap();
            let notify_bar = self.pci_device.bars[notify_cap.bar as usize]
                .as_ref()
                .unwrap();
            let Some(notify_offset) = notify_bar.notify_offset(
                notify_cap.offset,
                notify_cap.length,
                notify_cap.notify_off_multiplier,
                virtq_borrowed.queue_notify_off,
            ) else {
                log::error!("VirtIO queue notification address is outside its capability.");
                return Err(ErrorKind::InvalidData.into());
            };
            virtq_borrowed.set_notify_params(notify_bar as *const PciBar, notify_offset);

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

    /// Start every queue task only after all fallible device setup succeeds.
    pub(super) fn start_queue_tasks(&self) -> Result<()> {
        Virtqueue::start_tasks(&self.virtqueues)
    }

    /// Make the device live. Vsock publishes initial buffers before this call
    /// and sends their deferred notifications afterwards.
    pub(super) fn write_driver_ok(&self) {
        let cfg_bar: &PciBar = self.pci_device.bars[self.common_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let status_offset = self.common_cfg.offset as u64
            + offset_of!(VirtioPciCommonCfgLayout, device_status) as u64;

        // Step 8 (final): write DRIVER_OK.
        let mut status = cfg_bar.readb(status_offset);
        status |= DRIVER_OK_STATUS_BIT;
        cfg_bar.writeb(status_offset, status);
    }

    pub(super) fn driver_ok(&self) -> Result<()> {
        self.start_queue_tasks()?;
        self.write_driver_ok();
        Ok(())
    }
}

static mut MAPPER: Option<&'static dyn super::KernelAdapter> = None;

pub(super) fn mapper() -> &'static dyn super::KernelAdapter {
    unsafe { MAPPER.unwrap() }
}

pub fn discover_virtio_devices(
    mapper: &'static dyn super::KernelAdapter,
) -> std::io::Result<Vec<VirtioDevice>> {
    static ONCE: AtomicBool = AtomicBool::new(false);
    assert!(
        ONCE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    );

    unsafe { MAPPER = Some(mapper) };

    let pci_devices = pci::scan();
    let mut devices = vec![];

    for dev in &pci_devices {
        if let Ok(device) = VirtioDevice::parse(*dev) {
            devices.push(device);
        }
    }
    #[cfg(debug_assertions)]
    log::debug!("done initializing VirtIO");
    Ok(devices)
}
