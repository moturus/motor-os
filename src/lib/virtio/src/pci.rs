// PCI helpers.

#[allow(non_camel_case_types)]
pub type le64 = u64;
#[allow(non_camel_case_types)]
pub type le32 = u32;
#[allow(non_camel_case_types)]
pub type le16 = u16;

use alloc::vec::Vec;
use core::arch::asm;

pub const PCI_STATUS_CAP_LIST: u16 = 0x10;
pub const PCI_CAPABILITY_LIST: u8 = 0x34;

pub const PCI_CAP_MSI: u8 = 0x05;
pub const PCI_CAP_VENDOR: u8 = 0x09;
pub const PCI_CAP_MSIX: u8 = 0x11;

pub const PCI_CFG_COMMAND: u8 = 0x04;
pub const PCI_COMMAND_BUS_MASTER: u16 = 0x04;
pub const PCI_COMMAND_INTX_DISABLE: u16 = 0x400;

pub const PCIR_MSIX_CTRL: u8 = 0x02;
pub const PCIR_MSIX_TABLE: u8 = 0x04;
pub const PCIR_MSIX_PBA: u8 = 0x8;
pub const PCIM_MSIX_BIR_MASK: u32 = 0x7;
pub const PCIM_MSIXCTRL_TABLE_SIZE: u16 = 0x07ff;
pub const PCIM_MSIXCTRL_MSIX_ENABLE: u16 = 0x8000;
pub const PCIM_MSIXCTRL_FUNCTION_MASK: u16 = 0x4000;

pub const PCI_MSIX_ENTRY_CTRL_MASKBIT: u32 = 1;

#[derive(Clone, Copy, Debug)]
pub(super) struct PciDeviceID {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
}

impl PciDeviceID {
    fn new(bus: u8, slot: u8, func: u8) -> Self {
        assert!(slot < 32);
        assert!(func < 8);
        PciDeviceID { bus, slot, func }
    }

    fn prepare_access(&self, offset: u8) {
        let bus = self.bus as u32;
        let slot = self.slot as u32; // slot
        let func = self.func as u32;
        let offset = offset as u32;

        let address =
            ((bus << 16) | (slot << 11) | (func << 8) | (offset & 0xfc) | 0x80000000) as u32;
        let port = 0xcf8_u16;

        unsafe {
            asm!("out dx, eax", in("dx") port, in("eax") address, options(nomem, nostack, preserves_flags));
        }
    }

    pub fn read_config_u32(&self, offset: u8) -> u32 {
        self.prepare_access(offset);

        let result: u32;
        let port = 0xcfc_u16;
        unsafe {
            asm!("in eax, dx", out("eax") result, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        result
    }

    #[allow(dead_code)]
    pub fn write_config_u32(&self, offset: u8, value: u32) {
        self.prepare_access(offset);

        let port = 0xcfc_u16;
        unsafe {
            asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
        }
    }

    pub fn read_config_u16(&self, offset: u8) -> u16 {
        self.prepare_access(offset);

        let result: u16;
        let port = 0xcfc_u16 + (offset & 0x2) as u16;
        unsafe {
            asm!("in ax, dx", out("ax") result, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        result
    }

    pub fn write_config_u16(&self, offset: u8, value: u16) {
        self.prepare_access(offset);

        let port = 0xcfc_u16 + (offset & 0x2) as u16;
        unsafe {
            asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags));
        }
    }

    #[allow(dead_code)]
    pub fn read_config_u8(&self, offset: u8) -> u8 {
        self.prepare_access(offset);

        let result: u8;
        let port = 0xcfc_u16 + (offset & 0x3) as u16;
        unsafe {
            asm!("in al, dx", out("al") result, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        result
    }

    #[allow(dead_code)]
    fn write_config_u8(&self, offset: u8, value: u8) {
        self.prepare_access(offset);

        let port = 0xcfc_u16 + (offset & 0x3) as u16;
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
        }
    }

    pub fn vendor_id(&self) -> le16 {
        let res = self.read_config_u32(0);
        (res & 0xFFFF) as le16
    }

    pub fn device_id(&self) -> le16 {
        let res = self.read_config_u32(0);
        ((res >> 16) & 0xFFFF) as le16
    }

    fn valid(&self) -> bool {
        self.vendor_id() != 0xffff
    }

    pub fn header_type(&self) -> u8 {
        assert_eq!(self.func, 0);
        let res = self.read_config_u32(0x0C);
        ((res >> 16) & 0xFF) as u8
    }

    // See __pci_find_next_cap_ttl()
    // https://elixir.bootlin.com/linux/v5.16.1/source/drivers/pci/pci.c#L412
    pub fn find_capabilities(&self, capability: u8) -> alloc::vec::Vec<u8> {
        let mut result = alloc::vec::Vec::<u8>::new();

        let reg_d = self.read_config_u32(PCI_CAPABILITY_LIST);
        let capabilities_ptr: u8 = (reg_d & 0xFF) as u8;

        let mut pos = capabilities_ptr;
        let mut attempts_left: u8 = 48; // See PCI_FIND_CAP_TTL in Linux.

        while attempts_left > 0 {
            if pos < 0x40 {
                break;
            }

            pos &= !0x3;
            let cap_16 = self.read_config_u16(pos);

            let cap_id = (cap_16 & 0xff) as u8;
            if cap_id == capability {
                result.push(pos);
            }

            pos = (cap_16 >> 8) as u8;

            attempts_left -= 1;
        }

        result
    }
}

#[allow(dead_code)]
pub(super) struct PciBar {
    pci_device_id: PciDeviceID,

    idx: u8, // 0..=5
    offset: u8,
    phys_addr: u64,
    addr_size: u64,
    virt_addr: u64, // mapped

    is_64: bool,
    is_prefetchable: bool,
    is_mmio: bool,
}

impl PciBar {
    pub fn init(pci_device_id: PciDeviceID, idx: u8) -> Self {
        let offset = (idx << 2) + 0x10; // these are [0..5]
        let bar = pci_device_id.read_config_u32(offset);
        let is_mmio = bar & 1 == 0;
        let is_prefetchable = bar & 8 == 8;
        let is_64 = bar & 6 == 4;

        assert!(is_mmio); // We only support mmio.

        // For some reason, this is how bar size is determined, both in
        // osv and in linux.
        pci_device_id.write_config_u32(offset, !0x0);
        let sz_lo = pci_device_id.read_config_u32(offset) & 0xff_ff_ff_f0;
        pci_device_id.write_config_u32(offset, bar);

        let sz_hi = if is_64 {
            let prev = pci_device_id.read_config_u32(offset + 4);
            pci_device_id.write_config_u32(offset + 4, !0x0);
            let res = pci_device_id.read_config_u32(offset + 4);
            pci_device_id.write_config_u32(offset + 4, prev);
            res
        } else {
            0xff_ff_ff_ff
        };

        let sz: u64 = 1 + !(((sz_hi as u64) << 32) | (sz_lo as u64));

        // Note: a step is skipped here because x86; on arm there is
        // an extra step here, see osv::bar::bar in drivers/pci_function.cc
        let addr_lo = if is_mmio {
            bar & 0xff_ff_ff_f0
        } else {
            bar & 0xff_ff_ff_fc
        };

        let addr_hi = if is_64 {
            pci_device_id.read_config_u32(offset + 4)
        } else {
            0
        };

        let phys_addr: u64 = ((addr_hi as u64) << 32) | (addr_lo as u64);

        //log_trace!("bar: 0x{:x} mmio: {} prefetchable: {} is_64: {} sz: 0x{:x} addr: 0x{:x}",
        //    bar, mmio, prefetchable, is_64, sz, addr);

        log::debug!(
            "Mapping PciBar: device: {:?} bar: {} phys_addr: 0x{:x} sz: 0x{:x}",
            pci_device_id,
            idx,
            phys_addr,
            sz
        );

        let virt_addr = super::mapper().mmio_map(phys_addr, sz).unwrap();
        log::debug!(
            "Mapped PciBar: device: {:?} bar: {} phys_addr: 0x{:x} sz: 0x{:x} to virt 0x{:x}",
            pci_device_id,
            idx,
            phys_addr,
            sz,
            virt_addr
        );

        PciBar {
            pci_device_id,
            idx,
            offset,
            phys_addr,
            addr_size: sz,
            virt_addr,
            is_64,
            is_prefetchable,
            is_mmio,
        }
    }

    pub fn readb(&self, offset: u64) -> u8 {
        // unsafe { core::intrinsics::atomic_load_acq((virt_addr + offset) as *const u8) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::read_volatile((self.virt_addr + offset) as *const u8) }
    }

    pub fn writeb(&self, offset: u64, val: u8) {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::write_volatile((self.virt_addr + offset) as *mut u8, val) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    pub fn read_u16(&self, offset: u64) -> u16 {
        // unsafe { core::intrinsics::atomic_load_acq((virt_addr + offset) as *const u8) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::read_volatile((self.virt_addr + offset) as *const u16) }
    }

    pub fn write_u16(&self, offset: u64, val: u16) {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::write_volatile((self.virt_addr + offset) as *mut u16, val) }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    pub fn write_u16_unfenced(&self, offset: u64, val: u16) {
        unsafe { core::ptr::write_volatile((self.virt_addr + offset) as *mut u16, val) }
    }

    pub fn read_u32(&self, offset: u64) -> u32 {
        // unsafe { core::intrinsics::atomic_load_acq((virt_addr + offset) as *const u8) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::read_volatile((self.virt_addr + offset) as *const u32) }
    }

    pub fn write_u32(&self, offset: u64, val: u32) {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        unsafe { core::ptr::write_volatile((self.virt_addr + offset) as *mut u32, val) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    pub fn read_u64(&self, offset: u64) -> u64 {
        // unsafe { core::intrinsics::atomic_load_acq((virt_addr + offset) as *const u8) }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        unsafe {
            let lo = core::ptr::read_volatile((self.virt_addr + offset) as *const u32);
            let hi = core::ptr::read_volatile((self.virt_addr + offset + 4) as *const u32);
            (lo as u64) + ((hi as u64) << 32)
        }
    }

    pub fn write_u64(&self, offset: u64, val: u64) {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let lo = (val & 0xff_ff_ff_ff) as u32;
        let hi = (val >> 32) as u32;
        unsafe {
            core::ptr::write_volatile((self.virt_addr + offset) as *mut u32, lo);
            core::ptr::write_volatile((self.virt_addr + offset + 4) as *mut u32, hi);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

pub(super) struct PciDevice {
    pub id: PciDeviceID,

    pub bars: [Option<PciBar>; 6],
}

impl PciDevice {
    pub fn new(id: PciDeviceID) -> Self {
        let bars: [Option<PciBar>; 6] = [None, None, None, None, None, None];
        PciDevice { id, bars }
    }
}

pub(super) fn brute_force_scan() -> Vec<PciDeviceID> {
    // Make sure the scan happens only once.
    static ONCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    assert!(!ONCE.swap(true, core::sync::atomic::Ordering::Relaxed));

    let mut result = Vec::new();
    for bus in 0u8..=255 {
        for slot in 0u8..32 {
            let dev = PciDeviceID::new(bus, slot, 0);
            if !dev.valid() {
                continue;
            }

            result.push(dev.clone());

            if (dev.header_type() & 0x80) != 0 {
                // Multi-function: check functions 1 to 7.
                for func in 1u8..8 {
                    let dev = PciDeviceID::new(bus, slot, func);
                    if dev.valid() {
                        result.push(dev)
                    }
                }
            }
        }
    }
    result
}
