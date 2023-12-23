//! x2APIC, the most recent APIC on x86 for large servers with more than 255 cores.
use bit_field::BitField;

use super::*;
use crate::msr::{
    rdmsr, wrmsr, IA32_APIC_BASE, IA32_TSC_DEADLINE, IA32_X2APIC_APICID, IA32_X2APIC_EOI,
    IA32_X2APIC_ESR, IA32_X2APIC_ICR, IA32_X2APIC_LDR, IA32_X2APIC_LVT_LINT0,
    IA32_X2APIC_LVT_TIMER, IA32_X2APIC_SELF_IPI, IA32_X2APIC_SIVR, IA32_X2APIC_VERSION,
};

/// Represents an x2APIC driver instance.
#[derive(Debug)]
pub struct X2APIC {
    /// Initial base msr register value.
    base: u64,
}

impl Default for X2APIC {
    fn default() -> Self {
        X2APIC { base: 0x0 }
    }
}

impl X2APIC {
    /// Create a new x2APIC driver object for the local core.
    ///
    /// # Notes
    /// The object needs to be initialized by calling `attach()` first which
    /// enables the x2APIC. There should be only one x2APIC object created per
    /// core.
    pub const fn new() -> Self {
        X2APIC { base: 0x0 }
    }

    /// Attach to APIC (enable x2APIC mode, initialize LINT0)
    pub fn attach(&mut self) {
        // Enable
        unsafe {
            // Enable x2APIC mode globally
            self.base = rdmsr(IA32_APIC_BASE);
            self.base.set_bit(10, true); // Enable x2APIC
            self.base.set_bit(11, true); // Enable xAPIC
            wrmsr(IA32_APIC_BASE, self.base);

            // Enable this XAPIC (set bit 8, spurious IRQ vector 15)
            let svr: u64 = 1 << 8 | 15;
            wrmsr(IA32_X2APIC_SIVR, svr);

            // TODO: Fix magic number?
            let lint0 = 1 << 16 | (1 << 15) | (0b111 << 8) | 0x20;
            wrmsr(IA32_X2APIC_LVT_LINT0, lint0);

            let _esr = rdmsr(IA32_X2APIC_ESR);
        }
    }

    /// Detach from APIC (disable x2APIC and xAPIC mode).
    pub fn detach(&mut self) {
        unsafe {
            self.base = rdmsr(IA32_APIC_BASE);
            self.base.set_bit(10, false); // x2APIC
            self.base.set_bit(11, false); // xAPIC
            wrmsr(IA32_APIC_BASE, self.base);
        }
    }

    /// Send an IPI to yourself.
    ///
    /// # Safety
    /// Will interrupt core with `vector`.
    pub unsafe fn send_self_ipi(&self, vector: u64) {
        wrmsr(IA32_X2APIC_SELF_IPI, vector);
    }
}

/// Abstracts common interface of APIC (x2APIC, xAPIC) hardware devices.
impl ApicControl for X2APIC {
    /// Is a bootstrap processor?
    fn bsp(&self) -> bool {
        (self.base & (1 << 8)) > 0
    }

    /// Read local x2APIC ID.
    fn id(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_APICID) as u32 }
    }

    /// In x2APIC mode, the 32-bit logical x2APIC ID, can be read from LDR.
    fn logical_id(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_LDR) as u32 }
    }

    /// Read APIC version.
    fn version(&self) -> u32 {
        unsafe { rdmsr(IA32_X2APIC_VERSION) as u32 }
    }

    /// Enable TSC timer
    fn tsc_enable(&mut self, vector: u8) {
        unsafe {
            wrmsr(IA32_TSC_DEADLINE, 0);

            let mut lvt: u64 = rdmsr(IA32_X2APIC_LVT_TIMER);
            lvt &= !0xff;
            lvt |= vector as u64;

            // Unmask timer IRQ
            lvt.set_bit(16, false);

            // Enable TSC deadline mode
            lvt.set_bit(17, false);
            lvt.set_bit(18, true);
            wrmsr(IA32_X2APIC_LVT_TIMER, lvt);
        }
    }

    /// Set tsc deadline.
    fn tsc_set(&self, value: u64) {
        unsafe {
            crate::fence::mfence();
            wrmsr(IA32_TSC_DEADLINE, value);
        }
    }

    /// End Of Interrupt -- Acknowledge interrupt delivery.
    fn eoi(&mut self) {
        unsafe {
            wrmsr(IA32_X2APIC_EOI, 0);
        }
    }

    /// Send a INIT IPI to a core.
    unsafe fn ipi_init(&mut self, core: ApicId) {
        let icr = Icr::for_x2apic(
            0,
            core,
            DestinationShorthand::NoShorthand,
            DeliveryMode::Init,
            DestinationMode::Physical,
            DeliveryStatus::Idle,
            Level::Assert,
            TriggerMode::Level,
        );
        self.send_ipi(icr);
    }

    /// Deassert INIT IPI.
    unsafe fn ipi_init_deassert(&mut self) {
        let icr = Icr::for_x2apic(
            0,
            ApicId::X2Apic(0),
            // INIT deassert is always sent to everyone, so we are supposed to specify:
            DestinationShorthand::AllIncludingSelf,
            DeliveryMode::Init,
            DestinationMode::Physical,
            DeliveryStatus::Idle,
            Level::Deassert,
            TriggerMode::Level,
        );
        self.send_ipi(icr);
    }

    /// Send a STARTUP IPI to a core.
    unsafe fn ipi_startup(&mut self, core: ApicId, start_page: u8) {
        let icr = Icr::for_x2apic(
            start_page,
            core,
            DestinationShorthand::NoShorthand,
            DeliveryMode::StartUp,
            DestinationMode::Physical,
            DeliveryStatus::Idle,
            Level::Assert,
            TriggerMode::Edge,
        );
        self.send_ipi(icr);
    }

    /// Send a generic IPI.
    unsafe fn send_ipi(&mut self, icr: Icr) {
        wrmsr(IA32_X2APIC_ESR, 0);
        wrmsr(IA32_X2APIC_ESR, 0);

        wrmsr(IA32_X2APIC_ICR, icr.0);

        loop {
            let icr = rdmsr(IA32_X2APIC_ICR);
            if (icr >> 12 & 0x1) == 0 {
                break;
            }
            if rdmsr(IA32_X2APIC_ESR) > 0 {
                break;
            }
        }
    }
}
