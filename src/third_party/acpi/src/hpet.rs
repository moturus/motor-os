use crate::{platform::address::RawGenericAddress, sdt::SdtHeader, AcpiError, AcpiHandler, AcpiTable, AcpiTables};
use bit_field::BitField;

#[derive(Debug)]
pub enum PageProtection {
    None,
    /// Access to the rest of the 4KiB, relative to the base address, will not generate a fault.
    Protected4K,
    /// Access to the rest of the 64KiB, relative to the base address, will not generate a fault.
    Protected64K,
    Other,
}

/// Information about the High Precision Event Timer (HPET)
#[derive(Debug)]
pub struct HpetInfo {
    // TODO(3.0.0): unpack these fields directly, and get rid of methods
    pub event_timer_block_id: u32,
    pub base_address: usize,
    pub hpet_number: u8,
    /// The minimum number of clock ticks that can be set without losing interrupts (for timers in Periodic Mode)
    pub clock_tick_unit: u16,
    pub page_protection: PageProtection,
}

impl HpetInfo {
    pub fn new<H>(tables: &AcpiTables<H>) -> Result<HpetInfo, AcpiError>
    where
        H: AcpiHandler,
    {
        let hpet = unsafe {
            tables
                .get_sdt::<HpetTable>(crate::sdt::Signature::HPET)?
                .ok_or(AcpiError::TableMissing(crate::sdt::Signature::HPET))?
        };

        // Make sure the HPET's in system memory
        assert_eq!(hpet.base_address.address_space, 0);

        Ok(HpetInfo {
            event_timer_block_id: hpet.event_timer_block_id,
            base_address: hpet.base_address.address as usize,
            hpet_number: hpet.hpet_number,
            clock_tick_unit: hpet.clock_tick_unit,
            page_protection: match hpet.page_protection_and_oem.get_bits(0..4) {
                0 => PageProtection::None,
                1 => PageProtection::Protected4K,
                2 => PageProtection::Protected64K,
                3..=15 => PageProtection::Other,
                _ => unreachable!(),
            },
        })
    }

    pub fn hardware_rev(&self) -> u8 {
        self.event_timer_block_id.get_bits(0..8) as u8
    }

    pub fn num_comparators(&self) -> u8 {
        self.event_timer_block_id.get_bits(8..13) as u8
    }

    pub fn main_counter_is_64bits(&self) -> bool {
        self.event_timer_block_id.get_bit(13)
    }

    pub fn legacy_irq_capable(&self) -> bool {
        self.event_timer_block_id.get_bit(15)
    }

    pub fn pci_vendor_id(&self) -> u16 {
        self.event_timer_block_id.get_bits(16..32) as u16
    }
}

#[repr(C, packed)]
pub struct HpetTable {
    /// The contents of the HPET's 'General Capabilities and ID register'
    header: SdtHeader,
    event_timer_block_id: u32,
    base_address: RawGenericAddress,
    hpet_number: u8,
    clock_tick_unit: u16,
    /// Bits `0..4` specify the page protection guarantee. Bits `4..8` are reserved for OEM attributes.
    page_protection_and_oem: u8,
}

impl AcpiTable for HpetTable {
    fn header(&self) -> &SdtHeader {
        &self.header
    }
}
