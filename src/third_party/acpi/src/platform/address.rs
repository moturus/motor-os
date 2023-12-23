//! ACPI defines a Generic Address Structure (GAS), which provides a versatile way to describe register locations
//! in a wide range of address spaces.

use crate::AcpiError;
use core::convert::TryFrom;

/// This is the raw form of a Generic Address Structure, and follows the layout found in the ACPI tables. It does
/// not form part of the public API, and should be turned into a `GenericAddress` for most use-cases.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub(crate) struct RawGenericAddress {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum AddressSpace {
    SystemMemory,
    SystemIo,
    /// Describes a register in the configuration space of a PCI device in segment `0`, on bus `0`. The `address`
    /// field is of the format:
    /// ```ignore
    /// 64              48              32              16               0
    ///  +---------------+---------------+---------------+---------------+
    ///  |  reserved (0) |    device     |   function    |    offset     |
    ///  +---------------+---------------+---------------+---------------+
    /// ```
    PciConfigSpace,
    EmbeddedController,
    SMBus,
    SystemCmos,
    PciBarTarget,
    Ipmi,
    GeneralIo,
    GenericSerialBus,
    PlatformCommunicationsChannel,
    FunctionalFixedHardware,
    OemDefined(u8),
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum AccessSize {
    Undefined,
    ByteAccess,
    WordAccess,
    DWordAccess,
    QWordAccess,
}

impl TryFrom<u8> for AccessSize {
    type Error = AcpiError;

    fn try_from(size: u8) -> Result<Self, Self::Error> {
        match size {
            0 => Ok(AccessSize::Undefined),
            1 => Ok(AccessSize::ByteAccess),
            2 => Ok(AccessSize::WordAccess),
            3 => Ok(AccessSize::DWordAccess),
            4 => Ok(AccessSize::QWordAccess),
            _ => Err(AcpiError::InvalidGenericAddress),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct GenericAddress {
    pub address_space: AddressSpace,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: AccessSize,
    pub address: u64,
}

impl GenericAddress {
    pub(crate) fn from_raw(raw: RawGenericAddress) -> Result<GenericAddress, AcpiError> {
        let address_space = match raw.address_space {
            0x00 => AddressSpace::SystemMemory,
            0x01 => AddressSpace::SystemIo,
            0x02 => AddressSpace::PciConfigSpace,
            0x03 => AddressSpace::EmbeddedController,
            0x04 => AddressSpace::SMBus,
            0x05 => AddressSpace::SystemCmos,
            0x06 => AddressSpace::PciBarTarget,
            0x07 => AddressSpace::Ipmi,
            0x08 => AddressSpace::GeneralIo,
            0x09 => AddressSpace::GenericSerialBus,
            0x0a => AddressSpace::PlatformCommunicationsChannel,
            0x0b..=0x7e => return Err(AcpiError::InvalidGenericAddress),
            0x7f => AddressSpace::FunctionalFixedHardware,
            0x80..=0xbf => return Err(AcpiError::InvalidGenericAddress),
            0xc0..=0xff => AddressSpace::OemDefined(raw.address_space),
        };

        Ok(GenericAddress {
            address_space,
            bit_width: raw.bit_width,
            bit_offset: raw.bit_offset,
            access_size: AccessSize::try_from(raw.access_size)?,
            address: raw.address,
        })
    }
}
