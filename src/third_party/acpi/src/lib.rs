//! A library for parsing ACPI tables. This crate can be used by bootloaders and kernels for architectures that
//! support ACPI. This crate is not feature-complete, but can parse lots of the more common tables. Parsing the
//! ACPI tables is required for correctly setting up the APICs, HPET, and provides useful information about power
//! management and many other platform capabilities.
//!
//! This crate is designed to find and parse the static tables ACPI provides. It should be used in conjunction with
//! the `aml` crate, which is the (much less complete) AML parser used to parse the DSDT and SSDTs. These crates
//! are separate because some kernels may want to detect the static tables, but delay AML parsing to a later stage.
//!
//! This crate requires `alloc` to make heap allocations. If you are trying to find the RSDP in an environment that
//! does not have a heap (e.g. a bootloader), you can use the `rsdp` crate. The types from that crate are
//! compatible with `acpi`.
//!
//! ### Usage
//! To use the library, you will need to provide an implementation of the `AcpiHandler` trait, which allows the
//! library to make requests such as mapping a particular region of physical memory into the virtual address space.
//!
//! You then need to construct an instance of `AcpiTables`, which can be done in a few ways depending on how much
//! information you have:
//! * Use `AcpiTables::from_rsdp` if you have the physical address of the RSDP
//! * Use `AcpiTables::from_rsdt` if you have the physical address of the RSDT/XSDT
//! * Use `AcpiTables::search_for_rsdp_bios` if you don't have the address of either, but **you know you are
//! running on BIOS, not UEFI**
//! * Use `AcpiTables::from_tables_direct` if you are using the library in an unusual setting, such as in usermode,
//!   and have a custom method to enumerate and access the tables.
//!
//! `AcpiTables` stores the addresses of all of the tables detected on a platform. The SDTs are parsed by this
//! library, or can be accessed directly with `from_sdt`, while the `DSDT` and any `SSDTs` should be parsed with
//! `aml`.
//!
//! To gather information out of the static tables, a few of the types you should take a look at are:
//!    - [`PlatformInfo`](crate::platform::PlatformInfo) parses the FADT and MADT to create a nice view of the
//!      processor topology and interrupt controllers on `x86_64`, and the interrupt controllers on other platforms.
//!      `AcpiTables::platform_info` is a convenience method for constructing a `PlatformInfo`.
//!    - [`HpetInfo`](crate::hpet::HpetInfo) parses the HPET table and tells you how to configure the High
//!      Precision Event Timer.
//!    - [`PciConfigRegions`](crate::mcfg::PciConfigRegions) parses the MCFG and tells you how PCIe configuration
//!      space is mapped into physical memory.

/*
 * Contributing notes (you may find these useful if you're new to contributing to the library):
 *    - Accessing packed fields without UB: Lots of the structures defined by ACPI are defined with `repr(packed)`
 *      to prevent padding being introduced, which would make the structure's layout incorrect. In Rust, this
 *      creates a problem as references to these fields could be unaligned, which is undefined behaviour. For the
 *      majority of these fields, this problem can be easily avoided by telling the compiler to make a copy of the
 *      field's contents: this is the perhaps unfamiliar pattern of e.g. `!{ entry.flags }.get_bit(0)` we use
 *      around the codebase.
 */

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg_attr(test, macro_use)]
#[cfg(test)]
extern crate std;

pub mod bgrt;
pub mod fadt;
pub mod hpet;
pub mod madt;
pub mod mcfg;
pub mod platform;
pub mod sdt;

pub use crate::{
    fadt::PowerProfile,
    hpet::HpetInfo,
    madt::MadtError,
    mcfg::PciConfigRegions,
    platform::{interrupt::InterruptModel, PlatformInfo},
};
pub use rsdp::{
    handler::{AcpiHandler, PhysicalMapping},
    RsdpError,
};

use crate::sdt::{SdtHeader, Signature};
use alloc::{collections::BTreeMap, vec::Vec};
use core::mem;
use log::trace;
use rsdp::Rsdp;

#[derive(Debug)]
pub enum AcpiError {
    Rsdp(RsdpError),

    SdtInvalidSignature(Signature),
    SdtInvalidOemId(Signature),
    SdtInvalidTableId(Signature),
    SdtInvalidChecksum(Signature),

    TableMissing(Signature),
    InvalidFacsAddress,
    InvalidDsdtAddress,
    InvalidMadt(MadtError),
    InvalidGenericAddress,
}

pub struct AcpiTables<H>
where
    H: AcpiHandler,
{
    /// The revision of ACPI that the system uses, as inferred from the revision of the RSDT/XSDT.
    pub revision: u8,
    pub sdts: BTreeMap<sdt::Signature, Sdt>,
    pub dsdt: Option<AmlTable>,
    pub ssdts: Vec<AmlTable>,
    handler: H,
}

impl<H> AcpiTables<H>
where
    H: AcpiHandler,
{
    /// Create an `AcpiTables` if you have the physical address of the RSDP.
    pub unsafe fn from_rsdp(handler: H, rsdp_address: usize) -> Result<AcpiTables<H>, AcpiError> {
        let rsdp_mapping =
            unsafe { handler.map_physical_region::<Rsdp>(rsdp_address, mem::size_of::<Rsdp>()) };
        rsdp_mapping.validate().map_err(AcpiError::Rsdp)?;

        Self::from_validated_rsdp(handler, rsdp_mapping)
    }

    /// Search for the RSDP on a BIOS platform. This accesses BIOS-specific memory locations and will probably not
    /// work on UEFI platforms. See [Rsdp::search_for_rsdp_bios](rsdp_search::Rsdp::search_for_rsdp_bios) for
    /// details.
    pub unsafe fn search_for_rsdp_bios(handler: H) -> Result<AcpiTables<H>, AcpiError> {
        let rsdp_mapping =
            unsafe { Rsdp::search_for_on_bios(handler.clone()) }.map_err(AcpiError::Rsdp)?;
        Self::from_validated_rsdp(handler, rsdp_mapping)
    }

    /// Create an `AcpiTables` if you have a `PhysicalMapping` of the RSDP that you know is correct. This is called
    /// from `from_rsdp` after validation, but can also be used if you've searched for the RSDP manually on a BIOS
    /// system.
    pub fn from_validated_rsdp(
        handler: H,
        rsdp_mapping: PhysicalMapping<H, Rsdp>,
    ) -> Result<AcpiTables<H>, AcpiError> {
        let revision = rsdp_mapping.revision();

        if revision == 0 {
            /*
             * We're running on ACPI Version 1.0. We should use the 32-bit RSDT address.
             */
            let rsdt_address = rsdp_mapping.rsdt_address();
            unsafe { Self::from_rsdt(handler, revision, rsdt_address as usize) }
        } else {
            /*
             * We're running on ACPI Version 2.0+. We should use the 64-bit XSDT address, truncated
             * to 32 bits on x86.
             */
            let xsdt_address = rsdp_mapping.xsdt_address();
            unsafe { Self::from_rsdt(handler, revision, xsdt_address as usize) }
        }
    }

    /// Create an `AcpiTables` if you have the physical address of the RSDT. This is useful, for example, if your chosen
    /// bootloader reads the RSDP and passes you the address of the RSDT. You also need to supply the correct ACPI
    /// revision - if `0`, a RSDT is expected, while a `XSDT` is expected for greater revisions.
    pub unsafe fn from_rsdt(
        handler: H,
        revision: u8,
        rsdt_address: usize,
    ) -> Result<AcpiTables<H>, AcpiError> {
        let mut result = AcpiTables {
            revision,
            sdts: BTreeMap::new(),
            dsdt: None,
            ssdts: Vec::new(),
            handler,
        };

        let header = sdt::peek_at_sdt_header(&result.handler, rsdt_address);
        let mapping = unsafe {
            result
                .handler
                .map_physical_region::<SdtHeader>(rsdt_address, header.length as usize)
        };

        if revision == 0 {
            /*
             * ACPI Version 1.0. It's a RSDT!
             */
            mapping.validate(sdt::Signature::RSDT)?;

            let num_tables =
                (mapping.length as usize - mem::size_of::<SdtHeader>()) / mem::size_of::<u32>();
            let tables_base = ((mapping.virtual_start().as_ptr() as usize)
                + mem::size_of::<SdtHeader>()) as *const u32;

            for i in 0..num_tables {
                // result.process_sdt(unsafe { *tables_base.add(i) as usize })?;
                result.process_sdt(unsafe {
                    core::ptr::read_unaligned(tables_base.add(i)) as usize
                })?;
            }
        } else {
            /*
             * ACPI Version 2.0+. It's a XSDT!
             */
            mapping.validate(sdt::Signature::XSDT)?;

            let num_tables =
                (mapping.length as usize - mem::size_of::<SdtHeader>()) / mem::size_of::<u64>();
            let tables_base = ((mapping.virtual_start().as_ptr() as usize)
                + mem::size_of::<SdtHeader>()) as *const u64;

            for i in 0..num_tables {
                // result.process_sdt(unsafe { *tables_base.add(i) as usize })?;
                result.process_sdt(unsafe {
                    core::ptr::read_unaligned(tables_base.add(i)) as usize
                })?;
            }
        }

        Ok(result)
    }

    /// Construct an `AcpiTables` from a custom set of "discovered" tables. This is provided to allow the library
    /// to be used from unconventional settings (e.g. in userspace), for example with a `AcpiHandler` that detects
    /// accesses to specific physical addresses, and provides the correct data.
    pub fn from_tables_direct(
        handler: H,
        revision: u8,
        sdts: BTreeMap<sdt::Signature, Sdt>,
        dsdt: Option<AmlTable>,
        ssdts: Vec<AmlTable>,
    ) -> AcpiTables<H> {
        AcpiTables {
            revision,
            sdts,
            dsdt,
            ssdts,
            handler,
        }
    }

    fn process_sdt(&mut self, physical_address: usize) -> Result<(), AcpiError> {
        let header = sdt::peek_at_sdt_header(&self.handler, physical_address);
        trace!(
            "Found ACPI table with signature {:?} and length {:?}",
            header.signature,
            { header.length }
        );

        match header.signature {
            Signature::FADT => {
                use crate::fadt::Fadt;

                /*
                 * For whatever reason, they chose to put the DSDT inside the FADT, instead of just listing it
                 * as another SDT. We extract it here to provide a nicer public API.
                 */
                let fadt_mapping = unsafe {
                    self.handler
                        .map_physical_region::<Fadt>(physical_address, mem::size_of::<Fadt>())
                };
                fadt_mapping.validate()?;

                let dsdt_address = fadt_mapping.dsdt_address()?;
                let dsdt_header = sdt::peek_at_sdt_header(&self.handler, dsdt_address);
                self.dsdt = Some(AmlTable::new(dsdt_address, dsdt_header.length));

                /*
                 * We've already validated the FADT to get the DSDT out, so it doesn't need to be done again.
                 */
                self.sdts.insert(
                    Signature::FADT,
                    Sdt {
                        physical_address,
                        length: header.length,
                        validated: true,
                    },
                );
            }
            Signature::SSDT => {
                self.ssdts
                    .push(AmlTable::new(physical_address, header.length));
            }
            signature => {
                self.sdts.insert(
                    signature,
                    Sdt {
                        physical_address,
                        length: header.length,
                        validated: false,
                    },
                );
            }
        }

        Ok(())
    }

    /// Create a mapping to a SDT, given its signature. This validates the SDT if it has not already been
    /// validated.
    ///
    /// ### Safety
    /// The table's memory is naively interpreted as a `T`, and so you must be careful in providing a type that
    /// correctly represents the table's structure. Regardless of the provided type's size, the region mapped will
    /// be the size specified in the SDT's header. Providing a `T` that is larger than this, *may* lead to
    /// page-faults, aliasing references, or derefencing uninitialized memory (the latter two of which are UB).
    /// This isn't forbidden, however, because some tables rely on `T` being larger than a provided SDT in some
    /// versions of ACPI (the [`ExtendedField`](crate::sdt::ExtendedField) type will be useful if you need to do
    /// this. See our [`Fadt`](crate::fadt::Fadt) type for an example of this).
    pub unsafe fn get_sdt<T>(
        &self,
        signature: sdt::Signature,
    ) -> Result<Option<PhysicalMapping<H, T>>, AcpiError>
    where
        T: AcpiTable,
    {
        let sdt = match self.sdts.get(&signature) {
            Some(sdt) => sdt,
            None => return Ok(None),
        };
        let mapping = unsafe {
            self.handler
                .map_physical_region::<T>(sdt.physical_address, sdt.length as usize)
        };

        if !sdt.validated {
            mapping.header().validate(signature)?;
        }

        Ok(Some(mapping))
    }

    /// Convenience method for contructing a [`PlatformInfo`](crate::platform::PlatformInfo). This is one of the
    /// first things you should usually do with an `AcpiTables`, and allows to collect helpful information about
    /// the platform from the ACPI tables.
    pub fn platform_info(&self) -> Result<PlatformInfo, AcpiError> {
        PlatformInfo::new(self)
    }
}

pub struct Sdt {
    /// Physical address of the start of the SDT, including the header.
    pub physical_address: usize,
    /// Length of the table in bytes.
    pub length: u32,
    /// Whether this SDT has been validated. This is set to `true` the first time it is mapped and validated.
    pub validated: bool,
}

/// All types representing ACPI tables should implement this trait.
pub trait AcpiTable {
    fn header(&self) -> &sdt::SdtHeader;
}

#[derive(Debug)]
pub struct AmlTable {
    /// Physical address of the start of the AML stream (excluding the table header).
    pub address: usize,
    /// Length (in bytes) of the AML stream.
    pub length: u32,
}

impl AmlTable {
    /// Create an `AmlTable` from the address and length of the table **including the SDT header**.
    pub(crate) fn new(address: usize, length: u32) -> AmlTable {
        AmlTable {
            address: address + mem::size_of::<SdtHeader>(),
            length: length - mem::size_of::<SdtHeader>() as u32,
        }
    }
}
