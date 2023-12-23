//! This crate provides types for representing the RSDP (the Root System Descriptor Table; the first ACPI table)
//! and methods for searching for it on BIOS systems. Importantly, this crate (unlike `acpi`, which re-exports the
//! contents of this crate) does not need `alloc`, and so can be used in environments that can't allocate. This is
//! specifically meant to be used from bootloaders for finding the RSDP, so it can be passed to the payload. If you
//! don't have this requirement, and want to do more than just find the RSDP, you can use `acpi` instead of this
//! crate.
//!
//! To use this crate, you will need to provide an implementation of `AcpiHandler`. This is the same handler type
//! used in the `acpi` crate.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

pub mod handler;

use core::{mem, ops::Range, slice, str};
use handler::{AcpiHandler, PhysicalMapping};
use log::warn;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsdpError {
    NoValidRsdp,
    IncorrectSignature,
    InvalidOemId,
    InvalidChecksum,
}

/// The first structure found in ACPI. It just tells us where the RSDT is.
///
/// On BIOS systems, it is either found in the first 1KB of the Extended Bios Data Area, or between
/// 0x000E0000 and 0x000FFFFF. The signature is always on a 16 byte boundary. On (U)EFI, it may not
/// be located in these locations, and so an address should be found in the EFI configuration table
/// instead.
///
/// The recommended way of locating the RSDP is to let the bootloader do it - Multiboot2 can pass a
/// tag with the physical address of it. If this is not possible, a manual scan can be done.
///
/// If `revision > 0`, (the hardware ACPI version is Version 2.0 or greater), the RSDP contains
/// some new fields. For ACPI Version 1.0, these fields are not valid and should not be accessed.
/// For ACPI Version 2.0+, `xsdt_address` should be used (truncated to `u32` on x86) instead of
/// `rsdt_address`.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,

    /*
     * These fields are only valid for ACPI Version 2.0 and greater
     */
    length: u32,
    xsdt_address: u64,
    ext_checksum: u8,
    reserved: [u8; 3],
}

impl Rsdp {
    /// This searches for a RSDP on BIOS systems.
    ///
    /// ### Safety
    /// This function probes memory in three locations:
    ///    - It reads a word from `40:0e` to locate the EBDA.
    ///    - The first 1KiB of the EBDA (Extended BIOS Data Area).
    ///    - The BIOS memory area at `0xe0000..=0xfffff`.
    ///
    /// This should be fine on all BIOS systems. However, UEFI platforms are free to put the RSDP wherever they
    /// please, so this won't always find the RSDP. Further, prodding these memory locations may have unintended
    /// side-effects. On UEFI systems, the RSDP should be found in the Configuration Table, using two GUIDs:
    ///     - ACPI v1.0 structures use `eb9d2d30-2d88-11d3-9a16-0090273fc14d`.
    ///     - ACPI v2.0 or later structures use `8868e871-e4f1-11d3-bc22-0080c73c8881`.
    /// You should search the entire table for the v2.0 GUID before searching for the v1.0 one.
    pub unsafe fn search_for_on_bios<H>(handler: H) -> Result<PhysicalMapping<H, Rsdp>, RsdpError>
    where
        H: AcpiHandler,
    {
        let rsdp_address = {
            let mut rsdp_address = None;
            let areas = find_search_areas(handler.clone());

            'areas: for area in areas.iter() {
                let mapping = unsafe { handler.map_physical_region::<u8>(area.start, area.end - area.start) };

                for address in area.clone().step_by(16) {
                    let ptr_in_mapping =
                        unsafe { mapping.virtual_start().as_ptr().offset((address - area.start) as isize) };
                    let signature = unsafe { *(ptr_in_mapping as *const [u8; 8]) };

                    if signature == *RSDP_SIGNATURE {
                        match unsafe { *(ptr_in_mapping as *const Rsdp) }.validate() {
                            Ok(()) => {
                                rsdp_address = Some(address);
                                break 'areas;
                            }
                            Err(err) => warn!("Invalid RSDP found at {:#x}: {:?}", address, err),
                        }
                    }
                }
            }

            rsdp_address
        };

        match rsdp_address {
            Some(address) => {
                let rsdp_mapping = unsafe { handler.map_physical_region::<Rsdp>(address, mem::size_of::<Rsdp>()) };
                Ok(rsdp_mapping)
            }
            None => Err(RsdpError::NoValidRsdp),
        }
    }

    /// Checks that:
    ///     1) The signature is correct
    ///     2) The checksum is correct
    ///     3) For Version 2.0+, that the extension checksum is correct
    pub fn validate(&self) -> Result<(), RsdpError> {
        const RSDP_V1_LENGTH: usize = 20;

        // Check the signature
        if &self.signature != RSDP_SIGNATURE {
            return Err(RsdpError::IncorrectSignature);
        }

        // Check the OEM id is valid UTF8 (allows use of unwrap)
        if str::from_utf8(&self.oem_id).is_err() {
            return Err(RsdpError::InvalidOemId);
        }

        /*
         * `self.length` doesn't exist on ACPI version 1.0, so we mustn't rely on it. Instead,
         * check for version 1.0 and use a hard-coded length instead.
         */
        let length = if self.revision > 0 {
            // For Version 2.0+, include the number of bytes specified by `length`
            self.length as usize
        } else {
            RSDP_V1_LENGTH
        };

        let bytes = unsafe { slice::from_raw_parts(self as *const Rsdp as *const u8, length) };
        let sum = bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));

        if sum != 0 {
            return Err(RsdpError::InvalidChecksum);
        }

        Ok(())
    }

    pub fn oem_id(&self) -> &str {
        str::from_utf8(&self.oem_id).unwrap()
    }

    pub fn revision(&self) -> u8 {
        self.revision
    }

    pub fn rsdt_address(&self) -> u32 {
        self.rsdt_address
    }

    pub fn xsdt_address(&self) -> u64 {
        assert!(self.revision > 0, "Tried to read extended RSDP field with ACPI Version 1.0");
        self.xsdt_address
    }
}

/// Find the areas we should search for the RSDP in.
pub fn find_search_areas<H>(handler: H) -> [Range<usize>; 2]
where
    H: AcpiHandler,
{
    /*
     * Read the base address of the EBDA from its location in the BDA (BIOS Data Area). Not all BIOSs fill this out
     * unfortunately, so we might not get a sensible result. We shift it left 4, as it's a segment address.
     */
    let ebda_start_mapping =
        unsafe { handler.map_physical_region::<u16>(EBDA_START_SEGMENT_PTR, mem::size_of::<u16>()) };
    let ebda_start = (*ebda_start_mapping as usize) << 4;

    [
        /*
         * The main BIOS area below 1MiB. In practice, from my [Restioson's] testing, the RSDP is more often here
         * than the EBDA. We also don't want to search the entire possibele EBDA range, if we've failed to find it
         * from the BDA.
         */
        RSDP_BIOS_AREA_START..(RSDP_BIOS_AREA_END + 1),
        // Check if base segment ptr is in valid range for EBDA base
        if (EBDA_EARLIEST_START..EBDA_END).contains(&ebda_start) {
            // First KiB of EBDA
            ebda_start..ebda_start + 1024
        } else {
            // We don't know where the EBDA starts, so just search the largest possible EBDA
            EBDA_EARLIEST_START..(EBDA_END + 1)
        },
    ]
}

/// This (usually!) contains the base address of the EBDA (Extended Bios Data Area), shifted right by 4
const EBDA_START_SEGMENT_PTR: usize = 0x40e;
/// The earliest (lowest) memory address an EBDA (Extended Bios Data Area) can start
const EBDA_EARLIEST_START: usize = 0x80000;
/// The end of the EBDA (Extended Bios Data Area)
const EBDA_END: usize = 0x9ffff;
/// The start of the main BIOS area below 1mb in which to search for the RSDP (Root System Description Pointer)
const RSDP_BIOS_AREA_START: usize = 0xe0000;
/// The end of the main BIOS area below 1mb in which to search for the RSDP (Root System Description Pointer)
const RSDP_BIOS_AREA_END: usize = 0xfffff;
/// The RSDP (Root System Description Pointer)'s signature, "RSD PTR " (note trailing space)
const RSDP_SIGNATURE: &'static [u8; 8] = b"RSD PTR ";
