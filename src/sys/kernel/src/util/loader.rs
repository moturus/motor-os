use moto_sys::ErrorCode;

use crate::mm::{MappingOptions, PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};

// Segments a binary can have mapped in place.
const MAX_MAPPED: usize = 8;

struct Loader<'a> {
    address_space: &'a crate::mm::user::UserAddressSpace,

    // The ELF bytes, when they sit page-aligned in kernel-static memory (see
    // init::copy_sys_io): read-only segments are then mapped from them
    // instead of allocated and copied.
    bytes_start: Option<u64>,
    bytes_len: u64,

    // Segments mapped in place: (vaddr, size). Nothing is ever written there.
    mapped: [(u64, u64); MAX_MAPPED],
    num_mapped: usize,
}

impl Loader<'_> {
    fn is_mapped(&self, addr: u64, sz: u64) -> bool {
        self.mapped[..self.num_mapped]
            .iter()
            .any(|(start, size)| *start <= addr && addr + sz <= start + size)
    }

    // The kernel address of the file pages backing a read-only segment, if
    // the segment can be mapped from them: the file and memory images must
    // agree page for page.
    fn in_place_source(
        &self,
        header: &elfloader::ProgramHeader,
        vaddr_start: u64,
        num_pages: u64,
    ) -> Option<u64> {
        let bytes_start = self.bytes_start?;
        if header.file_size() != header.mem_size()
            || header.offset() & (PAGE_SIZE_SMALL - 1)
                != header.virtual_addr() & (PAGE_SIZE_SMALL - 1)
        {
            return None;
        }
        let file_start = header.offset() - (header.virtual_addr() - vaddr_start);
        let file_end = file_start + (num_pages << PAGE_SIZE_SMALL_LOG2);
        if file_end > crate::mm::align_up(self.bytes_len, PAGE_SIZE_SMALL) {
            return None;
        }
        Some(bytes_start + file_start)
    }
}

impl elfloader::ElfLoader for Loader<'_> {
    fn allocate(
        &mut self,
        load_headers: elfloader::LoadableHeaders,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        for header in load_headers {
            if header.flags().is_write() && header.flags().is_execute() {
                return Err(elfloader::ElfLoaderErr::UnsupportedElfFormat);
            }

            let vaddr_start = crate::mm::align_down(header.virtual_addr(), PAGE_SIZE_SMALL);
            let vaddr_end =
                crate::mm::align_up(header.virtual_addr() + header.mem_size(), PAGE_SIZE_SMALL);
            let num_pages = (vaddr_end - vaddr_start) >> PAGE_SIZE_SMALL_LOG2;

            let mut mapping_options = MappingOptions::USER_ACCESSIBLE;
            if header.flags().is_read() {
                mapping_options |= MappingOptions::READABLE;
            }
            if header.flags().is_write() {
                mapping_options |= MappingOptions::WRITABLE;
            }
            // The kernel writes through the direct map, so the user-side W
            // bit does not need to be set while loading executable text.
            if header.flags().is_execute() {
                mapping_options |= MappingOptions::EXECUTABLE;
            }

            let in_place = if header.flags().is_write() {
                None
            } else {
                self.in_place_source(&header, vaddr_start, num_pages)
            };
            if let Some(kernel_vaddr) = in_place {
                let mapped = self
                    .address_space
                    .map_kernel_static(vaddr_start, kernel_vaddr, num_pages, mapping_options)
                    .is_ok();
                if mapped {
                    if self.num_mapped == MAX_MAPPED {
                        return Err(elfloader::ElfLoaderErr::UnsupportedElfFormat);
                    }
                    self.mapped[self.num_mapped] = (vaddr_start, num_pages << PAGE_SIZE_SMALL_LOG2);
                    self.num_mapped += 1;
                    continue;
                }
            }

            self.address_space
                .allocate_user_fixed(vaddr_start, num_pages, mapping_options)
                .map_err(|_| elfloader::ElfLoaderErr::OutOfMemory)?;
        }
        Ok(())
    }

    fn load(
        &mut self,
        _flags: elfloader::Flags,
        base: elfloader::VAddr,
        region: &[u8],
    ) -> Result<(), elfloader::ElfLoaderErr> {
        if self.is_mapped(base, region.len() as u64) {
            return Ok(()); // Already there.
        }
        self.address_space
            .copy_to_user(region, base)
            .map_err(|_| elfloader::ElfLoaderErr::UnsupportedElfFormat)
    }

    fn relocate(
        &mut self,
        entry: elfloader::RelocationEntry,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use elfloader::RelocationType::x86_64;

        let remote_addr: u64 = entry.offset;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // We don't relocate: the binary is loaded at its link address,
                // so the addend is the value. A relocation into a segment
                // mapped in place cannot be applied.
                let addend: u64 = entry
                    .addend
                    .ok_or(elfloader::ElfLoaderErr::UnsupportedRelocationEntry)?;
                if self.is_mapped(remote_addr, core::mem::size_of::<u64>() as u64) {
                    return Err(elfloader::ElfLoaderErr::UnsupportedRelocationEntry);
                }

                let buf: &[u8] = unsafe {
                    core::slice::from_raw_parts(
                        &addend as *const _ as *const u8,
                        core::mem::size_of::<u64>(),
                    )
                };
                self.address_space
                    .copy_to_user(buf, remote_addr)
                    .map_err(|_| elfloader::ElfLoaderErr::UnsupportedRelocationEntry)
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            _ => {
                panic!("elf loader: unrecognized entry type: {:#?}", entry.rtype);
            }
        }
    }
}

// Loads the elf file at zero offset; returns the entry point address.
pub fn load_elf(
    elf_bytes: &[u8],
    address_space: &crate::mm::user::UserAddressSpace,
) -> Result<u64, ErrorCode> {
    let elf_binary = elfloader::ElfBinary::new(elf_bytes).map_err(|_| -> ErrorCode {
        log::error!("ELF parsing failed.");
        moto_rt::E_INVALID_ARGUMENT
    })?;

    if elf_binary.get_arch() != elfloader::Machine::X86_64 {
        log::error!("The ELF binary not X86_64.");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    if elf_binary.interpreter().is_some() {
        log::error!(
            "The ELF binary has a dynamic interpreter: {:?}.",
            elf_binary.interpreter()
        );
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let bytes_start = elf_bytes.as_ptr() as u64;
    let mut elf_loader = Loader {
        address_space,
        bytes_start: (bytes_start & (PAGE_SIZE_SMALL - 1) == 0).then_some(bytes_start),
        bytes_len: elf_bytes.len() as u64,
        mapped: [(0, 0); MAX_MAPPED],
        num_mapped: 0,
    };
    elf_binary.load(&mut elf_loader).map_err(|_| -> ErrorCode {
        log::error!("Could not load the kernel ELF binary.");
        moto_rt::E_INVALID_ARGUMENT
    })?;

    Ok(elf_binary.entry_point())
}
